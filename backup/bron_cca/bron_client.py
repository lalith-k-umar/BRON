from typing import Any, Dict, List, Optional, Sequence

from arango import ArangoClient


DEFAULT_DB_NAME = "BRON"
DEFAULT_HOST = "http://127.0.0.1:8529"


def resolve_collection_name(db: Any, *aliases: str) -> str:
    names = {c["name"] for c in db.collections() if not c["name"].startswith("_")}
    for alias in aliases:
        if alias in names:
            return alias
        lowercase = alias.lower()
        if lowercase in names:
            return lowercase
        title = alias[:1].upper() + alias[1:]
        if title in names:
            return title
        camel = "".join(part[:1].upper() + part[1:] for part in alias.split("_"))
        if camel in names:
            return camel
    raise KeyError(f"None of {aliases} found in BRON collections: {sorted(names)}")


def get_db(username: str = "root", password: str = "", db_name: str = DEFAULT_DB_NAME, host: str = DEFAULT_HOST):
    client = ArangoClient(hosts=host)
    return client.db(db_name, username=username, password=password, auth_method="basic")


def get_all_capecs(db: Any) -> List[Dict[str, str]]:
    capec_name = resolve_collection_name(db, "capec")
    aql = f"""
    FOR c IN {capec_name}
      RETURN {{id: c._key, name: c.name}}
    """
    return list(db.aql.execute(aql))


def get_all_cpe_ids(db: Any, limit: Optional[int] = None) -> List[str]:
    cpe_name = resolve_collection_name(db, "cpe")
    limit_clause = f"LIMIT {int(limit)}" if limit is not None else ""
    aql = f"""
    FOR c IN {cpe_name}
      {limit_clause}
      RETURN c._key
    """
    return list(db.aql.execute(aql))


def get_collection_names(db: Any) -> List[str]:
    return sorted(c["name"] for c in db.collections() if not c["name"].startswith("_"))


def _edge_names(db: Any) -> Dict[str, str]:
    return {
        "capec": resolve_collection_name(db, "capec"),
        "cpe": resolve_collection_name(db, "cpe"),
        "cve": resolve_collection_name(db, "cve"),
        "capec_cwe": resolve_collection_name(db, "capec_cwe", "CapecCwe"),
        "cwe_cve": resolve_collection_name(db, "cwe_cve", "CweCve"),
        "cve_cpe": resolve_collection_name(db, "cve_cpe", "CveCpe"),
    }


def sample_reachable_cpes(db: Any, n: int = 20) -> List[str]:
    """Return CPEs that sit on a CAPEC -> CWE -> CVE -> CPE path."""
    names = _edge_names(db)
    fetch = max(int(n) * 25, 100)
    aql = f"""
    FOR capec IN {names['capec']}
      FOR cwe IN 1..1 OUTBOUND capec {names['capec_cwe']}
        FOR cve IN 1..1 OUTBOUND cwe {names['cwe_cve']}
          FOR cpe IN 1..1 OUTBOUND cve {names['cve_cpe']}
            LIMIT {fetch}
            RETURN DISTINCT cpe._key
    """
    rows = list(db.aql.execute(aql))
    seen: List[str] = []
    for item in rows:
        if item not in seen:
            seen.append(item)
        if len(seen) >= n:
            break
    return seen[:n]


def infer_cve_score_field(doc: Dict[str, Any]) -> Any:
    metadata = doc.get("metadata")
    if isinstance(metadata, dict) and metadata.get("weight") is not None:
        return metadata["weight"]
    for key in ("cvss_score", "cvssV3_baseScore", "base_score", "score"):
        if key in doc:
            return doc[key]
    for key in ("metrics", "cvss"):
        if isinstance(doc.get(key), dict):
            for nested_key in ("cvssV3_baseScore", "baseScore", "score"):
                if nested_key in doc[key]:
                    return doc[key][nested_key]
    return 0.0


def _normalize_cache_row(row: Dict[str, Any], db: Any) -> Optional[Dict[str, Any]]:
    score = row.get("cvss")
    if score is None and row.get("cve"):
        cve_name = resolve_collection_name(db, "cve")
        cve_doc = db.collection(cve_name).get(row["cve"])
        score = infer_cve_score_field(cve_doc or {})
    if score is None or row.get("cpe") is None:
        return None
    return {"cve": row.get("cve"), "cpe": row.get("cpe"), "cvss": float(score)}


def _build_capec_cache_from_network(
    db: Any, capec_ids: Sequence[str], network_cpes: Sequence[str]
) -> Dict[str, List[Dict[str, Any]]]:
    names = _edge_names(db)
    capec_set = list(set(capec_ids))
    aql = f"""
    FOR cpe IN {names['cpe']}
      FILTER cpe._key IN @network_cpes
      FOR cve IN 1..1 INBOUND cpe {names['cve_cpe']}
        FOR cwe IN 1..1 INBOUND cve {names['cwe_cve']}
          FOR capec IN 1..1 INBOUND cwe {names['capec_cwe']}
            FILTER capec._key IN @capec_ids
            RETURN DISTINCT {{
              capec: capec._key,
              cve: cve._key,
              cpe: cpe._key,
              cvss: cve.metadata.weight
            }}
    """
    rows = list(
        db.aql.execute(
            aql,
            bind_vars={"network_cpes": list(network_cpes), "capec_ids": capec_set},
        )
    )
    cached: Dict[str, List[Dict[str, Any]]] = {cid: [] for cid in capec_set}
    for row in rows:
        normalized = _normalize_cache_row(row, db)
        if normalized is None:
            continue
        cached.setdefault(row["capec"], []).append(normalized)
    return cached


def _build_capec_cache(db: Any, capec_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    cached: Dict[str, List[Dict[str, Any]]] = {}
    names = _edge_names(db)
    for capec_id in set(capec_ids):
        aql = f"""
        FOR cwe IN 1..1 OUTBOUND CONCAT(@capec_coll, '/', @capec_id) {names['capec_cwe']}
          FOR cve IN 1..1 OUTBOUND cwe {names['cwe_cve']}
            FOR cpe IN 1..1 OUTBOUND cve {names['cve_cpe']}
              RETURN DISTINCT {{cve: cve._key, cpe: cpe._key, cvss: cve.metadata.weight}}
        """
        rows = list(
            db.aql.execute(
                aql,
                bind_vars={"capec_id": capec_id, "capec_coll": names["capec"]},
            )
        )
        cached[capec_id] = [row for row in (_normalize_cache_row(r, db) for r in rows) if row]
    return cached


def build_capec_cache(
    db: Any,
    capec_ids: Sequence[str],
    network_cpes: Optional[Sequence[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    if network_cpes:
        return _build_capec_cache_from_network(db, capec_ids, network_cpes)
    return _build_capec_cache(db, capec_ids)


def evaluate_attack_cached(
    cache: Dict[str, List[Dict[str, Any]]],
    capec_ids: Sequence[str],
    network: Dict[str, float],
) -> float:
    network_cpes = set(network)
    seen = set()
    total = 0.0
    for capec_id in capec_ids:
        for row in cache.get(capec_id, ()):
            cpe = row.get("cpe")
            cvss = row.get("cvss")
            if cpe not in network_cpes or cvss is None:
                continue
            key = (row.get("cve"), cpe)
            if key in seen:
                continue
            seen.add(key)
            total += float(cvss) * float(network.get(cpe, 0))
    return total


def evaluate_attack(db: Any, capec_ids: Sequence[str], network: Dict[str, float]) -> float:
    """Compute the attack reward for a triplet of CAPECs against a network mapping CPE to counts."""
    names = _edge_names(db)
    network_cpes = list(network.keys())
    aql = f"""
    FOR capec_id IN @capec_ids
      FOR cwe IN 1..1 OUTBOUND CONCAT(@capec_coll, '/', capec_id) {names['capec_cwe']}
        FOR cve IN 1..1 OUTBOUND cwe {names['cwe_cve']}
          FOR cpe IN 1..1 OUTBOUND cve {names['cve_cpe']}
            FILTER cpe._key IN @network_cpes
            RETURN DISTINCT {{cve: cve._key, cpe: cpe._key, cvss: cve.metadata.weight}}
    """
    rows = list(
        db.aql.execute(
            aql,
            bind_vars={
                "capec_ids": list(capec_ids),
                "network_cpes": network_cpes,
                "capec_coll": names["capec"],
            },
        )
    )
    seen = set()
    total = 0.0
    for row in rows:
        normalized = _normalize_cache_row(row, db)
        if normalized is None:
            continue
        cpe = normalized["cpe"]
        key = (normalized["cve"], cpe)
        if key in seen:
            continue
        seen.add(key)
        total += normalized["cvss"] * float(network.get(cpe, 0))
    return total


def introspect_db(db: Any) -> Dict[str, List[str]]:
    collections = db.collections()
    return {"collections": sorted(c["name"] for c in collections if not c["name"].startswith("_"))}
