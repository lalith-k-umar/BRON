from typing import Any, Dict, List, Optional, Sequence, Tuple

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


def _safe_resolve_collection_name(db: Any, *aliases: str) -> Optional[str]:
    """Safely resolve collection name if it exists, returning None if absent."""
    try:
        return resolve_collection_name(db, *aliases)
    except (KeyError, Exception):
        return None


def find_highest_rewarding_capec(
    capec_pool: Sequence[str],
    network: Dict[str, float],
    reward_fn: Any,
) -> Tuple[str, float]:
    """Find the single CAPEC in capec_pool that yields the highest attack reward on network."""
    if not capec_pool:
        raise ValueError("capec_pool cannot be empty")
    best_capec = max(
        capec_pool,
        key=lambda capec_id: reward_fn([capec_id], network),
    )
    best_reward = float(reward_fn([best_capec], network))
    return best_capec, best_reward


def get_capec_details(db: Any, capec_id: str) -> Dict[str, Any]:
    """Retrieve metadata for a single CAPEC node."""
    capec_name = resolve_collection_name(db, "capec")
    key = capec_id.split("/")[-1]
    capec_doc = None
    try:
        capec_doc = db.collection(capec_name).get(key)
    except Exception:
        pass

    if not capec_doc:
        aql = f"""
        FOR c IN {capec_name}
          FILTER c._key == @key OR c.original_id == @key OR c._id == @capec_id
          LIMIT 1
          RETURN c
        """
        try:
            rows = list(db.aql.execute(aql, bind_vars={"key": key, "capec_id": capec_id}))
            if rows:
                capec_doc = rows[0]
        except Exception:
            pass

    capec_doc = capec_doc or {}
    metadata = capec_doc.get("metadata", {}) if isinstance(capec_doc.get("metadata"), dict) else {}
    desc = (
        metadata.get("description")
        or metadata.get("extended_description")
        or capec_doc.get("description")
        or ""
    )
    return {
        "id": capec_doc.get("_key", key),
        "name": capec_doc.get("name", key),
        "original_id": capec_doc.get("original_id", ""),
        "description": desc,
        "likelihood": metadata.get("likelihood_of_attack", ""),
        "severity": metadata.get("typical_severity", ""),
    }


def get_capec_linked_cwes(db: Any, capec_id: str) -> List[Dict[str, Any]]:
    """Query all CWE weaknesses linked to a given CAPEC via capec_cwe."""
    capec_coll = resolve_collection_name(db, "capec")
    capec_cwe_coll = resolve_collection_name(db, "capec_cwe", "CapecCwe")
    key = capec_id.split("/")[-1]
    doc_id = f"{capec_coll}/{key}"

    aql = f"""
    FOR cwe IN 1..1 ANY @doc_id {capec_cwe_coll}
      RETURN DISTINCT {{
        id: cwe._key,
        original_id: cwe.original_id,
        name: cwe.name,
        description: (
          cwe.metadata.description != null ? cwe.metadata.description : (
            cwe.metadata.extended_description != null ? cwe.metadata.extended_description : cwe.description
          )
        )
      }}
    """
    try:
        return list(db.aql.execute(aql, bind_vars={"doc_id": doc_id}))
    except Exception:
        return []


def get_capec_linked_cves(
    db: Any, capec_id: str, network_cpes: Optional[Sequence[str]] = None
) -> List[Dict[str, Any]]:
    """Query all CVE vulnerabilities linked to a given CAPEC via CAPEC -> CWE -> CVE."""
    capec_coll = resolve_collection_name(db, "capec")
    capec_cwe_coll = resolve_collection_name(db, "capec_cwe", "CapecCwe")
    cwe_cve_coll = resolve_collection_name(db, "cwe_cve", "CweCve")
    key = capec_id.split("/")[-1]
    doc_id = f"{capec_coll}/{key}"

    cve_cpe_coll = _safe_resolve_collection_name(db, "cve_cpe", "CveCpe")

    if network_cpes and cve_cpe_coll:
        aql = f"""
        FOR cwe IN 1..1 ANY @doc_id {capec_cwe_coll}
          FOR cve IN 1..1 ANY cwe {cwe_cve_coll}
            LET cpes = (
              FOR cpe IN 1..1 ANY cve {cve_cpe_coll}
                RETURN cpe._key
            )
            LET matching_network_cpes = (
              FOR cpe_key IN cpes
                FILTER cpe_key IN @network_cpes
                RETURN cpe_key
            )
            RETURN DISTINCT {{
              id: cve._key,
              original_id: cve.original_id,
              name: cve.name,
              cvss: (
                cve.metadata.weight != null ? cve.metadata.weight : (
                  cve.cvss_score != null ? cve.cvss_score : 0.0
                )
              ),
              description: (
                cve.metadata.description != null ? cve.metadata.description : cve.description
              ),
              via_cwe: cwe._key,
              matching_network_cpes: matching_network_cpes,
              in_network: LENGTH(matching_network_cpes) > 0
            }}
        """
        try:
            return list(
                db.aql.execute(
                    aql,
                    bind_vars={"doc_id": doc_id, "network_cpes": list(network_cpes)},
                )
            )
        except Exception:
            pass

    aql = f"""
    FOR cwe IN 1..1 ANY @doc_id {capec_cwe_coll}
      FOR cve IN 1..1 ANY cwe {cwe_cve_coll}
        RETURN DISTINCT {{
          id: cve._key,
          original_id: cve.original_id,
          name: cve.name,
          cvss: (
            cve.metadata.weight != null ? cve.metadata.weight : (
              cve.cvss_score != null ? cve.cvss_score : 0.0
            )
          ),
          description: (
            cve.metadata.description != null ? cve.metadata.description : cve.description
          ),
          via_cwe: cwe._key,
          matching_network_cpes: [],
          in_network: false
        }}
    """
    try:
        return list(db.aql.execute(aql, bind_vars={"doc_id": doc_id}))
    except Exception:
        return []


def get_capec_linked_d3fend(db: Any, capec_id: str) -> List[Dict[str, Any]]:
    """Query all D3FEND mitigations linked to a CAPEC technique via ATT&CK technique or direct link."""
    capec_coll = resolve_collection_name(db, "capec")
    key = capec_id.split("/")[-1]
    doc_id = f"{capec_coll}/{key}"

    tech_capec_coll = _safe_resolve_collection_name(db, "TechniqueCapec", "technique_capec")
    d3fend_tech_coll = _safe_resolve_collection_name(
        db, "D3fend_mitigationTechnique", "d3fend_mitigation_technique", "d3fend_technique"
    )

    d3fend_results: List[Dict[str, Any]] = []

    # 1. Via ATT&CK Technique: CAPEC <-> Technique <-> D3FEND
    if tech_capec_coll and d3fend_tech_coll:
        aql = f"""
        FOR tech IN 1..1 ANY @doc_id {tech_capec_coll}
          FOR d3 IN 1..1 ANY tech {d3fend_tech_coll}
            RETURN DISTINCT {{
              id: (
                d3.metadata["d3fend-id"] != null ? d3.metadata["d3fend-id"] : (
                  d3.original_id != null ? d3.original_id : d3._key
                )
              ),
              key: d3._key,
              name: d3.name,
              description: (
                d3.metadata.description != null ? d3.metadata.description : d3.description
              ),
              via_technique: tech._key,
              technique_name: tech.name
            }}
        """
        try:
            rows = list(db.aql.execute(aql, bind_vars={"doc_id": doc_id}))
            d3fend_results.extend(rows)
        except Exception:
            pass

    # 2. Check direct edge collection if present
    direct_edge = _safe_resolve_collection_name(db, "capec_d3fend", "CapecD3fend", "d3fend_capec")
    if direct_edge:
        aql_direct = f"""
        FOR d3 IN 1..1 ANY @doc_id {direct_edge}
          RETURN DISTINCT {{
            id: (
              d3.metadata["d3fend-id"] != null ? d3.metadata["d3fend-id"] : (
                d3.original_id != null ? d3.original_id : d3._key
              )
            ),
            key: d3._key,
            name: d3.name,
            description: (
              d3.metadata.description != null ? d3.metadata.description : d3.description
            ),
            via_technique: null,
            technique_name: null
          }}
        """
        try:
            rows = list(db.aql.execute(aql_direct, bind_vars={"doc_id": doc_id}))
            d3fend_results.extend(rows)
        except Exception:
            pass

    # Deduplicate by id / key
    seen = set()
    deduped = []
    for item in d3fend_results:
        item_id = item.get("id") or item.get("key")
        if item_id and item_id not in seen:
            seen.add(item_id)
            deduped.append(item)
    return deduped


def get_capec_linked_artifacts(
    db: Any, capec_id: str, network_cpes: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    """Retrieve CAPEC details along with all linked CWE, CVE, and D3FEND entities."""
    capec_details = get_capec_details(db, capec_id)
    cwes = get_capec_linked_cwes(db, capec_id)
    cves = get_capec_linked_cves(db, capec_id, network_cpes=network_cpes)
    d3fend = get_capec_linked_d3fend(db, capec_id)

    unique_cwes = list({item["id"]: item for item in cwes if item.get("id")}.values())
    unique_cves = list({item["id"]: item for item in cves if item.get("id")}.values())
    unique_d3fend = list(
        {
            (item.get("id") or item.get("key")): item
            for item in d3fend
            if (item.get("id") or item.get("key"))
        }.values()
    )

    return {
        "capec": capec_details,
        "cwes": unique_cwes,
        "cves": unique_cves,
        "d3fend": unique_d3fend,
        "summary": {
            "total_cwes": len(unique_cwes),
            "total_cves": len(unique_cves),
            "network_cves": sum(1 for c in unique_cves if c.get("in_network")),
            "total_d3fend": len(unique_d3fend),
        },
    }


def format_capec_linked_artifacts(
    capec_id: str, linked_data: Dict[str, Any], reward: Optional[float] = None
) -> str:
    """Format linked CAPEC, CWE, CVE, and D3FEND data as a clean readable text report."""
    capec = linked_data.get("capec", {})
    cwes = linked_data.get("cwes", [])
    cves = linked_data.get("cves", [])
    d3fend = linked_data.get("d3fend", [])
    summary = linked_data.get("summary", {})

    lines = [
        "=" * 80,
        "             HIGHEST REWARDING CAPEC TECHNIQUE ANALYSIS",
        "=" * 80,
        f"CAPEC ID:       {capec_id}",
    ]
    if capec.get("name") and capec.get("name") != capec_id:
        lines.append(f"Name:           {capec.get('name')}")
    if reward is not None:
        lines.append(f"Reward Score:   {reward:.3f}")
    if capec.get("likelihood"):
        lines.append(f"Likelihood:     {capec.get('likelihood')}")
    if capec.get("severity"):
        lines.append(f"Severity:       {capec.get('severity')}")
    if capec.get("description"):
        desc = capec["description"].strip().replace("\n", " ")
        if len(desc) > 160:
            desc = desc[:157] + "..."
        lines.append(f"Description:    {desc}")

    # CWE Section
    lines.append("-" * 80)
    lines.append(f"LINKED CWE (Weaknesses): {len(cwes)} found")
    lines.append("-" * 80)
    if not cwes:
        lines.append("  (None found)")
    else:
        for item in cwes:
            cwe_id = item.get("id") or item.get("original_id") or "Unknown"
            name = item.get("name") or "No name available"
            lines.append(f"  * [{cwe_id}] {name}")
            if item.get("description"):
                desc = item["description"].strip().replace("\n", " ")
                if len(desc) > 120:
                    desc = desc[:117] + "..."
                lines.append(f"      {desc}")

    # CVE Section
    net_cves = summary.get("network_cves", sum(1 for c in cves if c.get("in_network")))
    lines.append("-" * 80)
    lines.append(f"LINKED CVE (Vulnerabilities): {len(cves)} found ({net_cves} active on network)")
    lines.append("-" * 80)
    if not cves:
        lines.append("  (None found)")
    else:
        sorted_cves = sorted(
            cves, key=lambda c: (0 if c.get("in_network") else 1, -float(c.get("cvss") or 0.0))
        )
        for item in sorted_cves:
            cve_id = item.get("id") or item.get("original_id") or "Unknown"
            cvss = float(item.get("cvss") or 0.0)
            status = " [ACTIVE ON NETWORK]" if item.get("in_network") else ""
            via = f" (via {item['via_cwe']})" if item.get("via_cwe") else ""
            lines.append(f"  * [{cve_id}] CVSS: {cvss:.1f}{status}{via}")
            if item.get("description"):
                desc = item["description"].strip().replace("\n", " ")
                if len(desc) > 120:
                    desc = desc[:117] + "..."
                lines.append(f"      {desc}")

    # D3FEND Section
    lines.append("-" * 80)
    lines.append(f"LINKED D3FEND (Defensive Mitigations): {len(d3fend)} found")
    lines.append("-" * 80)
    if not d3fend:
        lines.append("  (None found)")
    else:
        for item in d3fend:
            d3_id = item.get("id") or item.get("key") or "Unknown"
            name = item.get("name") or "No name available"
            tech_info = ""
            if item.get("via_technique"):
                tech_label = item["via_technique"]
                if item.get("technique_name"):
                    tech_label += f": {item['technique_name']}"
                tech_info = f" (via ATT&CK Technique {tech_label})"
            lines.append(f"  * [{d3_id}] {name}{tech_info}")
            if item.get("description"):
                desc = item["description"].strip().replace("\n", " ")
                if len(desc) > 120:
                    desc = desc[:117] + "..."
                lines.append(f"      {desc}")

    lines.append("=" * 80)
    return "\n".join(lines)


def display_capec_linked_artifacts(
    capec_id: str, linked_data: Dict[str, Any], reward: Optional[float] = None
) -> None:
    """Print the formatted report of linked CWE, CVE, and D3FEND to stdout."""
    output = format_capec_linked_artifacts(capec_id, linked_data, reward=reward)
    print(output, flush=True)

