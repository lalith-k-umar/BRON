import json
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Sequence

from arango import ArangoClient


DEFAULT_DB_NAME = "BRON"
DEFAULT_HOST = "http://127.0.0.1:8529"


def get_db(username: str = "root", password: str = "", db_name: str = DEFAULT_DB_NAME, host: str = DEFAULT_HOST):
    client = ArangoClient(hosts=host)
    return client.db(db_name, username=username, password=password, auth_method="basic")


def get_all_capecs(db: Any) -> List[Dict[str, str]]:
    aql = """
    FOR c IN capec
      RETURN {id: c._key, name: c.name}
    """
    return list(db.aql.execute(aql))


def get_all_cpe_ids(db: Any) -> List[str]:
    aql = """
    FOR c IN cpe
      RETURN c._key
    """
    return [row for row in db.aql.execute(aql)]


def get_collection_names(db: Any) -> List[str]:
    return sorted(c["name"] for c in db.collections() if not c["name"].startswith("_"))


def sample_reachable_cpes(db: Any, n: int = 20) -> List[str]:
    """Return a sample of reachable CPEs that are connected to CAPEC-derived CVEs.

    This is intentionally permissive because the exact collection names may vary between
    BRON snapshots. The implementation probes for the relevant edges and falls back to
    the stable names used by the build pipeline in this repo.
    """
    candidates = []
    for cpe_collection in ("cpe", "software"):
        if cpe_collection not in get_collection_names(db):
            continue
        try:
            aql = """
            FOR cve IN cve
              FILTER cve.cpe_ids != null
              LET has_path = (
                FOR v IN 1..1 INBOUND cve cwe_cve
                  RETURN 1
              )
              FILTER LENGTH(has_path) > 0
              FOR cpe_id IN cve.cpe_ids
                RETURN DISTINCT cpe_id
            """
            rows = list(db.aql.execute(aql))
            if rows:
                candidates.extend(rows)
        except Exception:
            continue

    seen = []
    for item in candidates:
        if item not in seen:
            seen.append(item)
    return seen[:n]


def infer_cve_score_field(doc: Dict[str, Any]) -> Any:
    for key in ("cvss_score", "cvssV3_baseScore", "base_score", "score"):
        if key in doc:
            return doc[key]
    for key in ("metrics", "cvss"):
        if isinstance(doc.get(key), dict):
            for nested_key in ("cvssV3_baseScore", "baseScore", "score"):
                if nested_key in doc[key]:
                    return doc[key][nested_key]
    return 0.0


def _build_capec_cache(db: Any, capec_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    cached: Dict[str, List[Dict[str, Any]]] = {}
    capec_names = set(capec_ids)
    for capec_id in capec_names:
        aql = """
        FOR cwe IN 1..1 OUTBOUND CONCAT('capec/', @capec_id) capec_cwe
          FOR cve IN 1..1 OUTBOUND cwe cwe_cve
            FILTER cve.cpe_ids != null
            FOR cpe_id IN cve.cpe_ids
              RETURN DISTINCT {cve: cve._key, cpe: cpe_id, cvss: cve.cvss_score}
        """
        rows = list(db.aql.execute(aql, bind_vars={"capec_id": capec_id}))
        normalized = []
        for row in rows:
            score = row.get("cvss")
            if score is None and row.get("cve"):
                cve_doc = db.collection("cve").get(row["cve"])
                score = infer_cve_score_field(cve_doc)
            if score is not None:
                normalized.append({"cve": row.get("cve"), "cpe": row.get("cpe"), "cvss": float(score)})
        cached[capec_id] = normalized
    return cached


def build_capec_cache(db: Any, capec_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return _build_capec_cache(db, capec_ids)


def evaluate_attack(db: Any, capec_ids: Sequence[str], network: Dict[str, float]) -> float:
    """Compute the attack reward for a triplet of CAPECs against a network mapping CPE to counts."""
    network_cpes = set(network.keys())
    seen = set()
    total = 0.0
    for capec_id in capec_ids:
        aql = """
        FOR cwe IN 1..1 OUTBOUND CONCAT('capec/', @capec_id) capec_cwe
          FOR cve IN 1..1 OUTBOUND cwe cwe_cve
            FILTER cve.cpe_ids != null
            FOR cpe_id IN cve.cpe_ids
              FILTER cpe_id IN @network_cpes
              RETURN DISTINCT {cve: cve._key, cpe: cpe_id, cvss: cve.cvss_score}
        """
        rows = list(db.aql.execute(aql, bind_vars={"capec_id": capec_id, "network_cpes": list(network_cpes)}))
        for row in rows:
            cpe = row.get("cpe")
            cvss = row.get("cvss")
            if cpe in network_cpes and cvss is not None:
                key = (row.get("cve"), cpe)
                if key in seen:
                    continue
                seen.add(key)
                total += float(cvss) * float(network.get(cpe, 0))
    return total


def introspect_db(db: Any) -> Dict[str, List[str]]:
    collections = db.collections()
    return {"collections": sorted(c["name"] for c in collections if not c["name"].startswith("_"))}
