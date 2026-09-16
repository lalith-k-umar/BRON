import json
from types import SimpleNamespace

from bron_cca.config import CCA_CONFIG
from bron_cca.coevolution import run_cca
from bron_cca.run_experiment import run_experiment
from bron_cca.environment import apply_patches
from bron_cca.genome import Genome


def test_cca_config_values_match_paper_defaults():
    assert CCA_CONFIG["population_size"] == 10
    assert CCA_CONFIG["mutation_probability"] == 0.1
    assert CCA_CONFIG["crossover_probability"] == 0.8
    assert CCA_CONFIG["elite_size"] == 0
    assert CCA_CONFIG["tournament_size"] == 2


def test_apply_patches_removes_selected_cpes():
    network = {"cpe:a": 2, "cpe:b": 1, "cpe:c": 3}
    updated = apply_patches(network, ["cpe:b", "cpe:c"])
    assert updated == {"cpe:a": 2}


def test_genome_crossover_and_mutation_preserve_pool_size():
    a = Genome(5, [0, 1, 2])
    b = Genome(5, [4, 3, 2])
    c1, c2 = Genome.crossover(a, b, p_cx=1.0)
    assert max(c1.genes) < 5
    assert max(c2.genes) < 5
    c1.mutate(p_mut=1.0)
    assert len(c1.genes) == 3
    assert all(0 <= gene < 5 for gene in c1.genes)


def test_cca_history_is_json_safe_and_explains_final_strategies():
    capecs = ["CAPEC-1", "CAPEC-2", "CAPEC-3"]
    cpes = ["cpe:1", "cpe:2", "cpe:3"]
    _, _, history = run_cca(
        n_generations=2,
        pop_size=4,
        p_mut=0.0,
        p_cx=0.0,
        elite_size=0,
        tourn_size=2,
        capec_pool=capecs,
        cpe_pool=cpes,
        base_network={cpe: 1 for cpe in cpes},
        reward_fn=lambda attacks, network: len(attacks) + len(network),
        seed=7,
    )

    json.dumps(history)
    assert len(history["generation_metrics"]) == 2
    assert history["evaluation_timing"]["attacker"] == "before_attacker_evolution"
    assert all(
        action in capecs
        for record in history["final_attacker_population"]
        for action in record["actions"]
    )


def test_run_experiment_preserves_seed_and_configuration_metadata():
    args = SimpleNamespace(
        n_generations=1,
        population_size=4,
        mutation_probability=0.0,
        crossover_probability=0.0,
        elite_size=0,
        tournament_size=2,
        n_runs=2,
        seed=11,
    )
    results = run_experiment(
        ["CAPEC-1", "CAPEC-2", "CAPEC-3"],
        ["cpe:1", "cpe:2", "cpe:3"],
        {"cpe:1": 1, "cpe:2": 1, "cpe:3": 1},
        lambda attacks, network: len(attacks) + len(network),
        args=args,
    )

    assert [result["seed"] for result in results] == [11, 12]
    assert results[0]["config"]["population_size"] == 4
    assert results[0]["base_network"] == {"size": 3, "total_weight": 3.0}


def test_find_highest_rewarding_capec():
    from bron_cca.bron_client import find_highest_rewarding_capec

    pool = ["CA-1", "CA-2", "CA-3"]
    network = {"cpe:1": 1}
    scores = {"CA-1": 4.5, "CA-2": 9.8, "CA-3": 2.1}
    best, reward = find_highest_rewarding_capec(
        pool, network, lambda attacks, net: scores[attacks[0]]
    )
    assert best == "CA-2"
    assert reward == 9.8


def test_format_capec_linked_artifacts():
    from bron_cca.bron_client import format_capec_linked_artifacts

    linked_data = {
        "capec": {
            "id": "CA-117",
            "name": "Interception",
            "description": "An adversary intercepts communication between components.",
            "likelihood": "High",
            "severity": "High",
        },
        "cwes": [
            {
                "id": "CWE-319",
                "original_id": "319",
                "name": "Cleartext Transmission of Sensitive Information",
                "description": "The application transmits sensitive data unencrypted.",
            }
        ],
        "cves": [
            {
                "id": "CVE-2021-9999",
                "original_id": "CVE-2021-9999",
                "name": "Vulnerability in Service",
                "cvss": 7.5,
                "description": "Allows cleartext sniffing.",
                "via_cwe": "CWE-319",
                "in_network": True,
            }
        ],
        "d3fend": [
            {
                "id": "D3-NTF",
                "name": "Network Traffic Filtering",
                "via_technique": "T1040",
                "technique_name": "Network Sniffing",
                "description": "Filter network traffic to block unauthorized interception.",
            }
        ],
        "summary": {
            "total_cwes": 1,
            "total_cves": 1,
            "network_cves": 1,
            "total_d3fend": 1,
        },
    }

    report = format_capec_linked_artifacts("CA-117", linked_data, reward=7.5)
    assert "CA-117" in report
    assert "Interception" in report
    assert "Reward Score:   7.500" in report
    assert "CWE-319" in report
    assert "CVE-2021-9999" in report
    assert "[ACTIVE ON NETWORK]" in report
    assert "D3-NTF" in report
    assert "T1040" in report


def test_dashboard_renders_linked_capec_artifacts():
    from bron_cca.dashboard import build_dashboard_html

    results = {
        "runs": [
            {
                "attacker_reward": [1.0, 2.0],
                "defender_reward": [-1.0, -2.0],
                "generation_metrics": [
                    {"asynchronous_zero_sum_residual": 0.0},
                    {"asynchronous_zero_sum_residual": 0.0},
                ],
                "final_attacker_population": [{"actions": ["CA-1"], "genes": [0]}],
                "final_defender_population": [{"actions": ["cpe:1"], "genes": [0]}],
            }
        ],
        "highest_rewarding_capec": {
            "id": "CA-117",
            "reward": 8.5,
            "linked_artifacts": {
                "capec": {"id": "CA-117", "name": "Interception"},
                "cwes": [{"id": "CWE-319", "name": "Cleartext Transmission"}],
                "cves": [{"id": "CVE-2021-9999", "cvss": 8.5, "in_network": True}],
                "d3fend": [{"id": "D3-NTF", "name": "Network Traffic Filtering"}],
            },
        },
    }

    html = build_dashboard_html(results)
    assert "Highest Rewarding CAPEC Technique: CA-117" in html
    assert "CWE-319" in html
    assert "CVE-2021-9999" in html
    assert "D3-NTF" in html


def test_get_capec_linked_artifacts_with_mock_db():
    from unittest.mock import MagicMock
    from bron_cca.bron_client import get_capec_linked_artifacts

    mock_db = MagicMock()
    mock_db.collections.return_value = [
        {"name": "capec"},
        {"name": "cwe"},
        {"name": "cve"},
        {"name": "cpe"},
        {"name": "capec_cwe"},
        {"name": "cwe_cve"},
        {"name": "cve_cpe"},
        {"name": "TechniqueCapec"},
        {"name": "D3fend_mitigationTechnique"},
    ]

    capec_doc = {
        "_key": "CA-117",
        "name": "Interception",
        "original_id": "117",
        "metadata": {"description": "Adversary intercepts data", "typical_severity": "High"},
    }
    mock_db.collection.return_value.get.return_value = capec_doc

    def mock_aql_execute(query, bind_vars=None):
        bind_vars = bind_vars or {}
        if "capec_cwe" in query and "cwe_cve" not in query:
            return [{"id": "CWE-319", "name": "Cleartext Transmission", "description": "Unencrypted"}]
        elif "cwe_cve" in query:
            return [
                {
                    "id": "CVE-2021-1234",
                    "original_id": "CVE-2021-1234",
                    "name": "Buffer Overflow",
                    "cvss": 7.5,
                    "description": "Network flaw",
                    "via_cwe": "CWE-319",
                    "matching_network_cpes": ["cpe:1"],
                    "in_network": True,
                }
            ]
        elif "D3fend_mitigationTechnique" in query:
            return [
                {
                    "id": "D3-NTF",
                    "name": "Network Traffic Filtering",
                    "description": "Filter traffic",
                    "via_technique": "T1040",
                    "technique_name": "Network Sniffing",
                }
            ]
        return []

    mock_db.aql.execute.side_effect = mock_aql_execute

    data = get_capec_linked_artifacts(mock_db, "CA-117", network_cpes=["cpe:1"])
    assert data["capec"]["id"] == "CA-117"
    assert data["capec"]["name"] == "Interception"
    assert len(data["cwes"]) == 1
    assert data["cwes"][0]["id"] == "CWE-319"
    assert len(data["cves"]) == 1
    assert data["cves"][0]["id"] == "CVE-2021-1234"
    assert data["cves"][0]["in_network"] is True
    assert len(data["d3fend"]) == 1
    assert data["d3fend"][0]["id"] == "D3-NTF"
    assert data["summary"]["network_cves"] == 1


