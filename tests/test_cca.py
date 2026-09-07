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
