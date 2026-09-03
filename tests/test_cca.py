import json

from bron_cca.config import CCA_CONFIG
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
