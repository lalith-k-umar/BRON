CCA_CONFIG = {
    "n_generations": 25,
    "population_size": 10,
    "mutation_probability": 0.1,
    "crossover_probability": 0.8,
    "elite_size": 0,
    "tournament_size": 2,
    "n_runs": 25,
}


def get_config():
    return dict(CCA_CONFIG)
