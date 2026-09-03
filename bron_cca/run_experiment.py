import argparse
import random

from .config import CCA_CONFIG
from .coevolution import run_cca


def parse_args():
    parser = argparse.ArgumentParser(description="Run CCA experiment against BRON")
    parser.add_argument("--n-generations", type=int, default=CCA_CONFIG["n_generations"])
    parser.add_argument("--population-size", type=int, default=CCA_CONFIG["population_size"])
    parser.add_argument("--mutation-probability", type=float, default=CCA_CONFIG["mutation_probability"])
    parser.add_argument("--crossover-probability", type=float, default=CCA_CONFIG["crossover_probability"])
    parser.add_argument("--elite-size", type=int, default=CCA_CONFIG["elite_size"])
    parser.add_argument("--tournament-size", type=int, default=CCA_CONFIG["tournament_size"])
    parser.add_argument("--n-runs", type=int, default=CCA_CONFIG["n_runs"])
    parser.add_argument("--seed", type=int, default=0)
    return parser.parse_args()


def run_experiment(capec_pool, cpe_pool, base_network, reward_fn, args=None):
    args = parse_args() if args is None else args
    histories = []
    for i in range(args.n_runs):
        seed = args.seed + i
        _, _, history = run_cca(
            n_generations=args.n_generations,
            pop_size=args.population_size,
            p_mut=args.mutation_probability,
            p_cx=args.crossover_probability,
            elite_size=args.elite_size,
            tourn_size=args.tournament_size,
            capec_pool=capec_pool,
            cpe_pool=cpe_pool,
            base_network=base_network,
            reward_fn=reward_fn,
            seed=seed,
        )
        histories.append(history)
    return histories


if __name__ == "__main__":
    raise SystemExit("Use run_experiment.run_experiment() from Python rather than executing this directly.")
