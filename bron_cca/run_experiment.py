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
    results = []
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
        history["seed"] = seed
        history["config"] = {
            "n_generations": args.n_generations,
            "population_size": args.population_size,
            "mutation_probability": args.mutation_probability,
            "crossover_probability": args.crossover_probability,
            "elite_size": args.elite_size,
            "tournament_size": args.tournament_size,
        }
        history["pools"] = {
            "capecs": list(capec_pool),
            "cpes": list(cpe_pool),
        }
        history["base_network"] = {
            "size": len(base_network),
            "total_weight": float(sum(base_network.values())),
        }
        results.append(history)
    return results


def find_and_display_best_capec_artifacts(
    capec_pool,
    network,
    reward_fn,
    db=None,
    network_cpes=None,
):
    """Convenience helper to find highest rewarding CAPEC and display its linked CVE, CWE, and D3FEND."""
    from .bron_client import (
        display_capec_linked_artifacts,
        find_highest_rewarding_capec,
        get_capec_linked_artifacts,
    )

    best_capec, best_reward = find_highest_rewarding_capec(capec_pool, network, reward_fn)
    print(f"best CAPEC: {best_capec} (reward: {best_reward:.3f})", flush=True)
    if db is not None:
        cpes = network_cpes if network_cpes is not None else list(network.keys())
        linked = get_capec_linked_artifacts(db, best_capec, network_cpes=cpes)
        display_capec_linked_artifacts(best_capec, linked, reward=best_reward)
        return best_capec, best_reward, linked
    return best_capec, best_reward, None


if __name__ == "__main__":
    raise SystemExit("Use run_experiment.run_experiment() from Python rather than executing this directly.")

