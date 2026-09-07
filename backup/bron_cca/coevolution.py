import random
from typing import Callable, List, Sequence, Tuple

import numpy as np

from .environment import apply_patches
from .genome import Genome


def tournament_select(pop, fitnesses, k=2):
    idxs = random.sample(range(len(pop)), k)
    best = max(idxs, key=lambda i: fitnesses[i])
    return pop[best]


def evolve_population(pop, fitnesses, p_mut, p_cx, elite_size, tourn_size):
    ranked = sorted(zip(pop, fitnesses), key=lambda x: -x[1])
    new_pop = [g for g, _ in ranked[:elite_size]]
    while len(new_pop) < len(pop):
        p1 = tournament_select(pop, fitnesses, tourn_size)
        p2 = tournament_select(pop, fitnesses, tourn_size)
        c1, c2 = Genome.crossover(p1, p2, p_cx)
        c1.mutate(p_mut)
        c2.mutate(p_mut)
        new_pop.extend([c1, c2])
    return new_pop[: len(pop)]


def mean_reward_of_population(attacker_pop, defender_pop, capec_pool, cpe_pool, base_network, reward_fn):
    attacker_rewards = []
    for atk in attacker_pop:
        atk_capecs = atk.decode(capec_pool)
        pairing_rewards = []
        for dfn in defender_pop:
            patched = dfn.decode(cpe_pool)
            network = apply_patches(base_network, patched)
            pairing_rewards.append(reward_fn(atk_capecs, network))
        attacker_rewards.append(np.mean(pairing_rewards))
    return attacker_rewards


def run_cca(
    n_generations,
    pop_size,
    p_mut,
    p_cx,
    elite_size,
    tourn_size,
    capec_pool,
    cpe_pool,
    base_network,
    reward_fn,
    seed=0,
):
    random.seed(seed)
    attacker_pop = [Genome(len(capec_pool)) for _ in range(pop_size)]
    defender_pop = [Genome(len(cpe_pool)) for _ in range(pop_size)]

    history = {"attacker_reward": [], "defender_reward": []}

    for gen in range(n_generations):
        atk_fitness = mean_reward_of_population(
            attacker_pop, defender_pop, capec_pool, cpe_pool, base_network, reward_fn
        )
        attacker_pop = evolve_population(
            attacker_pop, atk_fitness, p_mut, p_cx, elite_size, tourn_size
        )

        def_fitness = []
        for dfn in defender_pop:
            patched = dfn.decode(cpe_pool)
            network = apply_patches(base_network, patched)
            rewards = [reward_fn(atk.decode(capec_pool), network) for atk in attacker_pop]
            def_fitness.append(-np.mean(rewards))
        defender_pop = evolve_population(
            defender_pop, def_fitness, p_mut, p_cx, elite_size, tourn_size
        )

        history["attacker_reward"].append(np.mean(atk_fitness))
        history["defender_reward"].append(np.mean(def_fitness))
        print(
            f"Gen {gen:3d} | mean attacker reward: {np.mean(atk_fitness):.3f}",
            flush=True,
        )

    return attacker_pop, defender_pop, history
