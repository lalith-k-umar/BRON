# Implementing the BRON Competitive Coevolutionary Algorithm (CCA)
### Based on Section 3.3, Hemberg et al., "Enhancements to Threat, Vulnerability, and Mitigation Knowledge for Cyber Analytics, Hunting, and Simulations" (Digital Threats: Research and Practice, 2024)

Repo: [ALFA-group/BRON](https://github.com/ALFA-group/BRON)

---

## 0. What the paper actually describes (recap before coding)

Section 3.3 models a cyberattack as a **zero-sum, simultaneous-move game** between an attacker and a defender, played on a network. BRON's property graph is used as a **reward oracle** — it doesn't run the game itself, it just supplies the CVSS-based payoff for a chosen attack/defense pair. Two ML methods are compared for finding the Nash Equilibrium: **MARL** (out of scope here) and **CCA** (what you're building).

Key modeling decisions from the paper, which your implementation must reproduce:

| Element | Paper's definition |
|---|---|
| Attacker action | Select **3 CAPEC attack patterns** (a "triplet") from the CAPEC repository |
| Defender action | Select **3 CPE software configurations** to patch (increment to next version) |
| Network | An enterprise network model = a map of `{CPE: occurrence_count}`, 20 unique configs in the paper |
| Reward (attacker) | Sum of CVSS scores of every CPE on the network that is reachable from the chosen CAPECs via `CAPEC → CWE → CVE → CPE`, filtered to CPEs actually present on the network |
| Reward (defender) | `-reward(attacker)` (zero-sum / minimax) |
| Equilibrium concept | Mixed-strategy Nash Equilibrium — a **population** in CCA approximates a distribution over strategies, so mean population fitness ≈ expected reward of the mixed strategy |
| Algorithm family | Grammatical Evolution / genetic-algorithm-style coevolution: two populations (attack, defense) evolved in **alternating steps** — evolve+evaluate attackers against current defenders, then evolve+evaluate defenders against current (updated) attackers |
| Hyperparameters used (Table 16) | mutation prob. 0.1, crossover prob. 0.8, elite size 0, tournament size 2, population size 10 |

This is **not** a generic GA — the fitness function is entirely delegated to BRON graph traversals, so most of your engineering effort is in the query layer, not the evolutionary operators.

---

## 1. Prerequisites checklist

- [ ] ArangoDB running on WSL and reachable (default `http://127.0.0.1:8529`)
- [ ] BRON built into ArangoDB via `tutorials/build_bron.py` — confirm `build_bron.log` ends with `END building BRON`
- [ ] `python-arango` installed in your venv (`pip install python-arango`)
- [ ] Confirm the exact collection/edge names in your BRON instance — these can shift slightly between BRON versions, so **do not hardcode blindly**; introspect first:

```python
from arango import ArangoClient

client = ArangoClient(hosts="http://127.0.0.1:8529")
db = client.db("BRON", username="root", password="<your_pwd>")

print(sorted(c["name"] for c in db.collections() if not c["name"].startswith("_")))
```

Look for node collections resembling `capec`, `cwe`, `cve`, `technique`, `tactic`, `d3fend_mitigation`, etc., and edge collections resembling `capec_cwe`, `cwe_cve`, `cve_cpe` (or similarly named `*_link` / `*_edge` collections). Record the **actual names** you find — you'll plug them into the queries in Section 3. If your BRON build differs from what's below, adjust collection names accordingly; the AQL *pattern* stays the same.

---

## 2. Project layout

```
bron_cca/
├── bron_client.py        # thin wrapper around python-arango + AQL queries
├── environment.py         # Network model + reward function (the "oracle" call)
├── genome.py               # Attack/Defense genome representation + operators
├── coevolution.py         # CCA main loop (alternating GA)
├── config.py                # Hyperparameters (Table 16) + CLI args
├── evaluate.py             # Reward-vs-generation plotting (reproduces Fig. 3)
└── run_experiment.py     # entrypoint: n runs, seeds, output logging
```

---

## 3. BRON query layer (`bron_client.py`)

You need three query capabilities:

### 3.1 Pull the CAPEC universe (attacker's gene pool)

```python
def get_all_capecs(db):
    aql = """
    FOR c IN capec
      RETURN {id: c._key, name: c.name}
    """
    return list(db.aql.execute(aql))
```

### 3.2 Pull the CPE universe restricted to your simulated network

You are NOT pulling all CPEs in BRON (there are ~250k) — the paper fixes a **20-CPE enterprise network**. Define this network as a static config file (`network.json`) mapping CPE strings to occurrence counts, e.g.:

```json
{
  "cpe:2.3:a:apache:struts:2.5.16:*:*:*:*:*:*:*": 4,
  "cpe:2.3:a:php:phpmyadmin:4.8.0:*:*:*:*:*:*:*": 2,
  "...": 1
}
```

Populate this from BRON itself once, by sampling CPEs that actually have `CVE → CWE → CAPEC` paths (so your network isn't full of unreachable dead ends):

```python
def sample_reachable_cpes(db, n=20):
    aql = """
    FOR cve IN cve
      FILTER LENGTH(cve.cpe_ids) > 0
      LET has_cwe = (
        FOR v IN 1..1 INBOUND cve cwe_cve
          RETURN 1
      )
      FILTER LENGTH(has_cwe) > 0
      LIMIT 2000
      RETURN cve
    """
    # then join to cwe -> capec to confirm a full path exists, dedupe CPEs, sample n
    ...
```
(Adapt collection/edge names per your Section-1 introspection.)

### 3.3 The reward oracle: CAPEC triplet → CVSS sum over the network

This is the core BRON call, executed once per attacker genome per generation:

```python
def evaluate_attack(db, capec_ids: list[str], network: dict[str, float]) -> float:
    """
    Traverses CAPEC -> CWE -> CVE -> CPE for each chosen CAPEC,
    sums CVSS scores for CVEs whose CPE is present on the network.
    """
    aql = """
    FOR capec_id IN @capec_ids
      FOR cwe IN 1..1 OUTBOUND CONCAT('capec/', capec_id) capec_cwe
        FOR cve IN 1..1 OUTBOUND cwe cwe_cve
          FILTER cve.cpe_ids != null
          FOR cpe_id IN cve.cpe_ids
            FILTER cpe_id IN @network_cpes
            RETURN DISTINCT {cve: cve._key, cpe: cpe_id, cvss: cve.cvss_score}
    """
    bind_vars = {"capec_ids": capec_ids, "network_cpes": list(network.keys())}
    rows = list(db.aql.execute(aql, bind_vars=bind_vars))
    # weight by occurrence count on the network, matching the paper's
    # "sum of CVSS scores for every CPE occurrence affected"
    return sum(r["cvss"] * network.get(r["cpe"], 0) for r in rows if r["cvss"])
```

Notes:
- Collection/edge names (`capec_cwe`, `cwe_cve`) **must** match what you found in Section 1.
- `cve.cvss_score` field name may differ (`cvssV3_baseScore`, `metrics.cvss`, etc.) — check one CVE document with `db.collection("cve").random()`.
- Cache this traversal per CAPEC (not per triplet) — a CAPEC's downstream CVE set doesn't change within a run, so precompute `capec_id -> [(cve, cpe, cvss), ...]` once at startup and do set lookups in Python instead of hitting ArangoDB every generation. This is the single biggest performance win — the paper's 546 CAPECs × 20 CPEs is small enough to fully cache in memory.

### 3.4 Defense action semantics

A defense = 3 CPEs to "patch" (bump to next version). In the environment, patching a CPE removes it from the network's exposed-CPE set for that round (or replaces it with a hypothetical patched CPE with no known CVEs, per the paper's "no guarantee the upgrade fixes anything" caveat — simplest faithful implementation: **removal**).

```python
def apply_patches(network: dict, patched_cpes: list[str]) -> dict:
    return {cpe: count for cpe, count in network.items() if cpe not in patched_cpes}
```

---

## 4. Genome representation (`genome.py`)

Following the paper (Section 3.3.2), represent both attacker and defender genomes as **index triplets into a fixed candidate list** — this is simpler to implement in a GA than the RL cube-mapping trick (that trick was only needed because RL wants continuous action spaces; a GA can operate directly on discrete indices).

```python
import random

class Genome:
    """A genome is 3 indices into a fixed candidate pool (CAPECs or CPEs)."""
    def __init__(self, pool_size: int, genes: list[int] | None = None):
        self.pool_size = pool_size
        self.genes = genes or random.sample(range(pool_size), 3)

    def decode(self, pool: list[str]) -> list[str]:
        return [pool[i] for i in self.genes]

    def mutate(self, p_mut: float):
        for i in range(len(self.genes)):
            if random.random() < p_mut:
                self.genes[i] = random.randrange(self.pool_size)

    @staticmethod
    def crossover(a: "Genome", b: "Genome", p_cx: float):
        if random.random() < p_cx:
            point = random.randint(1, 2)
            child1 = Genome(a.pool_size, a.genes[:point] + b.genes[point:])
            child2 = Genome(a.pool_size, b.genes[:point] + a.genes[point:])
            return child1, child2
        return Genome(a.pool_size, a.genes[:]), Genome(b.pool_size, b.genes[:])
```

Allow duplicate genes within a triplet initially (the paper notes duplication as a known minor inefficiency, "outweighed by the benefits toward convergence" — don't over-engineer a fix here).

---

## 5. The coevolution loop (`coevolution.py`)

This is the direct implementation of Figure 2(a) in the paper: **alternating** evolution — attackers evolve and are scored against the *current* defender population; then defenders evolve and are scored against the *just-updated* attacker population.

```python
import random
import numpy as np
from genome import Genome

def tournament_select(pop, fitnesses, k=2):
    idxs = random.sample(range(len(pop)), k)
    best = max(idxs, key=lambda i: fitnesses[i])
    return pop[best]

def evolve_population(pop, fitnesses, p_mut, p_cx, elite_size, tourn_size):
    ranked = sorted(zip(pop, fitnesses), key=lambda x: -x[1])
    new_pop = [g for g, _ in ranked[:elite_size]]  # elite_size = 0 per Table 16
    while len(new_pop) < len(pop):
        p1 = tournament_select(pop, fitnesses, tourn_size)
        p2 = tournament_select(pop, fitnesses, tourn_size)
        c1, c2 = Genome.crossover(p1, p2, p_cx)
        c1.mutate(p_mut)
        c2.mutate(p_mut)
        new_pop.extend([c1, c2])
    return new_pop[:len(pop)]

def mean_reward_of_population(attacker_pop, defender_pop, capec_pool, cpe_pool,
                               base_network, reward_fn):
    """
    Mean expected utility: average CVSS reward over ALL attacker-defender pairings
    in the current generation (this is the 'mixed strategy NE' proxy from the paper).
    """
    attacker_rewards = []
    for atk in attacker_pop:
        atk_capecs = atk.decode(capec_pool)
        pairing_rewards = []
        for dfn in defender_pop:
            patched = dfn.decode(cpe_pool)
            network = apply_patches(base_network, patched)
            pairing_rewards.append(reward_fn(atk_capecs, network))
        attacker_rewards.append(np.mean(pairing_rewards))
    return attacker_rewards  # per-individual fitness = mean utility vs. defender pop

def run_cca(n_generations, pop_size, p_mut, p_cx, elite_size, tourn_size,
            capec_pool, cpe_pool, base_network, reward_fn, seed=0):
    random.seed(seed)
    attacker_pop = [Genome(len(capec_pool)) for _ in range(pop_size)]
    defender_pop = [Genome(len(cpe_pool)) for _ in range(pop_size)]

    history = {"attacker_reward": [], "defender_reward": []}

    for gen in range(n_generations):
        # --- Attacker step: evaluate vs current defenders, then evolve ---
        atk_fitness = mean_reward_of_population(
            attacker_pop, defender_pop, capec_pool, cpe_pool, base_network, reward_fn
        )
        attacker_pop = evolve_population(
            attacker_pop, atk_fitness, p_mut, p_cx, elite_size, tourn_size
        )

        # --- Defender step: evaluate vs the *updated* attackers, then evolve ---
        # defender fitness = negative of attacker reward (zero-sum)
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
        print(f"Gen {gen:3d} | mean attacker reward: {np.mean(atk_fitness):.3f}")

    return attacker_pop, defender_pop, history
```

This mirrors the paper's description almost line for line: *"The populations are evolved in alternating steps: First, the attack population is selected, varied, updated, and evaluated against the defenses, and then, the same for the defense population."*

---

## 6. Hyperparameters (`config.py`) — Table 16 from the paper

```python
CCA_CONFIG = {
    "n_generations": 25,          # matches Fig. 3's x-axis range
    "population_size": 10,
    "mutation_probability": 0.1,
    "crossover_probability": 0.8,
    "elite_size": 0,
    "tournament_size": 2,
    "n_runs": 5,                    # paper reports 5 runs with min/max shaded
}
```

---

## 7. Evaluation & plotting (`evaluate.py`) — reproducing Figure 3

```python
import numpy as np
import matplotlib.pyplot as plt

def plot_reward_curve(all_run_histories, out_path="cca_reward.png"):
    """all_run_histories: list of {'attacker_reward': [...]} dicts, one per run."""
    arr = np.array([h["attacker_reward"] for h in all_run_histories])  # (n_runs, n_gens)
    mean = arr.mean(axis=0)
    lo, hi = arr.min(axis=0), arr.max(axis=0)

    plt.plot(mean, label="CCA (GE) mean reward")
    plt.fill_between(range(len(mean)), lo, hi, alpha=0.3)
    plt.xlabel("Generation")
    plt.ylabel("Reward")
    plt.title("Average CCA reward vs training generation")
    plt.legend()
    plt.savefig(out_path)
```

Run the CCA `n_runs` times with different seeds, collect `history["attacker_reward"]` from each, and feed to `plot_reward_curve` — this reproduces the CCA half of Figure 3 (the MARL curve requires a separate RL implementation, which is a distinct effort from the CCA and out of scope for this file).

---

## 8. Sanity checks before trusting results

1. **Reward sanity**: pick one attacker genome manually decoded to CAPEC-13 (Subverting Environment Variable Values) and confirm your reward oracle returns a nonzero CVSS-weighted score against a network containing `Apache Struts 2.5.0-2.5.16` — this is the exact worked example in Section 3.1.2 of the paper (CVE-2018-11776).
2. **Zero-sum check**: `attacker_reward + defender_reward` should trend toward 0 as populations converge (defender reward is literally the negation).
3. **Diversity check**: log the number of *unique* CAPECs used by the converged attacker population each run — the paper reports ~108 unique CAPECs for CCA vs. 248 for MARL. If your CCA population collapses to 1–2 CAPECs immediately, your mutation rate is probably too low or tournament size too aggressive relative to population size 10.
4. **Cache correctness**: if you precompute the CAPEC→CVE/CPE/CVSS lookup table (Section 3.3), invalidate/rebuild it if you rebuild BRON with a newer snapshot — the sparsity table (Table 2 in the paper) implies most CAPECs will have **zero** reachable CVEs on any given small network; that's expected, not a bug.

---

## 9. Known deviations / simplifications to be explicit about

- The paper used a **continuous cube-based action space with an RL-specific coordinate-to-CAPEC mapping** only for the RL agent, because RL performs poorly on huge discrete spaces (162M+ combinations). Since CCA/GA operates natively on discrete genes, use the simpler direct index representation in Section 4 — don't port the RL cube trick into your GA, it isn't needed and isn't what the paper's CCA used either.
- Patch semantics ("remove CPE from network" vs. "increment version, possibly to an equally vulnerable version") is underspecified in the paper. Removal is the conservative, faithful-enough default; note this as an assumption in your writeup.
- If you want the MARL comparison from Figure 3 too, that's a separate Gym-environment + Stable-Baselines3 A2C effort (Appendix A.4) — a distinct implementation track from this file.

---

## 10. Suggested next steps for your CoRAD write-up

- Log `n_unique_capecs_used` and `n_unique_cpes_patched` per run to reproduce the paper's diversity comparison.
- Since you already have BOMRa/Node2Vec embeddings from earlier CoRAD work, an interesting extension beyond the paper: use embedding similarity to seed initial populations with *plausible* (not just random) CAPEC triplets, and see if convergence speed changes — this would be a genuine contribution beyond replication.
