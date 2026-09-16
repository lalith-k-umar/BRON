import os
import json
from pathlib import Path
from types import SimpleNamespace

from arango import ArangoClient

from bron_cca.config import CCA_CONFIG
from bron_cca.bron_client import (
    build_capec_cache,
    display_capec_linked_artifacts,
    evaluate_attack_cached,
    find_highest_rewarding_capec,
    get_all_capecs,
    get_capec_linked_artifacts,
    sample_reachable_cpes,
)
from bron_cca.coevolution import run_cca
from bron_cca.dashboard import write_dashboard
from bron_cca.environment import apply_patches
from bron_cca.evaluate import plot_reward_curve
from bron_cca.run_experiment import run_experiment


def _load_arango_password() -> str:
    env_pw = os.environ.get("BRON_PWD")
    if env_pw:
        return env_pw
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [
        Path("arango_root_password"),
        repo_root / "arango_root_password",
        repo_root / "graph_db" / "arango_root_password",
    ]
    for path in candidates:
        if path.is_file():
            return path.read_text().strip()
    raise FileNotFoundError(
        "Could not find arango_root_password in the working directory, repo root, or graph_db/"
    )


pw = _load_arango_password()
print("connecting to ArangoDB...", flush=True)
client = ArangoClient(hosts="http://127.0.0.1:8529")
db = client.db("BRON", username="root", password=pw, auth_method="basic")
print("connected", flush=True)

print("loading CAPEC pool...", flush=True)
capecs = [row["id"] for row in get_all_capecs(db)]
print(f"loaded {len(capecs)} CAPECs", flush=True)

print("sampling reachable CPEs...", flush=True)
cpes = sample_reachable_cpes(db, n=20)
if len(cpes) < 3:
    raise RuntimeError(
        f"Need at least 3 reachable CPEs for defender genomes, got {len(cpes)}"
    )
network = {cpe: 1 for cpe in cpes}
print(f"network has {len(cpes)} CPEs", flush=True)

print("building CAPEC reward cache for this network...", flush=True)
capec_cache = build_capec_cache(db, capecs, network_cpes=cpes)
nonzero = sum(1 for rows in capec_cache.values() if rows)
print(f"cache ready ({nonzero} CAPECs hit the network)", flush=True)


def reward_fn(capec_ids, net):
    return evaluate_attack_cached(capec_cache, capec_ids, net)


args = SimpleNamespace(
    n_generations=CCA_CONFIG["n_generations"],
    population_size=CCA_CONFIG["population_size"],
    mutation_probability=CCA_CONFIG["mutation_probability"],
    crossover_probability=CCA_CONFIG["crossover_probability"],
    elite_size=CCA_CONFIG["elite_size"],
    tournament_size=CCA_CONFIG["tournament_size"],
    n_runs=CCA_CONFIG["n_runs"],
    seed=0,
)
results = run_experiment(capecs, cpes, network, reward_fn, args=args)
all_histories = results
final_attackers = []
for result in results:
    final_attackers.extend(result["final_attacker_population"])

best_capec, best_capec_reward = find_highest_rewarding_capec(capecs, network, reward_fn)

final_attack_capec_ids = [attacker["actions"] for attacker in final_attackers]
best_cpe = min(
    cpes,
    key=lambda cpe: sum(
        reward_fn(capec_ids, apply_patches(network, [cpe]))
        for capec_ids in final_attack_capec_ids
    )
    / len(final_attack_capec_ids),
)
best_cpe_reward = sum(
    reward_fn(capec_ids, apply_patches(network, [best_cpe]))
    for capec_ids in final_attack_capec_ids
) / len(final_attack_capec_ids)

print(f"best CAPEC: {best_capec} (reward: {best_capec_reward:.3f})", flush=True)
print(
    f"best CPE patch: {best_cpe} "
    f"(mean remaining reward: {best_cpe_reward:.3f})",
    flush=True,
)

print("\nfetching linked CVE, CWE, and D3FEND for best CAPEC...", flush=True)
linked_artifacts = get_capec_linked_artifacts(db, best_capec, network_cpes=cpes)
display_capec_linked_artifacts(best_capec, linked_artifacts, reward=best_capec_reward)

output_dir = Path(os.environ.get("CCA_OUTPUT_DIR", "."))
output_dir.mkdir(parents=True, exist_ok=True)
results_path = output_dir / "cca_results.json"
results_payload = {
    "runs": results,
    "highest_rewarding_capec": {
        "id": best_capec,
        "reward": float(best_capec_reward),
        "linked_artifacts": linked_artifacts,
    },
    "best_cpe_patch": {
        "id": best_cpe,
        "mean_remaining_reward": float(best_cpe_reward),
    },
}
results_path.write_text(json.dumps(results_payload, indent=2), encoding="utf-8")
dashboard_path = output_dir / "cca_dashboard.html"
write_dashboard(results_payload, dashboard_path)
print(f"saved {results_path} and {dashboard_path}", flush=True)

plot_reward_curve(all_histories, out_path=output_dir / "cca_reward.png")
print(f"saved {output_dir / 'cca_reward.png'}", flush=True)

