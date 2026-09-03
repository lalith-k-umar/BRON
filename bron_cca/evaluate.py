import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def plot_reward_curve(all_run_histories, out_path="cca_reward.png"):
    """all_run_histories: list of {'attacker_reward': [...]} dicts, one per run."""
    arr = np.array([h["attacker_reward"] for h in all_run_histories])
    mean = arr.mean(axis=0)
    lo, hi = arr.min(axis=0), arr.max(axis=0)

    plt.plot(mean, label="CCA (GE) mean reward")
    plt.fill_between(range(len(mean)), lo, hi, alpha=0.3)
    plt.xlabel("Generation")
    plt.ylabel("Reward")
    plt.title("Average CCA reward vs training generation")
    plt.legend()
    plt.savefig(out_path)
