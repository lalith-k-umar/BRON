"""Competitive Coevolutionary Algorithm (CCA) for BRON."""

from .config import CCA_CONFIG
from .environment import apply_patches
from .genome import Genome
from .coevolution import run_cca, tournament_select, evolve_population, mean_reward_of_population
from .bron_client import (
    find_highest_rewarding_capec,
    get_capec_linked_artifacts,
    format_capec_linked_artifacts,
    display_capec_linked_artifacts,
)

__all__ = [
    "CCA_CONFIG",
    "apply_patches",
    "Genome",
    "run_cca",
    "tournament_select",
    "evolve_population",
    "mean_reward_of_population",
    "find_highest_rewarding_capec",
    "get_capec_linked_artifacts",
    "format_capec_linked_artifacts",
    "display_capec_linked_artifacts",
]

