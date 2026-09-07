from typing import Dict, Iterable, List


def apply_patches(network: Dict[str, float], patched_cpes: Iterable[str]) -> Dict[str, float]:
    patched = set(patched_cpes)
    return {cpe: count for cpe, count in network.items() if cpe not in patched}


def patch_network(network: Dict[str, float], patched_cpes: List[str]) -> Dict[str, float]:
    return apply_patches(network, patched_cpes)
