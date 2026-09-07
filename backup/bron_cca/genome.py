import random
from typing import List, Optional


class Genome:
    """A genome is 3 indices into a fixed candidate pool (CAPECs or CPEs)."""

    def __init__(self, pool_size: int, genes: Optional[List[int]] = None):
        self.pool_size = pool_size
        self.genes = list(genes) if genes is not None else random.sample(range(pool_size), 3)

    def decode(self, pool: List[str]) -> List[str]:
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
