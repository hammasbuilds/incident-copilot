"""Drain throughput on 200,000 synthetic lines in five shapes with random variables.

python bench.py
"""

import random
import time

from copilot.logs import DrainParser

rng = random.Random(0)
SHAPES = [
    "user {u} logged in from 10.0.{a}.{b}",
    "Connection to db-{a} failed after {b}ms",
    "GET /api/v1/items/{a} 200 {b}ms",
    "worker {a} restarted after {b} retries",
    "cache miss for key=item{a} shard={b}",
]
lines = [
    rng.choice(SHAPES).format(
        u=f"u{rng.randint(0, 5000)}x", a=rng.randint(0, 255), b=rng.randint(0, 999)
    )
    for _ in range(200_000)
]
start = time.perf_counter()
templates = DrainParser().parse(lines)
elapsed = time.perf_counter() - start
print(f"{len(lines):,} lines -> {len(templates)} templates in {elapsed:.1f}s")
for t in templates:
    print(f"  x{t.count:<6} {t.text}")
