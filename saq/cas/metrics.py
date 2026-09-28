"""Per-process timing of CAS operations (docs/CAS.md, "Observability").

Every public CASPool operation is timed as a whole and split into the phases that can dominate
it: hashing the source, encrypting, waiting for the object's row lock, writing the bytes,
verifying on read. The numbers accumulate in this process only, cumulative since it started (or
forked), keyed by (pool, operation, phase):

    with operation_timer(pool.name, "put") as timer:
        with timer.phase("spool"):
            ...

    snapshot()   # [{"pool", "operation", "phase", "count", "errors", "total_seconds", "max_seconds", "buckets"}]

"total" is the whole operation; the other phases are parts of it and need not add up to it. A
phase's buckets count the samples at or below each upper bound in BUCKET_BOUNDS and above the
previous one (the last bucket is everything slower), which is enough to read off a coarse
percentile without keeping samples.

Recording costs a perf_counter() pair and a dict update under a lock, so it is always on. Nothing
here raises into the operation being timed.
"""

import bisect
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, Optional

# upper bounds, in seconds, of the latency buckets
BUCKET_BOUNDS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

PHASE_TOTAL = "total"


@dataclass
class _Stat:
    count: int = 0
    errors: int = 0
    total: float = 0.0
    max: float = 0.0
    buckets: list[int] = field(default_factory=lambda: [0] * (len(BUCKET_BOUNDS) + 1))

    def add(self, seconds: float, error: bool) -> None:
        self.count += 1
        if error:
            self.errors += 1

        self.total += seconds
        if seconds > self.max:
            self.max = seconds

        self.buckets[bisect.bisect_left(BUCKET_BOUNDS, seconds)] += 1


_stats: dict[tuple[str, str, str], _Stat] = {}
_lock = threading.Lock()


def record(pool: str, operation: str, phase: str, seconds: float, error: bool = False) -> None:
    with _lock:
        stat = _stats.get((pool, operation, phase))
        if stat is None:
            stat = _stats[(pool, operation, phase)] = _Stat()

        stat.add(seconds, error)


class OperationTimer:
    """One timed operation. phase() times a part of it; count() bumps a counter that is not a
    duration (e.g. whether a put wrote bytes or found them already there)."""

    def __init__(self, pool: str, operation: str):
        self.pool = pool
        self.operation = operation

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        error = False
        try:
            yield
        except BaseException:
            error = True
            raise
        finally:
            record(self.pool, self.operation, name, time.perf_counter() - started, error)

    def count(self, name: str) -> None:
        record(self.pool, self.operation, name, 0.0)


@contextmanager
def operation_timer(pool: str, operation: str) -> Iterator[OperationTimer]:
    """Time a whole operation as its "total" phase; an exception counts as an error."""
    timer = OperationTimer(pool, operation)
    with timer.phase(PHASE_TOTAL):
        yield timer


def snapshot(pool: Optional[str] = None) -> list[dict]:
    """What this process has recorded, optionally for one pool, sorted by (pool, operation, phase)."""
    with _lock:
        items = sorted(_stats.items())

    return [{
        "pool": key[0], "operation": key[1], "phase": key[2], "count": stat.count, "errors": stat.errors,
        "total_seconds": stat.total, "max_seconds": stat.max, "buckets": list(stat.buckets),
    } for key, stat in items if pool is None or key[0] == pool]


def reset() -> None:
    """Forget everything recorded. Also runs in the child after fork, so a forked worker reports its
    own work only; it replaces rather than takes the lock, which another thread may have held at the
    moment of the fork."""
    global _stats, _lock
    _stats = {}
    _lock = threading.Lock()


def percentile(buckets: list[int], fraction: float) -> Optional[float]:
    """The bucket upper bound at or below which fraction of the samples fall (None past the last
    bound, or with no samples): a coarse percentile read off a snapshot's buckets."""
    count = sum(buckets)
    if count == 0:
        return None

    target = fraction * count
    running = 0
    for index, bucket in enumerate(buckets):
        running += bucket
        if running >= target:
            return BUCKET_BOUNDS[index] if index < len(BUCKET_BOUNDS) else None

    return None


os.register_at_fork(after_in_child=reset)
