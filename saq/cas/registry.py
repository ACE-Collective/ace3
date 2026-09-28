"""The process-wide CAS: pools built from get_config().cas, one read cache shared by all of them."""

import os
import threading
from typing import Optional

from saq.cas.backend import load_backend, resolve_data_path
from saq.cas.cache import ReadCache
from saq.cas.errors import PoolNotFound
from saq.cas.pool import CASPool
from saq.configuration.config import get_config
from saq.configuration.schema import CASConfig


class CAS:
    def __init__(self, config: CASConfig):
        self.config = config
        self.cache = ReadCache(resolve_data_path(config.read_cache.dir), config.read_cache.max_bytes)
        self._pools: dict[str, CASPool] = {}
        self._lock = threading.Lock()

    def pool_names(self) -> list[str]:
        return sorted(self.config.pools)

    def pool(self, name: str) -> CASPool:
        """The named pool, built on first use. Raises PoolNotFound for a name that is not
        configured and CASConfigError for a pool whose backend cannot be built (including a
        shared pool with a node-local custom backend)."""
        with self._lock:
            pool = self._pools.get(name)
            if pool is not None:
                return pool

            pool_config = self.config.pools.get(name)
            if pool_config is None:
                raise PoolNotFound(name)

            backend = load_backend(name, pool_config, self.config)
            pool = self._pools[name] = CASPool(name, pool_config, self.config, backend, self.cache)
            return pool

    def pools(self) -> list[CASPool]:
        return [self.pool(name) for name in self.pool_names()]


_cas: Optional[CAS] = None
_cas_lock = threading.Lock()


def get_cas() -> CAS:
    global _cas
    with _cas_lock:
        if _cas is None:
            _cas = CAS(get_config().cas)

        return _cas


def reset_cas() -> None:
    """Drop the process-wide CAS so the next get_cas() rebuilds it from the current config. Used by
    tests and after fork. Runs in the child after fork with nothing but an assignment: no logging,
    no locks (the parent's may be held), nothing that could block a dying process."""
    global _cas
    _cas = None


os.register_at_fork(after_in_child=reset_cas)
