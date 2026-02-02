"""Reusable TTL cache for FastAPI endpoints."""

import time
from typing import Any

from fastapi import Response


class TTLCache:
    """Simple in-memory keyed TTL cache for async FastAPI endpoints.

    Usage:
        _cache = TTLCache(ttl=300)

        @router.get("/things")
        async def list_things(response: Response):
            cached = _cache.get("things")
            if cached is not None:
                _cache.set_cache_headers(response)
                return cached

            data = ...  # expensive query
            _cache.set("things", data)
            _cache.set_cache_headers(response)
            return data
    """

    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self._entries: dict[str, tuple[Any, float]] = {}

    def get(self, key: str):
        """Return cached data for *key* if still valid, else None."""
        entry = self._entries.get(key)
        if entry is not None and (time.monotonic() - entry[1]) < self.ttl:
            return entry[0]
        return None

    def set(self, key: str, data: Any):
        """Store *data* under *key* with the current timestamp."""
        self._entries[key] = (data, time.monotonic())

    def clear(self):
        """Invalidate all cached entries."""
        self._entries.clear()

    def set_cache_headers(self, response: Response):
        """Set Cache-Control header on a FastAPI Response."""
        response.headers["Cache-Control"] = f"private, max-age={self.ttl}"
