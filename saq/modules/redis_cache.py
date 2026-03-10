import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import redis

from saq.constants import REDIS_DB_ANALYSIS_CACHE
from saq.json_encoding import _JSONEncoder
from saq.redis_client import get_redis_connection

logger = logging.getLogger(__name__)

CACHE_KEY_PREFIX = "ace:cache:"
CACHE_HITS_KEY = "ace:cache:hits"
CACHE_MISSES_KEY = "ace:cache:misses"


def _module_hits_key(module_name: str) -> str:
    return f"ace:cache:hits:{module_name}"


def _module_misses_key(module_name: str) -> str:
    return f"ace:cache:misses:{module_name}"


class RedisAnalysisCacheStrategy:
    """Redis-backed distributed analysis cache implementing AnalysisCacheStrategyInterface."""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self._redis = redis_client

    @property
    def redis(self) -> redis.Redis:
        if self._redis is None:
            self._redis = get_redis_connection(REDIS_DB_ANALYSIS_CACHE)
        return self._redis

    def _build_cache_key(self, module, observable) -> str:
        """Build a SHA-256 cache key from module and observable properties."""
        parts = [
            observable.type,
            observable.value,
            module.name,
            str(module.version),
        ]

        # Time bucketing: quantize observable time if cache_dedup_time_range is set
        dedup_range = getattr(module, "cache_dedup_time_range", None)
        if dedup_range is not None and observable.time is not None:
            bucket_seconds = int(dedup_range.total_seconds())
            if bucket_seconds > 0:
                bucket_index = int(observable.time.timestamp()) // bucket_seconds
                parts.append(str(bucket_index))

        # Extended version properties (sorted by key for determinism)
        cache_properties = {}
        if hasattr(module, "get_cache_properties"):
            cache_properties = module.get_cache_properties()
        elif hasattr(module, "extended_version"):
            cache_properties = module.extended_version

        if cache_properties:
            for key in sorted(cache_properties.keys()):
                parts.append(cache_properties[key])

        key_material = "\x00".join(parts)
        key_hash = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        return f"{CACHE_KEY_PREFIX}{key_hash}"

    def get_cached_analysis(self, module, observable) -> Optional[dict]:
        """Retrieve cached analysis data for the given module and observable."""
        cache_key = self._build_cache_key(module, observable)

        try:
            cached = self.redis.get(cache_key)
        except redis.RedisError:
            logger.warning("redis error during cache lookup for %s on %s", module.name, observable, exc_info=True)
            return None

        if cached is None:
            logger.debug("cache miss for %s on %s (key=%s)", module.name, observable, cache_key)
            try:
                pipe = self.redis.pipeline(transaction=False)
                pipe.incr(CACHE_MISSES_KEY)
                pipe.incr(_module_misses_key(module.name))
                pipe.execute()
            except redis.RedisError:
                pass
            return None

        logger.debug("cache hit for %s on %s (key=%s)", module.name, observable, cache_key)
        try:
            pipe = self.redis.pipeline(transaction=False)
            pipe.incr(CACHE_HITS_KEY)
            pipe.incr(_module_hits_key(module.name))
            pipe.execute()
        except redis.RedisError:
            pass

        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            logger.warning("corrupt cache entry for key %s, ignoring", cache_key)
            return None

    def store_analysis(self, module, observable, analysis_data: dict) -> bool:
        """Store analysis data in the cache with optional TTL."""
        cache_key = self._build_cache_key(module, observable)

        data = dict(analysis_data)
        data["cached_at"] = datetime.now(timezone.utc).isoformat()

        try:
            serialized = json.dumps(data, cls=_JSONEncoder)
        except (TypeError, ValueError):
            logger.warning("failed to serialize analysis data for cache key %s", cache_key, exc_info=True)
            return False

        try:
            expiration = getattr(module, "cache_expiration", None)
            if expiration is not None and expiration > 0:
                self.redis.setex(cache_key, int(expiration), serialized)
            else:
                self.redis.set(cache_key, serialized)
            logger.debug("stored cache entry for %s on %s (key=%s, ttl=%s)", module.name, observable, cache_key, expiration)
            return True
        except redis.RedisError:
            logger.warning("redis error storing cache for %s on %s", module.name, observable, exc_info=True)
            return False

    def invalidate_cache(self, module=None, observable=None) -> bool:
        """Invalidate cache entries. If both module and observable are given, invalidate the specific key.
        If only module is given, scan for all keys matching that module (expensive).
        If neither is given, flush the entire cache database."""
        try:
            if module is not None and observable is not None:
                cache_key = self._build_cache_key(module, observable)
                self.redis.delete(cache_key)
                return True

            if module is None and observable is None:
                self.redis.flushdb()
                return True

            # Pattern-based deletion is not efficient with SHA-256 keys,
            # but we support it for completeness. In practice, use specific invalidation.
            logger.warning("pattern-based cache invalidation is not supported with hashed keys")
            return False
        except redis.RedisError:
            logger.warning("redis error during cache invalidation", exc_info=True)
            return False
