from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import fakeredis
import pytest

from saq.modules.redis_cache import (
    CACHE_HITS_KEY,
    CACHE_KEY_PREFIX,
    CACHE_MISSES_KEY,
    RedisAnalysisCacheStrategy,
    _module_hits_key,
    _module_misses_key,
)

pytestmark = pytest.mark.unit


def _make_module(
    name="test_module",
    version=1,
    cache=True,
    cache_expiration=None,
    cache_dedup_time_range=None,
    extended_version=None,
    cache_properties=None,
):
    """Create a mock analysis module with cache-related attributes."""
    module = MagicMock()
    module.name = name
    module.version = version
    module.cache = cache
    module.cache_expiration = cache_expiration
    module.cache_dedup_time_range = cache_dedup_time_range
    module.extended_version = extended_version or {}
    if cache_properties is not None:
        module.get_cache_properties = MagicMock(return_value=cache_properties)
    else:
        module.get_cache_properties = MagicMock(return_value=dict(extended_version or {}))
    return module


def _make_observable(o_type="ipv4", value="1.2.3.4", time=None):
    """Create a mock observable."""
    obs = MagicMock()
    obs.type = o_type
    obs.value = value
    obs.time = time
    return obs


@pytest.fixture
def redis_client():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def cache(redis_client):
    return RedisAnalysisCacheStrategy(redis_client=redis_client)


class TestCacheKeyGeneration:
    """Tests for cache key generation correctness."""

    def test_same_inputs_produce_same_key(self, cache):
        module = _make_module()
        obs = _make_observable()
        key1 = cache._build_cache_key(module, obs)
        key2 = cache._build_cache_key(module, obs)
        assert key1 == key2
        assert key1.startswith(CACHE_KEY_PREFIX)

    def test_different_observable_value_produces_different_key(self, cache):
        module = _make_module()
        obs1 = _make_observable(value="1.2.3.4")
        obs2 = _make_observable(value="5.6.7.8")
        assert cache._build_cache_key(module, obs1) != cache._build_cache_key(module, obs2)

    def test_different_observable_type_produces_different_key(self, cache):
        module = _make_module()
        obs1 = _make_observable(o_type="ipv4")
        obs2 = _make_observable(o_type="hostname")
        assert cache._build_cache_key(module, obs1) != cache._build_cache_key(module, obs2)

    def test_different_module_name_produces_different_key(self, cache):
        mod1 = _make_module(name="module_a")
        mod2 = _make_module(name="module_b")
        obs = _make_observable()
        assert cache._build_cache_key(mod1, obs) != cache._build_cache_key(mod2, obs)

    def test_different_version_produces_different_key(self, cache):
        mod1 = _make_module(version=1)
        mod2 = _make_module(version=2)
        obs = _make_observable()
        assert cache._build_cache_key(mod1, obs) != cache._build_cache_key(mod2, obs)

    def test_no_time_skips_time_in_key(self, cache):
        module = _make_module(cache_dedup_time_range=timedelta(hours=1))
        obs_no_time = _make_observable(time=None)
        obs_with_time = _make_observable(time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
        # No time observable should produce a different key than one with time
        assert cache._build_cache_key(module, obs_no_time) != cache._build_cache_key(module, obs_with_time)


class TestTimeBucketing:
    """Tests for time deduplication bucketing."""

    def test_same_bucket_produces_same_key(self, cache):
        module = _make_module(cache_dedup_time_range=timedelta(hours=1))
        # Two times 5 minutes apart in the same 1-hour bucket
        t1 = datetime(2026, 1, 1, 12, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 15, 0, tzinfo=timezone.utc)
        obs1 = _make_observable(time=t1)
        obs2 = _make_observable(time=t2)
        assert cache._build_cache_key(module, obs1) == cache._build_cache_key(module, obs2)

    def test_different_bucket_produces_different_key(self, cache):
        module = _make_module(cache_dedup_time_range=timedelta(hours=1))
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 13, 0, 1, tzinfo=timezone.utc)
        obs1 = _make_observable(time=t1)
        obs2 = _make_observable(time=t2)
        assert cache._build_cache_key(module, obs1) != cache._build_cache_key(module, obs2)

    def test_no_dedup_range_ignores_time(self, cache):
        """Without cache_dedup_time_range, time does not affect the key."""
        module = _make_module(cache_dedup_time_range=None)
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 13, 0, 0, tzinfo=timezone.utc)
        obs1 = _make_observable(time=t1)
        obs2 = _make_observable(time=t2)
        assert cache._build_cache_key(module, obs1) == cache._build_cache_key(module, obs2)


class TestExtendedVersion:
    """Tests for extended version / cache properties."""

    def test_extended_version_changes_key(self, cache):
        mod1 = _make_module(cache_properties={"yara_commit": "abc123"})
        mod2 = _make_module(cache_properties={"yara_commit": "def456"})
        obs = _make_observable()
        assert cache._build_cache_key(mod1, obs) != cache._build_cache_key(mod2, obs)

    def test_extended_version_order_independent(self, cache):
        """Keys with same properties in different insertion order should match."""
        props = {"b_key": "val_b", "a_key": "val_a"}
        mod = _make_module(cache_properties=props)
        obs = _make_observable()
        key1 = cache._build_cache_key(mod, obs)
        # Same properties, different dict (order shouldn't matter since we sort)
        mod2 = _make_module(cache_properties={"a_key": "val_a", "b_key": "val_b"})
        key2 = cache._build_cache_key(mod2, obs)
        assert key1 == key2

    def test_empty_extended_version_same_as_no_properties(self, cache):
        mod1 = _make_module(cache_properties={})
        mod2 = _make_module(cache_properties={})
        obs = _make_observable()
        assert cache._build_cache_key(mod1, obs) == cache._build_cache_key(mod2, obs)


class TestCacheHitMiss:
    """Tests for cache hit/miss/store flows."""

    def test_cache_miss_returns_none(self, cache):
        module = _make_module()
        obs = _make_observable()
        result = cache.get_cached_analysis(module, obs)
        assert result is None

    def test_store_and_retrieve(self, cache):
        module = _make_module()
        obs = _make_observable()
        data = {"details": {"foo": "bar"}, "summary": "test", "tags": [], "observables": []}
        assert cache.store_analysis(module, obs, data) is True
        result = cache.get_cached_analysis(module, obs)
        assert result is not None
        assert result["details"] == {"foo": "bar"}
        assert result["summary"] == "test"
        assert "cached_at" in result

    def test_store_with_expiration(self, cache, redis_client):
        module = _make_module(cache_expiration=3600)
        obs = _make_observable()
        data = {"details": {}, "tags": []}
        assert cache.store_analysis(module, obs, data) is True

        # Verify TTL was set
        cache_key = cache._build_cache_key(module, obs)
        ttl = redis_client.ttl(cache_key)
        assert ttl > 0
        assert ttl <= 3600

    def test_store_without_expiration_has_no_ttl(self, cache, redis_client):
        module = _make_module(cache_expiration=None)
        obs = _make_observable()
        data = {"details": {}}
        cache.store_analysis(module, obs, data)

        cache_key = cache._build_cache_key(module, obs)
        ttl = redis_client.ttl(cache_key)
        assert ttl == -1  # -1 means no expiration

    def test_cache_metrics_tracked(self, cache, redis_client):
        module = _make_module(name="test_mod")
        obs = _make_observable()

        # Miss
        cache.get_cached_analysis(module, obs)
        assert redis_client.get(CACHE_MISSES_KEY) == "1"
        assert redis_client.get(_module_misses_key("test_mod")) == "1"

        # Store and hit
        cache.store_analysis(module, obs, {"details": {}})
        cache.get_cached_analysis(module, obs)
        assert redis_client.get(CACHE_HITS_KEY) == "1"
        assert redis_client.get(_module_hits_key("test_mod")) == "1"

    def test_corrupt_cache_entry_returns_none(self, cache, redis_client):
        module = _make_module()
        obs = _make_observable()
        cache_key = cache._build_cache_key(module, obs)
        redis_client.set(cache_key, "not valid json{{{")
        result = cache.get_cached_analysis(module, obs)
        assert result is None


class TestCacheInvalidation:
    """Tests for cache invalidation."""

    def test_invalidate_specific_entry(self, cache, redis_client):
        module = _make_module()
        obs = _make_observable()
        cache.store_analysis(module, obs, {"details": {}})
        assert cache.get_cached_analysis(module, obs) is not None

        assert cache.invalidate_cache(module=module, observable=obs) is True
        assert cache.get_cached_analysis(module, obs) is None

    def test_invalidate_all(self, cache, redis_client):
        mod1 = _make_module(name="mod1")
        mod2 = _make_module(name="mod2")
        obs = _make_observable()
        cache.store_analysis(mod1, obs, {"details": {}})
        cache.store_analysis(mod2, obs, {"details": {}})

        assert cache.invalidate_cache() is True
        assert cache.get_cached_analysis(mod1, obs) is None
        assert cache.get_cached_analysis(mod2, obs) is None

    def test_version_change_invalidates_naturally(self, cache):
        """Changing module version produces a different key, effectively invalidating the old cache."""
        obs = _make_observable()
        mod_v1 = _make_module(version=1)
        cache.store_analysis(mod_v1, obs, {"details": {"v": 1}})

        mod_v2 = _make_module(version=2)
        result = cache.get_cached_analysis(mod_v2, obs)
        assert result is None  # v2 key doesn't match v1 entry
