"""Unit tests for saq.analysis.cache.generate_cache_key."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from saq.analysis.cache import generate_cache_key
from saq.modules.config import AnalysisModuleConfig


def _make_observable(type_: str = "url", value: str = "https://example.com/", time=None):
    return SimpleNamespace(type=type_, value=value, time=time)


def _make_module(
    name: str = "test_module",
    version: int = 1,
    cache_ttl=timedelta(hours=1),
    extended_version=None,
):
    return SimpleNamespace(
        config=SimpleNamespace(name=name),
        version=version,
        cache_ttl=cache_ttl,
        extended_version=extended_version or {},
    )


class TestCacheKeyBasics:

    @pytest.mark.unit
    def test_returns_none_when_cache_ttl_is_none(self):
        key = generate_cache_key(_make_observable(), _make_module(cache_ttl=None))
        assert key is None

    @pytest.mark.unit
    def test_key_is_the_v2_digest_of_its_labelled_fields(self):
        """The key is stored in every cache row and looked up by later
        processes and releases, so it is pinned to a digest computed outside
        ACE: sha256 over ``label:length:value`` for format, type, value,
        module, version, config ("none" for a config without model_dump) and
        each extended_version pair in key order, e.g.
        ``f() { printf '%s:%s:%s' "$1" "${#2}" "$2"; }; { f format ace-analysis-cache-key-v2;
        f type url; f value https://example.com/; f module test_module; f version 1;
        f config none; f ext:rules_sha aaa; f ext:tool 1.0; } | shasum -a 256``."""
        key = generate_cache_key(
            _make_observable(),
            _make_module(extended_version={"tool": "1.0", "rules_sha": "aaa"}),
        )
        assert key == "81103554a7e911cdf1c44bdc2b6edf8949550131a017458f5696b1a3233991ea"


class TestCacheKeySensitivity:

    @pytest.mark.unit
    def test_changes_with_observable_value(self):
        mod = _make_module()
        k1 = generate_cache_key(_make_observable(value="https://a.example/"), mod)
        k2 = generate_cache_key(_make_observable(value="https://b.example/"), mod)
        assert k1 != k2

    @pytest.mark.unit
    def test_changes_with_observable_type(self):
        mod = _make_module()
        k1 = generate_cache_key(_make_observable(type_="url"), mod)
        k2 = generate_cache_key(_make_observable(type_="fqdn"), mod)
        assert k1 != k2

    @pytest.mark.unit
    def test_ignores_observable_time(self):
        """observable.time is deliberately excluded from the key — cacheable
        results are time-independent, and including time would defeat dedup
        for time-bearing observable types (IPs). Two observables identical
        but for their time must produce the SAME key."""
        mod = _make_module()
        t1 = datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 4, 17, 11, 0, tzinfo=timezone.utc)
        k1 = generate_cache_key(_make_observable(time=t1), mod)
        k2 = generate_cache_key(_make_observable(time=t2), mod)
        k_none = generate_cache_key(_make_observable(time=None), mod)
        assert k1 == k2 == k_none

    @pytest.mark.unit
    def test_changes_with_module_name(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(name="module_a"))
        k2 = generate_cache_key(obs, _make_module(name="module_b"))
        assert k1 != k2

    @pytest.mark.unit
    def test_changes_with_module_version(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(version=1))
        k2 = generate_cache_key(obs, _make_module(version=2))
        assert k1 != k2

    @pytest.mark.unit
    def test_changes_with_extended_version(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(extended_version={"rules_sha": "aaa"}))
        k2 = generate_cache_key(obs, _make_module(extended_version={"rules_sha": "bbb"}))
        assert k1 != k2

    @pytest.mark.unit
    def test_extended_version_ordering_is_stable(self):
        """Keys within extended_version should be sorted so insertion order
        doesn't change the cache key."""
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(extended_version={"a": "1", "b": "2"}))
        k2 = generate_cache_key(obs, _make_module(extended_version={"b": "2", "a": "1"}))
        assert k1 == k2

    @pytest.mark.unit
    def test_extended_version_keys_participate(self):
        """v2 fix: the v1 format hashed only extended_version VALUES, so
        {"tool_a": "1.0"} and {"tool_b": "1.0"} collided — a module
        changing WHICH tool it probes wouldn't shift its key."""
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(extended_version={"tool_a": "1.0"}))
        k2 = generate_cache_key(obs, _make_module(extended_version={"tool_b": "1.0"}))
        assert k1 != k2


class TestCacheKeyExtendedVersionEvaluatedOnce:
    """extended_version is an un-memoized property that re-probes the module's
    external tools on every access (e.g. qrcode shells out to zbarimg/gs/pdfinfo
    and hashes its filter file). generate_cache_key must evaluate it exactly
    once — accessing it per key rebuilt it O(keys) times and dominated
    cache-lookup latency for tool-heavy modules."""

    @pytest.mark.unit
    def test_extended_version_accessed_once_per_call(self):
        calls = {"n": 0}
        payload = {"tool_a": "1.0", "tool_b": "2.0", "tool_c": "3.0"}

        class _CountingModule:
            config = SimpleNamespace(name="counting_module")
            version = 1
            cache_ttl = timedelta(hours=1)

            @property
            def extended_version(self):
                calls["n"] += 1
                return payload

        key = generate_cache_key(_make_observable(), _CountingModule())
        assert calls["n"] == 1
        # and the key is byte-identical to the multi-key snapshot it derives from
        assert key == generate_cache_key(
            _make_observable(), _make_module(name="counting_module", extended_version=payload)
        )


class _SubclassConfig(AnalysisModuleConfig):
    """Stand-in for a module-specific config (get_config_class pattern)."""
    api_endpoint: str = "https://api.example.com/"


def _make_configured_module(config, version=1, cache_ttl=timedelta(hours=1)):
    return SimpleNamespace(
        config=config,
        version=version,
        cache_ttl=cache_ttl,
        extended_version={},
    )


def _subclass_config(**overrides):
    defaults = dict(
        name="test_module",
        python_module="saq.modules.test",
        python_class="Dummy",
        enabled=True,
    )
    defaults.update(overrides)
    return _SubclassConfig(**defaults)


class TestCacheKeyConfigHash:
    """v2: the module's resolved config participates in the key, so a
    YAML config edit invalidates the cache without a version bump.
    Operational and eligibility fields are excluded."""

    @pytest.mark.unit
    def test_module_specific_config_field_changes_key(self):
        obs = _make_observable()
        k1 = generate_cache_key(
            obs, _make_configured_module(_subclass_config(api_endpoint="https://a.example/")))
        k2 = generate_cache_key(
            obs, _make_configured_module(_subclass_config(api_endpoint="https://b.example/")))
        assert k1 != k2

    @pytest.mark.unit
    def test_python_class_change_changes_key(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_configured_module(_subclass_config(python_class="A")))
        k2 = generate_cache_key(obs, _make_configured_module(_subclass_config(python_class="B")))
        assert k1 != k2

    @pytest.mark.unit
    def test_operational_fields_do_not_change_key(self):
        obs = _make_observable()
        base = generate_cache_key(obs, _make_configured_module(_subclass_config()))
        for overrides in (
            dict(priority=99),
            dict(maximum_analysis_time=10),
            dict(semaphore_name="sem"),
            dict(cooldown_period=5),
            dict(description="a different description"),
            dict(enabled=False),
        ):
            assert generate_cache_key(
                obs, _make_configured_module(_subclass_config(**overrides))
            ) == base, f"key changed for operational override {overrides}"

    @pytest.mark.unit
    def test_eligibility_fields_do_not_change_key(self):
        obs = _make_observable()
        base = generate_cache_key(obs, _make_configured_module(_subclass_config()))
        for overrides in (
            dict(valid_observable_types=["url"]),
            dict(required_directives=["crawl"]),
            dict(valid_queues=["internal"]),
            dict(requires_detection_path=True),
            dict(file_size_limit=1024),
        ):
            assert generate_cache_key(
                obs, _make_configured_module(_subclass_config(**overrides))
            ) == base, f"key changed for eligibility override {overrides}"

    @pytest.mark.unit
    def test_cache_ttl_value_does_not_change_key(self):
        """Changing only the TTL must not orphan existing entries — TTL
        semantics are owned by expires_at, not the key."""
        obs = _make_observable()
        k1 = generate_cache_key(
            obs, _make_configured_module(_subclass_config(cache_ttl=3600), cache_ttl=timedelta(hours=1)))
        k2 = generate_cache_key(
            obs, _make_configured_module(_subclass_config(cache_ttl=60), cache_ttl=timedelta(minutes=1)))
        assert k1 == k2
