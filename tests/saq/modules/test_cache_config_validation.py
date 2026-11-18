"""Unit tests for AnalysisModuleConfig cache-related validators."""
from datetime import timedelta

import pytest
from pydantic import ValidationError

from saq.modules.config import AnalysisModuleConfig


def _base_config(**overrides):
    defaults = dict(
        name="t",
        python_module="saq.modules.test",
        python_class="Dummy",
        enabled=False,
    )
    defaults.update(overrides)
    return defaults


class TestCacheTtlValidation:

    @pytest.mark.unit
    def test_cache_ttl_defaults_to_none(self):
        cfg = AnalysisModuleConfig(**_base_config())
        assert cfg.cache_ttl is None

    @pytest.mark.unit
    def test_cache_ttl_accepts_timedelta(self):
        cfg = AnalysisModuleConfig(**_base_config(cache_ttl=timedelta(hours=1)))
        assert cfg.cache_ttl == timedelta(hours=1)

    @pytest.mark.unit
    def test_cache_ttl_accepts_seconds_int_from_yaml(self):
        # Pydantic coerces int seconds → timedelta, same as YAML loader provides.
        cfg = AnalysisModuleConfig(**_base_config(cache_ttl=3600))
        assert cfg.cache_ttl == timedelta(seconds=3600)

    @pytest.mark.unit
    def test_wide_diff_plus_cache_ttl_rejected(self):
        with pytest.raises(ValidationError, match="cache_ttl cannot be set when wide_diff is True"):
            AnalysisModuleConfig(
                **_base_config(wide_diff=True, cache_ttl=timedelta(hours=1))
            )

    @pytest.mark.unit
    def test_wide_diff_without_cache_ttl_ok(self):
        cfg = AnalysisModuleConfig(**_base_config(wide_diff=True))
        assert cfg.wide_diff is True
        assert cfg.cache_ttl is None

    @pytest.mark.unit
    def test_grouped_by_time_plus_cache_ttl_rejected(self):
        # A cache hit bypasses analyze() and therefore analysis_covered();
        # time-grouping and caching are semantically incompatible.
        with pytest.raises(ValidationError, match="cache_ttl cannot be set when is_grouped_by_time is True"):
            AnalysisModuleConfig(
                **_base_config(is_grouped_by_time=True, cache_ttl=timedelta(hours=1))
            )

    @pytest.mark.unit
    def test_grouped_by_time_without_cache_ttl_ok(self):
        cfg = AnalysisModuleConfig(**_base_config(
            is_grouped_by_time=True, observation_grouping_time_range=timedelta(minutes=10)))
        assert cfg.is_grouped_by_time is True
        assert cfg.cache_ttl is None
