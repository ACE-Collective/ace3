"""The analysis cache through a real engine run: the executor's lookup before a module runs, the replay
on a hit, the write after a live run, and the fallbacks when either fails.

test_executor_cache_hit.py covers _apply_cached_delta on its own; nothing else drives
_execute_module_analysis with a cacheable module, so these run the engine single threaded with
cache_test (saq/modules/test.py), whose every live run records a new run_id."""

import logging
import uuid

import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, F_FQDN, F_TEST
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.test import CacheTestAnalysis
from saq.util.uuid import get_storage_dir, storage_dir_from_uuid


def _analyze(value: str) -> tuple[RootAnalysis, CacheTestAnalysis]:
    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        tool="tool",
        tool_instance="tool_instance",
        alert_type="alert_type",
        desc="cache test",
        storage_dir=storage_dir_from_uuid(root_uuid),
        analysis_mode=ANALYSIS_MODE_ANALYSIS)
    root.initialize_storage()
    root.analysis_mode = "test_groups"
    observable = root.add_observable_by_spec(F_TEST, value)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("cache_test", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_uuid))
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(CacheTestAnalysis)
    assert isinstance(analysis, CacheTestAnalysis)
    return root, analysis


def _cache_hits(root: RootAnalysis) -> list:
    return [d for d in root.module_executions if d.from_cache_hit]


@pytest.fixture
def value() -> str:
    # the cache outlives a root, so every test analyzes its own value
    return f"cache-{uuid.uuid4()}"


@pytest.mark.integration
def test_second_root_replays_from_the_cache(value):
    first_root, first = _analyze(value)
    assert _cache_hits(first_root) == []

    second_root, second = _analyze(value)

    # the module did not run again: the analysis is the first run's
    assert second.details["run_id"] == first.details["run_id"]
    fqdn = second.get_observable_by_type(F_FQDN)
    assert fqdn is not None and fqdn.value == "cache-test.example.com"
    assert fqdn.has_tag("cache_test")

    hits = _cache_hits(second_root)
    assert len(hits) == 1
    assert hits[0].module_path.endswith(":CacheTestAnalysis")


@pytest.mark.integration
def test_other_value_is_a_miss(value):
    _, first = _analyze(value)
    _, other = _analyze(f"{value}-other")

    assert other.details["run_id"] != first.details["run_id"]


@pytest.mark.integration
def test_disabled_cache_runs_the_module(value, monkeypatch):
    _, first = _analyze(value)

    monkeypatch.setattr(get_config().analysis_cache, "enabled", False)
    second_root, second = _analyze(value)

    assert second.details["run_id"] != first.details["run_id"]
    assert _cache_hits(second_root) == []


@pytest.mark.integration
def test_failed_lookup_falls_through_to_a_live_run(value, monkeypatch, caplog):
    _, first = _analyze(value)

    def _fail(*args, **kwargs):
        raise RuntimeError("cache database unavailable")

    monkeypatch.setattr("saq.engine.executor.get_cached_delta", _fail)
    with caplog.at_level(logging.WARNING):
        second_root, second = _analyze(value)

    # replay failure is not a module failure: the module runs live
    assert second.details["run_id"] != first.details["run_id"]
    assert _cache_hits(second_root) == []
    records = [r for r in caplog.records if "cache replay failed" in r.getMessage()]
    assert len(records) == 1
    assert records[0].module_name == "cache_test"
    assert records[0].exc_info is not None


@pytest.mark.integration
def test_failed_write_keeps_the_analysis(value, monkeypatch, caplog):
    def _fail(*args, **kwargs):
        raise RuntimeError("cache database unavailable")

    monkeypatch.setattr("saq.engine.executor.put_cached_delta", _fail)
    with caplog.at_level(logging.WARNING):
        _, first = _analyze(value)

    assert first.details["run_id"]
    records = [r for r in caplog.records if "failed to write analysis cache" in r.getMessage()]
    assert len(records) == 1
    assert records[0].exc_info is not None

    # nothing was written, so the next root misses
    monkeypatch.undo()
    _, second = _analyze(value)
    assert second.details["run_id"] != first.details["run_id"]
