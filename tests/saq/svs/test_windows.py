"""A run's windows (saq.svs.windows, docs/SVS_RUNS.md, *Windows*)."""

import logging
from datetime import datetime, timedelta

import pytest
import yaml

from saq.configuration.config import get_config
from saq.signatures.model import SignatureLocation, SignatureType
from saq.svs import windows
from saq.svs.windows import InvalidHunt, attribution_window, cron_interval, hunt_latency, observation_window


def _hunt(path, uuid: str, enabled: bool = True, **rule):
    path.write_text(yaml.safe_dump({"rule": {"uuid": uuid, "name": uuid, "enabled": enabled, **rule}}))


@pytest.fixture
def hunt_dir(tmp_path, monkeypatch):
    directory = tmp_path / "hunts"
    directory.mkdir()
    location = SignatureLocation(signature_type=SignatureType.HUNT, path=str(directory), git_dirs=(), source="unittest")
    monkeypatch.setattr(windows, "hunt_locations", lambda: [location])
    windows.clear_cache()
    yield directory
    windows.clear_cache()


@pytest.mark.unit
@pytest.mark.parametrize("rule, expected", [
    ({"frequency": "00:15:00", "time_range": "00:15:00"}, timedelta(minutes=30)),
    ({"frequency": "00:15:00", "time_range": "00:15:00", "offset": "01:00:00"}, timedelta(minutes=90)),
    # time_ranges.TIMESPEC wins over time_range, as in QueryHunt
    ({"frequency": "01:00:00", "time_range": "00:01:00", "time_ranges": {"TIMESPEC": {"duration_before": "1:00:00:00"}}},
     timedelta(days=1, hours=1)),
    # a hunt type without a time range
    ({"frequency": "00:05:00"}, timedelta(minutes=5)),
    # daily at 02:00
    ({"frequency": "0 2 * * *", "time_range": "1:00:00:00"}, timedelta(days=2)),
])
def test_hunt_latency(rule, expected):
    assert hunt_latency(rule) == expected


@pytest.mark.unit
@pytest.mark.parametrize("rule", [{}, {"frequency": "not a schedule"}, {"frequency": "00:05:00", "offset": "soon"}])
def test_hunt_latency_rejects(rule):
    with pytest.raises(InvalidHunt):
        hunt_latency(rule)


@pytest.mark.unit
def test_cron_interval_is_the_largest_gap():
    # weekdays at 09:00: the weekend is the largest gap
    assert cron_interval("0 9 * * 1-5", datetime(2026, 10, 14)) == timedelta(days=3)


@pytest.mark.integration
def test_hunt_latencies_read_enabled_hunts(hunt_dir, caplog):
    _hunt(hunt_dir / "fast.yaml", "fast", frequency="00:05:00", time_range="00:05:00")
    _hunt(hunt_dir / "daily.yaml", "daily", frequency="1:00:00:00", time_range="1:00:00:00")
    _hunt(hunt_dir / "off.yaml", "off", enabled=False, frequency="7:00:00:00", time_range="7:00:00:00")
    _hunt(hunt_dir / "broken.yaml", "broken", frequency="whenever")
    _hunt(hunt_dir / "template.yaml", "template", frequency="7:00:00:00")
    (hunt_dir / "shared.include.yaml").write_text("rule: {}\n")

    with caplog.at_level(logging.WARNING):
        assert windows.hunt_latencies() == {"fast": timedelta(minutes=10), "daily": timedelta(days=2)}
    assert "broken.yaml" in caplog.text


@pytest.mark.integration
def test_hunt_latencies_are_cached(hunt_dir):
    _hunt(hunt_dir / "fast.yaml", "fast", frequency="00:05:00")
    assert windows.hunt_latencies() == {"fast": timedelta(minutes=5)}
    _hunt(hunt_dir / "slow.yaml", "slow", frequency="01:00:00")
    assert "slow" not in windows.hunt_latencies()
    windows.clear_cache()
    assert "slow" in windows.hunt_latencies()


@pytest.mark.integration
def test_the_first_run_waits_for_the_slowest_enabled_hunt(monkeypatch):
    """A test without expectations gets the slowest enabled hunt, not the floor [FR-10]."""
    monkeypatch.setattr(windows, "hunt_latencies", lambda: {"fast": timedelta(minutes=10), "daily": timedelta(days=2)})
    assert observation_window() == timedelta(days=2, minutes=30)
    assert observation_window(set()) == timedelta(days=2, minutes=30)


@pytest.mark.integration
def test_the_window_stays_within_floor_and_ceiling(monkeypatch):
    monkeypatch.setattr(windows, "hunt_latencies", lambda: {})
    assert observation_window() == timedelta(minutes=60)

    monkeypatch.setattr(windows, "hunt_latencies", lambda: {"weekly": timedelta(days=14)})
    assert observation_window() == timedelta(hours=72)

    config = get_config().svs.runs.observation_window
    monkeypatch.setattr(config, "slack_minutes", 0)
    monkeypatch.setattr(config, "floor_minutes", 5)
    monkeypatch.setattr(windows, "hunt_latencies", lambda: {"fast": timedelta(minutes=10)})
    assert observation_window() == timedelta(minutes=10)


@pytest.mark.integration
def test_the_window_with_expectations(monkeypatch):
    monkeypatch.setattr(windows, "hunt_latencies", lambda: {"fast": timedelta(hours=2), "daily": timedelta(days=2)})
    # a YARA rule (no hunt) fires during analysis: the floor
    assert observation_window({"some-yara-rule"}) == timedelta(minutes=60)
    assert observation_window({"some-yara-rule", "fast"}) == timedelta(hours=2, minutes=30)


@pytest.mark.integration
def test_attribution_window():
    assert attribution_window(timedelta(hours=1)) == timedelta(hours=25)


@pytest.mark.integration
def test_hunt_latencies_read_the_configured_hunt_types():
    windows.clear_cache()
    try:
        latencies = windows.hunt_latencies()
    finally:
        windows.clear_cache()
    assert all(isinstance(latency, timedelta) for latency in latencies.values())
