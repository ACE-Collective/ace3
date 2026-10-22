"""A run's windows (saq.svs.windows, docs/SVS_RUNS.md, *Windows*)."""

import logging
from datetime import datetime, timedelta

import pytest
import yaml

from saq.configuration.config import get_config
from saq.signatures.loaders.util import content_hash
from saq.svs import windows
from saq.svs.windows import InvalidHunt, attribution_window, cron_interval, hunt_latency, observation_window


def _hunt(path, uuid: str, enabled: bool = True, **rule):
    path.write_text(yaml.safe_dump({"rule": {"uuid": uuid, "name": uuid, "enabled": enabled, **rule}}))


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
def test_hunt_info_reads_tags(hunt_dir):
    """Coverage reads a hunt's mitre: tags (docs/SVS_COVERAGE.md, *Manual mappings*)."""
    _hunt(hunt_dir / "tagged.yaml", "tagged", frequency="00:05:00", tags=["mitre:T1059.001", "phishing", "mitre:T1059.001"])
    _hunt(hunt_dir / "scalar.yaml", "scalar", frequency="00:05:00", tags="mitre:T1547")
    _hunt(hunt_dir / "untagged.yaml", "untagged", frequency="00:05:00")

    info = windows.hunt_info()
    assert info["tagged"].tags == ("mitre:T1059.001", "phishing")
    assert info["scalar"].tags == ("mitre:T1547",)
    assert info["untagged"].tags == ()


@pytest.mark.integration
def test_hunt_info_keeps_every_hunt_for_results(hunt_dir):
    """A run's result needs the name, suppression and rule hash of hunts the windows skip: disabled
    ones, and ones whose timing can't be read."""
    _hunt(hunt_dir / "grouped.yaml", "grouped", frequency="00:05:00", suppression="1:00:00:00", group_by="host")
    _hunt(hunt_dir / "off.yaml", "off", enabled=False, frequency="00:05:00", dedup_key="{{ user }}")
    _hunt(hunt_dir / "broken.yaml", "broken", frequency="whenever", suppression="01:00:00")

    info = windows.hunt_info()
    assert set(info) == {"grouped", "off", "broken"}
    assert (info["grouped"].suppression, info["grouped"].grouped, info["grouped"].latency) == (
        timedelta(days=1), True, timedelta(minutes=5))
    assert (info["off"].enabled, info["off"].grouped, info["off"].suppression) == (False, True, None)
    assert (info["broken"].latency, info["broken"].suppression) == (None, timedelta(hours=1))
    # the inventory's hash: the raw file, as saq.signatures.loaders.hunt computes it
    assert info["grouped"].content_hash == content_hash((hunt_dir / "grouped.yaml").read_text())
    assert windows.hunt_latencies() == {"grouped": timedelta(minutes=5)}


@pytest.mark.integration
def test_hunt_latencies_are_cached(hunt_dir):
    _hunt(hunt_dir / "fast.yaml", "fast", frequency="00:05:00")
    assert windows.hunt_latencies() == {"fast": timedelta(minutes=5)}
    _hunt(hunt_dir / "slow.yaml", "slow", frequency="01:00:00")
    assert "slow" not in windows.hunt_latencies()
    windows.clear_cache()
    assert "slow" in windows.hunt_latencies()


@pytest.mark.integration
def test_the_first_run_waits_for_the_slowest_enabled_hunt(hunt_dir):
    """A test without expectations gets the slowest enabled hunt, not the floor [FR-10]."""
    _hunt(hunt_dir / "fast.yaml", "fast", frequency="00:05:00", time_range="00:05:00")
    _hunt(hunt_dir / "daily.yaml", "daily", frequency="1:00:00:00", time_range="1:00:00:00")
    _hunt(hunt_dir / "off.yaml", "off", enabled=False, frequency="7:00:00:00", time_range="7:00:00:00")
    assert observation_window() == timedelta(days=2, minutes=30)
    assert observation_window(set()) == timedelta(days=2, minutes=30)


@pytest.mark.integration
def test_the_window_stays_within_floor_and_ceiling(hunt_dir, monkeypatch):
    assert observation_window() == timedelta(minutes=60)

    _hunt(hunt_dir / "weekly.yaml", "weekly", frequency="7:00:00:00", time_range="7:00:00:00")
    windows.clear_cache()
    assert observation_window() == timedelta(hours=72)

    config = get_config().svs.runs.observation_window
    monkeypatch.setattr(config, "slack_minutes", 0)
    monkeypatch.setattr(config, "floor_minutes", 5)
    (hunt_dir / "weekly.yaml").unlink()
    _hunt(hunt_dir / "fast.yaml", "fast", frequency="00:05:00", time_range="00:05:00")
    windows.clear_cache()
    assert observation_window() == timedelta(minutes=10)


@pytest.mark.integration
def test_the_window_with_expectations(hunt_dir):
    _hunt(hunt_dir / "fast.yaml", "fast", frequency="01:00:00", time_range="01:00:00")
    _hunt(hunt_dir / "daily.yaml", "daily", frequency="1:00:00:00", time_range="1:00:00:00")
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
