"""A run's windows (docs/SVS_RUNS.md, *Windows*).

The observation window is how long a started run waits for its alerts before it ends: the worst-case
latency of the slowest signature the test is expected to fire, plus slack, within a floor and a
ceiling (svs.runs.observation_window). A hunt's worst-case latency is frequency + time_range +
offset; every other signature (YARA, analysis modules) fires while the alert is analyzed, so its
latency is 0 and the floor covers it. A test with no expectations yet, which is its first run, where
expectations are discovered, waits for the slowest *enabled* hunt instead [FR-10].

The attribution window is longer by svs.runs.attribution_extra_hours: alerts that arrive after the
run ended but inside it are still attributed, as late.

Hunts are read the way the signature inventory reads them (saq.signatures.loaders.hunt): the merged
`rule` dict of each hunt file, without the hunter's pydantic models, which need a running
HuntManager.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from croniter import croniter

from saq.configuration.config import get_config
from saq.constants import TIMESPEC_TOKEN
from saq.signatures.model import SignatureLocation, SignatureType
from saq.util.time import create_timedelta, is_timedelta_string

# a batch registers many runs back to back; each process reads the hunt files at most this often
HUNT_LATENCY_CACHE_SECONDS = 60

# how far ahead a cron frequency's firings are looked at for its largest gap, and at most how many
CRON_HORIZON = timedelta(days=7)
CRON_MAX_FIRINGS = 20000

_cache_lock = threading.Lock()
_cache: Optional[tuple[float, dict[str, "HuntInfo"]]] = None


class InvalidHunt(ValueError):
    pass


def _timespec(value) -> Optional[timedelta]:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not is_timedelta_string(value):
        raise InvalidHunt(f"{value!r} is not a time span")
    return create_timedelta(value)


def cron_interval(expression: str, start: Optional[datetime] = None) -> timedelta:
    """The largest gap between consecutive firings of a cron expression over the next week."""
    try:
        schedule = croniter(expression, start or datetime.now())
    except (TypeError, ValueError) as e:
        raise InvalidHunt(f"{expression!r} is neither a time span nor a cron expression") from e

    previous = schedule.get_next(datetime)
    horizon = previous + CRON_HORIZON
    largest = timedelta(0)
    for _ in range(CRON_MAX_FIRINGS):
        firing = schedule.get_next(datetime)
        largest = max(largest, firing - previous)
        if firing > horizon:
            break
        previous = firing
    return largest


def hunt_latency(rule: dict) -> timedelta:
    """The worst-case latency of a hunt's rule dict: frequency + time_range + offset. time_range
    prefers time_ranges.TIMESPEC.duration_before, as QueryHunt.time_range does; a hunt type without
    a time range (or an offset) counts it as 0. Raises InvalidHunt."""
    frequency = rule.get("frequency")
    if not isinstance(frequency, str) or not frequency:
        raise InvalidHunt("no frequency")
    interval = create_timedelta(frequency) if is_timedelta_string(frequency) else cron_interval(frequency)

    time_range = None
    time_ranges = rule.get("time_ranges")
    if isinstance(time_ranges, dict) and isinstance(time_ranges.get(TIMESPEC_TOKEN), dict):
        time_range = _timespec(time_ranges[TIMESPEC_TOKEN].get("duration_before"))
    if time_range is None:
        time_range = _timespec(rule.get("time_range"))

    offset = _timespec(rule.get("offset"))
    return interval + (time_range or timedelta(0)) + (offset or timedelta(0))


def hunt_locations() -> list[SignatureLocation]:
    """The rule directories of the schedulable hunt types."""
    # local: saq.signatures.locations imports the yara scanner, which aceapi_v2 (whose run API
    # imports this module) must import without (tests/saq/test_imports.py)
    from saq.signatures.locations import get_signature_locations

    return get_signature_locations(SignatureType.HUNT)


@dataclass(frozen=True)
class HuntInfo:
    """What SVS needs of a hunt: its window latency, for a run's result its name, suppression and
    rule hash, and for coverage its tags."""
    uuid: str
    name: str
    enabled: bool
    # frequency + time_range + offset; None when the hunt's timing can't be read
    latency: Optional[timedelta]
    # its suppression period, None without one (or when it can't be read)
    suppression: Optional[timedelta]
    # it groups by group_by, so it suppresses each group inside its query results and the hunter
    # records the runs it dropped a match for (svs_suppressed_matches); a hunt without it suppresses
    # as a whole, by not running, and that can only be inferred from its alerts
    per_group: bool
    # the content hash of its file, as the signature inventory computes it
    content_hash: str
    # its tags, as the signature inventory reads them (mitre: tags map it to ATT&CK techniques)
    tags: tuple[str, ...] = ()


def _read_hunts() -> dict[str, HuntInfo]:
    # local: both import the saq.collectors.hunter package, which imports the collector and engine
    # stack, which imports aceapi_v2, whose run API imports this module
    from saq.collectors.hunter.loader import load_merged_yaml
    from saq.signatures.loaders.hunt import is_hunt_file
    from saq.signatures.loaders.util import content_hash, normalize_tags

    result: dict[str, HuntInfo] = {}
    for location in hunt_locations():
        if not os.path.isdir(location.path):
            logging.warning("hunt rule_dir %s is not a directory; its hunts don't count toward svs run windows",
                            location.path)
            continue

        for entry in sorted(os.scandir(location.path), key=lambda e: e.name):
            if not entry.is_file() or not is_hunt_file(entry.name):
                continue

            try:
                merged, _ = load_merged_yaml(entry.path)
                rule = merged.get("rule") if isinstance(merged, dict) else None
                if not isinstance(rule, dict) or not rule.get("uuid"):
                    continue
                with open(entry.path, "r", encoding="utf-8", errors="surrogateescape") as fp:
                    source = fp.read()
            except Exception as e:
                logging.warning("unable to read hunt %s for svs: %s", entry.path, e)
                continue

            enabled = rule.get("enabled") is True
            latency = None
            try:
                latency = hunt_latency(rule)
            except Exception as e:
                if enabled:
                    logging.warning("unable to read the latency of hunt %s for svs run windows: %s", entry.path, e)

            suppression = None
            try:
                suppression = _timespec(rule.get("suppression"))
            except Exception as e:
                logging.warning("unable to read the suppression of hunt %s for svs run results: %s", entry.path, e)

            uuid = str(rule["uuid"]).strip()
            info = HuntInfo(uuid=uuid, name=str(rule.get("name") or "unnamed"), enabled=enabled, latency=latency,
                            suppression=suppression, per_group=bool(rule.get("group_by")),
                            content_hash=content_hash(source), tags=normalize_tags(rule.get("tags")))
            # one uuid in two files: the enabled one counts, then the slower
            previous = result.get(uuid)
            if previous is None or (info.enabled, info.latency or timedelta(0)) > (
                    previous.enabled, previous.latency or timedelta(0)):
                result[uuid] = info

    return result


def hunt_info() -> dict[str, HuntInfo]:
    """{hunt uuid: HuntInfo} of every hunt, enabled or not, cached per process for
    HUNT_LATENCY_CACHE_SECONDS."""
    global _cache
    with _cache_lock:
        if _cache is not None and time.monotonic() - _cache[0] < HUNT_LATENCY_CACHE_SECONDS:
            return _cache[1]

        hunts = _read_hunts()
        _cache = (time.monotonic(), hunts)
        return hunts


def hunt_latencies() -> dict[str, timedelta]:
    """{hunt uuid: worst-case latency} of every enabled hunt whose timing can be read."""
    return {uuid: info.latency for uuid, info in hunt_info().items() if info.enabled and info.latency is not None}


def clear_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = None


def observation_window(expected_signature_uuids: Optional[set[str]] = None) -> timedelta:
    """How long a started run waits for its alerts. With expectations, it is the worst-case latency
    of the slowest expected signature plus slack; without any, that of the slowest enabled hunt plus
    slack [FR-10]. Either way within the configured floor and ceiling."""
    config = get_config().svs.runs.observation_window
    floor = timedelta(minutes=config.floor_minutes)
    ceiling = timedelta(hours=config.ceiling_hours)

    latencies = hunt_latencies()
    if expected_signature_uuids:
        slowest = max((latencies.get(uuid, timedelta(0)) for uuid in expected_signature_uuids), default=timedelta(0))
    else:
        slowest = max(latencies.values(), default=timedelta(0))

    return min(max(slowest + timedelta(minutes=config.slack_minutes), floor), ceiling)


def attribution_window(observation: timedelta) -> timedelta:
    """How long after a run starts its alerts are still attributed: the observation window plus
    svs.runs.attribution_extra_hours."""
    return observation + timedelta(hours=get_config().svs.runs.attribution_extra_hours)
