"""The link from a run to the site's own log search (docs/SVS.md, Part 5, *Debugging a run*;
docs/SVS_RUNS.md, *Logs*). ACE builds it from svs.log_search_url and never queries it."""

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from saq.configuration.config import get_config
from saq.database.model import SVSRun


def _epoch(value: datetime) -> str:
    # run times are naive, written with datetime.now() on hosts that run in UTC, as the API reports them
    return str(int(value.replace(tzinfo=timezone.utc).timestamp()))


def log_search_window(run: SVSRun, now: datetime) -> tuple[datetime, datetime]:
    """Where a search for the run's records starts and ends: its start (its registration while it
    hasn't started) to the end of its attribution window (when it was canceled or closed if it never
    got one), or now when that is still to come."""
    earliest = run.started_at or run.created_at
    end = run.attribution_ends_at or run.canceled_at or run.closed_at
    latest = end if end is not None and end < now else now
    return earliest, max(latest, earliest)


def log_search_url(run: SVSRun, now: Optional[datetime] = None) -> Optional[str]:
    """svs.log_search_url for the run, each value URL-encoded; None when it isn't set. The config
    validates the template's names (saq.configuration.schema.SVSConfig)."""
    template = get_config().svs.log_search_url
    if not template:
        return None

    earliest, latest = log_search_window(run, now or datetime.now())
    values = {"run_uuid": run.uuid, "marker": run.marker, "test_guid": run.test_guid,
              "earliest": _epoch(earliest), "latest": _epoch(latest)}
    return template.format(**{name: quote(value, safe="") for name, value in values.items()})
