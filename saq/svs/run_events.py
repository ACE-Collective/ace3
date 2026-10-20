"""Rows of a run's event log (svs_run_events, docs/SVS_API.md, *Run events*), and the fields of a
record about a run. The run lifecycle (saq/svs/runs.py), attribution (saq/svs/attribution.py),
results (saq/svs/results.py) and decisions (saq/svs/expectations.py) all append to the event log,
each in its own transaction."""

import json
from datetime import datetime
from typing import Optional

from saq.database.model import SVSRun, SVSRunEvent
from saq.svs.constants import RunEventKind


def new_run_event(run_id: int, kind: RunEventKind, actor: str, *, actor_user_id: Optional[int] = None,
                  from_state: Optional[str] = None, to_state: Optional[str] = None,
                  details: Optional[dict] = None, now: Optional[datetime] = None) -> SVSRunEvent:
    """An event row for the caller to add to its session."""
    return SVSRunEvent(
        run_id=run_id,
        kind=kind.value,
        from_state=from_state,
        to_state=to_state,
        actor=actor[:256],
        actor_user_id=actor_user_id,
        details=json.dumps(details, sort_keys=True, default=str) if details is not None else None,
        created_at=now or datetime.now())


def run_log_fields(run: SVSRun) -> dict:
    """The fields every record about a run carries (docs/SVS.md, Part 5, *Logging contract*)."""
    return {"svs_run": run.uuid, "svs_test": run.test_guid, "svs_marker": run.marker}
