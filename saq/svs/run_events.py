"""Rows of a run's event log (svs_run_events, docs/SVS_API.md, *Run events*). The run lifecycle
(saq/svs/runs.py) and attribution (saq/svs/attribution.py) both append to it, each in its own
transaction."""

import json
from datetime import datetime
from typing import Optional

from saq.database.model import SVSRunEvent
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
