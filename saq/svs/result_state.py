"""Whether a run's live result is current (svs_run_result_state, docs/SVS_RUNS.md, *Results*).

Everything that changes what a run's result would be marks the run stale in its own transaction:
attribution (saq/svs/attribution.py), a run ending (saq/svs/runs.py), and a decision about the
test (saq/svs/expectations.py). Marking bumps the run's generation; a computation
(saq/svs/results.py) reads the generation before it reads anything else and clears stale only if
the generation is still the one it read, so a change that lands while it computes is never lost.
"""

from typing import Iterable, Optional

from sqlalchemy import literal, select, true
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.database.model import SVSRun, SVSRunResultState
from saq.svs.constants import RunState

# the runs whose live result is kept current: a started run has none yet, but marking it closes
# the race with its end (an attribution written as it ends is never missed)
RESULT_STATES = (RunState.STARTED.value, RunState.ENDED.value, RunState.REVIEWED.value)


def mark_runs_stale(session, *conditions, run_ids: Optional[Iterable[int]] = None) -> None:
    """Marks stale, in the caller's transaction, the results of the runs in RESULT_STATES that match
    conditions (and are among run_ids, when given). One statement, in run id order, so two writers
    lock the rows in the same order."""
    statement = select(SVSRun.id, literal(1), true()).where(SVSRun.state.in_(RESULT_STATES), *conditions)
    if run_ids is not None:
        run_ids = sorted(set(run_ids))
        if not run_ids:
            return
        statement = statement.where(SVSRun.id.in_(run_ids))

    session.execute(
        mysql_insert(SVSRunResultState)
        .from_select(["run_id", "generation", "stale"], statement.order_by(SVSRun.id))
        .on_duplicate_key_update(generation=SVSRunResultState.generation + 1, stale=True))
