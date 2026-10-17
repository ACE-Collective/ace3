"""The coverage refresh lock (docs/SVS_COVERAGE.md, *Refresh*): the single svs_coverage_state row,
locked FOR UPDATE for the whole transaction of a refresh, a snapshot, or a worklist resolution, so
none of them computes from what another one is about to change. Its own module because both
saq.svs.coverage and saq.svs.worklist take it, and coverage imports worklist."""

from sqlalchemy import insert, select

from saq.database.model import SVSCoverageState

# the id of the single svs_coverage_state row
STATE_ID = 1


def lock_refresh(session) -> SVSCoverageState:
    """Locks the svs_coverage_state row (creating it the first time) in session's transaction."""
    session.execute(insert(SVSCoverageState).prefix_with("IGNORE").values(id=STATE_ID))
    return session.execute(
        select(SVSCoverageState).where(SVSCoverageState.id == STATE_ID).with_for_update()).scalar_one()
