"""The runs screen's filters (saq.svs.run_filters)."""

from datetime import datetime

import pytest
from sqlalchemy import select, update

from saq.constants import DISPOSITION_FALSE_POSITIVE
from saq.database.model import SVSAttribution, SVSRun
from saq.database.pool import get_db
from saq.svs import runs
from saq.svs.constants import RUN_STATES
from saq.svs.hosts import build_spec, create_host
from saq.svs.refusals import Caller
from saq.svs.run_filters import needs_attention_condition, run_filter_conditions
from saq.svs.runs import Registration, TargetSpec
from tests.saq.helpers import insert_alert
from tests.saq.svs.conftest import add_catalog_test, attribute_to_run, set_disposition

# several runs on one test host are fixtures here; the host's claim is tested in test_runs.py
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("overlapping_runs")]

GUID = "aaaaaaaa-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def setup(no_hunts):
    add_catalog_test(GUID)
    create_host(build_spec("win10-01"), None)


def _run(state: str, changed_since_review: bool = False) -> str:
    run_uuid = runs.register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"),
                             Caller(name="art-launcher")).uuid
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.uuid == run_uuid)
               .values(state=state, changed_since_review=changed_since_review))
    db.commit()
    return run_uuid


def test_needs_attention():
    """Ended and not reviewed, failed, or reviewed and changed since; nothing else."""
    plain = {state: _run(state) for state in RUN_STATES}
    changed = {state: _run(state, changed_since_review=True) for state in ("reviewed", "closed")}

    db = get_db()
    db.expire_all()
    # the flag means nothing outside reviewed
    assert set(db.execute(select(SVSRun.uuid).where(needs_attention_condition())).scalars()) == {
        plain["ended"], plain["error"], changed["reviewed"]}


def test_terminal_runs_holding_open_alerts_need_attention():
    open_alert = insert_alert()
    closed_alert = insert_alert()
    set_disposition(closed_alert.uuid, DISPOSITION_FALSE_POSITIVE)

    holding = {state: attribute_to_run(open_alert.uuid, state).uuid for state in ("closed", "reviewed", "canceled")}
    done = attribute_to_run(closed_alert.uuid, "closed").uuid
    removed = attribute_to_run(open_alert.uuid, "closed", content_hash="1" * 64)
    db = get_db()
    db.execute(update(SVSAttribution).where(SVSAttribution.run_id == removed.id)
               .values(removed_at=datetime.now(), removed_by="svs"))
    db.commit()

    db.expire_all()
    needing = set(db.execute(select(SVSRun.uuid).where(needs_attention_condition())).scalars())
    # a canceled run still attributes: it is not done with yet
    assert needing == {holding["closed"], holding["reviewed"]}

    with_open_alerts = set(db.execute(select(SVSRun.uuid).where(*run_filter_conditions(
        [{"name": "Has Open Alerts", "values": ["true"]}]))).scalars())
    assert with_open_alerts == set(holding.values())
    without = set(db.execute(select(SVSRun.uuid).where(*run_filter_conditions(
        [{"name": "Has Open Alerts", "values": ["false"]}]))).scalars())
    assert without == {done, removed.uuid}


def test_the_reason_filter_finds_the_reason_a_run_ended_early():
    ended_early, closed, failed = _run("ended"), _run("closed"), _run("error")
    db = get_db()
    for run_uuid, values in ((ended_early, {"end_reason": "the test failed to run"}),
                             (closed, {"close_reason": "start timeout"}),
                             (failed, {"error_reason": "the launcher reported a failure"})):
        db.execute(update(SVSRun).where(SVSRun.uuid == run_uuid).values(**values))
    db.commit()

    def matching(value: str) -> set[str]:
        return set(db.execute(select(SVSRun.uuid).where(*run_filter_conditions(
            [{"name": "Reason", "values": [value]}]))).scalars())

    assert matching("failed to run") == {ended_early}
    assert matching("fail") == {ended_early, failed}
    assert matching("timeout") == {closed}
