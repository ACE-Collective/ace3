"""The runs screen's filters (saq.svs.run_filters)."""

import pytest
from sqlalchemy import select, update

from saq.database.model import SVSRun
from saq.database.pool import get_db
from saq.svs import runs
from saq.svs.constants import RUN_STATES
from saq.svs.hosts import build_spec, create_host
from saq.svs.refusals import Caller
from saq.svs.run_filters import needs_attention_condition
from saq.svs.runs import Registration, TargetSpec
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

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
