"""PUT /api/v2/alerts/owner: sets the owner of alerts (take, assign or unassign), leaving the ones
another analyst owns alone unless taking them was confirmed."""

import logging

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.configuration.config import get_config
from saq.configuration.schema import ConfigApiKey
from saq.database.model import Alert, User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user
from saq.util import sha256_str
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import audit_actor_of, audit_actors, audit_record, insert_alert

pytestmark = pytest.mark.integration

PATH = "/alerts/owner"


@pytest.fixture
def other_analyst():
    """An analyst other than the caller, who owns alerts."""
    user = add_user("jane_owner", "jane_owner@localhost", "Jane", "password")
    yield user
    delete_user("jane_owner")


@pytest.fixture
def assignee():
    """An analyst the caller hands alerts to."""
    user = add_user("raj_assignee", "raj_assignee@localhost", "Raj", "password")
    yield user
    delete_user("raj_assignee")


def _caller_id() -> int:
    return get_db().query(User).filter(User.username == "unittest").one().id


def _owned_by(alert: Alert, user_id: int) -> None:
    db = get_db()
    db.execute(Alert.__table__.update().where(Alert.id == alert.id).values(owner_id=user_id))
    db.commit()


def _owner_of(alert: Alert) -> int | None:
    db = get_db()
    db.expire_all()
    return db.get(Alert, alert.id).owner_id


def _body(alerts: list[Alert], owner_id: int | None, take_owned: dict | None = None) -> dict:
    body = {"alert_uuids": [alert.uuid for alert in alerts], "owner_id": owner_id}
    if take_owned is not None:
        body["take_owned"] = take_owned
    return body


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    assert (await unauth_client.put(PATH, json={"alert_uuids": ["x"], "owner_id": None})).status_code == 401


@pytest.mark.asyncio
async def test_requires_alert_write(_override_db_session, session: AsyncSession, test_user):
    alert = insert_alert()
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("alert", "read")])
    async with api_key_client(key) as reader:
        assert (await reader.put(PATH, json=_body([alert], test_user.id))).status_code == 403
    assert _owner_of(alert) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"alert_uuids": [], "owner_id": None},
    # owner_id is required: leaving it out must not quietly unassign
    {"alert_uuids": ["x"]},
])
async def test_rejects_an_incomplete_request(client: AsyncClient, body):
    assert (await client.put(PATH, json=body)).status_code == 422


@pytest.mark.asyncio
async def test_take(client: AsyncClient, client_actor, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    alerts = [insert_alert(), insert_alert()]

    response = await client.put(PATH, json=_body(alerts, _caller_id()))

    assert response.status_code == 200
    assert response.json() == {"applied": [alert.uuid for alert in alerts], "skipped": {}, "message": None}
    for alert in alerts:
        assert _owner_of(alert) == _caller_id()
    audit = audit_record(caplog, "user unittest set the owner of alerts")
    assert (*audit_actor_of(audit), audit.alert_uuids, audit.owner_id) == (
        *client_actor, [alert.uuid for alert in alerts], _caller_id())


@pytest.mark.asyncio
async def test_take_leaves_an_alert_another_analyst_owns_alone(client: AsyncClient, other_analyst):
    owned = insert_alert()
    _owned_by(owned, other_analyst.id)
    unowned = insert_alert()

    response = await client.put(PATH, json=_body([owned, unowned], _caller_id()))

    assert response.json() == {
        "applied": [unowned.uuid],
        "skipped": {owned.uuid: "Jane"},
        "message": "took ownership of 1 alerts; left 1 alert owned by Jane alone",
    }
    assert _owner_of(owned) == other_analyst.id
    assert _owner_of(unowned) == _caller_id()


@pytest.mark.asyncio
async def test_take_a_confirmed_alert(client: AsyncClient, other_analyst, client_actor, caplog):
    caplog.set_level(logging.INFO)
    owned = insert_alert()
    _owned_by(owned, other_analyst.id)

    response = await client.put(PATH, json=_body([owned], _caller_id(), {owned.uuid: other_analyst.id}))

    assert response.json()["applied"] == [owned.uuid]
    assert _owner_of(owned) == _caller_id()
    assert audit_actors(caplog, "alert ownership taken") == [client_actor]


@pytest.mark.asyncio
async def test_a_confirmation_for_another_owner_changes_nothing(client: AsyncClient, other_analyst):
    """The confirmation names who had the alert when the analyst looked; if it changed hands
    since, the analyst agreed to take it from someone else, so it is left alone."""
    owned = insert_alert()
    _owned_by(owned, other_analyst.id)

    response = await client.put(PATH, json=_body([owned], _caller_id(), {owned.uuid: _caller_id() + 1000}))

    assert response.json()["skipped"] == {owned.uuid: "Jane"}
    assert _owner_of(owned) == other_analyst.id


@pytest.mark.asyncio
async def test_assign(client: AsyncClient, assignee, other_analyst):
    unowned = insert_alert()
    already_theirs = insert_alert()
    _owned_by(already_theirs, assignee.id)
    someone_elses = insert_alert()
    _owned_by(someone_elses, other_analyst.id)

    response = await client.put(PATH, json=_body([unowned, already_theirs, someone_elses], assignee.id))

    assert response.json() == {
        "applied": [unowned.uuid, already_theirs.uuid],
        "skipped": {someone_elses.uuid: "Jane"},
        "message": "assigned 2 alerts to Raj; left 1 alert owned by Jane alone",
    }
    assert _owner_of(unowned) == assignee.id
    assert _owner_of(someone_elses) == other_analyst.id


@pytest.mark.asyncio
async def test_unassign(client: AsyncClient, other_analyst):
    mine = insert_alert()
    _owned_by(mine, _caller_id())
    theirs = insert_alert()
    _owned_by(theirs, other_analyst.id)

    response = await client.put(PATH, json=_body([mine, theirs], None))

    assert response.json() == {
        "applied": [mine.uuid],
        "skipped": {theirs.uuid: "Jane"},
        "message": "unassigned 1 alerts; left 1 alert owned by Jane alone",
    }
    assert _owner_of(mine) is None
    assert _owner_of(theirs) == other_analyst.id


@pytest.mark.asyncio
async def test_the_new_owner_must_be_an_enabled_user(client: AsyncClient, assignee):
    alert = insert_alert()

    assert (await client.put(PATH, json=_body([alert], 999999))).status_code == 422

    db = get_db()
    db.execute(User.__table__.update().where(User.id == assignee.id).values(enabled=False))
    db.commit()
    assert (await client.put(PATH, json=_body([alert], assignee.id))).status_code == 422
    assert _owner_of(alert) is None


@pytest.mark.asyncio
async def test_a_key_that_is_not_a_user_cannot_change_owners(_override_db_session, monkeypatch):
    alert = insert_alert()
    plaintext = "6a0c3b5e-0f1d-4b8e-9a7c-2e4f6d8b0a1c"
    monkeypatch.setattr(get_config(), "apikeys", {
        "service": ConfigApiKey(key=sha256_str(plaintext), scope=["alert:write"]),
    })

    async with api_key_client(plaintext) as service_client:
        response = await service_client.put(PATH, json={"alert_uuids": [alert.uuid], "owner_id": None})

    assert response.status_code == 400
