"""GET /api/v2/alerts/{alert_uuid}/meta: what the alert page polls for while it is open."""

import uuid
from datetime import datetime

import pytest
from httpx import AsyncClient

from saq.database.model import Alert, User
from saq.database.pool import get_db
from saq.database.util.alert import touch_alerts
from saq.database.util.locking import acquire_lock, release_lock
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration


def _meta_path(alert_uuid: str) -> str:
    return f"/alerts/{alert_uuid}/meta"


def _set_owner(alert_uuid: str, user_id: int, owner_time: datetime) -> None:
    db = get_db()
    db.execute(Alert.__table__.update().where(Alert.uuid == alert_uuid).values(owner_id=user_id, owner_time=owner_time))
    db.commit()


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    assert (await unauth_client.get(_meta_path(str(uuid.uuid4())))).status_code == 401


@pytest.mark.asyncio
async def test_requires_alert_read(noperm_client: AsyncClient):
    assert (await noperm_client.get(_meta_path(str(uuid.uuid4())))).status_code == 403


@pytest.mark.asyncio
async def test_invalid_uuid(client: AsyncClient):
    assert (await client.get(_meta_path("not-a-uuid"))).status_code == 400


@pytest.mark.asyncio
async def test_unknown_alert(client: AsyncClient):
    assert (await client.get(_meta_path(str(uuid.uuid4())))).status_code == 404


@pytest.mark.asyncio
async def test_unowned_alert(client: AsyncClient):
    alert = insert_alert()

    response = await client.get(_meta_path(alert.uuid))

    assert response.status_code == 200
    # polled every few seconds: never served from a cache
    assert response.headers["Cache-Control"] == "private, no-store"
    meta = response.json()
    assert meta["owner_id"] is None
    assert meta["owner_name"] is None
    assert meta["owner_time"] is None
    assert meta["is_locked"] is False
    assert meta["version"] == alert.version
    assert isinstance(meta["status"], str)


@pytest.mark.asyncio
async def test_owned_alert(client: AsyncClient):
    alert = insert_alert()
    user = get_db().query(User).filter(User.username == "unittest").one()
    _set_owner(alert.uuid, user.id, datetime(2026, 3, 30, 12, 0, 0))

    meta = (await client.get(_meta_path(alert.uuid))).json()

    assert meta["owner_id"] == user.id
    assert meta["owner_name"] == user.gui_display
    assert meta["owner_time"] == "2026-03-30T12:00:00Z"


@pytest.mark.asyncio
async def test_version_follows_the_alert(client: AsyncClient):
    alert = insert_alert()
    first = (await client.get(_meta_path(alert.uuid))).json()["version"]

    touch_alerts([alert.uuid])
    get_db().commit()

    assert (await client.get(_meta_path(alert.uuid))).json()["version"] != first


@pytest.mark.asyncio
async def test_locked_alert(client: AsyncClient):
    alert = insert_alert()
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(alert.uuid, lock_uuid, lock_owner="test-engine")
    try:
        meta = (await client.get(_meta_path(alert.uuid))).json()
    finally:
        release_lock(alert.uuid, lock_uuid)

    assert meta["is_locked"] is True
    assert meta["status"] == "Analyzing (test-engine)"
