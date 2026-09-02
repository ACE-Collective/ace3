"""The AI app's alert routes: ai:alert gating over the shared v2 alert service -- the alert itself
with its version token (ETag / If-None-Match), the saq.log, and the encrypted package download."""

import uuid

import pytest

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------------------ GET /alerts/{uuid}

@pytest.mark.asyncio
async def test_get_alert_requires_auth(unauth_client):
    assert (await unauth_client.get(f"/alerts/{uuid.uuid4()}")).status_code == 401


@pytest.mark.asyncio
async def test_get_alert_requires_ai_alert_scope(_override_db_session, session, test_user):
    from tests.aceapi_ai.conftest import api_key_client
    from tests.aceapi_v2.conftest import make_api_key

    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "fake"), ("ai", "event")])
    async with api_key_client(key) as client:
        assert (await client.get(f"/alerts/{uuid.uuid4()}")).status_code == 403
        assert (await client.get(f"/alerts/{uuid.uuid4()}/logs")).status_code == 403


@pytest.mark.asyncio
async def test_get_alert_missing_is_404_and_invalid_is_400(ai_scoped_client):
    assert (await ai_scoped_client.get(f"/alerts/{uuid.uuid4()}")).status_code == 404
    assert (await ai_scoped_client.get("/alerts/not-a-uuid")).status_code == 400
    assert (await ai_scoped_client.get(f"/alerts/{uuid.uuid4()}/logs")).status_code == 404


@pytest.mark.asyncio
async def test_get_alert_returns_version_and_honours_if_none_match(ai_scoped_client):
    """Same contract as the v2 route: ETag = version token, 304 on a match (weak validators and lists
    included), a fresh token once the alert changes."""
    from saq.database.pool import get_db
    from saq.database.util.alert import touch_alerts
    from tests.saq.helpers import insert_alert

    alert = insert_alert()
    response = await ai_scoped_client.get(f"/alerts/{alert.uuid}")
    assert response.status_code == 200
    etag = response.headers["ETag"]
    assert response.json()["result"]["version"] == etag.strip('"')

    response = await ai_scoped_client.get(f"/alerts/{alert.uuid}", headers={"If-None-Match": etag})
    assert response.status_code == 304
    assert response.headers["ETag"] == etag
    assert response.content == b""

    response = await ai_scoped_client.get(f"/alerts/{alert.uuid}", headers={"If-None-Match": f'"other", W/{etag}'})
    assert response.status_code == 304

    touch_alerts([alert.uuid])
    get_db().commit()
    response = await ai_scoped_client.get(f"/alerts/{alert.uuid}", headers={"If-None-Match": etag})
    assert response.status_code == 200
    assert response.headers["ETag"] != etag


@pytest.mark.asyncio
async def test_get_alert_logs_serves_saq_log(ai_scoped_client):
    import os

    from tests.saq.helpers import insert_alert

    alert = insert_alert()
    # a fresh test alert has no saq.log (the engine writes it during analysis): absent -> 404, present -> the file
    assert (await ai_scoped_client.get(f"/alerts/{alert.uuid}/logs")).status_code == 404
    with open(os.path.join(alert.storage_dir, "saq.log"), "w") as fp:
        fp.write("[2026-09-02 14:00:00,000] first line\n")
    response = await ai_scoped_client.get(f"/alerts/{alert.uuid}/logs")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text.startswith("[2026-09-02 14:00:00,000] first line")


# --------------------------------------------------------------------- GET /alerts/{uuid}/download


@pytest.mark.asyncio
async def test_download_requires_auth(unauth_client):
    response = await unauth_client.get(f"/alerts/{uuid.uuid4()}/download")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_download_requires_ai_alert_scope(_override_db_session, session, test_user):
    from tests.aceapi_ai.conftest import api_key_client
    from tests.aceapi_v2.conftest import make_api_key

    # ai:fake only -- no ai:alert
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "fake")])
    async with api_key_client(key) as client:
        response = await client.get(f"/alerts/{uuid.uuid4()}/download")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_download_missing_alert_is_404(ai_scoped_client):
    response = await ai_scoped_client.get(f"/alerts/{uuid.uuid4()}/download")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_download_invalid_uuid_is_400(ai_scoped_client):
    response = await ai_scoped_client.get("/alerts/not-a-uuid/download")
    assert response.status_code == 400
