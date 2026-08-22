"""The AI app's alert download route: ai:alert gating over the shared zip service."""

import uuid

import pytest

pytestmark = pytest.mark.integration


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
