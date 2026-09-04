"""The design's central CI invariant: a key scoped to the AI surface is denied everywhere else.

Authenticates with a key scoped exactly like a real AI investigation key (ai:<backend> + ai:alert +
ai:event) and asserts 403 on every non-public aceapi_v2 route, and on every AI route outside the
key's own backends. Guards against a future route shipping without a permission gate -- the scope
filter lives in require_permission, so an authenticated-but-ungated route would be reachable by ANY key.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aceapi_v2.application import app as v2_app
from aceapi_v2.database import get_async_session
from tests.aceapi_v2.conftest import make_api_key
from tests.saq.test_permission_catalog import _FASTAPI_PUBLIC_PATHS, _iter_effective_routes

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def ai_key(session, test_user) -> str:
    return await make_api_key(
        session, test_user.id, inherit=False, scope=[("ai", "fake"), ("ai", "alert"), ("ai", "event")])


@pytest_asyncio.fixture
async def _override_v2_db_session(connection):
    """The same test-transaction override the aceapi_v2 conftest applies, but on the v2 app,
    so this module can drive both apps against one transaction."""
    from sqlalchemy.ext.asyncio import AsyncSession

    async def override_get_session():
        session = AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    v2_app.dependency_overrides[get_async_session] = override_get_session
    yield
    v2_app.dependency_overrides.clear()


def _fill_path_params(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


@pytest.mark.asyncio
async def test_ai_scoped_key_is_403_on_every_gated_v2_route(_override_v2_db_session, ai_key):
    checked = 0
    async with AsyncClient(
        transport=ASGITransport(app=v2_app),
        base_url="http://test",
        headers={"x-ace-auth": ai_key},
    ) as client:
        for path, methods, _ in _iter_effective_routes(v2_app):
            if path in _FASTAPI_PUBLIC_PATHS:
                continue

            for method in methods:
                request_kwargs = {}
                if method in ("POST", "PUT", "PATCH"):
                    request_kwargs["json"] = {}
                response = await client.request(method, _fill_path_params(path), **request_kwargs)
                assert response.status_code == 403, (
                    f"{method} {path} returned {response.status_code} for an ai-scoped key; "
                    "every non-public aceapi_v2 route must deny it with 403")
                checked += 1

    assert checked > 20  # sanity: the sweep actually covered the API surface


@pytest.mark.asyncio
async def test_ai_scoped_key_reaches_only_its_own_backends(_override_db_session, session, test_user):
    from tests.aceapi_ai.conftest import api_key_client

    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "fake"), ("ai", "alert"), ("ai", "event")])
    end = datetime.now(timezone.utc)
    body = {
        "query": "search x",
        "start_time": (end - timedelta(hours=1)).isoformat(),
        "end_time": end.isoformat(),
    }
    unknown = "11111111-1111-1111-1111-111111111111"

    async with api_key_client(key) as client:
        # in scope: the fake backend, the alert reads and the event read (each 404s on an unknown
        # id, i.e. the request got past the gate)
        assert (await client.post("/query/fake", json=body)).status_code == 200
        assert (await client.get(f"/alerts/{unknown}")).status_code == 404
        assert (await client.get(f"/alerts/{unknown}/logs")).status_code == 404
        assert (await client.get(f"/alerts/{unknown}/download")).status_code == 404
        assert (await client.get("/events/999999")).status_code == 404

        # out of scope: the splunk backend route exists but the key's scope does not cover it
        assert (await client.post("/query/splunk", json=body)).status_code == 403


@pytest.mark.asyncio
async def test_alert_and_event_reads_need_their_own_minor(_override_db_session, session, test_user):
    """ai:alert does not open /events and ai:event does not open /alerts -- the two minors are independent."""
    from tests.aceapi_ai.conftest import api_key_client

    unknown = "11111111-1111-1111-1111-111111111111"
    alert_only = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "alert")])
    event_only = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "event")])

    async with api_key_client(alert_only) as client:
        assert (await client.get(f"/alerts/{unknown}")).status_code == 404
        assert (await client.get("/events/999999")).status_code == 403
    async with api_key_client(event_only) as client:
        assert (await client.get("/events/999999")).status_code == 404
        for path in (f"/alerts/{unknown}", f"/alerts/{unknown}/logs", f"/alerts/{unknown}/download"):
            assert (await client.get(path)).status_code == 403, path
