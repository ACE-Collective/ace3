"""The node-to-node application served by the http-api-engine container (docs/ENGINE_API.md).

nginx sends /api/v2/engine/ to that container, so it must serve every engine route the full
application does, and nothing a user would call: anything else mounted there would let user
traffic back onto the workers this container exists to keep free for the engines.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from aceapi_v2.application import create_app
from aceapi_v2.app_factory import create_engine_app

ENGINE_APP_PREFIXES = ("/engine/", "/health/", "/common/")


def _route_paths(app) -> set[str]:
    # read from the schema: included routers are not flattened into app.routes
    return set(app.openapi()["paths"])


@pytest.mark.unit
def test_engine_app_serves_every_engine_route():
    full_engine_paths = {path for path in _route_paths(create_app()) if path.startswith("/engine/")}
    assert full_engine_paths, "no /engine/ routes in the full application"
    assert full_engine_paths <= _route_paths(create_engine_app())


@pytest.mark.unit
def test_engine_app_serves_nothing_else():
    paths = _route_paths(create_engine_app())
    assert paths
    assert {path for path in paths if not path.startswith(ENGINE_APP_PREFIXES)} == set()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_engine_app_answers_ping():
    async with AsyncClient(transport=ASGITransport(app=create_engine_app()), base_url="http://test") as client:
        response = await client.get("/health/ping")

    assert response.status_code == 200
    assert response.json() == {"result": "pong"}
