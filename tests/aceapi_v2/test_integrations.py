"""The API routes an integration registers (aceapi_v2/integrations.py), served under
/api/v2/integrations/<name>."""

from typing import Annotated

import pytest
from fastapi import APIRouter, Depends
from httpx import ASGITransport, AsyncClient

from aceapi_v2 import application, integrations
from aceapi_v2.application import app, create_app
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import require_permission

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def registry(monkeypatch):
    """An empty registry, so these tests do not see the routers of the integrations installed here
    and leave none of theirs behind. They build their own apps, on the empty router: the
    module-level app would keep serving a router registered on the real one for the rest of the
    session."""
    router = APIRouter()
    monkeypatch.setattr(integrations, "router", router)
    monkeypatch.setattr(application, "integrations_router", router)
    monkeypatch.setattr(integrations, "_ROUTERS", {})


def _router() -> APIRouter:
    router = APIRouter()

    @router.get("/gated")
    async def gated(auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))]) -> dict:
        return {"user": auth.auth_name}

    @router.get("/ungated")
    async def ungated() -> dict:
        return {}

    return router


def _paths(fastapi_app) -> list[str]:
    return list(fastapi_app.openapi()["paths"])


def _client(fastapi_app, api_key: str | None = None) -> AsyncClient:
    # the session override the client fixtures put on the module-level app, so the API key they
    # mint is visible to this app too
    fastapi_app.dependency_overrides.update(app.dependency_overrides)
    return AsyncClient(transport=ASGITransport(app=fastapi_app), base_url="http://test",
                       headers={"x-ace-auth": api_key} if api_key else {})


class TestRegistration:
    def test_served_under_the_integration_name(self):
        integrations.register_integration_router("vendor", _router())

        assert {"/integrations/vendor/gated", "/integrations/vendor/ungated"} <= set(_paths(create_app()))

    @pytest.mark.asyncio
    async def test_registered_after_the_app_was_built(self, _override_db_session, valid_api_key):
        """Integrations are imported during initialize_environment(), after importing aceapi_v2
        has built the module-level app. This holds because FastAPI resolves an included router's
        routes per request (it has since 0.141); if an upgrade changes that, this fails."""
        built = create_app()

        integrations.register_integration_router("vendor", _router())

        async with _client(built, valid_api_key) as client:
            assert (await client.get("/integrations/vendor/gated")).status_code == 200

    def test_registering_the_same_router_again_does_nothing(self):
        router = _router()
        integrations.register_integration_router("vendor", router)
        integrations.register_integration_router("vendor", router)

        assert _paths(create_app()).count("/integrations/vendor/gated") == 1

    def test_a_name_belongs_to_one_router(self):
        integrations.register_integration_router("vendor", _router())

        with pytest.raises(ValueError):
            integrations.register_integration_router("vendor", _router())

    @pytest.mark.parametrize("name", ["", "Vendor", "a/b", "a_b", "-a", "a-"])
    def test_invalid_names(self, name):
        with pytest.raises(ValueError):
            integrations.register_integration_router(name, _router())


class TestAccess:
    @pytest.mark.asyncio
    async def test_every_route_requires_a_credential(self, _override_db_session):
        """Even one the integration left without a permission gate (which
        tests/saq/test_permission_catalog.py fails)."""
        integrations.register_integration_router("vendor", _router())

        async with _client(create_app()) as client:
            assert (await client.get("/integrations/vendor/ungated")).status_code == 401
            assert (await client.get("/integrations/vendor/gated")).status_code == 401

    @pytest.mark.asyncio
    async def test_a_gated_route(self, _override_db_session, valid_api_key):
        integrations.register_integration_router("vendor", _router())

        async with _client(create_app(), valid_api_key) as client:
            response = await client.get("/integrations/vendor/gated")

        assert response.status_code == 200, response.text
        assert response.json() == {"user": "unittest"}
