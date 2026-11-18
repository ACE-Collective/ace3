"""The API routes an integration declares with api_router in its integration_<name>: block, served under
/api/v2/integrations/<name>."""

import logging
import sys
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from aceapi_v2.application import create_app
from tests.aceapi_v2.conftest import v2_app

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _tests_app_built_first():
    """Builds the app the other tests use, if no test in this worker has yet, before a test here declares
    its integrations: built after, it would serve their routers for the rest of the session."""
    v2_app()


@pytest.fixture
def router_module(tmp_path, monkeypatch) -> str:
    """The name of a module, importable but not yet imported, that defines an integration's router: one
    route behind a permission gate and one without."""
    name = f"vendor_api_{uuid.uuid4().hex}"
    (tmp_path / f"{name}.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import APIRouter, Depends\n"
        "from aceapi_v2.auth.schemas import ApiAuthResult\n"
        "from aceapi_v2.dependencies import require_permission\n"
        "router = APIRouter()\n"
        "not_a_router = object()\n"
        "@router.get('/gated')\n"
        "async def gated(auth: Annotated[ApiAuthResult, Depends(require_permission('alert', 'read'))]) -> dict:\n"
        "    return {'user': auth.auth_name}\n"
        "@router.get('/ungated')\n"
        "async def ungated() -> dict:\n"
        "    return {}\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name
    sys.modules.pop(name, None)


def _paths(fastapi_app) -> list[str]:
    return list(fastapi_app.openapi()["paths"])


def _client(fastapi_app, api_key: str | None = None) -> AsyncClient:
    # the session override the client fixtures put on v2_app(), so the API key they mint is visible
    # to this app too
    fastapi_app.dependency_overrides.update(v2_app().dependency_overrides)
    return AsyncClient(transport=ASGITransport(app=fastapi_app), base_url="http://test",
                       headers={"x-ace-auth": api_key} if api_key else {})


class TestDeclaration:
    def test_served_under_the_integration_name(self, declare_integration, router_module):
        declare_integration("vendor", api_router=f"{router_module}:router")

        assert {"/integrations/vendor/gated", "/integrations/vendor/ungated"} <= set(_paths(create_app()))

    def test_imported_only_when_an_app_is_built(self, declare_integration, router_module):
        declare_integration("vendor", api_router=f"{router_module}:router")
        assert router_module not in sys.modules

        create_app()

        assert router_module in sys.modules

    def test_a_disabled_integration_is_not_served(self, declare_integration, router_module):
        declare_integration("vendor", api_router=f"{router_module}:router", enabled=False)

        assert not [path for path in _paths(create_app()) if path.startswith("/integrations/")]
        assert router_module not in sys.modules

    def test_an_integration_without_a_router(self, declare_integration, router_module):
        declare_integration("vendor", api_router=None)
        declare_integration("other", api_router=f"{router_module}:router")

        paths = _paths(create_app())

        assert not [path for path in paths if path.startswith("/integrations/vendor")]
        assert "/integrations/other/gated" in paths

    @pytest.mark.parametrize("target", ["no_such_integration_module:router", "{module}:no_such_router",
                                        "{module}:not_a_router"])
    def test_one_that_fails_to_load_is_logged_and_left_out(self, declare_integration, router_module, caplog, target):
        target = target.format(module=router_module)
        declare_integration("broken", api_router=target)
        declare_integration("vendor", api_router=f"{router_module}:router")

        with caplog.at_level(logging.ERROR):
            paths = _paths(create_app())

        assert "/integrations/vendor/gated" in paths
        assert not [path for path in paths if path.startswith("/integrations/broken")]
        errors = [record for record in caplog.records
                  if record.getMessage() == f"unable to load the api_router of integration broken from {target}"]
        assert len(errors) == 1
        assert errors[0].levelno == logging.ERROR and errors[0].exc_info is not None
        assert (errors[0].integration, errors[0].hook, errors[0].target) == ("broken", "api_router", target)


class TestTheTestsApp:
    def test_does_not_serve_what_these_tests_declare(self, declare_integration, router_module):
        declare_integration("vendor", api_router=f"{router_module}:router")

        assert not [path for path in _paths(v2_app()) if path.startswith("/integrations/vendor")]


class TestAccess:
    @pytest.mark.asyncio
    async def test_every_route_requires_a_credential(self, declare_integration, router_module, _override_db_session):
        """Even one the integration left without a permission gate (which
        tests/saq/test_permission_catalog.py fails)."""
        declare_integration("vendor", api_router=f"{router_module}:router")

        async with _client(create_app()) as client:
            assert (await client.get("/integrations/vendor/ungated")).status_code == 401
            assert (await client.get("/integrations/vendor/gated")).status_code == 401

    @pytest.mark.asyncio
    async def test_a_gated_route(self, declare_integration, router_module, _override_db_session, valid_api_key):
        declare_integration("vendor", api_router=f"{router_module}:router")

        async with _client(create_app(), valid_api_key) as client:
            response = await client.get("/integrations/vendor/gated")

        assert response.status_code == 200, response.text
        assert response.json() == {"user": "unittest"}
