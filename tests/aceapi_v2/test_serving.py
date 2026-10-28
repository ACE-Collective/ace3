from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from aceapi_v2.app_factory import create_engine_app
from aceapi_v2.serving import serve_under


@pytest.mark.unit
@pytest.mark.asyncio
async def test_serves_the_path_nginx_forwards():
    application = serve_under("/api/v2", create_engine_app())
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        assert (await client.get("/api/v2/health/ping")).status_code == 200
        assert (await client.get("/health/ping")).status_code == 404
        # what the docs page builds its URLs from
        assert (await client.get("/api/v2/openapi.json")).json()["servers"] == [{"url": "/api/v2"}]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_the_app_sees_the_prefix_as_its_root_path():
    app = FastAPI()

    @app.get("/where")
    async def where(request: Request):
        return {"root_path": request.scope["root_path"], "url": str(request.url)}

    async with AsyncClient(transport=ASGITransport(app=serve_under("/ai/v1", app)), base_url="http://test") as client:
        assert (await client.get("/ai/v1/where")).json() == {"root_path": "/ai/v1", "url": "http://test/ai/v1/where"}


@pytest.mark.unit
def test_runs_the_lifespan_of_the_app():
    events = []

    @asynccontextmanager
    async def lifespan(app):
        events.append("startup")
        yield
        events.append("shutdown")

    with TestClient(serve_under("/api/v2", FastAPI(lifespan=lifespan))):
        assert events == ["startup"]

    assert events == ["startup", "shutdown"]
