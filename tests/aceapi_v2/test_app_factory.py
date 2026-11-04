"""The lifespan both API apps share: its shutdown half releases a uvicorn worker's database connections."""

import logging

import pytest

from aceapi_v2 import app_factory
from aceapi_v2.app_factory import create_engine_app
from aceapi_v2.application import create_app

APP_FACTORIES = [pytest.param(create_app, id="user"), pytest.param(create_engine_app, id="engine")]


@pytest.fixture
def shutdown_calls(monkeypatch):
    calls = []

    async def dispose():
        calls.append("dispose")

    monkeypatch.setattr(app_factory, "dispose_engines_for_current_loop", dispose)
    monkeypatch.setattr(app_factory, "shutdown_loop", lambda: calls.append("shutdown_loop"))
    return calls


def _raise(name):
    raise RuntimeError(f"{name} failed")


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize("factory", APP_FACTORIES)
async def test_shutdown_disposes_the_engines_and_stops_the_loop(factory, shutdown_calls):
    app = factory()
    async with app.router.lifespan_context(app):
        assert shutdown_calls == []

    # each exactly once; they release the engines of different loops, so their order is not part of the contract
    assert sorted(shutdown_calls) == ["dispose", "shutdown_loop"]


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize("factory", APP_FACTORIES)
async def test_a_failed_dispose_is_logged_and_the_loop_still_stops(factory, shutdown_calls, monkeypatch, caplog):
    async def dispose():
        _raise("dispose")

    monkeypatch.setattr(app_factory, "dispose_engines_for_current_loop", dispose)
    caplog.set_level(logging.DEBUG, logger=app_factory.__name__)

    app = factory()
    async with app.router.lifespan_context(app):
        pass

    assert shutdown_calls == ["shutdown_loop"]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert str(errors[0].exc_info[1]) == "dispose failed"


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize("factory", APP_FACTORIES)
async def test_a_failed_loop_shutdown_is_logged(factory, shutdown_calls, monkeypatch, caplog):
    monkeypatch.setattr(app_factory, "shutdown_loop", lambda: _raise("shutdown_loop"))
    caplog.set_level(logging.DEBUG, logger=app_factory.__name__)

    app = factory()
    async with app.router.lifespan_context(app):
        pass

    assert shutdown_calls == ["dispose"]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert str(errors[0].exc_info[1]) == "shutdown_loop failed"
