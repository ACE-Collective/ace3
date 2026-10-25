import ast
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.dependencies.models import _is_async_gen_callable, _is_coroutine_callable
from sqlalchemy import text

from aceapi_v2 import sync
from aceapi_v2.application import app as v2_app
from aceapi_v2.sync import run_db_in_thread
from saq.configuration.config import get_database_config
from saq.constants import DB_ACE
from saq.database import pool
from saq.database.pool import get_db, get_db_connection
from tests.saq.helpers import WaitTimedOutError, wait_for_condition
from tests.saq.test_permission_catalog import _iter_effective_routes

REPO_ROOT = Path(__file__).resolve().parents[2]

# every way to put sync code on a pool thread from async code; inside the FastAPI apps only
# run_db_in_thread may, because only it removes the thread's get_db() session
_THREAD_POOL_ENTRY_POINTS = frozenset({
    "run_in_threadpool",
    "iterate_in_threadpool",
    "contextmanager_in_threadpool",
    "to_thread",
    "run_in_executor",
})


def _leave_open():
    # a SELECT through get_db() and no commit, as Persistable.register_persistence_source() does
    get_db().execute(text("SELECT 1"))


def _lose_connection():
    # MySQL server has gone away inside the transaction: the session refuses every later
    # statement with PendingRollbackError until it is rolled back
    get_db().execute(text("SELECT 1"))
    get_db().connection().invalidate()


def _session_and_select():
    return get_db()(), get_db().execute(text("SELECT 1")).scalar()


@pytest.mark.integration
@pytest.mark.parametrize("leave_session", [_leave_open, _lose_connection])
def test_run_db_in_thread_never_sees_a_session_left_on_its_thread(leave_session):
    async def _run():
        # one worker thread, so every call below runs on the thread leave_session left its session on
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))

        def _leave():
            leave_session()
            return get_db()()

        left = await asyncio.to_thread(_leave)
        # without the wrapper the next call on that thread gets the same session
        assert await asyncio.to_thread(get_db()) is left
        return left, await run_db_in_thread(_session_and_select)

    left, (session, value) = asyncio.run(_run())
    assert session is not left
    assert value == 1


@pytest.fixture
def ace_pool_of_two(monkeypatch):
    """A fresh ace engine that holds two connections and waits 2 seconds for one, not 30."""
    config = get_database_config(DB_ACE)
    monkeypatch.setattr(config, "pool_size", 1)
    monkeypatch.setattr(config, "max_overflow", 1)
    build_engine_options = pool._build_engine_options
    monkeypatch.setattr(pool, "_build_engine_options", lambda c: {**build_engine_options(c), "pool_timeout": 2})
    monkeypatch.setattr(pool, "_db_sessions", {})
    monkeypatch.setattr(pool, "_db_engine_by_name", {})
    monkeypatch.setattr(pool, "_db_engines", set())
    sync._db_thread_slots.cache_clear()
    yield
    for engine in pool._db_engines:
        engine.dispose()


@pytest.mark.integration
def test_calls_holding_an_orm_and_a_cursor_connection_cannot_exhaust_the_pool(ace_pool_of_two):
    holding = []
    holding_lock = threading.Lock()

    def _orm_then_cursor():
        # the ORM session keeps its connection until the call ends, as an alert lookup does
        # before acquire_lock()
        get_db().execute(text("SELECT 1"))
        with holding_lock:
            holding.append(threading.get_ident())

        # give the other call the chance to take the pool's second connection, as it would
        # if both were let in
        try:
            wait_for_condition(lambda: len(holding) == 2, timeout=1)
        except WaitTimedOutError:
            pass

        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT 1")
            return cursor.fetchone()[0]

    async def _run():
        return await asyncio.gather(run_db_in_thread(_orm_then_cursor), run_db_in_thread(_orm_then_cursor))

    # one call at a time (half the pool), so neither waits on a connection the other holds
    assert sync._db_thread_slots()._initial_value == 1
    assert asyncio.run(_run()) == [1, 1]


@pytest.mark.unit
def test_db_thread_slots_are_half_the_ace_pool(monkeypatch):
    config = get_database_config(DB_ACE)
    monkeypatch.setattr(config, "pool_size", 5)
    monkeypatch.setattr(config, "max_overflow", 10)
    sync._db_thread_slots.cache_clear()
    assert sync._db_thread_slots()._initial_value == 7

    # never none at all
    monkeypatch.setattr(config, "pool_size", 1)
    monkeypatch.setattr(config, "max_overflow", 0)
    sync._db_thread_slots.cache_clear()
    assert sync._db_thread_slots()._initial_value == 1


@pytest.mark.unit
def test_run_db_in_thread_removes_the_sessions_when_fn_raises():
    def _fail():
        raise ValueError(f"called after {remove.call_count} removal")

    with patch("aceapi_v2.sync.remove_all_sessions") as remove:
        with pytest.raises(ValueError, match="called after 1 removal"):
            asyncio.run(run_db_in_thread(_fail))

    assert remove.call_count == 2


def _calls_run_in_thread_pool(dependant):
    """The endpoint and dependencies FastAPI runs through its own run_in_threadpool, decided with
    the predicates FastAPI itself uses."""
    if dependant.call is not None and not (
            _is_coroutine_callable(dependant.call) or _is_async_gen_callable(dependant.call)):
        yield dependant.call

    for sub in dependant.dependencies:
        yield from _calls_run_in_thread_pool(sub)


@pytest.mark.unit
def test_every_route_and_dependency_is_async():
    # imported here: the AI app builds its backend registry from the loaded configuration
    import aceapi_ai.application

    sync_calls = []
    route_count = 0
    for app_name, app in (("aceapi_v2", v2_app), ("aceapi_ai", aceapi_ai.application.app)):
        for path, methods, dependant in _iter_effective_routes(app):
            route_count += 1
            sync_calls.extend(
                (app_name, sorted(methods), path, getattr(call, "__qualname__", repr(call)))
                for call in _calls_run_in_thread_pool(dependant))

    # guard against the walk going vacuous (see _iter_effective_routes)
    assert route_count > 40, f"route enumeration only found {route_count} routes"
    assert not sync_calls, (
        "FastAPI runs these sync endpoints and dependencies on a pool thread that never removes its "
        f"get_db() session; make them async and use run_db_in_thread: {sync_calls}")


def _thread_pool_references(path: Path):
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.alias):
            name = node.name.rsplit(".", 1)[-1]
        else:
            continue

        if name in _THREAD_POOL_ENTRY_POINTS:
            yield f"{path.relative_to(REPO_ROOT)}:{node.lineno} {name}"


@pytest.mark.unit
def test_only_run_db_in_thread_moves_work_to_a_thread():
    references = [
        reference
        for package in ("aceapi_v2", "aceapi_ai")
        for path in sorted((REPO_ROOT / package).rglob("*.py"))
        if path != REPO_ROOT / "aceapi_v2" / "sync.py"
        for reference in _thread_pool_references(path)
    ]

    assert not references, (
        "sync code in the FastAPI apps goes to a thread through aceapi_v2.sync.run_db_in_thread, "
        f"which removes the thread's get_db() session before and after: {references}")
