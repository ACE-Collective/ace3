from collections.abc import AsyncGenerator

import fakeredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)

import aceapi_ai.application
from aceapi_ai.ratelimit import rate_limiter
from aceapi_v2.database import build_database_url, get_async_session
from saq.database.model import User
from tests.aceapi_v2.conftest import make_api_key


def get_app():
    # resolved lazily: the AI app singleton builds its backend registry from the loaded
    # configuration, which does not exist at test-collection time
    return aceapi_ai.application.app


@pytest.fixture(autouse=True)
def ai_redis(monkeypatch):
    """Backs the AI rate limiter with fakeredis, keyed by database on one shared server.

    REDIS_DB_AI_RATE_LIMIT is one database on a redis shared by every xdist worker and by any
    ACE container pointed at the same server. Emptying it here -- which is what this fixture
    used to do -- reset counters another worker was in the middle of asserting on, and wiped a
    running AI API's rate limit state as a side effect. An in-process fake gives each test its
    own server, so there is nothing to share and nothing to flush.

    Returns the connection factory, for tests that seed limiter state directly.
    """
    server = fakeredis.FakeServer()
    connections: dict[int, fakeredis.FakeStrictRedis] = {}

    def _get_connection(database, config_name=None):
        if database not in connections:
            connections[database] = fakeredis.FakeStrictRedis(
                server=server, db=database, decode_responses=True)

        return connections[database]

    # the limiter binds the name at import, so the patch has to land on its module rather than
    # on saq.redis_client
    monkeypatch.setattr("aceapi_ai.ratelimit.get_redis_connection", _get_connection)

    # the module singleton caches its connection and its registered script for the life of the
    # process; drop both so this test resolves through the patch above and the next one does not
    # inherit this test's fake server
    monkeypatch.setattr(rate_limiter, "_connection", None)
    monkeypatch.setattr(rate_limiter, "_acquire_script", None)

    return _get_connection


def api_key_client(api_key: str) -> AsyncClient:
    """An AsyncClient against the AI app authenticating via the x-ace-auth header."""
    return AsyncClient(
        transport=ASGITransport(app=get_app()),
        base_url="http://test",
        headers={"x-ace-auth": api_key},
    )


@pytest_asyncio.fixture
async def engine() -> AsyncGenerator[AsyncEngine]:
    engine = create_async_engine(build_database_url(), echo=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def connection(engine: AsyncEngine) -> AsyncGenerator[AsyncConnection]:
    """Connection with outer transaction that rolls back after test."""
    async with engine.connect() as conn:
        trans = await conn.begin()
        try:
            yield conn
        finally:
            await trans.rollback()


@pytest_asyncio.fixture
async def session(connection: AsyncConnection) -> AsyncGenerator[AsyncSession]:
    """Session bound to the shared connection using savepoints (see tests/aceapi_v2/conftest.py)."""
    session = AsyncSession(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        await session.close()


@pytest_asyncio.fixture
async def _override_db_session(connection: AsyncConnection):
    """Override get_async_session on the AI app to use the test transaction."""

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

    get_app().dependency_overrides[get_async_session] = override_get_session
    yield
    get_app().dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(session: AsyncSession) -> User:
    result = await session.execute(select(User).where(User.username == "unittest"))
    user = result.scalar_one_or_none()
    if user is None:
        raise ValueError("unittest user not found in database")
    return user


@pytest_asyncio.fixture
async def unauth_client(_override_db_session) -> AsyncGenerator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=get_app()),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def client(_override_db_session, session: AsyncSession, test_user: User) -> AsyncGenerator[AsyncClient]:
    """Client holding an inherit-scoped key for the unittest user (full user permissions)."""
    key = await make_api_key(session, test_user.id, inherit=True)
    async with api_key_client(key) as client:
        yield client


@pytest_asyncio.fixture
async def ai_scoped_client(_override_db_session, session: AsyncSession, test_user: User) -> AsyncGenerator[AsyncClient]:
    """Client holding a key scoped exactly like a real AI investigation key: ai:fake + ai:alert + ai:event."""
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "fake"), ("ai", "alert"), ("ai", "event")])
    async with api_key_client(key) as client:
        yield client
