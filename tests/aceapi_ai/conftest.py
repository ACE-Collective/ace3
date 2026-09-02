from collections.abc import AsyncGenerator

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
from aceapi_v2.database import build_database_url, get_async_session
from saq.database.model import User
from tests.aceapi_v2.conftest import make_api_key


def get_app():
    # resolved lazily: the AI app singleton builds its backend registry from the loaded
    # configuration, which does not exist at test-collection time
    return aceapi_ai.application.app


@pytest.fixture(autouse=True)
def _clear_ai_rate_limit_state():
    """Empty the AI rate limiter's dedicated redis database so counters never leak between tests."""
    from saq.constants import REDIS_DB_AI_RATE_LIMIT
    from saq.redis_client import get_redis_connection

    get_redis_connection(REDIS_DB_AI_RATE_LIMIT).flushdb()
    yield


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
