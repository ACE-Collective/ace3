from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)

from aceapi_v2.application import app
from aceapi_v2.database import build_database_url, get_async_session
from aceapi_v2.users.service import create_user_api_key
from saq.database.model import User


async def make_api_key(session: AsyncSession, user_id: int, *, inherit: bool = True, scope=None) -> str:
    """Mint an API key for a user in a test and return the plaintext.

    An inherit key authenticates as the user with the user's full permissions -- the direct
    replacement for the retired JWT test auth. Pass inherit=False + a scope list of (major, minor)
    ApiKeyScope-like objects to test scoped keys. Flushed onto the shared test connection so the
    app's auth session sees it.
    """
    from aceapi_v2.users.schemas import ApiKeyScope

    scope_objs = [ApiKeyScope(major=m, minor=n) for (m, n) in (scope or [])]
    _, plaintext = await create_user_api_key(
        session, user_id, name="test", inherit=inherit, scope=scope_objs
    )
    await session.flush()
    return plaintext


def api_key_client(api_key: str) -> AsyncClient:
    """An AsyncClient that authenticates with the given API key via the x-ace-auth header."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"x-ace-auth": api_key},
    )


@pytest_asyncio.fixture
async def engine() -> AsyncGenerator[AsyncEngine]:
    """Function-scoped engine."""
    engine = create_async_engine(build_database_url(), echo=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def connection(engine: AsyncEngine) -> AsyncGenerator[AsyncConnection]:
    """Connection with outer transaction that rolls back after test.

    This provides automatic cleanup - all changes made during the test
    are rolled back when the test completes.
    """
    async with engine.connect() as conn:
        trans = await conn.begin()
        try:
            yield conn
        finally:
            await trans.rollback()


@pytest_asyncio.fixture
async def session(connection: AsyncConnection) -> AsyncGenerator[AsyncSession]:
    """Session bound to the shared connection using savepoints.

    - join_transaction_mode="create_savepoint": commit() only commits a savepoint,
      not the outer transaction
    - expire_on_commit=False: prevents lazy-load greenlet errors when accessing
      attributes after commit
    - Shares transaction view with API sessions (both bound to same connection)
    """
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
    """Override get_async_session to use the test transaction."""

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

    app.dependency_overrides[get_async_session] = override_get_session
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def unauth_client(_override_db_session) -> AsyncGenerator[AsyncClient]:
    """HTTP client without authentication credentials."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture
async def client(
    _override_db_session, valid_api_key: str
) -> AsyncGenerator[AsyncClient]:
    """HTTP client authenticated with an inherit-scoped API key for the test user."""
    async with api_key_client(valid_api_key) as client:
        yield client


@pytest_asyncio.fixture
async def test_user(session: AsyncSession) -> User:
    """Get the unittest user for testing."""
    result = await session.execute(select(User).where(User.username == "unittest"))
    user = result.scalar_one_or_none()
    if user is None:
        raise ValueError("unittest user not found in database")
    return user


@pytest_asyncio.fixture
async def valid_api_key(session: AsyncSession, test_user: User) -> str:
    """An inherit-scoped API key for the test user (full user permissions)."""
    return await make_api_key(session, test_user.id, inherit=True)


@pytest_asyncio.fixture
async def invalid_api_key() -> str:
    """A well-formed key value that matches no stored key (authentication must fail)."""
    return "00000000-0000-0000-0000-000000000000"


@pytest_asyncio.fixture
async def noperm_client(_override_db_session, session: AsyncSession) -> AsyncGenerator[AsyncClient]:
    """Authenticated as a user with NO permissions, via an inherit key. Because the intersection's
    user half denies, every permission-gated route returns 403 (the successor to the old
    'token for a phantom user id' pattern)."""
    user = User(username="noperm_test", email="noperm_test@e.com", display_name="noperm", password="pw")
    session.add(user)
    await session.flush()
    key = await make_api_key(session, user.id, inherit=True)
    async with api_key_client(key) as client:
        yield client
