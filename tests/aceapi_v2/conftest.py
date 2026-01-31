from collections.abc import AsyncGenerator
from datetime import timedelta

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

from aceapi_v2.application import app
from aceapi_v2.auth import create_access_token
from aceapi_v2.database import build_database_url, get_async_session
from saq.database.model import User


@pytest.fixture(autouse=True)
def global_function_setup():
    """Override global fixture - savepoint rollback handles cleanup for these tests."""
    yield


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
    _override_db_session, valid_access_token: str
) -> AsyncGenerator[AsyncClient]:
    """HTTP client with a valid Bearer token pre-set."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {valid_access_token}"},
    ) as client:
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
async def expired_access_token(test_user: User) -> str:
    """Expired access token for the test user."""
    return create_access_token(
        test_user.username,
        test_user.id,
        expires_delta=-timedelta(minutes=1),
    )


@pytest_asyncio.fixture
async def valid_access_token(test_user: User) -> str:
    """Valid access token for the test user."""
    return create_access_token(test_user.username, test_user.id)
