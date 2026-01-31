"""Tests for aceapi_v2 authentication router."""

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from saq.database.model import User, hash_password

pytestmark = pytest.mark.integration


# TODO: These tests are temporary and should be deleted once all users
# are migrated to bcrypt password hashes.
class TestPasswordHashMigration:
    """Test automatic password hash migration from werkzeug to bcrypt.

    Migration happens in User.verify_password() - any code path that verifies
    a password will automatically migrate legacy werkzeug hashes to bcrypt.
    """

    @pytest.mark.asyncio
    async def test_verify_password_migrates_werkzeug_hash(self, session):
        """Test that User.verify_password migrates werkzeug hashes to bcrypt."""
        username = "model_migrate_user"
        password = "testpassword123"

        # Create user with werkzeug hash
        werkzeug_hash = generate_password_hash(password)
        user = User(
            username=username,
            email=f"{username}@localhost",
            password_hash=werkzeug_hash,
            display_name="Model Migration Test User",
            queue="default",
            timezone="UTC",
            enabled=True,
        )
        session.add(user)
        await session.commit()

        # Verify it's a werkzeug hash
        assert not user.password_hash.startswith("$2"), "Expected werkzeug hash"

        # Call verify_password - this should migrate the hash
        assert user.verify_password(password) is True

        # Verify the hash was updated in-memory to bcrypt
        assert user.password_hash.startswith(
            "$2b$"
        ), f"Expected bcrypt hash, got: {user.password_hash[:20]}..."

        # Commit and verify it persists
        await session.commit()
        session.expire_all()

        result = await session.execute(select(User).where(User.username == username))
        refreshed_user = result.scalar_one()
        assert refreshed_user.password_hash.startswith("$2b$")

        # Verify password still works with new hash
        assert refreshed_user.verify_password(password) is True

    @pytest.mark.asyncio
    async def test_verify_password_does_not_change_bcrypt_hash(self, session):
        """Test that User.verify_password doesn't modify bcrypt hashes."""
        username = "model_bcrypt_user"
        password = "testpassword456"

        # Create user with bcrypt hash
        bcrypt_hash = hash_password(password)
        user = User(
            username=username,
            email=f"{username}@localhost",
            password_hash=bcrypt_hash,
            display_name="Model Bcrypt Test User",
            queue="default",
            timezone="UTC",
            enabled=True,
        )
        session.add(user)
        await session.commit()
        original_hash = user.password_hash

        # Call verify_password
        assert user.verify_password(password) is True

        # Hash should be unchanged
        assert user.password_hash == original_hash

    @pytest.mark.asyncio
    async def test_api_login_migrates_werkzeug_hash(self, session, unauth_client):
        """Test that API login migrates werkzeug password hashes to bcrypt."""
        username = "api_migrate_user"
        password = "testpassword123"

        # Create user with werkzeug hash
        werkzeug_hash = generate_password_hash(password)
        user = User(
            username=username,
            email=f"{username}@localhost",
            password_hash=werkzeug_hash,
            display_name="API Migration Test User",
            queue="default",
            timezone="UTC",
            enabled=True,
        )
        session.add(user)
        await session.commit()
        user_id = user.id

        # Verify it's a werkzeug hash
        assert not user.password_hash.startswith("$2"), "Expected werkzeug hash"

        # Login via the API
        response = await unauth_client.post(
            "/auth/token",
            data={"username": username, "password": password},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

        # Verify the hash has been migrated to bcrypt
        session.expire_all()
        result = await session.execute(
            select(User.password_hash).where(User.id == user_id)
        )
        row = result.first()
        assert row.password_hash.startswith(
            "$2b$"
        ), f"Expected bcrypt hash, got: {row.password_hash[:20]}..."

        # Verify login still works with the new hash
        response = await unauth_client.post(
            "/auth/token",
            data={"username": username, "password": password},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_api_login_does_not_change_bcrypt_hash(self, session, unauth_client):
        """Test that API login doesn't modify bcrypt password hashes."""
        username = "api_bcrypt_user"
        password = "testpassword456"

        # Create user with bcrypt hash
        bcrypt_hash = hash_password(password)
        user = User(
            username=username,
            email=f"{username}@localhost",
            password_hash=bcrypt_hash,
            display_name="API Bcrypt Test User",
            queue="default",
            timezone="UTC",
            enabled=True,
        )
        session.add(user)
        await session.commit()
        user_id = user.id
        original_hash = user.password_hash

        # Login via the API
        response = await unauth_client.post(
            "/auth/token",
            data={"username": username, "password": password},
        )
        assert response.status_code == 200

        # Verify the hash has NOT changed
        session.expire_all()
        result = await session.execute(
            select(User.password_hash).where(User.id == user_id)
        )
        row = result.first()
        assert row.password_hash == original_hash, "Bcrypt hash should not be modified"
