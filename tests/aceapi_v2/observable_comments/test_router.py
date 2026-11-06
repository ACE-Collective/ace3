"""Tests for aceapi_v2 observable comments router."""

import hashlib

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Observable, ObservableComment, User

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8")).digest()


class TestObservableComments:
    """Test observable comment CRUD endpoints."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        """Unauthenticated requests should return 401."""
        response = await unauth_client.get("/observable-comments/1")
        assert response.status_code == 401

        response = await unauth_client.post("/observable-comments/", json={
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "comment": "test",
        })
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_comment(
        self, session: AsyncSession, client: AsyncClient, test_user: User
    ):
        """Creating a comment should return 201 with correct structure."""
        # Pre-create the observable
        obs = Observable(type="ipv4", sha256=_sha256("1.2.3.4"), value=b"1.2.3.4")
        session.add(obs)
        await session.commit()

        response = await client.post("/observable-comments/", json={
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "comment": "suspicious IP",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["comment"] == "suspicious IP"
        assert data["user_id"] == test_user.id
        assert data["observable_id"] == obs.id
        assert "id" in data
        assert "insert_date" in data
        assert data["edited_at"] is None
        assert "user_display_name" in data

    @pytest.mark.asyncio
    async def test_create_comment_auto_creates_observable(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Commenting on a non-existent observable should auto-create the DB row."""
        response = await client.post("/observable-comments/", json={
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
            "comment": "known bad domain",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["comment"] == "known bad domain"

        # Verify the observable was created in DB
        result = await session.execute(
            select(Observable).where(
                Observable.type == "fqdn",
                Observable.sha256 == _sha256("evil.example.com"),
            )
        )
        db_obs = result.scalar_one_or_none()
        assert db_obs is not None
        assert data["observable_id"] == db_obs.id

    @pytest.mark.asyncio
    async def test_list_comments(
        self, session: AsyncSession, client: AsyncClient, test_user: User
    ):
        """Listing comments for an observable should return all its comments, and only its own."""
        obs = Observable(type="ipv4", sha256=_sha256("10.0.0.1"), value=b"10.0.0.1")
        other = Observable(type="ipv4", sha256=_sha256("10.0.0.2"), value=b"10.0.0.2")
        session.add_all([obs, other])
        await session.commit()
        session.add(ObservableComment(user_id=test_user.id, observable_id=other.id, comment="another observable's"))

        # Add two comments
        for text in ["first comment", "second comment"]:
            session.add(ObservableComment(
                user_id=test_user.id,
                observable_id=obs.id,
                comment=text,
            ))
        await session.commit()

        response = await client.get(f"/observable-comments/{obs.id}")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert len(data["data"]) == 2
        comments = [c["comment"] for c in data["data"]]
        assert "first comment" in comments
        assert "second comment" in comments

    @pytest.mark.asyncio
    async def test_update_comment(
        self, session: AsyncSession, client: AsyncClient, test_user: User
    ):
        """Updating a comment should change its text."""
        obs = Observable(type="url", sha256=_sha256("http://bad.com"), value=b"http://bad.com")
        session.add(obs)
        await session.commit()

        comment = ObservableComment(
            user_id=test_user.id,
            observable_id=obs.id,
            comment="original text",
        )
        session.add(comment)
        await session.commit()

        response = await client.patch(
            f"/observable-comments/{comment.id}",
            json={"comment": "updated text"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["comment"] == "updated text"

        await session.refresh(comment)
        assert comment.comment == "updated text"
        # the edit is timestamped, and the comment keeps the time it was made
        assert comment.edited_at is not None
        assert comment.edited_at >= comment.insert_date
        assert data["edited_at"] == comment.edited_at.isoformat()
        assert data["insert_date"] == comment.insert_date.isoformat()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stored, sent", [
        ("same text", "same text"),
        # the edit box sends LF line breaks for a comment stored with CRLF ones
        ("first line\r\nsecond line", "first line\nsecond line"),
        # the upload form stores its comment as typed; the edit box sends it trimmed
        ("looks benign\r\n", "looks benign"),
        (" looks benign", "looks benign"),
    ])
    async def test_update_comment_without_a_change(
        self, session: AsyncSession, client: AsyncClient, test_user: User, stored: str, sent: str
    ):
        """Saving a comment's text untouched does not mark it edited."""
        obs = Observable(type="ipv4", sha256=_sha256("10.0.0.6"), value=b"10.0.0.6")
        session.add(obs)
        await session.commit()
        comment = ObservableComment(user_id=test_user.id, observable_id=obs.id, comment=stored)
        session.add(comment)
        await session.commit()

        response = await client.patch(f"/observable-comments/{comment.id}", json={"comment": sent})
        assert response.status_code == 200
        assert response.json()["edited_at"] is None

        await session.refresh(comment)
        assert comment.comment == stored
        assert comment.edited_at is None

    @pytest.mark.asyncio
    async def test_update_comment_author_only(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Updating another user's comment should return 403."""
        obs = Observable(type="ipv4", sha256=_sha256("10.0.0.3"), value=b"10.0.0.3")
        session.add(obs)
        await session.commit()

        # Create a comment by a different user (user_id=99999 won't match test_user)
        other_user = User(
            username="other_user",
            email="other@test.com",
            password_hash="unused",
            display_name="Other User",
            queue="default",
            timezone="UTC",
            enabled=True,
        )
        session.add(other_user)
        await session.commit()

        comment = ObservableComment(
            user_id=other_user.id,
            observable_id=obs.id,
            comment="other's comment",
        )
        session.add(comment)
        await session.commit()

        response = await client.patch(
            f"/observable-comments/{comment.id}",
            json={"comment": "trying to edit"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_comment(
        self, session: AsyncSession, client: AsyncClient, test_user: User
    ):
        """Deleting own comment should return 204."""
        obs = Observable(type="ipv4", sha256=_sha256("10.0.0.4"), value=b"10.0.0.4")
        session.add(obs)
        await session.commit()

        comment = ObservableComment(
            user_id=test_user.id,
            observable_id=obs.id,
            comment="to be deleted",
        )
        session.add(comment)
        await session.commit()

        response = await client.delete(f"/observable-comments/{comment.id}")
        assert response.status_code == 204

        # Verify it's gone
        result = await session.execute(
            select(ObservableComment).where(ObservableComment.id == comment.id)
        )
        assert result.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_delete_comment_author_only(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Deleting another user's comment should return 403."""
        obs = Observable(type="ipv4", sha256=_sha256("10.0.0.5"), value=b"10.0.0.5")
        session.add(obs)
        await session.commit()

        other_user = User(
            username="other_user_del",
            email="other_del@test.com",
            password_hash="unused",
            display_name="Other User Del",
            queue="default",
            timezone="UTC",
            enabled=True,
        )
        session.add(other_user)
        await session.commit()

        comment = ObservableComment(
            user_id=other_user.id,
            observable_id=obs.id,
            comment="not yours",
        )
        session.add(comment)
        await session.commit()

        response = await client.delete(f"/observable-comments/{comment.id}")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_comment_not_found(self, client: AsyncClient):
        """Deleting a non-existent comment should return 404."""
        response = await client.delete("/observable-comments/999999")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_comment_on_file_uses_content_hash_identity(
        self, session: AsyncSession, client: AsyncClient
    ):
        """A file observable's DB identity is unhex(value), not sha256(value), so the comment
        must land on the engine-indexed row rather than creating a mis-keyed duplicate."""
        content_hash = "ef" * 32
        engine_indexed = Observable(
            type="file", sha256=bytes.fromhex(content_hash), value=content_hash.encode("utf8"))
        session.add(engine_indexed)
        await session.commit()

        response = await client.post("/observable-comments/", json={
            "observable_type": "file",
            "observable_value": content_hash.upper(),
            "comment": "known dropper",
        })
        assert response.status_code == 201
        assert response.json()["observable_id"] == engine_indexed.id

        # no second row was created for the same file
        result = await session.execute(
            select(Observable).where(Observable.type == "file"))
        assert len(result.scalars().all()) == 1

    @pytest.mark.asyncio
    async def test_create_comment_unknown_type_returns_400(
        self, client: AsyncClient, session: AsyncSession
    ):
        """Commenting creates the observable row if it does not exist, so an unregistered type
        would permanently pollute the shared observables table."""
        response = await client.post("/observable-comments/", json={
            "observable_type": "not_a_real_type",
            "observable_value": "x",
            "comment": "should fail",
        })
        assert response.status_code == 400
        assert "not a valid observable type" in response.json()["detail"]

        result = await session.execute(
            select(Observable).where(Observable.type == "not_a_real_type")
        )
        assert result.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_create_comment_invalid_value_returns_400(self, client: AsyncClient):
        response = await client.post("/observable-comments/", json={
            "observable_type": "file",
            "observable_value": "not-a-hex-digest",
            "comment": "should fail",
        })
        assert response.status_code == 400
