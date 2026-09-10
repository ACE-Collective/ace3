"""Tests for the aceapi_v2 user preferences router."""

import json

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.aceapi_v2.conftest import api_key_client, make_api_key
from saq.database.model import User, UserPreference
from saq.gui.manage_columns import MANAGE_COLUMN_IDS

pytestmark = pytest.mark.integration

BASE = "/users/me/preferences"
COLUMNS = f"{BASE}/manage_columns"


@pytest_asyncio.fixture
async def other_client(_override_db_session, session: AsyncSession):
    """A second authenticated user, for the isolation tests. Preferences need no permission
    grant, so no permission row is inserted."""
    user = User(username="other_prefs", email="other_prefs@e.com", display_name="Other", password="pw")
    session.add(user)
    await session.flush()
    key = await make_api_key(session, user.id, inherit=True)
    async with api_key_client(key) as client:
        yield client


class TestAuth:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get(BASE)).status_code == 401
        assert (await unauth_client.put(COLUMNS, json={})).status_code == 401

    @pytest.mark.asyncio
    async def test_needs_no_permission_grant(self, noperm_client: AsyncClient):
        """A preference is the caller's own GUI state: being a user is enough."""
        assert (await noperm_client.get(BASE)).status_code == 200
        assert (await noperm_client.put(COLUMNS, json={"hidden": ["queue"]})).status_code == 200


class TestDefaults:
    @pytest.mark.asyncio
    async def test_every_registered_key_is_reported_with_its_default(self, client: AsyncClient):
        response = await client.get(BASE)
        assert response.status_code == 200
        data = response.json()["data"]
        assert "manage_columns" in data
        columns = data["manage_columns"]
        assert columns["is_default"] is True
        assert columns["updated_at"] is None
        assert columns["value"] == {"order": list(MANAGE_COLUMN_IDS), "hidden": []}

    @pytest.mark.asyncio
    async def test_get_one_default(self, client: AsyncClient):
        response = await client.get(COLUMNS)
        assert response.status_code == 200
        assert response.json()["key"] == "manage_columns"
        assert response.json()["is_default"] is True

    @pytest.mark.asyncio
    async def test_unknown_key_is_404(self, client: AsyncClient):
        assert (await client.get(f"{BASE}/no_such_key")).status_code == 404
        assert (await client.put(f"{BASE}/no_such_key", json={})).status_code == 404
        assert (await client.delete(f"{BASE}/no_such_key")).status_code == 404


class TestWrite:
    @pytest.mark.asyncio
    async def test_put_stores_and_reads_back(self, client: AsyncClient, session: AsyncSession, test_user: User):
        body = {"order": ["status", "date", "description", "queue", "owner", "disposition", "remediation"], "hidden": ["queue", "owner"]}
        response = await client.put(COLUMNS, json=body)
        assert response.status_code == 200, response.text
        saved = response.json()
        assert saved["is_default"] is False
        assert saved["updated_at"] is not None
        assert saved["value"] == body

        # the stored row holds the normalized JSON
        row = (await session.execute(
            select(UserPreference).where(UserPreference.user_id == test_user.id, UserPreference.key == "manage_columns")
        )).scalar_one()
        assert json.loads(row.value_json) == body

        again = await client.get(COLUMNS)
        assert again.json()["value"] == body
        assert again.json()["is_default"] is False

    @pytest.mark.asyncio
    async def test_put_replaces_rather_than_duplicates(self, client: AsyncClient, session: AsyncSession, test_user: User):
        assert (await client.put(COLUMNS, json={"hidden": ["queue"]})).status_code == 200
        assert (await client.put(COLUMNS, json={"hidden": ["owner"]})).status_code == 200
        rows = (await session.execute(
            select(UserPreference).where(UserPreference.user_id == test_user.id, UserPreference.key == "manage_columns")
        )).scalars().all()
        assert len(rows) == 1
        assert json.loads(rows[0].value_json)["hidden"] == ["owner"]

    @pytest.mark.asyncio
    async def test_normalization(self, client: AsyncClient):
        """Unknown ids are dropped, duplicates collapse, missing columns are appended in
        default order, required columns cannot be hidden, and hidden is emitted in default
        order."""
        response = await client.put(COLUMNS, json={
            "order": ["queue", "bogus", "queue", "status"],
            "hidden": ["description", "status", "bogus", "date"],
        })
        assert response.status_code == 200, response.text
        value = response.json()["value"]
        assert value["order"] == ["queue", "status", "date", "description", "remediation", "owner", "disposition"]
        assert value["hidden"] == ["date", "status"]

    @pytest.mark.asyncio
    async def test_wrong_shape_is_422(self, client: AsyncClient):
        assert (await client.put(COLUMNS, json={"order": "date"})).status_code == 422
        assert (await client.put(COLUMNS, json={"columns": ["date"]})).status_code == 422

    @pytest.mark.asyncio
    async def test_delete_resets_to_default(self, client: AsyncClient):
        assert (await client.put(COLUMNS, json={"hidden": ["queue"]})).status_code == 200
        response = await client.delete(COLUMNS)
        assert response.status_code == 200
        assert response.json()["is_default"] is True
        assert response.json()["value"]["hidden"] == []
        assert (await client.get(COLUMNS)).json()["is_default"] is True

    @pytest.mark.asyncio
    async def test_delete_of_an_unset_preference_is_fine(self, client: AsyncClient):
        assert (await client.delete(COLUMNS)).status_code == 200


class TestIsolation:
    @pytest.mark.asyncio
    async def test_users_do_not_see_each_others_preferences(self, client: AsyncClient, other_client: AsyncClient):
        assert (await client.put(COLUMNS, json={"hidden": ["queue"]})).status_code == 200
        assert (await other_client.get(COLUMNS)).json()["is_default"] is True

        assert (await other_client.put(COLUMNS, json={"hidden": ["owner"]})).status_code == 200
        assert (await client.get(COLUMNS)).json()["value"]["hidden"] == ["queue"]


class TestStaleRow:
    @pytest.mark.asyncio
    async def test_unreadable_stored_value_falls_back_to_default(self, client: AsyncClient, session: AsyncSession, test_user: User):
        """A row this release cannot parse must not take the page down."""
        session.add(UserPreference(user_id=test_user.id, key="manage_columns", value_json="not json"))
        await session.flush()
        response = await client.get(COLUMNS)
        assert response.status_code == 200
        assert response.json()["is_default"] is True
        assert response.json()["value"]["order"] == list(MANAGE_COLUMN_IDS)

    @pytest.mark.asyncio
    async def test_stale_column_ids_are_repaired_on_read(self, client: AsyncClient, session: AsyncSession, test_user: User):
        session.add(UserPreference(user_id=test_user.id, key="manage_columns",
                                   value_json=json.dumps({"order": ["removed_column", "date"], "hidden": ["removed_column"]})))
        await session.flush()
        value = (await client.get(COLUMNS)).json()["value"]
        assert value["order"][0] == "date"
        assert set(value["order"]) == set(MANAGE_COLUMN_IDS)
        assert value["hidden"] == []
