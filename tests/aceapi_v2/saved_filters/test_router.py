"""Tests for the aceapi_v2 saved filters router."""

import json
from datetime import datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.aceapi_v2.conftest import api_key_client, make_api_key
from saq.database.model import AuthUserPermission, SavedFilter, User

pytestmark = pytest.mark.integration

BASE = "/saved-filters"

QUEUE_FILTER = [{"name": "Queue", "inverted": False, "values": ["default"]}]


@pytest_asyncio.fixture
async def other_client(_override_db_session, session: AsyncSession):
    """A second authenticated analyst, for the ownership boundary tests.

    The permission row is inserted through the SAME async session the test runs in. Calling
    the synchronous add_user_permission() helper here instead deadlocks: it opens its own
    connection and blocks on row locks the test's open transaction is already holding."""
    user = User(username="other_analyst", email="other@e.com", display_name="Other", password="pw")
    session.add(user)
    await session.flush()
    session.add(AuthUserPermission(user_id=user.id, major="*", minor="*", effect="ALLOW"))
    await session.flush()
    key = await make_api_key(session, user.id, inherit=True)
    async with api_key_client(key) as client:
        yield client


async def _create(client: AsyncClient, name: str, **kwargs) -> dict:
    body = {"name": name, "filters": QUEUE_FILTER}
    body.update(kwargs)
    response = await client.post(f"{BASE}/", json=body)
    assert response.status_code == 201, response.text
    return response.json()


# updated_at is a MySQL TIMESTAMP with no fractional seconds, so a write that lands in the same
# whole second as the create bumps it to the same value. Backdating first is what makes the
# "did the response report the bump?" assertions below deterministic instead of ~1-in-5 flaky.
STALE_UPDATED_AT = datetime(2020, 1, 1, 0, 0, 0)


async def _backdate_updated_at(session: AsyncSession, filter_uuid: str) -> None:
    """Force a known-old updated_at. An explicit value in the UPDATE overrides ON UPDATE
    CURRENT_TIMESTAMP, and the test session shares the API's connection so the write is
    visible to the request that follows."""
    await session.execute(
        update(SavedFilter).where(SavedFilter.uuid == filter_uuid).values(
            updated_at=STALE_UPDATED_AT))
    await session.commit()


async def _stored_updated_at(session: AsyncSession, filter_uuid: str) -> datetime:
    """The row's real updated_at, read as a bare column so no identity map can answer it."""
    return (await session.execute(
        select(SavedFilter.updated_at).where(SavedFilter.uuid == filter_uuid))).scalar_one()


class TestAuth:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get(f"{BASE}/")).status_code == 401

    @pytest.mark.asyncio
    async def test_requires_permission(self, noperm_client: AsyncClient):
        assert (await noperm_client.get(f"{BASE}/")).status_code == 403


class TestCrud:
    @pytest.mark.asyncio
    async def test_create_and_read_round_trip(self, client: AsyncClient):
        created = await _create(client, "My Filter", description="notes")

        assert created["name"] == "My Filter"
        assert created["description"] == "notes"
        assert created["kind"] == "named"
        assert created["filters"] == QUEUE_FILTER
        assert created["quick_filter_order"] is None
        assert created["owner_display_name"]

        fetched = await client.get(f"{BASE}/{created['uuid']}")
        assert fetched.status_code == 200
        assert fetched.json()["uuid"] == created["uuid"]

    @pytest.mark.asyncio
    async def test_duplicate_name_conflicts(self, client: AsyncClient):
        await _create(client, "Dupe")
        response = await client.post(f"{BASE}/", json={"name": "Dupe", "filters": QUEUE_FILTER})
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_update(self, client: AsyncClient):
        created = await _create(client, "Before")
        response = await client.patch(f"{BASE}/{created['uuid']}", json={
            "name": "After",
            "filters": [{"name": "Tag", "inverted": True, "values": ["x"]}],
        })

        assert response.status_code == 200
        assert response.json()["name"] == "After"
        assert response.json()["filters"][0]["inverted"] is True

    @pytest.mark.asyncio
    async def test_update_returns_the_bumped_updated_at(
        self, client: AsyncClient, session: AsyncSession
    ):
        """The response must report the row's real updated_at, not the value the request
        session happened to load before its own UPDATE bumped it server-side."""
        created = await _create(client, "Before")
        await _backdate_updated_at(session, created["uuid"])

        response = await client.patch(f"{BASE}/{created['uuid']}", json={"name": "After"})

        returned = datetime.fromisoformat(response.json()["updated_at"])
        assert returned != STALE_UPDATED_AT
        assert returned == await _stored_updated_at(session, created["uuid"])

    @pytest.mark.asyncio
    async def test_delete(self, client: AsyncClient):
        created = await _create(client, "Doomed")
        assert (await client.delete(f"{BASE}/{created['uuid']}")).status_code == 204
        assert (await client.get(f"{BASE}/{created['uuid']}")).status_code == 404

    @pytest.mark.asyncio
    async def test_unknown_uuid_is_404(self, client: AsyncClient):
        assert (await client.get(f"{BASE}/does-not-exist")).status_code == 404
        assert (await client.delete(f"{BASE}/does-not-exist")).status_code == 404

    @pytest.mark.asyncio
    async def test_rejects_invalid_filter_name(self, client: AsyncClient):
        response = await client.post(f"{BASE}/", json={
            "name": "Bad", "filters": [{"name": "Nope", "values": ["x"]}]})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_rejects_unparseable_date_token_at_write_time(self, client: AsyncClient):
        """A bad date must never reach storage: it would raise on every subsequent /manage
        load, leaving the analyst's queue broken until someone reset their filters by hand."""
        response = await client.post(f"{BASE}/", json={
            "name": "Bad Date",
            "filters": [{"name": "Alert Date", "values": ["-7dd"]}]})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_accepts_relative_date_token(self, client: AsyncClient):
        created = await _create(
            client, "Relative", filters=[{"name": "Alert Date", "inverted": False, "values": ["-24h@h"]}])
        assert created["filters"][0]["values"] == ["-24h@h"]

    @pytest.mark.asyncio
    async def test_relative_token_stored_verbatim_not_resolved(
        self, client: AsyncClient, session: AsyncSession
    ):
        """THE storage-side half of the re-evaluation invariant. If anything ever resolves a
        token to an absolute range on the way in, a saved "Last 24h" silently freezes to
        whenever it was saved."""
        created = await _create(
            client, "Verbatim", filters=[{"name": "Alert Date", "inverted": False, "values": ["-24h"]}])

        row = (await session.execute(
            select(SavedFilter).where(SavedFilter.uuid == created["uuid"]))).scalar_one()
        assert json.loads(row.filters_json)[0]["values"] == ["-24h"]


class TestOwnership:
    @pytest.mark.asyncio
    async def test_another_users_filter_is_not_readable(
        self, client: AsyncClient, other_client: AsyncClient
    ):
        """There is no cross-user read: sharing goes through self-describing URLs, not rows."""
        created = await _create(client, "Mine")
        assert (await other_client.get(f"{BASE}/{created['uuid']}")).status_code == 404

    @pytest.mark.asyncio
    async def test_another_users_filter_cannot_be_updated(
        self, client: AsyncClient, other_client: AsyncClient
    ):
        created = await _create(client, "Mine")
        response = await other_client.patch(f"{BASE}/{created['uuid']}", json={"name": "Stolen"})
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_another_users_filter_cannot_be_deleted(
        self, client: AsyncClient, other_client: AsyncClient
    ):
        created = await _create(client, "Mine")
        assert (await other_client.delete(f"{BASE}/{created['uuid']}")).status_code == 403

    @pytest.mark.asyncio
    async def test_list_only_returns_own_filters(
        self, client: AsyncClient, other_client: AsyncClient
    ):
        await _create(client, "Mine")
        await _create(other_client, "Theirs")

        names = [f["name"] for f in (await client.get(f"{BASE}/")).json()["data"]]
        assert "Mine" in names and "Theirs" not in names


class TestQuickFilters:
    @pytest.mark.asyncio
    async def test_set_membership_and_order(self, client: AsyncClient):
        a = await _create(client, "A")
        b = await _create(client, "B")
        c = await _create(client, "C")

        response = await client.put(f"{BASE}/quick-filters",
                                    json={"filter_uuids": [c["uuid"], a["uuid"]]})
        assert response.status_code == 200

        by_uuid = {f["uuid"]: f for f in response.json()["data"]}
        assert by_uuid[c["uuid"]]["quick_filter_order"] == 0
        assert by_uuid[a["uuid"]]["quick_filter_order"] == 1
        assert by_uuid[b["uuid"]]["quick_filter_order"] is None

    @pytest.mark.asyncio
    async def test_unpinning_renumbers_densely(self, client: AsyncClient):
        """Orders are always renumbered 0..N-1 so repeated pin/unpin cycles cannot leave
        gaps that make the badge order look arbitrary."""
        a = await _create(client, "A")
        b = await _create(client, "B")
        c = await _create(client, "C")

        await client.put(f"{BASE}/quick-filters",
                         json={"filter_uuids": [a["uuid"], b["uuid"], c["uuid"]]})
        response = await client.put(f"{BASE}/quick-filters",
                                    json={"filter_uuids": [a["uuid"], c["uuid"]]})

        orders = sorted(f["quick_filter_order"] for f in response.json()["data"]
                        if f["quick_filter_order"] is not None)
        assert orders == [0, 1]

    @pytest.mark.asyncio
    async def test_is_idempotent(self, client: AsyncClient):
        a = await _create(client, "A")
        payload = {"filter_uuids": [a["uuid"]]}

        first = await client.put(f"{BASE}/quick-filters", json=payload)
        second = await client.put(f"{BASE}/quick-filters", json=payload)
        assert first.json() == second.json()

    @pytest.mark.asyncio
    async def test_returns_the_bumped_updated_at(
        self, client: AsyncClient, session: AsyncSession
    ):
        """The deterministic half of test_is_idempotent: pinning a filter bumps updated_at
        server-side, so the response has to carry the new value. Serving the pre-UPDATE one
        is what made two identical PUTs return different bodies."""
        a = await _create(client, "A")
        await _backdate_updated_at(session, a["uuid"])

        response = await client.put(f"{BASE}/quick-filters", json={"filter_uuids": [a["uuid"]]})

        returned = datetime.fromisoformat(response.json()["data"][0]["updated_at"])
        assert returned != STALE_UPDATED_AT
        assert returned == await _stored_updated_at(session, a["uuid"])

    @pytest.mark.asyncio
    async def test_empty_list_unpins_everything(self, client: AsyncClient):
        a = await _create(client, "A", quick_filter=True)
        assert a["quick_filter_order"] == 0

        response = await client.put(f"{BASE}/quick-filters", json={"filter_uuids": []})
        assert all(f["quick_filter_order"] is None for f in response.json()["data"])

    @pytest.mark.asyncio
    async def test_rejects_unknown_uuid(self, client: AsyncClient):
        response = await client.put(f"{BASE}/quick-filters", json={"filter_uuids": ["nope"]})
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_another_users_uuid(
        self, client: AsyncClient, other_client: AsyncClient
    ):
        theirs = await _create(other_client, "Theirs")
        response = await client.put(f"{BASE}/quick-filters", json={"filter_uuids": [theirs["uuid"]]})
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_list_returns_pinned_first_in_badge_order(self, client: AsyncClient):
        await _create(client, "Zebra")
        b = await _create(client, "Bravo")
        await client.put(f"{BASE}/quick-filters", json={"filter_uuids": [b["uuid"]]})

        names = [f["name"] for f in (await client.get(f"{BASE}/")).json()["data"]]
        assert names[0] == "Bravo"


class TestScratchRows:
    @pytest.mark.asyncio
    async def test_upsert_is_a_singleton(self, client: AsyncClient, session: AsyncSession, test_user):
        """Bounding scratch rows to one per kind per user is what keeps this table from
        growing on every filter edit."""
        first = await client.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})
        second = await client.put(f"{BASE}/scratch/working", json={
            "filters": [{"name": "Tag", "inverted": False, "values": ["x"]}]})

        assert first.status_code == second.status_code == 200
        assert first.json()["uuid"] == second.json()["uuid"], "a second row was created"
        assert second.json()["filters"][0]["name"] == "Tag"

        rows = (await session.execute(
            select(SavedFilter).where(SavedFilter.user_id == test_user.id,
                                      SavedFilter.kind == "working"))).scalars().all()
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_working_and_temp_are_separate_singletons(self, client: AsyncClient):
        working = await client.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})
        temp = await client.put(f"{BASE}/scratch/temp", json={"filters": QUEUE_FILTER})

        assert working.json()["uuid"] != temp.json()["uuid"]

    @pytest.mark.asyncio
    async def test_label_is_stored(self, client: AsyncClient):
        response = await client.put(f"{BASE}/scratch/temp", json={
            "filters": QUEUE_FILTER, "label": "Tag: needs_research"})
        assert response.json()["description"] == "Tag: needs_research"

    @pytest.mark.asyncio
    async def test_overwrite_returns_the_bumped_updated_at(
        self, client: AsyncClient, session: AsyncSession
    ):
        """The overwrite branch reads the row, UPDATEs it and projects it without an
        intervening SELECT, so it is the third place a stale updated_at can escape."""
        first = await client.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})
        await _backdate_updated_at(session, first.json()["uuid"])

        second = await client.put(f"{BASE}/scratch/working", json={
            "filters": [{"name": "Tag", "inverted": False, "values": ["x"]}]})

        returned = datetime.fromisoformat(second.json()["updated_at"])
        assert returned != STALE_UPDATED_AT
        assert returned == await _stored_updated_at(session, first.json()["uuid"])

    @pytest.mark.asyncio
    async def test_scratch_rows_are_excluded_from_the_list(self, client: AsyncClient):
        await client.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})
        await client.put(f"{BASE}/scratch/temp", json={"filters": QUEUE_FILTER})

        assert all(f["kind"] == "named" for f in (await client.get(f"{BASE}/")).json()["data"])

    @pytest.mark.asyncio
    async def test_unknown_kind_is_404(self, client: AsyncClient):
        response = await client.put(f"{BASE}/scratch/bogus", json={"filters": QUEUE_FILTER})
        assert response.status_code == 404


class TestSeeding:
    @pytest.mark.asyncio
    async def test_seeds_the_two_defaults_in_order(self, session: AsyncSession, test_user):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id)
        filters = await service.get_saved_filters_for_user(session, test_user.id)
        seeded = [f for f in filters if f.name in ("Last 24h", "Last 7d")]

        assert [f.name for f in seeded] == ["Last 24h", "Last 7d"]
        assert [f.quick_filter_order for f in seeded] == [0, 1]

    @pytest.mark.asyncio
    async def test_seeded_defaults_use_relative_tokens(self, session: AsyncSession, test_user):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id)
        filters = await service.get_saved_filters_for_user(session, test_user.id)
        last_24h = next(f for f in filters if f.name == "Last 24h")
        date_entry = next(e for e in last_24h.filters if e.name == "Alert Date")

        assert date_entry.values == ["-24h"]

    @pytest.mark.asyncio
    async def test_seeds_only_once(self, session: AsyncSession, test_user):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id)
        await service.ensure_default_saved_filters(session, test_user.id)
        second = await service.get_saved_filters_for_user(session, test_user.id)

        assert len([f for f in second if f.name == "Last 24h"]) == 1

    @pytest.mark.asyncio
    async def test_does_not_reseed_after_the_analyst_deletes_the_defaults(
        self, session: AsyncSession, test_user
    ):
        """An analyst who deliberately deleted both defaults must not find them back on the
        next page load. This is the trap in the naive 'seed if no quick filters' guard."""
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id)
        seeded = await service.get_saved_filters_for_user(session, test_user.id)
        for f in seeded:
            await service.delete_saved_filter(session, f.uuid, test_user.id)

        # A working row still exists, exactly as it would in a real session. It is what
        # makes "has this user ever been seeded?" answerable without a extra flag column.
        from aceapi_v2.saved_filters.schemas import ScratchFilterWrite
        await service.upsert_scratch_filter(
            session, test_user.id, "working", ScratchFilterWrite(filters=QUEUE_FILTER))

        await service.ensure_default_saved_filters(session, test_user.id)
        again = await service.get_saved_filters_for_user(session, test_user.id)
        assert again == [], "deleted defaults must not be resurrected"

    @pytest.mark.asyncio
    async def test_listing_never_seeds_on_its_own(self, session: AsyncSession, test_user):
        """Listing is what the POLLED refresh endpoint does every 30s, and a polled endpoint
        must never write (docs/GUI_DATASTAR.md). Seeding is a separate, explicit call."""
        from aceapi_v2.saved_filters import service

        assert await service.get_saved_filters_for_user(session, test_user.id) == []
