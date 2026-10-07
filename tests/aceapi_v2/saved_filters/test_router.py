"""Tests for the aceapi_v2 saved filters router."""

import json
from datetime import datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic import field_validator

from tests.aceapi_v2.conftest import api_key_client, make_api_key
from saq.database.model import AuthUserPermission, SavedFilter, User
from saq.gui.filter_entry import FilterEntryBase
from saq.gui.filter_screens import FILTER_SCREENS, FilterScreen

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
    @pytest.mark.parametrize("value", ["not-a-uuid", "6f3a1b2c-1111-2222-3333-444455556666:"])
    async def test_rejects_bad_detection_point_value_at_write_time(self, client: AsyncClient, value):
        response = await client.post(f"{BASE}/", json={
            "name": "Bad Detection Point",
            "filters": [{"name": "Detection Point", "values": [value]}]})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_accepts_detection_point_value(self, client: AsyncClient):
        created = await _create(
            client, "Detection Point", filters=[{"name": "Detection Point", "inverted": False,
                                                 "values": ["6F3A1B2C-1111-2222-3333-444455556666:v1"]}])
        assert created["filters"][0]["values"] == ["6f3a1b2c-1111-2222-3333-444455556666:v1"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["QRCodeAnalysis", ["saq.modules.file_analysis.qrcode", "QRCodeAnalysis"]])
    async def test_rejects_a_value_that_is_not_a_module_path(self, client: AsyncClient, value):
        response = await client.post(f"{BASE}/", json={
            "name": "Bad Analysis",
            "filters": [{"name": "Analysis", "values": [value]}]})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_accepts_analysis_module_path(self, client: AsyncClient):
        created = await _create(
            client, "QR codes", filters=[{"name": "Analysis", "inverted": False,
                                          "values": ["saq.modules.file_analysis.qrcode:QRCodeAnalysis"]}])
        assert created["filters"][0]["values"] == ["saq.modules.file_analysis.qrcode:QRCodeAnalysis"]

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


class TestWrites:
    """What the manage page's Save as and Save rely on, now that they call the API."""

    @pytest.mark.asyncio
    async def test_an_empty_filter_is_refused(self, client: AsyncClient):
        """Clearing every row and saving is a mistake, not a request to save "match everything"."""
        assert (await client.post(f"{BASE}/", json={"name": "Empty", "filters": []})).status_code == 422
        created = await _create(client, "Mine")
        assert (await client.patch(f"{BASE}/{created['uuid']}", json={"filters": []})).status_code == 422

    @pytest.mark.asyncio
    async def test_a_metadata_update_leaves_the_filters_alone(self, client: AsyncClient):
        """Rename and the quick-filter toggles must not need to know what the filter contains."""
        created = await _create(client, "Before")
        response = await client.patch(f"{BASE}/{created['uuid']}", json={"name": "After"})
        assert response.json()["filters"] == QUEUE_FILTER

    @pytest.mark.asyncio
    async def test_a_rejected_update_writes_nothing(self, client: AsyncClient):
        created = await _create(client, "Mine")
        bad = await client.patch(f"{BASE}/{created['uuid']}", json={
            "name": "Renamed", "filters": [{"name": "Alert Date", "inverted": False, "values": ["-7dd"]}]})
        assert bad.status_code == 422
        stored = (await client.get(f"{BASE}/{created['uuid']}")).json()
        assert (stored["name"], stored["filters"]) == ("Mine", QUEUE_FILTER)


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

        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        filters = await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")
        seeded = [f for f in filters if f.name in ("Last 24h", "Last 7d")]

        assert [f.name for f in seeded] == ["Last 24h", "Last 7d"]
        assert [f.quick_filter_order for f in seeded] == [0, 1]

    @pytest.mark.asyncio
    async def test_each_screen_seeds_its_own_defaults(self, session: AsyncSession, test_user):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id, screen="svs_samples")
        samples = await service.get_saved_filters_for_user(session, test_user.id, screen="svs_samples")
        assert [(f.name, f.quick_filter_order) for f in samples] == [("Conflicted", 0), ("Missing data", 1)]
        assert [e.model_dump() for e in samples[0].filters] == [
            {"name": "Label", "inverted": False, "values": ["conflicted"]}]

        # seeding one screen does not count as having been seeded on another
        alerts = await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")
        assert not [f for f in alerts if f.name in ("Conflicted", "Missing data")]

    @pytest.mark.asyncio
    async def test_seeded_defaults_use_relative_tokens(self, session: AsyncSession, test_user):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        filters = await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")
        last_24h = next(f for f in filters if f.name == "Last 24h")
        date_entry = next(e for e in last_24h.filters if e.name == "Alert Date")

        assert date_entry.values == ["-24h"]

    @pytest.mark.asyncio
    async def test_seeds_only_once(self, session: AsyncSession, test_user):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        second = await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")

        assert len([f for f in second if f.name == "Last 24h"]) == 1

    @pytest.mark.asyncio
    async def test_does_not_reseed_after_the_analyst_deletes_the_defaults(
        self, session: AsyncSession, test_user
    ):
        """An analyst who deliberately deleted both defaults must not find them back on the
        next page load. This is the trap in the naive 'seed if no quick filters' guard."""
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        seeded = await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")
        for f in seeded:
            await service.delete_saved_filter(session, f.uuid, test_user.id)

        # A working row still exists, exactly as it would in a real session. It is what
        # makes "has this user ever been seeded?" answerable without a extra flag column.
        from aceapi_v2.saved_filters.schemas import ScratchFilterWrite
        await service.upsert_scratch_filter(
            session, test_user.id, "working", ScratchFilterWrite(filters=QUEUE_FILTER), screen="alerts")

        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        again = await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")
        assert again == [], "deleted defaults must not be resurrected"

    @pytest.mark.asyncio
    async def test_listing_never_seeds_on_its_own(self, session: AsyncSession, test_user):
        """Listing is what the POLLED refresh endpoint does every 30s, and a polled endpoint
        must never write (docs/GUI_DATASTAR.md). Seeding is a separate, explicit call."""
        from aceapi_v2.saved_filters import service

        assert await service.get_saved_filters_for_user(session, test_user.id, screen="alerts") == []


# a second screen with a filter vocabulary of its own, standing in for the SVS screens
class _ColorEntry(FilterEntryBase):
    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value != "Color":
            raise ValueError(f"unknown filter name {value!r}")
        return value


TEST_SCREEN = FilterScreen(name="test_screen", entry_model=_ColorEntry, slugs={"Color": "color"})
COLOR_FILTER = [{"name": "Color", "inverted": False, "values": ["red"]}]


@pytest.fixture
def test_screen(monkeypatch):
    monkeypatch.setitem(FILTER_SCREENS, TEST_SCREEN.name, TEST_SCREEN)
    return TEST_SCREEN


class TestScreens:
    @pytest.mark.asyncio
    async def test_rows_default_to_the_alert_screen(self, client: AsyncClient):
        created = await _create(client, "Default screen")
        assert created["screen"] == "alerts"

    @pytest.mark.asyncio
    async def test_a_name_is_unique_per_screen(self, client: AsyncClient, test_screen):
        await _create(client, "Mine")
        other = await client.post(f"{BASE}/?screen=test_screen", json={"name": "Mine", "filters": COLOR_FILTER})
        assert other.status_code == 201, other.text
        assert other.json()["screen"] == "test_screen"

        duplicate = await client.post(f"{BASE}/?screen=test_screen", json={"name": "Mine", "filters": COLOR_FILTER})
        assert duplicate.status_code == 409

    @pytest.mark.asyncio
    async def test_lists_are_per_screen(self, client: AsyncClient, test_screen):
        await _create(client, "Alert filter")
        await client.post(f"{BASE}/?screen=test_screen", json={"name": "Color filter", "filters": COLOR_FILTER})

        alerts = [f["name"] for f in (await client.get(f"{BASE}/")).json()["data"]]
        colors = [f["name"] for f in (await client.get(f"{BASE}/?screen=test_screen")).json()["data"]]
        assert alerts == ["Alert filter"]
        assert colors == ["Color filter"]

    @pytest.mark.asyncio
    async def test_filters_are_validated_against_their_screen(self, client: AsyncClient, test_screen):
        # an alert filter on the test screen, and a test-screen filter on the alert screen
        wrong_screen = await client.post(f"{BASE}/?screen=test_screen", json={"name": "x", "filters": QUEUE_FILTER})
        assert wrong_screen.status_code == 422
        wrong_alerts = await client.post(f"{BASE}/", json={"name": "x", "filters": COLOR_FILTER})
        assert wrong_alerts.status_code == 422
        assert isinstance(wrong_alerts.json()["detail"], list)

    @pytest.mark.asyncio
    async def test_an_update_is_validated_against_the_rows_own_screen(self, client: AsyncClient, test_screen):
        created = (await client.post(f"{BASE}/?screen=test_screen", json={"name": "c", "filters": COLOR_FILTER})).json()

        bad = await client.patch(f"{BASE}/{created['uuid']}", json={"filters": QUEUE_FILTER})
        assert bad.status_code == 422
        good = await client.patch(f"{BASE}/{created['uuid']}", json={
            "filters": [{"name": "Color", "inverted": True, "values": ["blue"]}]})
        assert good.status_code == 200
        assert good.json()["filters"][0]["values"] == ["blue"]

    @pytest.mark.asyncio
    async def test_scratch_rows_are_singletons_per_screen(
        self, client: AsyncClient, session: AsyncSession, test_user, test_screen
    ):
        alerts_first = await client.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})
        screen_first = await client.put(f"{BASE}/scratch/working?screen=test_screen", json={"filters": COLOR_FILTER})
        screen_second = await client.put(f"{BASE}/scratch/working?screen=test_screen", json={"filters": COLOR_FILTER})
        alerts_second = await client.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})

        assert alerts_first.json()["uuid"] == alerts_second.json()["uuid"]
        assert screen_first.json()["uuid"] == screen_second.json()["uuid"]
        assert alerts_first.json()["uuid"] != screen_first.json()["uuid"]

        rows = (await session.execute(
            select(SavedFilter.screen).where(SavedFilter.user_id == test_user.id,
                                             SavedFilter.kind == "working"))).scalars().all()
        assert sorted(rows) == ["alerts", "test_screen"]

    @pytest.mark.asyncio
    async def test_quick_filters_are_per_screen(self, client: AsyncClient, test_screen):
        alert_filter = await _create(client, "Alert badge", quick_filter=True)
        color = (await client.post(f"{BASE}/?screen=test_screen", json={
            "name": "Color badge", "filters": COLOR_FILTER, "quick_filter": True})).json()
        # each screen numbers its badges from 0
        assert alert_filter["quick_filter_order"] == 0
        assert color["quick_filter_order"] == 0

        # another screen's filter cannot be pinned on this one
        response = await client.put(f"{BASE}/quick-filters?screen=test_screen",
                                    json={"filter_uuids": [alert_filter["uuid"]]})
        assert response.status_code == 400

        # unpinning everything on one screen leaves the other screen's badges alone
        response = await client.put(f"{BASE}/quick-filters?screen=test_screen", json={"filter_uuids": []})
        assert response.status_code == 200
        alerts = (await client.get(f"{BASE}/")).json()["data"]
        assert [f["quick_filter_order"] for f in alerts] == [0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method, path, body", [
        ("get", "/?screen=nope", None),
        ("post", "/?screen=nope", {"name": "x", "filters": QUEUE_FILTER}),
        ("put", "/quick-filters?screen=nope", {"filter_uuids": []}),
        ("put", "/scratch/working?screen=nope", {"filters": QUEUE_FILTER}),
    ])
    async def test_unknown_screen_is_404(self, client: AsyncClient, method, path, body):
        kwargs = {"json": body} if body is not None else {}
        response = await getattr(client, method)(f"{BASE}{path}", **kwargs)
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_with_a_screen_never_returns_another_screens_row(
        self, client: AsyncClient, session: AsyncSession, test_user, test_screen
    ):
        """The alert page applies whatever filter it is handed to the alert query, so it must
        never be handed another screen's filter names."""
        from aceapi_v2.saved_filters import service

        created = (await client.post(f"{BASE}/?screen=test_screen", json={"name": "c", "filters": COLOR_FILTER})).json()
        assert await service.get_saved_filter(session, created["uuid"], test_user.id, screen="alerts") is None
        found = await service.get_saved_filter(session, created["uuid"], test_user.id, screen="test_screen")
        assert found.filters[0].name == "Color"
        # by uuid alone, the row is found whatever its screen
        assert (await client.get(f"{BASE}/{created['uuid']}")).json()["screen"] == "test_screen"

    @pytest.mark.asyncio
    async def test_screens_without_defaults_seed_nothing(self, session: AsyncSession, test_user, test_screen):
        from aceapi_v2.saved_filters import service

        await service.ensure_default_saved_filters(session, test_user.id, screen="test_screen")
        assert await service.get_saved_filters_for_user(session, test_user.id, screen="test_screen") == []

    @pytest.mark.asyncio
    async def test_seeding_is_per_screen(self, session: AsyncSession, test_user, test_screen):
        """Rows on another screen do not count as "already seeded" for the alert screen."""
        from aceapi_v2.saved_filters import service
        from aceapi_v2.saved_filters.schemas import ScratchFilterWrite

        await service.upsert_scratch_filter(
            session, test_user.id, "working", ScratchFilterWrite(filters=COLOR_FILTER), screen="test_screen")
        await service.ensure_default_saved_filters(session, test_user.id, screen="alerts")
        names = [f.name for f in await service.get_saved_filters_for_user(session, test_user.id, screen="alerts")]
        assert names == ["Last 24h", "Last 7d"]


# a screen whose data is read with signature:read, like the SVS samples
SIGNATURE_SCREEN = FilterScreen(name="test_signature_screen", entry_model=_ColorEntry, slugs={"Color": "color"},
                                permission=("signature", "read"))


@pytest.fixture
def signature_screen(monkeypatch):
    monkeypatch.setitem(FILTER_SCREENS, SIGNATURE_SCREEN.name, SIGNATURE_SCREEN)
    return SIGNATURE_SCREEN


async def _client_with_permissions(session: AsyncSession, username: str, permissions: list[tuple[str, str]]):
    user = User(username=username, email=f"{username}@e.com", display_name=username, password="pw")
    session.add(user)
    await session.flush()
    for major, minor in permissions:
        session.add(AuthUserPermission(user_id=user.id, major=major, minor=minor, effect="ALLOW"))
    await session.flush()
    return api_key_client(await make_api_key(session, user.id, inherit=True))


@pytest_asyncio.fixture
async def signature_reader(_override_db_session, session: AsyncSession):
    """A user who may read signatures and nothing about alerts."""
    async with await _client_with_permissions(session, "signature_reader", [("signature", "read")]) as client:
        yield client


@pytest_asyncio.fixture
async def alert_reader(_override_db_session, session: AsyncSession):
    """A user who may read alerts and nothing about signatures."""
    async with await _client_with_permissions(session, "alert_reader", [("alert", "read")]) as client:
        yield client


SIG = f"{BASE}/?screen={SIGNATURE_SCREEN.name}"


class TestScreenPermissions:
    """Each screen's saved filters need the permission that reads the screen's data."""

    @pytest.mark.asyncio
    async def test_the_screens_permission_is_enough(self, signature_reader: AsyncClient, signature_screen):
        created = await signature_reader.post(SIG, json={"name": "Mine", "filters": COLOR_FILTER, "quick_filter": True})
        assert created.status_code == 201, created.text
        filter_uuid = created.json()["uuid"]

        assert [f["name"] for f in (await signature_reader.get(SIG)).json()["data"]] == ["Mine"]
        assert (await signature_reader.get(f"{BASE}/{filter_uuid}")).status_code == 200
        assert (await signature_reader.patch(f"{BASE}/{filter_uuid}", json={"name": "Renamed"})).status_code == 200
        reorder = await signature_reader.put(f"{BASE}/quick-filters?screen={SIGNATURE_SCREEN.name}",
                                             json={"filter_uuids": [filter_uuid]})
        assert reorder.status_code == 200
        scratch = await signature_reader.put(f"{BASE}/scratch/working?screen={SIGNATURE_SCREEN.name}",
                                             json={"filters": COLOR_FILTER})
        assert scratch.status_code == 200
        assert (await signature_reader.delete(f"{BASE}/{filter_uuid}")).status_code == 204

    @pytest.mark.asyncio
    async def test_another_screens_permission_is_not(self, signature_reader: AsyncClient, signature_screen):
        assert (await signature_reader.get(f"{BASE}/")).status_code == 403
        assert (await signature_reader.post(f"{BASE}/", json={"name": "x", "filters": QUEUE_FILTER})).status_code == 403
        assert (await signature_reader.put(f"{BASE}/quick-filters", json={"filter_uuids": []})).status_code == 403
        assert (await signature_reader.put(f"{BASE}/scratch/working", json={"filters": QUEUE_FILTER})).status_code == 403

    @pytest.mark.asyncio
    async def test_an_alert_reader_cannot_use_a_signature_screen(self, alert_reader: AsyncClient, signature_screen):
        assert (await alert_reader.get(f"{BASE}/")).status_code == 200
        assert (await alert_reader.get(SIG)).status_code == 403
        assert (await alert_reader.post(SIG, json={"name": "x", "filters": COLOR_FILTER})).status_code == 403

    @pytest.mark.asyncio
    async def test_a_row_is_checked_against_its_own_screen(
        self, alert_reader: AsyncClient, session: AsyncSession, signature_screen
    ):
        """A row addressed by uuid carries its screen; holding another screen's permission does
        not reach it, even for its owner."""
        mine = await _create(alert_reader, "Mine")
        # the owner loses access to the row's screen: move the row to the signature screen
        await session.execute(
            update(SavedFilter).where(SavedFilter.uuid == mine["uuid"]).values(
                screen=SIGNATURE_SCREEN.name, filters_json=json.dumps(COLOR_FILTER)))
        await session.commit()

        assert (await alert_reader.get(f"{BASE}/{mine['uuid']}")).status_code == 403
        assert (await alert_reader.patch(f"{BASE}/{mine['uuid']}", json={"name": "x"})).status_code == 403
        assert (await alert_reader.delete(f"{BASE}/{mine['uuid']}")).status_code == 403

    @pytest.mark.asyncio
    async def test_an_unknown_row_is_404_to_a_user_of_some_screen(self, signature_reader: AsyncClient, signature_screen):
        assert (await signature_reader.get(f"{BASE}/no-such-uuid")).status_code == 404
        assert (await signature_reader.get(f"{BASE}/?screen=no_such_screen")).status_code == 404

    @pytest.mark.asyncio
    async def test_a_user_of_no_screen_is_refused_even_an_unknown_row(self, signature_reader: AsyncClient, monkeypatch):
        """Without a screen gated by signature:read registered, signature:read opens no screen at all."""
        for name, screen in list(FILTER_SCREENS.items()):
            if screen.permission == ("signature", "read"):
                monkeypatch.delitem(FILTER_SCREENS, name)
        assert (await signature_reader.get(f"{BASE}/no-such-uuid")).status_code == 403
        assert (await signature_reader.get(f"{BASE}/?screen=no_such_screen")).status_code == 403
