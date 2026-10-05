"""Tests for the aceapi_v2 filter screens router."""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from pydantic import field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import AuthUserPermission, User
from saq.gui.filter_entry import FilterEntryBase
from saq.gui.filter_names import FILTER_SLUGS
from saq.gui.filter_screens import FILTER_SCREENS, FilterField, FilterFieldKind, FilterScreen
from tests.aceapi_v2.conftest import api_key_client, make_api_key

pytestmark = pytest.mark.integration

BASE = "/filter-screens"

ALERT_FILTERS = [
    {"name": "Queue", "inverted": False, "values": ["default"]},
    {"name": "Disposition", "inverted": False, "values": ["OPEN", "FALSE_POSITIVE"]},
    {"name": "Tag", "inverted": True, "values": ["whitelisted"]},
    {"name": "Alert Date", "inverted": False, "values": ["-7d"]},
    {"name": "Description", "inverted": False, "values": ["with:colon,and comma"]},
]
ALERT_PARAMS = ["queue:default", "disposition:OPEN,FALSE_POSITIVE", "!tag:whitelisted", "alert_date:-7d"]


class _ColorEntry(FilterEntryBase):
    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in ("Color", "Size"):
            raise ValueError(f"unknown filter name {value!r}")
        return value


SIGNATURE_SCREEN = FilterScreen(
    name="test_signature_screen",
    entry_model=_ColorEntry,
    slugs={"Color": "color", "Size": "size"},
    permission=("signature", "read"),
    fields=(FilterField("Color", FilterFieldKind.MULTI, ("red", "blue")),
            FilterField("Size", FilterFieldKind.TEXT)),
)


@pytest.fixture
def signature_screen(monkeypatch):
    monkeypatch.setitem(FILTER_SCREENS, SIGNATURE_SCREEN.name, SIGNATURE_SCREEN)
    return SIGNATURE_SCREEN


@pytest_asyncio.fixture
async def signature_reader(_override_db_session, session: AsyncSession):
    """A user who may read signatures and nothing about alerts."""
    user = User(username="signature_reader", email="signature_reader@e.com", display_name="sig", password="pw")
    session.add(user)
    await session.flush()
    session.add(AuthUserPermission(user_id=user.id, major="signature", minor="read", effect="ALLOW"))
    await session.flush()
    async with api_key_client(await make_api_key(session, user.id, inherit=True)) as client:
        yield client


class TestAccess:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get(f"{BASE}/alerts")).status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method, path", [
        ("get", "/alerts"),
        ("post", "/alerts/encode"),
        ("get", "/alerts/decode?f=queue:default"),
    ])
    async def test_requires_the_screens_permission(self, noperm_client: AsyncClient, method, path):
        kwargs = {"json": {"filters": []}} if method == "post" else {}
        assert (await getattr(noperm_client, method)(f"{BASE}{path}", **kwargs)).status_code == 403

    @pytest.mark.asyncio
    async def test_each_screen_has_its_own_permission(self, signature_reader: AsyncClient, signature_screen):
        assert (await signature_reader.get(f"{BASE}/{SIGNATURE_SCREEN.name}")).status_code == 200
        assert (await signature_reader.get(f"{BASE}/alerts")).status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_screen_is_404(self, client: AsyncClient):
        assert (await client.get(f"{BASE}/nope")).status_code == 404


class TestDescriptor:
    @pytest.mark.asyncio
    async def test_the_alert_screen_lists_its_slugs(self, client: AsyncClient):
        body = (await client.get(f"{BASE}/alerts")).json()
        assert body["name"] == "alerts"
        assert {f["name"]: f["slug"] for f in body["filters"]} == dict(FILTER_SLUGS)
        # the manage page has its own editor
        assert all(f["kind"] is None for f in body["filters"])

    @pytest.mark.asyncio
    async def test_a_screen_with_fields_describes_them(self, client: AsyncClient, signature_screen):
        body = (await client.get(f"{BASE}/{SIGNATURE_SCREEN.name}")).json()
        assert body["filters"] == [
            {"name": "Color", "slug": "color", "kind": "multi", "options": ["red", "blue"]},
            {"name": "Size", "slug": "size", "kind": "text", "options": []},
        ]


class TestEncoding:
    @pytest.mark.asyncio
    async def test_encode_matches_the_published_format(self, client: AsyncClient):
        response = await client.post(f"{BASE}/alerts/encode", json={"filters": ALERT_FILTERS[:4]})
        assert response.status_code == 200, response.text
        assert response.json()["f"] == ALERT_PARAMS

    @pytest.mark.asyncio
    async def test_round_trip(self, client: AsyncClient):
        encoded = (await client.post(f"{BASE}/alerts/encode", json={"filters": ALERT_FILTERS})).json()["f"]
        decoded = await client.get(f"{BASE}/alerts/decode", params=[("f", value) for value in encoded])
        assert decoded.status_code == 200, decoded.text
        assert decoded.json() == {"filters": ALERT_FILTERS, "warnings": []}

    @pytest.mark.asyncio
    async def test_a_screen_uses_its_own_slugs(self, client: AsyncClient, signature_screen):
        filters = [{"name": "Color", "inverted": True, "values": ["red", "blue"]}]
        encoded = (await client.post(f"{BASE}/{SIGNATURE_SCREEN.name}/encode", json={"filters": filters})).json()["f"]
        assert encoded == ["!color:red,blue"]
        decoded = await client.get(f"{BASE}/{SIGNATURE_SCREEN.name}/decode", params={"f": encoded})
        assert decoded.json()["filters"] == filters

    @pytest.mark.asyncio
    async def test_encode_refuses_a_filter_the_screen_does_not_support(self, client: AsyncClient):
        bad_name = await client.post(f"{BASE}/alerts/encode", json={"filters": [{"name": "Color", "inverted": False, "values": ["x"]}]})
        assert bad_name.status_code == 422
        bad_date = await client.post(f"{BASE}/alerts/encode", json={"filters": [{"name": "Alert Date", "inverted": False, "values": ["-7dd"]}]})
        assert bad_date.status_code == 422

    @pytest.mark.asyncio
    async def test_decode_skips_an_unknown_slug_with_a_warning(self, client: AsyncClient):
        response = await client.get(f"{BASE}/alerts/decode", params=[("f", "queue:default"), ("f", "gone:x")])
        assert response.status_code == 200
        body = response.json()
        assert body["filters"] == [ALERT_FILTERS[0]]
        assert len(body["warnings"]) == 1 and "gone" in body["warnings"][0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["queue", ":default", "alert_date:-7dd"])
    async def test_decode_refuses_a_broken_link(self, client: AsyncClient, value):
        assert (await client.get(f"{BASE}/alerts/decode", params={"f": value})).status_code == 422
