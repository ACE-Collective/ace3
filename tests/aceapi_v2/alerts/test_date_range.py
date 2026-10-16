"""GET /api/v2/alerts/date-range: the window a date filter value means right now."""

from datetime import datetime, timedelta

import pytest
import pytz
from httpx import AsyncClient

from saq.util.relative_time import format_date_range

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    assert (await unauth_client.get("/alerts/date-range", params={"value": "-24h"})).status_code == 401


@pytest.mark.asyncio
async def test_requires_alert_read(noperm_client: AsyncClient):
    assert (await noperm_client.get("/alerts/date-range", params={"value": "-24h"})).status_code == 403


@pytest.mark.asyncio
async def test_relative_value(client: AsyncClient):
    response = await client.get("/alerts/date-range", params={"value": "-24h"})

    assert response.status_code == 200
    body = response.json()
    start = datetime.fromisoformat(body["start"])
    end = datetime.fromisoformat(body["end"])
    assert end - start == timedelta(hours=24)
    assert body["text"] == format_date_range(start, end, pytz.utc)


@pytest.mark.asyncio
async def test_snaps_in_the_given_timezone(client: AsyncClient):
    """`@d` is midnight where the analyst is, which is why the browser passes its timezone."""
    tz = pytz.timezone("America/Chicago")

    body = (await client.get("/alerts/date-range", params={"value": "-1d@d - @d", "tz": tz.zone})).json()

    start = datetime.fromisoformat(body["start"]).astimezone(tz)
    end = datetime.fromisoformat(body["end"]).astimezone(tz)
    assert (start.hour, start.minute, end.hour, end.minute) == (0, 0, 0, 0)
    assert body["text"] == format_date_range(start, end, tz)


@pytest.mark.asyncio
async def test_value_that_does_not_parse_is_422(client: AsyncClient):
    response = await client.get("/alerts/date-range", params={"value": "next tuesday"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_unknown_timezone_is_422(client: AsyncClient):
    response = await client.get("/alerts/date-range", params={"value": "-24h", "tz": "Mars/Olympus_Mons"})
    assert response.status_code == 422
