"""GET /api/v2/alerts/count: how many alerts GET /alerts lists for a set of filters (and, for an
Observable Pattern that cannot be run, the 422 every alert listing gives)."""

import json

import pytest
from httpx import AsyncClient

from saq.constants import DISPOSITION_FALSE_POSITIVE, DISPOSITION_OPEN
from saq.database.model import Alert, User
from saq.database.pool import get_db
from saq.gui import filter_query
from saq.gui.alert import GUIAlert
from saq.gui.filter_url import encode_filter_query
from tests.saq.helpers import attach_observable, insert_alert

pytestmark = pytest.mark.integration


def _set(alert: Alert, **values) -> None:
    db = get_db()
    db.execute(Alert.__table__.update().where(Alert.id == alert.id).values(**values))
    db.commit()


def _reset_filters(user: User) -> list:
    """The manage page's "Reset" filter for this user (app/analysis/views/session/filters.py
    ::_default_filters, which reads current_user)."""
    return [
        {"name": "Disposition", "inverted": False, "values": [DISPOSITION_OPEN]},
        {"name": "Owner", "inverted": False, "values": ["None", user.display_name]},
        {"name": "Queue", "inverted": False, "values": [user.queue]},
    ]


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    assert (await unauth_client.get("/alerts/count")).status_code == 401


@pytest.mark.asyncio
async def test_requires_alert_read(noperm_client: AsyncClient):
    assert (await noperm_client.get("/alerts/count")).status_code == 403


@pytest.mark.asyncio
async def test_unknown_filter_is_422(client: AsyncClient):
    assert (await client.get("/alerts/count", params={"f": "no_such_filter:x"})).status_code == 422


@pytest.mark.asyncio
async def test_counts_what_the_listing_lists(client: AsyncClient):
    for _ in range(3):
        insert_alert()
    # scoped to this node's alerts, as the listing is
    _set(insert_alert(), location="some-other-node")

    response = await client.get("/alerts/count")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.json() == {"count": 3}
    assert len((await client.get("/alerts/")).json()["data"]) == 3


@pytest.mark.asyncio
async def test_reset_filter_count_matches_the_gui(client: AsyncClient):
    """The manage page's tab dot used to be counted by the GUI's own query; the API's count of
    the same filters must agree with it."""
    db = get_db()
    user = db.query(User).filter(User.username == "unittest").one()
    someone_else = db.query(User).filter(User.username == "ace").one()

    waiting_unowned = insert_alert()
    _set(waiting_unowned, disposition=DISPOSITION_OPEN, owner_id=None, queue=user.queue)
    waiting_mine = insert_alert()
    _set(waiting_mine, disposition=DISPOSITION_OPEN, owner_id=user.id, queue=user.queue)
    theirs = insert_alert()
    _set(theirs, disposition=DISPOSITION_OPEN, owner_id=someone_else.id, queue=user.queue)
    closed = insert_alert()
    _set(closed, disposition=DISPOSITION_FALSE_POSITIVE, owner_id=None, queue=user.queue)
    other_queue = insert_alert()
    _set(other_queue, disposition=DISPOSITION_OPEN, owner_id=None, queue="some_other_queue")

    filters = _reset_filters(user)
    response = await client.get("/alerts/count", params=[("f", f) for f in encode_filter_query(filters)])

    assert response.status_code == 200, response.text
    assert response.json()["count"] == 2
    assert response.json()["count"] == filter_query.count_alerts(filters, entity=GUIAlert)


def _pattern(pattern: str) -> dict:
    return {"f": encode_filter_query([{"name": "Observable Pattern", "inverted": False,
                                       "values": [["fqdn", pattern]]}])}


@pytest.mark.asyncio
async def test_counts_an_observable_pattern(client: AsyncClient):
    attach_observable(insert_alert(), "fqdn", "mail.evil.com")
    attach_observable(insert_alert(), "fqdn", "evil.com.attacker.net")

    response = await client.get("/alerts/count", params=_pattern("*.evil.com"))
    assert response.status_code == 200 and response.json() == {"count": 1}


@pytest.mark.asyncio
async def test_a_wildcard_at_both_ends_is_422(client: AsyncClient):
    response = await client.get("/alerts/count", params=_pattern("*evil*"))
    assert response.status_code == 422 and "both ends" in json.dumps(response.json())


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/alerts/count", "/alerts/", "/alerts/export/csv"])
async def test_a_pattern_that_matches_too_many_observables_is_422(client: AsyncClient, monkeypatch, path):
    """Refused, rather than counting or listing alerts without the filter."""
    attach_observable(insert_alert(), "fqdn", "mail.evil.com")
    monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 0)

    response = await client.get(path, params=_pattern("*.evil.com"))
    assert response.status_code == 422
    assert "matches more than 0 observables" in response.json()["detail"]
