"""The feeds endpoints, /api/v2/feeds (docs/FEED_WATCHES.md)."""

import logging

import pytest
from httpx import AsyncClient

from saq.crypto import decrypt_chunk
from saq.database.model import Feed
from tests.saq.feeds.conftest import fresh, make_entry, make_feed

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

BODY = {"name": "Vendor advisories", "url": "https://vendor.example/feed.xml"}


def _row(feed_id) -> Feed:
    return fresh(Feed, feed_id)


async def test_a_feed_is_added_with_its_credentials_never_shown(client: AsyncClient, caplog):
    with caplog.at_level(logging.INFO):
        response = await client.post("/feeds/", json={**BODY, "auth_type": "basic", "auth_name": "reader",
                                                             "auth_secret": "s3cret"})
    assert response.status_code == 201, response.text
    feed = response.json()
    assert feed["has_secret"] and feed["auth_name"] == "reader" and feed["poll_interval_seconds"] == 900
    assert "s3cret" not in response.text
    assert "s3cret" not in caplog.text
    assert decrypt_chunk(_row(feed["id"]).auth_secret) == b"s3cret"

    listed = (await client.get("/feeds/")).json()
    assert [item["id"] for item in listed["data"]] == [feed["id"]]
    assert "s3cret" not in str(listed) and "auth_secret" not in listed["data"][0]


@pytest.mark.parametrize("body, message", [
    ({**BODY, "url": "file:///etc/passwd"}, "http or https"),
    ({**BODY, "poll_interval_seconds": 10}, "at least 300"),
    ({**BODY, "auth_type": "header", "auth_name": "Authorization"}, "auth_secret is required"),
    ({**BODY, "auth_type": "basic", "auth_secret": "x"}, "needs a user"),
])
async def test_a_feed_that_cannot_be_polled_is_refused(client: AsyncClient, body, message):
    response = await client.post("/feeds/", json=body)
    assert response.status_code == 422
    assert message in response.text


async def test_a_feed_is_edited_and_its_credentials_kept_or_removed(client: AsyncClient):
    feed = (await client.post("/feeds/", json={**BODY, "auth_type": "header", "auth_name": "Authorization",
                                                      "auth_secret": "Bearer a"})).json()
    edited = await client.patch(f"/feeds/{feed['id']}", json={"name": "renamed", "poll_interval_seconds": 600})
    assert edited.status_code == 200, edited.text
    assert edited.json()["name"] == "renamed" and edited.json()["has_secret"]
    assert decrypt_chunk(_row(feed["id"]).auth_secret) == b"Bearer a"

    removed = (await client.patch(f"/feeds/{feed['id']}", json={"auth_type": "none"})).json()
    assert not removed["has_secret"] and removed["auth_type"] == "none"
    assert _row(feed["id"]).auth_secret is None


async def test_a_feed_moved_to_another_url_starts_with_a_baseline_again(client: AsyncClient):
    feed = make_feed(etag='"v1"')
    assert _row(feed.id).baselined_at is not None
    renamed = await client.patch(f"/feeds/{feed.id}", json={"name": "renamed", "url": feed.url})
    assert renamed.status_code == 200, renamed.text
    assert _row(feed.id).baselined_at is not None

    moved = await client.patch(f"/feeds/{feed.id}", json={"url": "https://other-vendor.example/atom.xml"})
    assert moved.status_code == 200, moved.text
    row = _row(feed.id)
    # the next poll stores what the new url carries for preview only
    assert row.baselined_at is None and row.etag is None


async def test_a_deleted_feed_stops_at_once(client: AsyncClient):
    feed = (await client.post("/feeds/", json=BODY)).json()
    assert (await client.delete(f"/feeds/{feed['id']}")).status_code == 204
    row = _row(feed["id"])
    assert row.deleted_at is not None and not row.enabled
    assert (await client.get(f"/feeds/{feed['id']}")).status_code == 404
    assert (await client.get("/feeds/")).json()["data"] == []


async def test_the_entries_are_listed_newest_first_in_pages(client: AsyncClient):
    feed = make_feed()
    entries = [make_entry(feed, identity=f"e{index}", content="x" * 5000 if index == 2 else "short") for index in range(3)]
    page = (await client.get(f"/feeds/{feed.id}/entries", params={"limit": 2})).json()
    assert [item["identity"] for item in page["data"]] == ["e2", "e1"]
    assert page["data"][0]["text_truncated"] and len(page["data"][0]["text"]) == 4000
    rest = (await client.get(f"/feeds/{feed.id}/entries", params={"limit": 2, "cursor": page["next_cursor"]})).json()
    assert [item["id"] for item in rest["data"]] == [entries[0].id] and rest["next_cursor"] is None


async def test_reading_and_writing_need_their_permissions(noperm_client: AsyncClient):
    assert (await noperm_client.get("/feeds/")).status_code == 403
    assert (await noperm_client.post("/feeds/", json=BODY)).status_code == 403
