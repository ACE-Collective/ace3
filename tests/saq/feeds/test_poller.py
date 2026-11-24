"""Polling feeds (docs/FEED_WATCHES.md, *Polling*)."""

import logging

import pytest
import requests
from sqlalchemy import select, text

from saq.crypto import encrypt_chunk
from saq.database.model import Feed, FeedEntry
from saq.database.pool import get_db
from saq.feeds import poller
from saq.feeds.entries import ParsedEntry, ParsedFeed
from saq.feeds.poller import html_to_text, poll_feed
from tests.saq.feeds.conftest import fresh, make_feed, service_config

URL = "https://vendor.example/feed.xml"

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor &amp; Co advisories</title>
<item><guid>urn:adv:1</guid><title>Widget &lt;b&gt;flaw&lt;/b&gt;</title><link>https://vendor.example/1</link>
<description>&lt;p&gt;It is &lt;b&gt;actively exploited&lt;/b&gt;.&lt;/p&gt;</description><category>exploited</category>
<pubDate>Mon, 02 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>No guid</title><link>https://vendor.example/2</link><description>second</description></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Atom advisories</title>
<entry><id>tag:vendor,2026:1</id><title>Atom entry</title><link href="https://vendor.example/a1"/>
<updated>2026-11-02T10:00:00Z</updated><content type="html">&lt;p&gt;full &lt;i&gt;text&lt;/i&gt;&lt;/p&gt;</content></entry>
</feed>"""


def _entries() -> list[FeedEntry]:
    db = get_db()
    db.expire_all()
    return db.execute(select(FeedEntry).order_by(FeedEntry.id)).scalars().all()


def _feed(feed_id) -> Feed:
    return fresh(Feed, feed_id)


@pytest.mark.unit
def test_html_is_stripped_to_text():
    assert html_to_text("<p>It is <b>actively</b>\n exploited</p><script>alert(1)</script>") == "It is actively exploited"
    assert html_to_text("") is None


@pytest.mark.unit
def test_rss_and_atom_are_parsed():
    pytest.importorskip("feedparser")
    rss = poller.parse_feed(RSS)
    assert rss.title == "Vendor & Co advisories"
    first, second = rss.entries
    assert (first.guid, first.title, first.summary, first.categories) == \
        ("urn:adv:1", "Widget flaw", "It is actively exploited .", ("exploited",))
    assert first.published_at.isoformat() == "2026-11-02T10:00:00"
    assert second.guid is None and second.link == "https://vendor.example/2"

    atom = poller.parse_feed(ATOM)
    assert atom.entries[0].guid == "tag:vendor,2026:1"
    assert atom.entries[0].content == "full text"


@pytest.mark.unit
def test_a_document_that_is_not_a_feed():
    pytest.importorskip("feedparser")
    with pytest.raises(poller.FeedFetchError):
        poller.parse_feed(b"\x00\x01 not xml at all")


PARSED = ParsedFeed(title="Vendor advisories", entries=[ParsedEntry(guid="1", title="One", summary="first")])


@pytest.mark.integration
def test_a_poll_stores_the_entries_and_its_validators(requests_mock, monkeypatch):
    monkeypatch.setattr(poller, "parse_feed", lambda body: PARSED)
    feed = make_feed(url=URL, baselined=False)
    requests_mock.get(URL, content=b"<rss/>", headers={"ETag": '"v1"', "Last-Modified": "Mon, 02 Nov 2026 10:00:00 GMT"})

    assert poll_feed(feed.id, service_config())

    feed = _feed(feed.id)
    assert feed.title == "Vendor advisories"
    assert (feed.etag, feed.last_modified) == ('"v1"', "Mon, 02 Nov 2026 10:00:00 GMT")
    assert feed.baselined_at is not None and feed.last_success_at is not None and feed.next_poll_at is not None
    assert [(entry.identity, entry.baseline) for entry in _entries()] == [("1", True)]

    # the next poll is conditional
    requests_mock.get(URL, status_code=304)
    assert poll_feed(feed.id, service_config())
    sent = requests_mock.last_request.headers
    assert sent["If-None-Match"] == '"v1"' and sent["If-Modified-Since"] == "Mon, 02 Nov 2026 10:00:00 GMT"
    assert len(_entries()) == 1


@pytest.mark.integration
@pytest.mark.parametrize("auth_type, expected", [("basic", "Basic dXNlcjpwYXNzd29yZA=="), ("header", "Bearer token")])
def test_a_poll_sends_the_decrypted_credentials(requests_mock, monkeypatch, auth_type, expected):
    monkeypatch.setattr(poller, "parse_feed", lambda body: PARSED)
    name, secret = ("user", "password") if auth_type == "basic" else ("Authorization", "Bearer token")
    feed = make_feed(url=URL, auth_type=auth_type, auth_name=name, auth_secret=encrypt_chunk(secret.encode()))
    requests_mock.get(URL, content=b"<rss/>")

    assert poll_feed(feed.id, service_config())
    assert requests_mock.last_request.headers["Authorization"] == expected


@pytest.mark.integration
@pytest.mark.parametrize("failure, message", [
    ({"exc": requests.exceptions.ConnectionError("refused")}, "refused"),
    ({"status_code": 404}, "HTTP 404"),
    ({"content": b"x" * 4096}, "larger than 1024 bytes"),
])
def test_a_failed_poll_is_logged_and_recorded(requests_mock, caplog, failure, message):
    feed = make_feed(url=URL)
    requests_mock.get(URL, **failure)
    config = service_config()
    config.max_feed_bytes = 1024

    with caplog.at_level(logging.WARNING):
        assert not poll_feed(feed.id, config)

    feed = _feed(feed.id)
    assert message in feed.last_error
    assert feed.last_failure_at is not None and feed.last_success_at is None and feed.next_poll_at is not None
    (record,) = [record for record in caplog.records if "unable to poll feed" in record.getMessage()]
    assert record.levelname == "WARNING" and record.feed_id == feed.id


@pytest.mark.integration
def test_a_bug_while_polling_is_an_error(requests_mock, monkeypatch, caplog):
    def broken(body):
        raise KeyError("oops")

    monkeypatch.setattr(poller, "parse_feed", broken)
    feed = make_feed(url=URL)
    requests_mock.get(URL, content=b"<rss/>")
    with caplog.at_level(logging.ERROR):
        assert not poll_feed(feed.id, service_config())
    assert any(record.levelname == "ERROR" and record.exc_info for record in caplog.records)
    assert "internal error" in _feed(feed.id).last_error


@pytest.mark.integration
def test_only_due_feeds_are_polled():
    due = make_feed(name="due")
    later = make_feed(name="later", url="https://other.example/feed")
    disabled = make_feed(name="disabled", url="https://third.example/feed", enabled=False)
    db = get_db()
    db.execute(text("UPDATE feeds SET next_poll_at = NOW() + INTERVAL 1 HOUR WHERE id = :id"), {"id": later.id})
    db.commit()
    assert poller.due_feeds() == [due.id]
    assert disabled.id not in poller.due_feeds()
