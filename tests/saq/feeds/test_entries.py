"""Entry identity, versions, storage and expiry (docs/FEED_WATCHES.md, *Entries*)."""

from datetime import datetime

import pytest
from sqlalchemy import func, select, text

from saq.configuration.config import get_config
from saq.database.model import Feed, FeedDecision, FeedDelivery, FeedEntry
from saq.database.pool import get_db
from saq.feeds.entries import (
    ParsedEntry,
    ParsedFeed,
    content_hash,
    entry_identity,
    mark_current_entries_seen,
    normalize_text,
    prune_entries,
    store_entries,
)
from tests.saq.feeds.conftest import make_entry, make_feed


@pytest.mark.unit
def test_identity_is_the_guid_then_the_link_then_a_hash():
    assert entry_identity(ParsedEntry(guid=" urn:advisory:1 ", link="https://a/1", title="t")) == "urn:advisory:1"
    assert entry_identity(ParsedEntry(guid="  ", link="https://a/1", title="t")) == "https://a/1"
    hashed = entry_identity(ParsedEntry(title="Only a title"))
    assert hashed.startswith("sha256:")
    assert hashed == entry_identity(ParsedEntry(title="Only a title"))
    assert hashed != entry_identity(ParsedEntry(title="Another title"))


@pytest.mark.unit
def test_content_hash_ignores_the_entry_timestamps():
    first = ParsedEntry(guid="1", title="t", summary="s", published_at=datetime(2026, 1, 1))
    bumped = ParsedEntry(guid="1", title="t", summary="s", published_at=datetime(2026, 2, 1), updated_at=datetime(2026, 2, 1))
    edited = ParsedEntry(guid="1", title="t", summary="s, now exploited")
    assert content_hash(first) == content_hash(bumped)
    assert content_hash(first) != content_hash(edited)


@pytest.mark.unit
def test_normalize_text_folds_unicode_and_whitespace():
    assert normalize_text("CVE‑2026  1234\n\tis exploited") == normalize_text("CVE‑2026 1234 is exploited")
    assert normalize_text("ｆｕｌｌｗｉｄｔｈ") == "fullwidth"


def _now() -> datetime:
    return get_db().execute(select(func.now())).scalar()


def _versions(feed_id: int) -> list[FeedEntry]:
    db = get_db()
    db.expire_all()
    return db.execute(select(FeedEntry).where(FeedEntry.feed_id == feed_id).order_by(FeedEntry.id)).scalars().all()


@pytest.mark.integration
def test_first_poll_is_a_baseline_and_an_edit_is_a_new_version():
    feed = make_feed(baselined=False)
    parsed = ParsedFeed(entries=[ParsedEntry(guid="1", title="Advisory", summary="a flaw"),
                                 ParsedEntry(guid="2", title="Other", summary="other")])

    first = store_entries(feed.id, parsed, baseline=True, now=_now())
    get_db().commit()
    assert (first.new, first.seen) == (2, 0)
    rows = _versions(feed.id)
    assert all(row.baseline and row.evaluated_at is not None for row in rows)

    again = store_entries(feed.id, parsed, baseline=False, now=_now())
    get_db().commit()
    assert (again.new, again.seen) == (0, 2)

    edited = ParsedFeed(entries=[ParsedEntry(guid="1", title="Advisory", summary="a flaw, now actively exploited"),
                                 ParsedEntry(guid="2", title="Other", summary="other")])
    third = store_entries(feed.id, edited, baseline=False, now=_now())
    get_db().commit()
    assert (third.new, third.seen) == (1, 1)
    rows = _versions(feed.id)
    assert len(rows) == 3
    assert rows[2].identity == "1" and rows[2].identity_hash == rows[0].identity_hash
    assert not rows[2].baseline and rows[2].evaluated_at is None


@pytest.mark.integration
def test_a_304_keeps_what_the_last_response_carried_from_expiring():
    feed = make_feed()
    old = make_entry(feed, identity="gone")
    current = make_entry(feed, identity="current")
    db = get_db()
    db.execute(text("UPDATE feed_entries SET last_seen_at = NOW() - INTERVAL 10 DAY WHERE id = :id"), {"id": old.id})
    db.execute(text("UPDATE feed_entries SET last_seen_at = NOW() - INTERVAL 2 DAY WHERE id = :id"), {"id": current.id})
    db.execute(text("UPDATE feeds SET last_content_at = NOW() - INTERVAL 3 DAY WHERE id = :id"), {"id": feed.id})
    db.commit()
    db.expire_all()

    assert mark_current_entries_seen(db.get(Feed, feed.id), _now()) == 1
    db.commit()
    ages = dict(db.execute(text("SELECT identity, TIMESTAMPDIFF(DAY, last_seen_at, NOW()) FROM feed_entries")).all())
    assert ages == {"gone": 10, "current": 0}


@pytest.mark.integration
def test_prune_deletes_expired_versions_and_deleted_feeds(monkeypatch):
    monkeypatch.setattr(get_config().feeds, "entry_retention_days", 90)
    monkeypatch.setattr(get_config().feeds, "prune_batch_size", 1)
    feed = make_feed()
    expired = make_entry(feed, identity="expired")
    kept = make_entry(feed, identity="kept")
    deleted_feed = make_feed(name="deleted", url="https://other.example/feed")
    make_entry(deleted_feed, identity="a")
    make_entry(deleted_feed, identity="b")
    db = get_db()
    db.add(FeedDecision(cache_key="k" * 64, kind="replay", entry_id=expired.id, status="pending", created_at=datetime.now()))
    db.execute(text("UPDATE feed_entries SET last_seen_at = NOW() - INTERVAL 91 DAY WHERE id = :id"), {"id": expired.id})
    db.execute(text("UPDATE feeds SET deleted_at = NOW() WHERE id = :id"), {"id": deleted_feed.id})
    db.commit()
    kept_id, deleted_id = kept.id, deleted_feed.id

    assert prune_entries() == 3
    db.expire_all()
    assert [row.id for row in db.execute(select(FeedEntry)).scalars()] == [kept_id]
    assert db.get(Feed, deleted_id) is None
    assert db.execute(select(FeedDecision)).first() is None


@pytest.mark.integration
def test_prune_keeps_a_delivery_while_its_entry_has_a_version_left(monkeypatch):
    feed = make_feed()
    entry = make_entry(feed, identity="alerted")
    db = get_db()
    for identity_hash, root in ((entry.identity_hash, "a"), ("f" * 64, "b")):
        db.add(FeedDelivery(feed_id=feed.id, identity_hash=identity_hash, queue="default", root_uuid=root * 36,
                            submission_key="k", state="staged"))
    db.commit()
    db.execute(text("UPDATE feed_deliveries SET created_at = NOW() - INTERVAL 200 DAY"))
    db.commit()

    prune_entries()
    db.expire_all()
    assert [row.identity_hash for row in db.execute(select(FeedDelivery)).scalars()] == [entry.identity_hash]
