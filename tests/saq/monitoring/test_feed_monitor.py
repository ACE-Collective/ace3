"""The stale feed monitor (docs/FEED_WATCHES.md, *Polling*)."""

import logging

import pytest
from sqlalchemy import text

from saq.database.pool import get_db
from saq.monitoring.monitors import feed_monitor
from saq.monitoring.monitors.feed_monitor import FeedMonitor
from tests.saq.feeds.conftest import make_feed


@pytest.mark.integration
def test_feeds_without_a_recent_success_are_reported(monkeypatch, caplog):
    dead = make_feed(name="dead", url="https://dead.example/feed", last_error="HTTP 500")
    healthy = make_feed(name="healthy", url="https://healthy.example/feed")
    new = make_feed(name="new", url="https://new.example/feed")
    never = make_feed(name="never", url="https://never.example/feed")
    disabled = make_feed(name="disabled", url="https://disabled.example/feed", enabled=False)
    db = get_db()
    db.execute(text("UPDATE feeds SET last_success_at = NOW() - INTERVAL 2 DAY WHERE id IN (:a, :b)"), {"a": dead.id, "b": disabled.id})
    db.execute(text("UPDATE feeds SET last_success_at = NOW() WHERE id = :id"), {"id": healthy.id})
    db.execute(text("UPDATE feeds SET created_at = NOW() - INTERVAL 2 DAY WHERE id = :id"), {"id": never.id})
    db.commit()
    new_id = new.id
    emitted = []
    monkeypatch.setattr(feed_monitor, "emit_monitor", lambda monitor, value: emitted.append((monitor.path, value)))

    with caplog.at_level(logging.WARNING):
        FeedMonitor("feeds", 300).execute()

    assert [(path, value["feed_name"]) for path, value in emitted] == [("feeds.stale", "dead"), ("feeds.stale", "never")]
    assert emitted[0][1]["last_error"] == "HTTP 500"
    assert new_id not in [value["feed_id"] for _, value in emitted]
    assert sum("has had no successful poll" in record.getMessage() for record in caplog.records) == 2
