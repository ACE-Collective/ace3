import logging

from sqlalchemy import or_, select

from saq.configuration.config import get_config
from saq.database.model import Feed
from saq.database.pool import get_db, remove_all_sessions
from saq.feeds.entries import seconds_ago
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_FEED_STALE
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


def stale_feeds() -> list[dict]:
    """The enabled feeds with no successful poll for feeds.stale_after_minutes. A feed added less
    than that long ago counts from when it was added."""
    stale_after = get_config().feeds.stale_after_minutes * 60
    rows = get_db().execute(
        select(Feed)
        .where(Feed.enabled.is_(True), Feed.deleted_at.is_(None),
               or_(Feed.last_success_at < seconds_ago(stale_after),
                   Feed.last_success_at.is_(None) & (Feed.created_at < seconds_ago(stale_after))))
        .order_by(Feed.id)).scalars().all()
    return [{
        "feed_id": feed.id,
        "feed_name": feed.name,
        "feed_url": feed.url,
        "last_success_at": feed.last_success_at.isoformat() if feed.last_success_at else None,
        "last_failure_at": feed.last_failure_at.isoformat() if feed.last_failure_at else None,
        "last_error": feed.last_error,
    } for feed in rows]


class FeedMonitor(ACEThreadedMonitor):
    """Reports each feed that has gone feeds.stale_after_minutes without a successful poll, so a dead
    feed reaches the operator (docs/FEED_WATCHES.md). Feeds are shared, so like the other distributed
    monitors this is meant to run on one node."""

    def execute(self):
        try:
            for record in stale_feeds():
                logging.warning("feed %s (%s) has had no successful poll since %s: %s", record["feed_name"],
                                record["feed_url"], record["last_success_at"] or "it was added", record["last_error"],
                                extra={"feed_id": record["feed_id"], "feed_url": record["feed_url"]})
                emit_monitor(MONITOR_FEED_STALE, record)
        finally:
            remove_all_sessions()
