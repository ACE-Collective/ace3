"""Feed entries: what one parsed entry is, how it is identified, and how a poll stores it
(docs/FEED_WATCHES.md, *Entries*)."""

import hashlib
import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select, text, update

from saq.configuration.config import get_config
from saq.database.model import Feed, FeedDelivery, FeedEntry
from saq.database.pool import get_db

# the matchable fields of an entry, in the order a rule is run over them; a rule sees which one it
# is scanning in the external variable `field`
ENTRY_FIELDS = ("title", "summary", "content", "categories")

TITLE_MAX = 1024
URL_MAX = 2048

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class ParsedEntry:
    """One entry as the feed supplied it, its HTML already stripped to text."""
    guid: Optional[str] = None
    link: Optional[str] = None
    title: Optional[str] = None
    summary: Optional[str] = None
    content: Optional[str] = None
    categories: tuple[str, ...] = ()
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass(frozen=True)
class ParsedFeed:
    title: Optional[str] = None
    entries: list[ParsedEntry] = field(default_factory=list)


def normalize_text(value: Optional[str]) -> str:
    """NFKC with every run of whitespace made one space: what an excerpt is compared after."""
    if not value:
        return ""
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", value)).strip()


def entry_identity(entry: ParsedEntry) -> str:
    """The guid (RSS) or id (Atom), else the link, else a hash of the title and link."""
    if entry.guid and entry.guid.strip():
        return entry.guid.strip()
    if entry.link and entry.link.strip():
        return entry.link.strip()
    digest = hashlib.sha256(f"{entry.title or ''}\n{entry.link or ''}".encode("utf-8", "replace")).hexdigest()
    return f"sha256:{digest}"


def identity_hash(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()


def content_hash(entry: ParsedEntry) -> str:
    """Changes exactly when the text the feed supplied does; the entry's timestamps are left out, so
    a feed that only bumps them makes no new version."""
    canonical = json.dumps([entry.title, entry.link, entry.summary, entry.content, list(entry.categories)],
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def entry_fields(entry: FeedEntry) -> dict[str, str]:
    """The matchable fields of a stored entry version."""
    return {
        "title": entry.title or "",
        "summary": entry.summary or "",
        "content": entry.content or "",
        "categories": entry.categories or "",
    }


def entry_text(entry: FeedEntry) -> str:
    """The entry's text, without the title: its content, else its summary."""
    return entry.content or entry.summary or ""


def _cut(value: Optional[str], length: int) -> Optional[str]:
    return value[:length] if value else value


@dataclass
class StoreResult:
    new: int = 0
    seen: int = 0


def store_entries(feed_id: int, parsed: ParsedFeed, baseline: bool, now: datetime) -> StoreResult:
    """Stores the entries of one successful poll in the caller's transaction (the caller commits).
    A version already stored is only marked seen; a new one is added, and is evaluated later unless
    this is the feed's first poll (baseline), whose entries are only for preview. now is the poll's
    time by the database's clock, which the caller also writes to feed.last_content_at."""
    result = StoreResult()
    versions: dict[tuple[str, str], tuple[str, ParsedEntry]] = {}
    for entry in parsed.entries:
        identity = entry_identity(entry)
        versions.setdefault((identity_hash(identity), content_hash(entry)), (identity, entry))

    if not versions:
        return result

    db = get_db()
    existing = {
        (row.identity_hash, row.content_hash): row.id
        for row in db.execute(
            select(FeedEntry.id, FeedEntry.identity_hash, FeedEntry.content_hash)
            .where(FeedEntry.feed_id == feed_id,
                   FeedEntry.identity_hash.in_({key[0] for key in versions}))).all()}

    seen_ids = [existing[key] for key in versions if key in existing]
    if seen_ids:
        db.execute(update(FeedEntry).where(FeedEntry.id.in_(seen_ids)).values(last_seen_at=now))
        result.seen = len(seen_ids)

    for key, (identity, entry) in versions.items():
        if key in existing:
            continue

        db.add(FeedEntry(
            feed_id=feed_id,
            identity=identity[:URL_MAX],
            identity_hash=key[0],
            content_hash=key[1],
            title=_cut(entry.title, TITLE_MAX),
            link=_cut(entry.link, URL_MAX),
            published_at=entry.published_at,
            updated_at=entry.updated_at,
            summary=entry.summary,
            content=entry.content,
            categories="\n".join(entry.categories) or None,
            baseline=baseline,
            first_seen_at=now,
            last_seen_at=now,
            evaluated_at=func.now() if baseline else None,
        ))
        result.new += 1

    return result


def mark_current_entries_seen(feed: Feed, now: datetime) -> int:
    """A 304 says the feed still carries what its last 200 did: every version that response carried
    (seen at or after feed.last_content_at) is seen again, so it does not expire while the feed is
    unchanged. In the caller's transaction. The comparison holds only while a poll writes one time,
    now, to both last_seen_at and feed.last_content_at: two NOW()s can fall in different seconds."""
    if feed.last_content_at is None:
        return 0
    return get_db().execute(
        update(FeedEntry)
        .where(FeedEntry.feed_id == feed.id, FeedEntry.last_seen_at >= feed.last_content_at)
        .values(last_seen_at=now)).rowcount


def _delete_batches(statement_ids, delete_statement, batch_size: int, what: str, extra: dict) -> int:
    """Deletes the rows statement_ids selects, batch_size at a time, one transaction each."""
    db = get_db()
    total = 0
    while True:
        ids = db.execute(statement_ids.limit(batch_size)).scalars().all()
        if not ids:
            return total
        db.execute(delete_statement(ids))
        db.commit()
        total += len(ids)
        logging.debug("deleted %d %s", len(ids), what, extra=extra)


def prune_entries(should_stop=lambda: False) -> int:
    """Deletes the entry versions not seen for feeds.entry_retention_days, and the deleted feeds'
    entries and then the feeds, in primary-key batches. Their decisions, labels and replay results go
    with them (ON DELETE CASCADE, a handful of rows per version)."""
    config = get_config().feeds
    db = get_db()
    total = 0

    expired = (select(FeedEntry.id)
               .where(FeedEntry.last_seen_at < days_ago(config.entry_retention_days))
               .order_by(FeedEntry.id))
    total += _delete_batches(expired, lambda ids: delete(FeedEntry).where(FeedEntry.id.in_(ids)),
                             config.prune_batch_size, "expired feed entries", {})

    for feed_id in db.execute(select(Feed.id).where(Feed.deleted_at.is_not(None))).scalars().all():
        if should_stop():
            break
        of_feed = select(FeedEntry.id).where(FeedEntry.feed_id == feed_id).order_by(FeedEntry.id)
        total += _delete_batches(of_feed, lambda ids: delete(FeedEntry).where(FeedEntry.id.in_(ids)),
                                 config.prune_batch_size, "entries of a deleted feed", {"feed_id": feed_id})
        deliveries = select(FeedDelivery.id).where(FeedDelivery.feed_id == feed_id).order_by(FeedDelivery.id)
        _delete_batches(deliveries, lambda ids: delete(FeedDelivery).where(FeedDelivery.id.in_(ids)),
                        config.prune_batch_size, "deliveries of a deleted feed", {"feed_id": feed_id})
        db.execute(delete(Feed).where(Feed.id == feed_id))
        db.commit()
        logging.info("removed deleted feed %s", feed_id, extra={"feed_id": feed_id})

    # a delivery outlives its version so a later version of an entry that alerted is still ignored;
    # once no version of the entry is left, nothing can be ignored any more
    orphaned = (select(FeedDelivery.id)
                .where(FeedDelivery.created_at < days_ago(config.entry_retention_days),
                       ~select(FeedEntry.id).where(FeedEntry.feed_id == FeedDelivery.feed_id,
                                                   FeedEntry.identity_hash == FeedDelivery.identity_hash).exists())
                .order_by(FeedDelivery.id))
    _delete_batches(orphaned, lambda ids: delete(FeedDelivery).where(FeedDelivery.id.in_(ids)),
                    config.prune_batch_size, "feed deliveries of expired entries", {})
    return total


def days_ago(days: int):
    """NOW() less days, computed by the database."""
    return func.date_sub(func.now(), text(f"INTERVAL {int(days)} DAY"))


def seconds_ago(seconds: int):
    return func.date_sub(func.now(), text(f"INTERVAL {int(seconds)} SECOND"))


def seconds_from_now(seconds: int):
    return func.date_add(func.now(), text(f"INTERVAL {int(seconds)} SECOND"))
