"""Feeds service for ACE API v2 (docs/FEED_WATCHES.md). Synchronous; the router runs each function
through run_db_in_thread."""

from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy import func, select

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import decode_cursor, encode_cursor
from aceapi_v2.feeds import schemas
from saq.configuration.config import get_config
from saq.crypto import encrypt_chunk
from saq.database.model import Feed, FeedEntry, User
from saq.database.pool import get_db
from saq.logging import log_audit

TEXT_MAX = 4000


def require_user(auth: ApiAuthResult) -> int:
    # a feed records who added it; a config API key belongs to nobody
    if auth.auth_user_id is None:
        raise HTTPException(status_code=422, detail="this action records who took it: it requires a user's API key or session")
    return auth.auth_user_id


def _check_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=422, detail="the feed url must be an http or https URL")
    return url


def _check_interval(seconds: Optional[int]) -> int:
    config = get_config().feeds
    if seconds is None:
        return config.default_poll_interval_seconds
    if seconds < config.min_poll_interval_seconds:
        raise HTTPException(status_code=422, detail=f"poll_interval_seconds must be at least {config.min_poll_interval_seconds}")
    return seconds


def _apply_auth(feed: Feed, auth_type: str, auth_name: Optional[str], auth_secret: Optional[str]) -> None:
    if auth_type == "none":
        feed.auth_type, feed.auth_name, feed.auth_secret = "none", None, None
        return
    if not (auth_name or "").strip():
        raise HTTPException(status_code=422, detail="basic auth needs a user, and a header its name")
    if auth_secret is None and (feed.auth_secret is None or feed.auth_type != auth_type):
        raise HTTPException(status_code=422, detail="auth_secret is required")
    feed.auth_type = auth_type
    feed.auth_name = auth_name.strip()
    if auth_secret is not None:
        feed.auth_secret = encrypt_chunk(auth_secret.encode("utf-8"))


def _to_schema(feed: Feed, username: Optional[str]) -> schemas.Feed:
    return schemas.Feed(
        id=feed.id, name=feed.name, url=feed.url, title=feed.title, poll_interval_seconds=feed.poll_interval_seconds,
        enabled=feed.enabled, auth_type=feed.auth_type, auth_name=feed.auth_name, has_secret=feed.auth_secret is not None,
        baselined_at=feed.baselined_at, last_poll_at=feed.last_poll_at, last_success_at=feed.last_success_at,
        last_failure_at=feed.last_failure_at, last_error=feed.last_error, next_poll_at=feed.next_poll_at,
        created_by=username, created_at=feed.created_at)


def _statement():
    return select(Feed, User.username).outerjoin(User, User.id == Feed.created_by_user_id).where(Feed.deleted_at.is_(None))


def _parse_id(payload: dict) -> int:
    (row_id,) = payload["k"]
    return int(row_id)


def list_feeds(cursor: Optional[str], limit: int) -> schemas.FeedPage:
    statement = _statement()
    if cursor is not None:
        statement = statement.where(Feed.id > decode_cursor(cursor, _parse_id))
    rows = get_db().execute(statement.order_by(Feed.id).limit(limit + 1)).all()
    next_cursor = encode_cursor(k=[rows[limit - 1][0].id]) if len(rows) > limit else None
    return schemas.FeedPage(data=[_to_schema(feed, username) for feed, username in rows[:limit]], next_cursor=next_cursor)


def _get(feed_id: int) -> tuple[Feed, Optional[str]]:
    row = get_db().execute(_statement().where(Feed.id == feed_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"feed {feed_id} does not exist")
    return row[0], row[1]


def get_feed(feed_id: int) -> schemas.Feed:
    return _to_schema(*_get(feed_id))


def create_feed(body: schemas.FeedRequest, auth: ApiAuthResult) -> schemas.Feed:
    user_id = require_user(auth)
    feed = Feed(name=body.name.strip(), url=_check_url(body.url), poll_interval_seconds=_check_interval(body.poll_interval_seconds),
                enabled=body.enabled, created_by_user_id=user_id, created_at=func.now())
    _apply_auth(feed, body.auth_type, body.auth_name, body.auth_secret)
    db = get_db()
    db.add(feed)
    db.commit()
    log_audit("added feed %s (%s)", feed.name, feed.url, auth=auth, feed_id=feed.id, feed_url=feed.url)
    return get_feed(feed.id)


def update_feed(feed_id: int, body: schemas.FeedUpdate, auth: ApiAuthResult) -> schemas.Feed:
    require_user(auth)
    feed, _ = _get(feed_id)
    if body.name is not None:
        feed.name = body.name.strip()
    if body.url is not None and body.url.strip() != feed.url:
        feed.url = _check_url(body.url)
        # the validators belong to the old url
        feed.etag = feed.last_modified = None
    if body.poll_interval_seconds is not None:
        feed.poll_interval_seconds = _check_interval(body.poll_interval_seconds)
    if body.enabled is not None:
        feed.enabled = body.enabled
    if body.auth_type is not None or body.auth_secret is not None or body.auth_name is not None:
        _apply_auth(feed, body.auth_type or feed.auth_type,
                    body.auth_name if body.auth_name is not None else feed.auth_name, body.auth_secret)
    # an edit takes effect on the next pass
    feed.next_poll_at = None
    get_db().commit()
    changed = sorted(key for key, value in body.model_dump(exclude_unset=True).items() if key != "auth_secret" or value)
    log_audit("changed feed %s: %s", feed.name, ", ".join(changed), auth=auth, feed_id=feed.id)
    return get_feed(feed.id)


def delete_feed(feed_id: int, auth: ApiAuthResult) -> None:
    """Stops the feed at once; service_feed_watch deletes its entries in batches, then the feed."""
    require_user(auth)
    feed, _ = _get(feed_id)
    feed.enabled = False
    feed.deleted_at = func.now()
    get_db().commit()
    log_audit("deleted feed %s (%s)", feed.name, feed.url, auth=auth, feed_id=feed.id)


def _entry(entry: FeedEntry) -> schemas.FeedEntry:
    text = entry.content or entry.summary or ""
    return schemas.FeedEntry(
        id=entry.id, feed_id=entry.feed_id, identity=entry.identity, title=entry.title, link=entry.link,
        published_at=entry.published_at, updated_at=entry.updated_at,
        categories=entry.categories.split("\n") if entry.categories else [], text=text[:TEXT_MAX],
        text_truncated=len(text) > TEXT_MAX, content_hash=entry.content_hash, baseline=entry.baseline,
        first_seen_at=entry.first_seen_at, last_seen_at=entry.last_seen_at)


def list_entries(feed_id: int, cursor: Optional[str], limit: int) -> schemas.FeedEntryPage:
    """The feed's entry versions, newest first."""
    _get(feed_id)
    statement = select(FeedEntry).where(FeedEntry.feed_id == feed_id)
    if cursor is not None:
        statement = statement.where(FeedEntry.id < decode_cursor(cursor, _parse_id))
    rows = get_db().execute(statement.order_by(FeedEntry.id.desc()).limit(limit + 1)).scalars().all()
    next_cursor = encode_cursor(k=[rows[limit - 1].id]) if len(rows) > limit else None
    return schemas.FeedEntryPage(data=[_entry(entry) for entry in rows[:limit]], next_cursor=next_cursor)
