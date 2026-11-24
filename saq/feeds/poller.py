"""Polling feeds (docs/FEED_WATCHES.md, *Polling*). Only service_feed_watch imports this module: it is
the only one that imports feedparser.

Each feed is fetched once per poll_interval_seconds however many watches read it, with a conditional
request (If-None-Match, If-Modified-Since). A fetch that fails is logged at WARNING and recorded on the
feed (last_failure_at, last_error), which the GUI shows and the feed monitor reports once the feed has
gone feeds.stale_after_minutes without a success."""

import calendar
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup
from sqlalchemy import func, or_, select

from saq.crypto import decrypt_chunk
from saq.database.model import Feed
from saq.database.pool import get_db
from saq.feeds.entries import ParsedEntry, ParsedFeed, mark_current_entries_seen, seconds_from_now, store_entries
from saq.feeds.service_config import FeedWatchServiceConfig
from saq.proxy import proxies

# the most of an error kept on the feed row
ERROR_MAX = 2000

USER_AGENT = "ACE feed watch"


class FeedFetchError(Exception):
    """The feed could not be fetched or parsed; the message is recorded on the feed."""


@dataclass(frozen=True)
class FetchResult:
    not_modified: bool
    body: bytes = b""
    etag: Optional[str] = None
    last_modified: Optional[str] = None


def html_to_text(value: Optional[str]) -> Optional[str]:
    """The text of an HTML fragment, its whitespace collapsed to what a reader would see."""
    if not value:
        return None
    text = BeautifulSoup(value, "html.parser").get_text(" ")
    text = " ".join(text.split())
    return text or None


def _time(value) -> Optional[datetime]:
    """feedparser's parsed times are UTC struct_time."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(calendar.timegm(value), tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, ValueError, TypeError):
        # a feed with a nonsense date: the entry is kept without it
        return None


def parse_feed(body: bytes) -> ParsedFeed:
    """Parses an RSS or Atom document. Raises FeedFetchError for one that is not a feed."""
    # imported here: only this service parses feeds (docs/IMPORTS.md), and the module stays importable
    # where feedparser is not installed
    import feedparser

    parsed = feedparser.parse(body)
    if parsed.get("bozo") and not parsed.get("entries") and not parsed.get("feed"):
        raise FeedFetchError(f"not an RSS or Atom feed: {parsed.get('bozo_exception')}")

    entries = []
    for item in parsed.get("entries", []):
        content = None
        if item.get("content"):
            content = "\n".join(part.get("value", "") for part in item["content"] if part.get("value"))

        entries.append(ParsedEntry(
            guid=item.get("id") or item.get("guid"),
            link=item.get("link"),
            title=html_to_text(item.get("title")),
            summary=html_to_text(item.get("summary")),
            content=html_to_text(content),
            categories=tuple(tag["term"] for tag in item.get("tags", []) if tag.get("term")),
            published_at=_time(item.get("published_parsed")),
            updated_at=_time(item.get("updated_parsed")),
        ))

    return ParsedFeed(title=html_to_text(parsed.get("feed", {}).get("title")), entries=entries)


def _auth(feed: Feed) -> tuple[Optional[tuple[str, str]], dict[str, str]]:
    if feed.auth_type == "none" or not feed.auth_secret:
        return None, {}
    secret = decrypt_chunk(feed.auth_secret).decode("utf-8")
    if feed.auth_type == "basic":
        return (feed.auth_name or "", secret), {}
    return None, {feed.auth_name: secret}


def _shut_down(fileno: int) -> None:
    """Shuts down the connection whose socket is fileno, so a read blocked on it returns at once."""
    # a duplicate of the descriptor: closing it leaves the response's own socket for the response to close
    sock = socket.socket(fileno=os.dup(fileno))
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        # the peer closed it already: the read it would have ended has ended
        pass
    finally:
        sock.close()


def fetch_feed(feed: Feed, config: FeedWatchServiceConfig) -> FetchResult:
    """One conditional GET of the feed, its body capped at max_feed_bytes and cut off once the fetch
    has run fetch_deadline_seconds (connecting and the headers are bounded by the timeouts). Raises FeedFetchError for an HTTP error, a body that is too large or a
    fetch past its deadline, and requests' exceptions for a fetch that failed."""
    deadline = time.monotonic() + config.fetch_deadline_seconds
    auth, headers = _auth(feed)
    headers = {"User-Agent": USER_AGENT, **headers}
    if feed.etag:
        headers["If-None-Match"] = feed.etag
    if feed.last_modified:
        headers["If-Modified-Since"] = feed.last_modified

    with requests.get(feed.url, headers=headers, auth=auth, proxies=proxies(config.fetch_proxy), stream=True,
                      timeout=(config.fetch_connect_timeout_seconds, config.fetch_read_timeout_seconds)) as response:
        if response.status_code == 304:
            return FetchResult(not_modified=True)
        if response.status_code >= 400:
            raise FeedFetchError(f"HTTP {response.status_code}")

        # the read timeout bounds each read, not the body: a server sending a byte at a time would
        # keep this loop, and with it the whole feed loop, going for as long as it liked
        try:
            fileno = response.raw.fileno()
        except OSError:
            # no socket under it (a response read from memory): nothing to wait on
            fileno = None
        expired = threading.Event()
        # held while the connection is shut down, and taken before the response closes its socket, so
        # the descriptor is never another socket's by the time it is shut down
        finished = threading.Lock()
        done = False

        def expire():
            with finished:
                if done:
                    return
                expired.set()
                if fileno is not None:
                    _shut_down(fileno)

        watchdog = threading.Timer(max(0.0, deadline - time.monotonic()), expire)
        watchdog.daemon = True
        watchdog.start()
        body = bytearray()
        try:
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > config.max_feed_bytes:
                    raise FeedFetchError(f"the response is larger than {config.max_feed_bytes} bytes")
        except Exception as e:
            if expired.is_set():
                raise FeedFetchError(f"the response took longer than {config.fetch_deadline_seconds:g}s") from e
            raise
        finally:
            with finished:
                done = True
            watchdog.cancel()
        if expired.is_set():
            # a body without a length simply ends when its connection is shut down
            raise FeedFetchError(f"the response took longer than {config.fetch_deadline_seconds:g}s")

        return FetchResult(not_modified=False, body=bytes(body), etag=response.headers.get("ETag"),
                           last_modified=response.headers.get("Last-Modified"))


def due_feeds() -> list[int]:
    """The feeds whose next poll is due, by the database's clock."""
    return get_db().execute(
        select(Feed.id)
        .where(Feed.enabled.is_(True), Feed.deleted_at.is_(None),
               or_(Feed.next_poll_at.is_(None), Feed.next_poll_at <= func.now()))
        .order_by(Feed.next_poll_at, Feed.id)).scalars().all()


def poll_feed(feed_id: int, config: FeedWatchServiceConfig) -> bool:
    """Polls one feed and stores what it carries. Returns whether the poll succeeded; a failure is
    logged at WARNING and recorded on the feed, and the next poll is scheduled either way."""
    db = get_db()
    feed = db.get(Feed, feed_id)
    if feed is None or feed.deleted_at is not None or not feed.enabled:
        return False

    extra = {"feed_id": feed.id, "feed_name": feed.name, "feed_url": feed.url}
    feed.last_poll_at = func.now()
    feed.next_poll_at = seconds_from_now(feed.poll_interval_seconds)
    # the next poll is scheduled whatever happens to this one, and no transaction stays open while
    # the feed answers
    db.commit()
    try:
        fetched = fetch_feed(feed, config)
        # one time for every row this poll writes (mark_current_entries_seen)
        now = db.execute(select(func.now())).scalar()
        if fetched.not_modified:
            seen = mark_current_entries_seen(feed, now)
            feed.last_content_at = now
            result_text = f"not modified ({seen} entries still current)"
        else:
            parsed = parse_feed(fetched.body)
            baseline = feed.baselined_at is None
            stored = store_entries(feed.id, parsed, baseline=baseline, now=now)
            feed.title = (parsed.title or feed.title or "")[:512] or None
            feed.etag = (fetched.etag or "")[:512] or None
            feed.last_modified = (fetched.last_modified or "")[:128] or None
            feed.last_content_at = now
            if baseline:
                feed.baselined_at = func.now()
            result_text = f"{stored.new} new versions, {stored.seen} already stored" + (" (first poll: preview only)" if baseline else "")

        feed.last_success_at = func.now()
        db.commit()
        logging.info("polled feed %s: %s", feed.name, result_text, extra=extra)
        return True
    except (requests.RequestException, FeedFetchError) as e:
        error = str(e)
        logging.warning("unable to poll feed %s (%s): %s", feed.name, feed.url, error, extra=extra)
    except Exception as e:
        # anything else is a bug here, not a feed that is down
        logging.exception("unable to poll feed %s (%s): %s", feed.name, feed.url, e, extra=extra)
        error = f"internal error: {e}"

    db.rollback()
    feed = db.get(Feed, feed_id)
    if feed is not None:
        feed.last_poll_at = func.now()
        feed.next_poll_at = seconds_from_now(feed.poll_interval_seconds)
        feed.last_failure_at = func.now()
        feed.last_error = error[:ERROR_MAX]
        db.commit()
    return False
