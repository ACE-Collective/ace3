"""Decisions: what each watch makes of each new entry version, and asking the LLM the questions that
are pending (docs/FEED_WATCHES.md, *Decisions*).

evaluate_entries gives every enabled watch of a feed a decision row for each version the feed brought
that is not baseline: decided at once by the rule alone for a definition without a question (or whose
rule did not match), pending for one whose question must be asked. A version of an entry that already
alerted to a watch's queue gets no row for that watch: the update is ignored. classify_pending asks the
pending questions, replays' as well as watches', one row at a time.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.dialects.mysql import insert

from saq.database.model import FeedDecision, FeedDelivery, FeedEntry, FeedWatch, FeedWatchFeed
from saq.database.pool import get_db
from saq.error.reporting import log_loop_exception, log_peer_unavailable
from saq.feeds.definitions import Definition, DefinitionSet
from saq.feeds.entries import entry_fields, entry_text, seconds_from_now
from saq.feeds.llm import (
    DECISION_MATCH,
    DECISION_NO_MATCH,
    TEXT_MAX,
    LLMInvalidOutput,
    LLMRateLimited,
    LLMUnauthorized,
    LLMUnavailable,
    ask,
    entry_text as llm_entry_text,
)
from saq.feeds.service_config import FeedWatchServiceConfig

STATUS_PENDING = "pending"
STATUS_DECIDED = "decided"
STATUS_FAILED = "failed"

KIND_WATCH = "watch"
KIND_REPLAY = "replay"

# how long an invalid reply waits, times its attempt, before it is asked again
INVALID_RETRY_SECONDS = 60

# a 429 without a Retry-After pauses this long (within retry_after_cap_seconds)
DEFAULT_RATE_LIMIT_SECONDS = 60

EVALUATE_BATCH = 200


def cache_key(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def watch_cache_key(entry_id: int, watch: FeedWatch, definition: Definition, model: str, prompt: str) -> str:
    return cache_key(KIND_WATCH, entry_id, watch.id, watch.version, definition.content_hash, model, prompt)


def replay_cache_key(question: str, prompt: str, entry_id: int, model: str) -> str:
    return cache_key(KIND_REPLAY, question, prompt, entry_id, model)


def watch_version(row_version: Optional[int], definition_hash: Optional[str]) -> str:
    """How a watch version is shown: the row's version and the definition's content hash."""
    return f"v{row_version}:{(definition_hash or '')[:12]}"


class ScanError(Exception):
    """A definition's rule failed on an entry (it timed out): the definition's to fix, not a bug. Raised
    by Matcher.scan, which wraps yara's error so this module, which the API imports, never loads yara."""


@dataclass
class Matcher:
    """What evaluate_entries needs of the definitions: which are usable and a way to run each rule.
    scan(definition, fields) returns (matched, field, excerpt) and raises ScanError for a scan that
    failed."""
    definitions: DefinitionSet
    usable: set[str]
    scan: Callable[[Definition, dict[str, str]], tuple[bool, Optional[str], Optional[str]]]
    model: str = ""


def _decision_row(entry: FeedEntry, watch: FeedWatch, definition: Definition, matcher: Matcher,
                  fields: dict[str, str], scans: dict) -> dict:
    prompt = matcher.definitions.prompt_hash or ""
    row = dict(kind=KIND_WATCH, entry_id=entry.id, watch_id=watch.id, watch_row_version=watch.version,
               definition_name=definition.name, definition_hash=definition.content_hash,
               deliver=watch.mode == "delivering", queue=watch.queue, created_at=func.now(), model="",
               prompt_hash="", attempts=0)

    matched = None
    if definition.yara:
        if definition.name not in scans:
            extra = {"definition": definition.name, "feed_entry_id": entry.id}
            try:
                scans[definition.name] = matcher.scan(definition, fields)
            except ScanError as e:
                logging.warning("the rule of feed watch definition %s failed on entry %s: %s", definition.name,
                                entry.id, e, extra=extra)
                scans[definition.name] = e
            except Exception as e:
                # a bug in the scan, not the rule: the decision still fails, so the batch goes on
                logging.error("unable to run the rule of feed watch definition %s on entry %s: %s", definition.name,
                              entry.id, e, exc_info=e, extra=extra)
                scans[definition.name] = e
        scanned = scans[definition.name]
        if isinstance(scanned, Exception):
            row.update(status=STATUS_FAILED, last_error=f"the rule failed: {scanned}"[:TEXT_MAX], decided_at=func.now())
            row["cache_key"] = watch_cache_key(entry.id, watch, definition, "", "")
            return row
        matched, field_name, excerpt = scanned
        row.update(yara_matched=matched, yara_field=field_name, yara_excerpt=excerpt)

    if definition.question:
        # a version the rule turned away is decided without asking, under the same configuration as
        # the versions asked, so the evaluation scores them together
        row.update(question=definition.question, model=matcher.model, prompt_hash=prompt)
        row["cache_key"] = watch_cache_key(entry.id, watch, definition, matcher.model, prompt)
        if matched is False:
            row.update(status=STATUS_DECIDED, decision=DECISION_NO_MATCH, decided_at=func.now())
        else:
            row.update(status=STATUS_PENDING)
    else:
        row.update(status=STATUS_DECIDED, decision=DECISION_MATCH if matched else DECISION_NO_MATCH,
                   decided_at=func.now())
        row["cache_key"] = watch_cache_key(entry.id, watch, definition, "", "")
    return row


def evaluate_entries(matcher: Matcher, should_stop: Callable[[], bool] = lambda: False) -> int:
    """Gives the next versions waiting for evaluation their decision rows, and marks them evaluated.
    Returns how many versions it evaluated."""
    db = get_db()
    entries = db.execute(select(FeedEntry).where(FeedEntry.evaluated_at.is_(None))
                         .order_by(FeedEntry.id).limit(EVALUATE_BATCH)).scalars().all()
    if not entries:
        return 0

    feed_ids = {entry.feed_id for entry in entries}
    watches: dict[int, list[FeedWatch]] = {}
    for watch, feed_id in db.execute(
            select(FeedWatch, FeedWatchFeed.feed_id).join(FeedWatchFeed, FeedWatchFeed.watch_id == FeedWatch.id)
            .where(FeedWatchFeed.feed_id.in_(feed_ids), FeedWatch.enabled.is_(True))).all():
        watches.setdefault(feed_id, []).append(watch)

    delivered = {(row.feed_id, row.identity_hash, row.queue) for row in db.execute(
        select(FeedDelivery.feed_id, FeedDelivery.identity_hash, FeedDelivery.queue)
        .where(FeedDelivery.feed_id.in_(feed_ids),
               FeedDelivery.identity_hash.in_({entry.identity_hash for entry in entries}))).all()}

    rows = []
    done = []
    for entry in entries:
        if should_stop():
            break
        fields = entry_fields(entry)
        scans: dict = {}
        for watch in watches.get(entry.feed_id, []):
            if (entry.feed_id, entry.identity_hash, watch.queue) in delivered:
                # an update of an entry that already alerted to this queue is ignored
                continue
            definition = matcher.definitions.definitions.get(watch.definition_name)
            if definition is None or watch.definition_name not in matcher.usable:
                # flagged on the watch in the GUI; it matches nothing
                continue
            rows.append(_decision_row(entry, watch, definition, matcher, fields, scans))
        done.append(entry.id)

    if rows:
        db.execute(insert(FeedDecision).prefix_with("IGNORE"), rows)
    if done:
        db.execute(update(FeedEntry).where(FeedEntry.id.in_(done)).values(evaluated_at=func.now()))
    db.commit()
    logging.info("evaluated %d feed entry versions: %d decisions", len(done), len(rows))
    return len(done)


@dataclass
class ClassifierState:
    """What the classifier remembers between passes, in this process only."""
    # the configuration a 401 or 403 came with: nothing is asked until it changes
    refused_fingerprint: Optional[str] = None
    # a 429 pauses classification until this time.monotonic()
    paused_until: float = 0.0
    prompt_missing_logged: bool = False


def config_fingerprint(config) -> str:
    return hashlib.sha256(json.dumps(config.model_dump(), sort_keys=True, default=str).encode()).hexdigest()


def _fail(row: FeedDecision, error: str) -> None:
    row.status = STATUS_FAILED
    row.last_error = error[:TEXT_MAX]
    row.decided_at = func.now()


def classify_pending(config: FeedWatchServiceConfig, definitions: DefinitionSet, state: ClassifierState,
                     should_stop: Callable[[], bool] = lambda: False) -> int:
    """Asks the pending questions, a batch at a time, watches' before replays'. Returns how many it
    answered or failed."""
    llm = config.llm
    if llm is None:
        return 0

    fingerprint = config_fingerprint(llm)
    if state.refused_fingerprint == fingerprint or time.monotonic() < state.paused_until:
        return 0

    db = get_db()
    rows = db.execute(
        select(FeedDecision)
        .where(FeedDecision.status == STATUS_PENDING,
               or_(FeedDecision.next_attempt_at.is_(None), FeedDecision.next_attempt_at <= func.now()))
        .order_by(case((FeedDecision.kind == KIND_WATCH, 0), else_=1), FeedDecision.id)
        .limit(llm.batch_size)).scalars().all()
    if not rows:
        return 0

    if definitions.prompt is None:
        if not state.prompt_missing_logged:
            logging.error("feed watch decisions are pending, but the definitions repository has no system prompt "
                          "(system_prompt.md): no question is asked until it does")
            state.prompt_missing_logged = True
        return 0
    state.prompt_missing_logged = False

    handled = 0
    for row in rows:
        if should_stop():
            break

        extra = {"feed_decision_id": row.id, "feed_entry_id": row.entry_id, "feed_watch_id": row.watch_id,
                 "definition": row.definition_name, "llm_model": llm.model}
        if row.kind == KIND_WATCH:
            # an entry is evaluated once, so a watch's question is asked under the model and prompt
            # configured now, which the row then records, rather than failed and its alert lost
            row.model = llm.model
            row.prompt_hash = definitions.prompt_hash
        elif (row.model and row.model != llm.model) or (row.prompt_hash and row.prompt_hash != definitions.prompt_hash):
            # a replay's answer is found again by its (question, prompt, entry, model) key, which an
            # answer under another configuration would make wrong; the analyst replays the draft again
            changed = "the configured model" if row.model and row.model != llm.model else "the system prompt"
            _fail(row, f"{changed} changed before the question was asked")
            db.commit()
            logging.warning("feed replay decision %s failed: %s changed", row.id, changed, extra=extra)
            handled += 1
            continue

        entry = db.get(FeedEntry, row.entry_id)
        sent = llm_entry_text(entry.title, entry_text(entry), llm.max_entry_chars)
        # no transaction stays open while the endpoint answers
        db.commit()
        try:
            answer = ask(llm, definitions.prompt, row.question, sent)
        except LLMInvalidOutput as e:
            row.attempts += 1
            row.last_error = str(e)[:TEXT_MAX]
            row.truncated = sent.truncated
            if row.attempts >= llm.max_attempts:
                _fail(row, f"no valid reply after {row.attempts} attempts: {e}")
                db.commit()
                logging.error("feed decision %s failed after %d attempts: %s", row.id, row.attempts, e, exc_info=e,
                              extra=extra)
            else:
                row.next_attempt_at = seconds_from_now(INVALID_RETRY_SECONDS * row.attempts)
                db.commit()
                logging.warning("feed decision %s got an invalid reply (attempt %d): %s", row.id, row.attempts, e,
                                extra=extra)
            handled += 1
            continue
        except LLMUnavailable as e:
            db.rollback()
            if not log_peer_unavailable(e, "feed watch llm endpoint", extra=extra):
                if e.__cause__ is None:
                    # a 5xx: the endpoint is up and says it can't answer
                    logging.warning("feed watch llm endpoint failed: %s", e, extra=extra)
                else:
                    # a certificate that does not verify, say: nothing is asked until an operator fixes
                    # the configuration
                    log_loop_exception(e, "feed watch llm endpoint failed", extra=extra)
            return handled
        except LLMRateLimited as e:
            db.rollback()
            pause = min(e.retry_after if e.retry_after is not None else DEFAULT_RATE_LIMIT_SECONDS,
                        llm.retry_after_cap_seconds)
            state.paused_until = time.monotonic() + pause
            logging.warning("feed watch llm endpoint is rate limiting: pausing %.0fs", pause, extra=extra)
            return handled
        except LLMUnauthorized as e:
            db.rollback()
            state.refused_fingerprint = fingerprint
            logging.error("the feed watch llm endpoint refused the configured credentials (%s): no question is asked "
                          "until service_feed_watch.llm changes", e, exc_info=e, extra=extra)
            return handled

        row.status = STATUS_DECIDED
        row.decision = answer.decision
        row.excerpt = answer.excerpt
        row.rationale = answer.rationale
        row.response_model = answer.response_model
        row.prompt_tokens = answer.prompt_tokens
        row.completion_tokens = answer.completion_tokens
        row.latency_ms = answer.latency_ms
        row.truncated = sent.truncated
        row.attempts += 1
        row.model = llm.model
        row.prompt_hash = definitions.prompt_hash
        row.last_error = None
        row.decided_at = func.now()
        db.commit()
        handled += 1

    return handled
