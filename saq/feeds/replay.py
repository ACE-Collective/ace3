"""Running replays (docs/FEED_WATCHES.md, *Replay*), in service_feed_watch.

A replay is a draft rule and question an analyst pasted, queued by the API. The service runs the rule
over the entries of the chosen feeds first seen in the last feeds.replay_days days (the newest
feeds.replay_max_entries of them) and records each answer. For an entry the rule matched (or every
entry, without a rule) it asks the question through a replay decision keyed on (question, prompt,
entry, model), so the same draft replayed again reuses the answers it already has. The replay stays
running until none of its decisions is pending.
"""

import json
import logging
from typing import Callable

import yara
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.mysql import insert

from saq.configuration.config import get_config
from saq.database.model import FeedDecision, FeedEntry, FeedReplay, FeedReplayResult
from saq.database.pool import get_db
from saq.feeds.decisions import KIND_REPLAY, STATUS_PENDING, replay_cache_key
from saq.feeds.definitions import DefinitionSet
from saq.feeds.entries import days_ago, entry_fields
from saq.feeds.matching import RuleError, compile_rule, scan_entry

ERROR_MAX = 4000


def _fail(replay: FeedReplay, error: str) -> None:
    db = get_db()
    replay.state = "failed"
    replay.error = error[:ERROR_MAX]
    replay.finished_at = func.now()
    db.commit()
    logging.info("feed replay %s failed: %s", replay.id, error, extra={"feed_replay_id": replay.id})


def start_replay(replay: FeedReplay, definitions: DefinitionSet, model: str,
                 should_stop: Callable[[], bool] = lambda: False) -> None:
    """Scans the replay's entries and asks for its decisions; the replay is then running until they
    are answered."""
    db = get_db()
    replay.state = "running"
    db.commit()
    try:
        _scan(replay, definitions, model, should_stop)
    except Exception as e:
        # nothing else would touch a running replay with no entry count again
        db.rollback()
        logging.exception("feed replay %s failed: %s", replay.id, e, extra={"feed_replay_id": replay.id})
        _fail(replay, f"internal error: {e}")


def requeue_interrupted() -> int:
    """Queues again the replays a stopped or killed service left running before it had scanned them.
    Run when the service starts: only one runs, so none of them is still being scanned."""
    db = get_db()
    count = db.execute(update(FeedReplay).where(FeedReplay.state == "running", FeedReplay.entry_count.is_(None))
                       .values(state="queued")).rowcount
    db.commit()
    if count:
        logging.info("queued %d interrupted feed replays again", count)
    return count


def _scan(replay: FeedReplay, definitions: DefinitionSet, model: str, should_stop: Callable[[], bool]) -> None:
    db = get_db()
    config = get_config().feeds
    rules = None
    if replay.yara:
        try:
            rules = compile_rule(replay.yara)
        except RuleError as e:
            _fail(replay, f"the rule does not compile: {e}")
            return

    feed_ids = json.loads(replay.feed_ids)
    entries = db.execute(
        select(FeedEntry)
        .where(FeedEntry.feed_id.in_(feed_ids), FeedEntry.first_seen_at >= days_ago(config.replay_days))
        .order_by(FeedEntry.id.desc()).limit(config.replay_max_entries)).scalars().all()

    prompt = definitions.prompt_hash or ""
    results = []
    asked: dict[int, str] = {}
    for entry in entries:
        if should_stop():
            # it is queued again and starts over when the service does
            db.rollback()
            replay.state = "queued"
            db.commit()
            return

        result = {"replay_id": replay.id, "entry_id": entry.id}
        matched = None
        if rules is not None:
            try:
                scanned = scan_entry(rules, entry_fields(entry))
            except yara.Error as e:
                # the draft's rule timed out: the analyst's to fix, shown on the replay
                _fail(replay, f"the rule failed on entry {entry.id}: {e}")
                return
            matched = scanned.matched
            result.update(yara_matched=matched, yara_field=scanned.field, yara_excerpt=scanned.excerpt)
        if replay.question and matched is not False:
            asked[entry.id] = replay_cache_key(replay.question, prompt, entry.id, model)
        results.append(result)

    if asked:
        db.execute(insert(FeedDecision).prefix_with("IGNORE"), [
            dict(cache_key=key, kind=KIND_REPLAY, entry_id=entry_id, question=replay.question, model=model,
                 prompt_hash=prompt, status=STATUS_PENDING, attempts=0, created_at=func.now())
            for entry_id, key in asked.items()])
        ids = dict(db.execute(select(FeedDecision.cache_key, FeedDecision.id)
                              .where(FeedDecision.cache_key.in_(asked.values()))).all())
        for result in results:
            key = asked.get(result["entry_id"])
            if key is not None:
                result["decision_id"] = ids.get(key)

    if results:
        db.execute(insert(FeedReplayResult).prefix_with("IGNORE"), results)
    replay.entry_count = len(results)
    db.commit()
    logging.info("feed replay %s scanned %d entries and asks %d questions", replay.id, len(results), len(asked),
                 extra={"feed_replay_id": replay.id})


def finish_replays() -> int:
    """Marks done the running replays none of whose decisions is pending."""
    db = get_db()
    pending = (select(FeedReplayResult.id)
               .join(FeedDecision, FeedDecision.id == FeedReplayResult.decision_id)
               .where(FeedReplayResult.replay_id == FeedReplay.id, FeedDecision.status == STATUS_PENDING)
               .exists())
    finished = db.execute(update(FeedReplay)
                          .where(FeedReplay.state == "running", FeedReplay.entry_count.is_not(None), ~pending)
                          .values(state="done", finished_at=func.now())).rowcount
    db.commit()
    return finished


def run_replays(definitions: DefinitionSet, model: str, should_stop: Callable[[], bool] = lambda: False) -> int:
    """Starts the queued replays, oldest first, and finishes the answered ones."""
    db = get_db()
    started = 0
    for replay in db.execute(select(FeedReplay).where(FeedReplay.state == "queued")
                             .order_by(FeedReplay.id).limit(5)).scalars().all():
        if should_stop():
            break
        start_replay(replay, definitions, model, should_stop)
        started += 1
    finish_replays()
    return started


def prune_replays() -> int:
    """Deletes the replays older than feeds.replay_retention_days, one per transaction: each takes its
    results with it, at most feeds.replay_max_entries rows. Their decisions stay for the next replay of
    the same draft, until their entries expire."""
    db = get_db()
    total = 0
    while True:
        replay_id = db.execute(select(FeedReplay.id)
                               .where(FeedReplay.created_at < days_ago(get_config().feeds.replay_retention_days))
                               .order_by(FeedReplay.id).limit(1)).scalar()
        if replay_id is None:
            return total
        db.execute(delete(FeedReplay).where(FeedReplay.id == replay_id))
        db.commit()
        total += 1
