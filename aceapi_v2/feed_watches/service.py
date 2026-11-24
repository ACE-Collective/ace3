"""Feed watches service for ACE API v2 (docs/FEED_WATCHES.md). Synchronous; the router runs each
function through run_db_in_thread. Every list is keyset paged and built with one query per kind of
row, never one per watch."""

import json
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import and_, case, delete, func, select, true
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import InvalidListingRequest, decode_cursor, encode_cursor
from aceapi_v2.feed_watches import schemas
from aceapi_v2.feeds.service import require_user
from saq.database.model import (
    Feed,
    FeedDecision,
    FeedDefinition,
    FeedDelivery,
    FeedEntry,
    FeedLabel,
    FeedReplay,
    FeedReplayResult,
    FeedWatch,
    FeedWatchFeed,
    User,
)
from saq.database.pool import get_db
from saq.feeds.decisions import STATUS_FAILED, STATUS_PENDING, watch_version
from saq.feeds.evaluation import evaluate_watch
from saq.feeds.llm import DECISION_MATCH
from saq.logging import log_audit

TEXT_MAX = 2000


def _parse_id(payload: dict) -> int:
    (row_id,) = payload["k"]
    return int(row_id)


def _page(rows: list, limit: int, key) -> tuple[list, Optional[str]]:
    if len(rows) > limit:
        return rows[:limit], encode_cursor(k=[key(rows[limit - 1])])
    return rows, None


#
# definitions
#

def _definition(row: FeedDefinition) -> schemas.Definition:
    return schemas.Definition(name=row.name, repository=row.repository, path=row.path, commit=row.commit,
                              content_hash=row.content_hash, yara=row.yara, question=row.question,
                              present=row.present, error=row.error, usable=is_usable(row))


def is_usable(row: Optional[FeedDefinition]) -> bool:
    # a name defined twice keeps its first definition, which the error then only notes
    return row is not None and row.present and (row.error is None or row.error.startswith("also defined in"))


def list_definitions(cursor: Optional[str], limit: int) -> schemas.DefinitionPage:
    statement = select(FeedDefinition)
    if cursor is not None:
        statement = statement.where(FeedDefinition.id > decode_cursor(cursor, _parse_id))
    rows = get_db().execute(statement.order_by(FeedDefinition.id).limit(limit + 1)).scalars().all()
    rows, next_cursor = _page(rows, limit, lambda row: row.id)
    return schemas.DefinitionPage(data=[_definition(row) for row in rows], next_cursor=next_cursor)


#
# watches
#

def _watches(watch_rows: list) -> list[schemas.Watch]:
    """The API view of (watch, created_by, updated_by) rows, with three queries for all of them."""
    db = get_db()
    ids = [row[0].id for row in watch_rows]
    feeds: dict[int, list[schemas.FeedRef]] = {}
    definitions = {}
    counts: dict[int, dict[str, int]] = {}
    if ids:
        for watch_id, feed_id, name in db.execute(
                select(FeedWatchFeed.watch_id, Feed.id, Feed.name).join(Feed, Feed.id == FeedWatchFeed.feed_id)
                .where(FeedWatchFeed.watch_id.in_(ids), Feed.deleted_at.is_(None)).order_by(Feed.id)).all():
            feeds.setdefault(watch_id, []).append(schemas.FeedRef(id=feed_id, name=name))
        names = {row[0].definition_name for row in watch_rows}
        definitions = {row.name: row for row in db.execute(
            select(FeedDefinition).where(FeedDefinition.name.in_(names))).scalars().all()}
        for watch_id, status, count in db.execute(
                select(FeedDecision.watch_id, FeedDecision.status, func.count())
                .where(FeedDecision.watch_id.in_(ids), FeedDecision.status.in_((STATUS_PENDING, STATUS_FAILED)))
                .group_by(FeedDecision.watch_id, FeedDecision.status)).all():
            counts.setdefault(watch_id, {})[status] = count

    result = []
    for watch, created_by, updated_by in watch_rows:
        definition = definitions.get(watch.definition_name)
        flag = None
        if definition is None or not definition.present:
            flag = f"definition {watch.definition_name} is missing from the definitions repositories"
        elif not is_usable(definition):
            flag = f"definition {watch.definition_name} can't be used: {definition.error}"
        warning = schemas.QUESTION_ONLY_WARNING if definition is not None and definition.question and not definition.yara else None
        result.append(schemas.Watch(
            id=watch.id, name=watch.name, definition_name=watch.definition_name,
            definition=_definition(definition) if definition is not None else None, flag=flag, warning=warning,
            queue=watch.queue, mode=watch.mode, enabled=watch.enabled, version=watch.version,
            watch_version=watch_version(watch.version, definition.content_hash if definition else None),
            feeds=feeds.get(watch.id, []),
            pending_decisions=counts.get(watch.id, {}).get(STATUS_PENDING, 0),
            failed_decisions=counts.get(watch.id, {}).get(STATUS_FAILED, 0),
            created_by=created_by, created_at=watch.created_at, updated_by=updated_by, updated_at=watch.updated_at))
    return result


def _watch_statement():
    creator, updater = aliased(User), aliased(User)
    return (select(FeedWatch, creator.username, updater.username)
            .outerjoin(creator, creator.id == FeedWatch.created_by_user_id)
            .outerjoin(updater, updater.id == FeedWatch.updated_by_user_id))


def list_watches(cursor: Optional[str], limit: int) -> schemas.WatchPage:
    statement = _watch_statement()
    if cursor is not None:
        statement = statement.where(FeedWatch.id > decode_cursor(cursor, _parse_id))
    rows = get_db().execute(statement.order_by(FeedWatch.id).limit(limit + 1)).all()
    rows, next_cursor = _page(rows, limit, lambda row: row[0].id)
    return schemas.WatchPage(data=_watches(rows), next_cursor=next_cursor)


def get_watch(watch_id: int) -> schemas.Watch:
    row = get_db().execute(_watch_statement().where(FeedWatch.id == watch_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"feed watch {watch_id} does not exist")
    return _watches([row])[0]


def _check_feeds(feed_ids: list[int]) -> list[int]:
    feed_ids = sorted(set(feed_ids))
    found = set(get_db().execute(select(Feed.id).where(Feed.id.in_(feed_ids), Feed.deleted_at.is_(None))).scalars().all())
    missing = [feed_id for feed_id in feed_ids if feed_id not in found]
    if missing:
        raise HTTPException(status_code=422, detail=f"no such feeds: {', '.join(map(str, missing))}")
    return feed_ids


def _check_definition(name: str) -> str:
    name = name.strip()
    if get_db().execute(select(FeedDefinition.id).where(FeedDefinition.name == name, FeedDefinition.present.is_(True))).scalar() is None:
        raise HTTPException(status_code=422, detail=f"definition {name} is not in the definitions repositories")
    return name


def _set_feeds(watch_id: int, feed_ids: list[int]) -> None:
    db = get_db()
    db.execute(delete(FeedWatchFeed).where(FeedWatchFeed.watch_id == watch_id))
    db.add_all(FeedWatchFeed(watch_id=watch_id, feed_id=feed_id) for feed_id in feed_ids)


def create_watch(body: schemas.WatchRequest, auth: ApiAuthResult) -> schemas.Watch:
    user_id = require_user(auth)
    db = get_db()
    watch = FeedWatch(name=body.name.strip(), definition_name=_check_definition(body.definition_name),
                      queue=body.queue.strip(), mode=body.mode, enabled=body.enabled, version=1,
                      created_by_user_id=user_id, updated_by_user_id=user_id,
                      created_at=func.now(), updated_at=func.now())
    feed_ids = _check_feeds(body.feed_ids)
    try:
        db.add(watch)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"a feed watch is already named {body.name.strip()}") from None
    _set_feeds(watch.id, feed_ids)
    db.commit()
    log_audit("created feed watch %s (%s, %s to queue %s)", watch.name, watch.definition_name, watch.mode, watch.queue,
              auth=auth, feed_watch_id=watch.id, feed_ids=feed_ids)
    return get_watch(watch.id)


def update_watch(watch_id: int, body: schemas.WatchUpdate, auth: ApiAuthResult) -> schemas.Watch:
    """Every edit is a new version of the watch."""
    user_id = require_user(auth)
    db = get_db()
    watch = db.get(FeedWatch, watch_id)
    if watch is None:
        raise HTTPException(status_code=404, detail=f"feed watch {watch_id} does not exist")

    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        return get_watch(watch_id)
    if body.name is not None:
        watch.name = body.name.strip()
    if body.definition_name is not None:
        watch.definition_name = _check_definition(body.definition_name)
    if body.queue is not None:
        watch.queue = body.queue.strip()
    if body.mode is not None:
        watch.mode = body.mode
    if body.enabled is not None:
        watch.enabled = body.enabled
    if body.feed_ids is not None:
        _set_feeds(watch.id, _check_feeds(body.feed_ids))
    watch.version = FeedWatch.version + 1
    watch.updated_by_user_id = user_id
    watch.updated_at = func.now()
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"a feed watch is already named {body.name}") from None
    log_audit("changed feed watch %s: %s", watch.name, ", ".join(sorted(changes)), auth=auth, feed_watch_id=watch.id,
              changes={key: value for key, value in changes.items()})
    return get_watch(watch_id)


#
# decisions
#

def _entry_ref(entry: FeedEntry) -> schemas.EntryRef:
    return schemas.EntryRef(id=entry.id, feed_id=entry.feed_id, title=entry.title, link=entry.link,
                            published_at=entry.published_at, first_seen_at=entry.first_seen_at)


def list_decisions(status: Optional[str], watch_id: Optional[int], cursor: Optional[str], limit: int) -> schemas.DecisionPage:
    """Decisions newest first; status failed is what the operator looks at."""
    statement = (select(FeedDecision, FeedEntry, FeedDelivery.root_uuid)
                 .join(FeedEntry, FeedEntry.id == FeedDecision.entry_id)
                 .outerjoin(FeedDelivery, FeedDelivery.id == FeedDecision.delivery_id))
    if status is not None:
        if status not in ("pending", "decided", "failed"):
            raise InvalidListingRequest("status must be pending, decided or failed")
        statement = statement.where(FeedDecision.status == status)
    if watch_id is not None:
        statement = statement.where(FeedDecision.watch_id == watch_id)
    if cursor is not None:
        statement = statement.where(FeedDecision.id < decode_cursor(cursor, _parse_id))
    rows = get_db().execute(statement.order_by(FeedDecision.id.desc()).limit(limit + 1)).all()
    rows, next_cursor = _page(rows, limit, lambda row: row[0].id)
    data = []
    for decision, entry, root_uuid in rows:
        data.append(schemas.Decision(
            id=decision.id, kind=decision.kind, entry=_entry_ref(entry), watch_id=decision.watch_id,
            watch_version=watch_version(decision.watch_row_version, decision.definition_hash) if decision.watch_id else None,
            definition_name=decision.definition_name, status=decision.status, decision=decision.decision,
            excerpt=decision.excerpt, rationale=decision.rationale, yara_matched=decision.yara_matched,
            yara_excerpt=decision.yara_excerpt, yara_field=decision.yara_field, attempts=decision.attempts,
            last_error=decision.last_error, model=decision.model, response_model=decision.response_model,
            prompt_hash=decision.prompt_hash, prompt_tokens=decision.prompt_tokens,
            completion_tokens=decision.completion_tokens, latency_ms=decision.latency_ms, truncated=decision.truncated,
            alert_uuid=root_uuid, created_at=decision.created_at, decided_at=decision.decided_at))
    return schemas.DecisionPage(data=data, next_cursor=next_cursor)


#
# replays
#

def create_replay(body: schemas.ReplayRequest, auth: ApiAuthResult) -> schemas.Replay:
    user_id = require_user(auth)
    yara_source = (body.yara or "").strip() or None
    question = (body.question or "").strip() or None
    if not yara_source and not question:
        raise HTTPException(status_code=422, detail="a replay needs a yara rule, a question, or both")
    if body.watch_id is not None and get_db().get(FeedWatch, body.watch_id) is None:
        raise HTTPException(status_code=422, detail=f"feed watch {body.watch_id} does not exist")

    db = get_db()
    replay = FeedReplay(yara=yara_source, question=question, feed_ids=json.dumps(_check_feeds(body.feed_ids)),
                        watch_id=body.watch_id, state="queued", created_by_user_id=user_id, created_at=func.now())
    db.add(replay)
    db.commit()
    log_audit("queued feed replay %s", replay.id, auth=auth, feed_replay_id=replay.id)
    return get_replay(replay.id)


def get_replay(replay_id: int) -> schemas.Replay:
    db = get_db()
    row = db.execute(select(FeedReplay, User.username).outerjoin(User, User.id == FeedReplay.created_by_user_id)
                     .where(FeedReplay.id == replay_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"feed replay {replay_id} does not exist")
    replay, username = row

    counts = db.execute(
        select(func.count(FeedReplayResult.id),
               func.coalesce(func.sum(case((FeedReplayResult.yara_matched.is_(True), 1), else_=0)), 0),
               func.count(FeedDecision.id),
               func.coalesce(func.sum(case((FeedDecision.status == "pending", 1), else_=0)), 0),
               func.coalesce(func.sum(case((FeedDecision.status == "failed", 1), else_=0)), 0),
               func.coalesce(func.sum(case((FeedDecision.decision == "match", 1), else_=0)), 0),
               func.coalesce(func.sum(case((FeedDecision.decision == "no_match", 1), else_=0)), 0),
               func.coalesce(func.sum(case((FeedDecision.decision == "insufficient_evidence", 1), else_=0)), 0))
        .select_from(FeedReplayResult)
        .outerjoin(FeedDecision, FeedDecision.id == FeedReplayResult.decision_id)
        .where(FeedReplayResult.replay_id == replay_id)).one()
    return schemas.Replay(
        id=replay.id, state=replay.state, error=replay.error, yara=replay.yara, question=replay.question,
        feed_ids=json.loads(replay.feed_ids), watch_id=replay.watch_id,
        warning=schemas.QUESTION_ONLY_WARNING if replay.question and not replay.yara else None,
        counts=schemas.ReplayCounts(entries=counts[0], rule_matched=counts[1], asked=counts[2], pending=counts[3],
                                    failed=counts[4], match=counts[5], no_match=counts[6],
                                    insufficient_evidence=counts[7]),
        created_by=username, created_at=replay.created_at, finished_at=replay.finished_at)


def _matched(replay: FeedReplay, result: FeedReplayResult, decision: Optional[FeedDecision]) -> Optional[bool]:
    if replay.yara and result.yara_matched is False:
        return False
    if not replay.question:
        return bool(result.yara_matched)
    if decision is None or decision.status == STATUS_PENDING:
        return None
    return decision.decision == DECISION_MATCH


def list_replay_results(replay_id: int, outcome: Optional[str], cursor: Optional[str], limit: int) -> schemas.ReplayResultPage:
    """The replay's entries, newest first. outcome: match (the draft would alert) or miss."""
    db = get_db()
    replay = db.get(FeedReplay, replay_id)
    if replay is None:
        raise HTTPException(status_code=404, detail=f"feed replay {replay_id} does not exist")

    statement = (select(FeedReplayResult, FeedEntry, FeedDecision, FeedLabel.label)
                 .join(FeedEntry, FeedEntry.id == FeedReplayResult.entry_id)
                 .outerjoin(FeedDecision, FeedDecision.id == FeedReplayResult.decision_id)
                 .outerjoin(FeedLabel, (FeedLabel.entry_id == FeedReplayResult.entry_id) & (FeedLabel.watch_id == replay.watch_id))
                 .where(FeedReplayResult.replay_id == replay_id))
    if outcome is not None:
        matched = and_(FeedReplayResult.yara_matched.is_(True) if replay.yara else true(),
                       FeedDecision.decision == DECISION_MATCH if replay.question else true())
        if outcome == "match":
            statement = statement.where(matched)
        elif outcome == "miss":
            statement = statement.where(~matched)
        else:
            raise InvalidListingRequest("outcome must be match or miss")
    if cursor is not None:
        statement = statement.where(FeedReplayResult.entry_id < decode_cursor(cursor, _parse_id))
    rows = db.execute(statement.order_by(FeedReplayResult.entry_id.desc()).limit(limit + 1)).all()
    rows, next_cursor = _page(rows, limit, lambda row: row[0].entry_id)

    data = []
    for result, entry, decision, label in rows:
        text = entry.content or entry.summary or ""
        data.append(schemas.ReplayResult(
            entry=_entry_ref(entry), text=text[:TEXT_MAX], yara_matched=result.yara_matched,
            yara_excerpt=result.yara_excerpt, yara_field=result.yara_field,
            status=decision.status if decision else None, decision=decision.decision if decision else None,
            excerpt=decision.excerpt if decision else None, rationale=decision.rationale if decision else None,
            last_error=decision.last_error if decision else None, matched=_matched(replay, result, decision),
            label=label))
    return schemas.ReplayResultPage(data=data, next_cursor=next_cursor)


#
# labels and evaluation
#

def set_label(watch_id: int, entry_id: int, label: str, auth: ApiAuthResult) -> None:
    user_id = require_user(auth)
    db = get_db()
    if db.get(FeedWatch, watch_id) is None:
        raise HTTPException(status_code=404, detail=f"feed watch {watch_id} does not exist")
    if db.get(FeedEntry, entry_id) is None:
        raise HTTPException(status_code=404, detail=f"feed entry {entry_id} does not exist")
    db.execute(mysql_insert(FeedLabel)
               .values(watch_id=watch_id, entry_id=entry_id, label=label, user_id=user_id, updated_at=func.now())
               .on_duplicate_key_update(label=label, user_id=user_id, updated_at=func.now()))
    db.commit()
    log_audit("labeled feed entry %s %s for feed watch %s", entry_id, label, watch_id, auth=auth,
              feed_watch_id=watch_id, feed_entry_id=entry_id, label=label)


def remove_label(watch_id: int, entry_id: int, auth: ApiAuthResult) -> None:
    require_user(auth)
    db = get_db()
    if db.execute(delete(FeedLabel).where(FeedLabel.watch_id == watch_id, FeedLabel.entry_id == entry_id)).rowcount == 0:
        raise HTTPException(status_code=404, detail="the entry has no label for the watch")
    db.commit()
    log_audit("removed the label of feed entry %s for feed watch %s", entry_id, watch_id, auth=auth,
              feed_watch_id=watch_id, feed_entry_id=entry_id)


def get_evaluation(watch_id: int) -> schemas.Evaluation:
    if get_db().get(FeedWatch, watch_id) is None:
        raise HTTPException(status_code=404, detail=f"feed watch {watch_id} does not exist")
    return schemas.Evaluation.model_validate(evaluate_watch(watch_id).to_dict())
