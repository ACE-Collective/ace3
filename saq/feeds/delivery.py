"""Delivering matches as alerts (docs/FEED_WATCHES.md, *Delivery*).

One alert per entry identity and queue: every watch that matched the entry for that queue is on the
same root. A match waits up to feeds.delivery_wait_seconds for the other delivering watches of its
queue to decide on the same version, so they arrive together.

The feed_deliveries row is what makes it once. It is written, with the decisions it delivers pointing
at it, before the root is staged, in one transaction: a second version of the entry finds it and is
ignored, and a crash before the root is staged leaves it pending, so the next pass stages it again
with the same root uuid. The root carries a submission key derived from the feed, the entry identity
and the queue, which the collector's DuplicateSubmissionFilter checks before it schedules anything.
"""

import logging
import os
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.submission_file_manager import SubmissionFileManager
from saq.configuration.config import get_config
from saq.constants import ALERT_TYPE_FEED_WATCH, ANALYSIS_MODE_CORRELATION
from saq.database.model import Feed, FeedDecision, FeedDelivery, FeedEntry, FeedWatch
from saq.database.pool import get_db
from saq.environment import get_global_runtime_settings
from saq.feeds.decisions import KIND_WATCH, STATUS_DECIDED, STATUS_PENDING, watch_version
from saq.feeds.entries import entry_text
from saq.feeds.llm import DECISION_MATCH

TOOL = "feed_watch"
DESCRIPTION_MAX = 1024
# the most of the entry's text the alert carries
ALERT_TEXT_MAX = 20000
CANDIDATE_LIMIT = 500


def submission_key(feed_id: int, identity_hash: str, queue: str) -> str:
    return f"feed_watch:{feed_id}:{identity_hash}:{queue}"


@dataclass
class Group:
    feed_id: int
    identity_hash: str
    queue: str
    decisions: list[FeedDecision] = field(default_factory=list)

    @property
    def entry_id(self) -> int:
        """The newest version that matched."""
        return max(decision.entry_id for decision in self.decisions)


def _live_matches():
    """Matches that a delivering watch made at the version it still has, not yet delivered."""
    return (select(FeedDecision, FeedEntry.feed_id, FeedEntry.identity_hash)
            .join(FeedEntry, FeedEntry.id == FeedDecision.entry_id)
            .join(FeedWatch, FeedWatch.id == FeedDecision.watch_id)
            .where(FeedDecision.kind == KIND_WATCH,
                   FeedDecision.deliver.is_(True),
                   FeedDecision.delivery_id.is_(None),
                   FeedDecision.status == STATUS_DECIDED,
                   FeedDecision.decision == DECISION_MATCH,
                   FeedWatch.enabled.is_(True),
                   FeedWatch.mode == "delivering",
                   FeedWatch.version == FeedDecision.watch_row_version,
                   FeedWatch.queue == FeedDecision.queue))


def ready_groups(wait_seconds: int) -> list[Group]:
    """The matches to deliver now, by entry identity and queue: those no delivering watch of the same
    queue is still deciding on, and those that waited wait_seconds."""
    db = get_db()
    groups: dict[tuple, Group] = {}
    for decision, feed_id, identity in db.execute(_live_matches().order_by(FeedDecision.id).limit(CANDIDATE_LIMIT)).all():
        key = (feed_id, identity, decision.queue)
        groups.setdefault(key, Group(feed_id, identity, decision.queue)).decisions.append(decision)

    if not groups:
        return []

    entry_ids = {decision.entry_id for group in groups.values() for decision in group.decisions}
    waiting = {(row.entry_id, row.queue) for row in db.execute(
        select(FeedDecision.entry_id, FeedDecision.queue)
        .where(FeedDecision.entry_id.in_(entry_ids), FeedDecision.kind == KIND_WATCH,
               FeedDecision.deliver.is_(True), FeedDecision.status == STATUS_PENDING)).all()}
    now = db.execute(select(func.now())).scalar()

    ready = []
    for group in groups.values():
        oldest = min(decision.created_at for decision in group.decisions)
        still_deciding = any((decision.entry_id, group.queue) in waiting for decision in group.decisions)
        if not still_deciding or (now - oldest).total_seconds() >= wait_seconds:
            ready.append(group)
    return ready


def claim(group: Group) -> Optional[FeedDelivery]:
    """Writes the delivery and points the group's decisions at it, in one transaction. Returns None when
    the entry already alerted to the queue: the decisions then point at that delivery, and this version
    is ignored."""
    db = get_db()
    delivery = FeedDelivery(feed_id=group.feed_id, identity_hash=group.identity_hash, queue=group.queue,
                            entry_id=group.entry_id, root_uuid=str(uuid.uuid4()),
                            submission_key=submission_key(group.feed_id, group.identity_hash, group.queue),
                            state="pending", created_at=func.now())
    ids = [decision.id for decision in group.decisions]
    try:
        db.add(delivery)
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.execute(select(FeedDelivery.id).where(
            FeedDelivery.feed_id == group.feed_id, FeedDelivery.identity_hash == group.identity_hash,
            FeedDelivery.queue == group.queue)).scalar_one()
        db.execute(update(FeedDecision).where(FeedDecision.id.in_(ids)).values(delivery_id=existing))
        db.commit()
        logging.info("feed entry %s already alerted to queue %s; the new matches are ignored", group.entry_id,
                     group.queue, extra={"feed_id": group.feed_id, "feed_entry_id": group.entry_id,
                                         "queue": group.queue, "feed_delivery_id": existing})
        return None

    db.execute(update(FeedDecision).where(FeedDecision.id.in_(ids)).values(delivery_id=delivery.id))
    db.commit()
    return delivery


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    return value.replace(tzinfo=timezone.utc) if value is not None else None


def build_root(delivery: FeedDelivery, staging_tmp_dir: str) -> RootAnalysis:
    """The alert of a delivery, built in staging_tmp_dir from what the database holds."""
    db = get_db()
    feed = db.get(Feed, delivery.feed_id)
    entry = db.get(FeedEntry, delivery.entry_id) if delivery.entry_id is not None else None
    if entry is None:
        raise ValueError(f"feed delivery {delivery.id} has no entry left to alert on")

    matches = []
    for decision, watch_name in db.execute(
            select(FeedDecision, FeedWatch.name).join(FeedWatch, FeedWatch.id == FeedDecision.watch_id)
            .where(FeedDecision.delivery_id == delivery.id).order_by(FeedDecision.id)).all():
        matches.append({
            "watch_id": decision.watch_id,
            "watch": watch_name,
            "watch_version": watch_version(decision.watch_row_version, decision.definition_hash),
            "definition": decision.definition_name,
            "definition_hash": decision.definition_hash,
            "feed_entry_id": decision.entry_id,
            "excerpt": decision.excerpt or decision.yara_excerpt,
            "excerpt_source": "llm" if decision.excerpt else "yara",
            "yara_field": decision.yara_field,
            "rationale": decision.rationale,
            "model": decision.response_model or decision.model or None,
            "prompt_hash": decision.prompt_hash or None,
        })

    publisher = feed.title or feed.name
    root_uuid = delivery.root_uuid
    storage_dir = os.path.join(staging_tmp_dir, root_uuid)
    if os.path.exists(storage_dir):
        # what a crashed attempt left half built
        shutil.rmtree(storage_dir)

    text = entry_text(entry)
    root = RootAnalysis(
        uuid=root_uuid,
        storage_dir=storage_dir,
        desc=f"{publisher}: {entry.title or entry.link or entry.identity}"[:DESCRIPTION_MAX],
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        tool=TOOL,
        tool_instance=get_global_runtime_settings().saq_node,
        alert_type=ALERT_TYPE_FEED_WATCH,
        event_time=_utc(entry.published_at or entry.updated_at),
        queue=delivery.queue,
        details={
            "feed": {"id": feed.id, "name": feed.name, "url": feed.url, "publisher": publisher},
            "entry": {
                "id": entry.id,
                "identity": entry.identity,
                "title": entry.title,
                "link": entry.link,
                "published_at": entry.published_at.isoformat() if entry.published_at else None,
                "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
                "content_hash": entry.content_hash,
                "categories": entry.categories.split("\n") if entry.categories else [],
                "text": text[:ALERT_TEXT_MAX],
                "text_truncated": len(text) > ALERT_TEXT_MAX,
            },
            "matches": matches,
        })
    root.initialize_storage()
    for match in matches:
        root.add_detection_point(f"feed watch {match['watch']} ({match['watch_version']}) matched")
    return root


def stage(delivery: FeedDelivery, file_manager: SubmissionFileManager) -> None:
    """Stages the delivery's root unless a crashed attempt already did, and marks it staged."""
    if not os.path.isdir(file_manager.get_staging_path(delivery.root_uuid)):
        root = build_root(delivery, file_manager.get_staging_tmp_dir())
        file_manager.stage_submission(Submission(root, key=delivery.submission_key))

    db = get_db()
    db.execute(update(FeedDelivery).where(FeedDelivery.id == delivery.id)
               .values(state="staged", staged_at=func.now()))
    db.commit()
    logging.info("feed watch alert %s staged for queue %s", delivery.root_uuid, delivery.queue,
                 extra={"root_uuid": delivery.root_uuid, "feed_delivery_id": delivery.id, "feed_id": delivery.feed_id,
                        "feed_entry_id": delivery.entry_id, "queue": delivery.queue})


def deliver(file_manager: SubmissionFileManager, should_stop: Callable[[], bool] = lambda: False) -> int:
    """Stages what a crashed pass left pending, then the matches that are ready. Returns how many roots
    it staged."""
    db = get_db()
    staged = 0
    for delivery in db.execute(select(FeedDelivery).where(FeedDelivery.state == "pending")
                               .order_by(FeedDelivery.id).limit(CANDIDATE_LIMIT)).scalars().all():
        if should_stop():
            return staged
        extra = {"feed_delivery_id": delivery.id, "root_uuid": delivery.root_uuid}
        logging.info("staging feed delivery %s again after an interrupted attempt", delivery.id, extra=extra)
        try:
            stage(delivery, file_manager)
            staged += 1
        except Exception as e:
            # it stays pending and is tried again on the next pass
            db.rollback()
            logging.exception("unable to stage feed delivery %s: %s", delivery.id, e, extra=extra)

    for group in ready_groups(get_config().feeds.delivery_wait_seconds):
        if should_stop():
            break
        delivery = claim(group)
        if delivery is None:
            continue
        try:
            stage(delivery, file_manager)
            staged += 1
        except Exception as e:
            # committed as pending, so the next pass stages it again
            db.rollback()
            logging.exception("unable to stage feed delivery %s: %s", delivery.id, e,
                              extra={"feed_delivery_id": delivery.id, "root_uuid": delivery.root_uuid})
    return staged
