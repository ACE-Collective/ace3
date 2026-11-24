"""Delivering matches as alerts, once per entry and queue (docs/FEED_WATCHES.md, *Delivery*)."""

import logging
import os

import pytest
from sqlalchemy import delete, func, select, text

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import CollectorService
from saq.configuration.config import get_config
from saq.constants import ALERT_TYPE_FEED_WATCH, ANALYSIS_MODE_CORRELATION
from saq.database.model import FeedDecision, FeedDelivery, FeedEntry, IncomingWorkload
from saq.database.pool import get_db
from saq.feeds import delivery
from saq.feeds.delivery import deliver, submission_key
from saq.feeds.service import FeedWatchCollector
from tests.saq.feeds.conftest import make_entry, make_feed, make_watch, service_config


def _decision(entry, watch, status="decided", decision="match", **fields) -> FeedDecision:
    db = get_db()
    row = FeedDecision(cache_key=os.urandom(32).hex(), kind="watch", entry_id=entry.id, watch_id=watch.id,
                       watch_row_version=watch.version, definition_name=watch.definition_name,
                       definition_hash="d" * 64, status=status, decision=decision if status == "decided" else None,
                       deliver=watch.mode == "delivering", queue=watch.queue, created_at=func.now(), **fields)
    db.add(row)
    db.commit()
    return row


def _crash(*args, **kwargs):
    raise RuntimeError("disk full")


@pytest.fixture
def collector_service() -> CollectorService:
    collector = FeedWatchCollector()
    service = CollectorService(collector, config=service_config())
    collector.file_manager = service.file_manager
    return service


def _staged(collector_service) -> list[RootAnalysis]:
    roots = []
    for root_uuid in collector_service.file_manager.list_staged_submissions():
        root = RootAnalysis(storage_dir=collector_service.file_manager.get_staging_path(root_uuid))
        root.load()
        roots.append(root)
    return roots


@pytest.mark.integration
def test_watches_that_match_an_entry_for_one_queue_make_one_alert(collector_service):
    feed = make_feed(title="Vendor Security Advisories")
    entry = make_entry(feed, identity="urn:adv:1", title="Widget Server flaw exploited", content="It is actively exploited.")
    first = make_watch(feed, "exploited", name="exploitation")
    second = make_watch(feed, "widget", name="widget products")
    other_queue = make_watch(feed, "exploited", name="intel copy", queue="intel")
    shadow = make_watch(feed, "exploited", name="shadow", mode="shadow")
    _decision(entry, first, yara_excerpt="It is actively exploited.", yara_field="content")
    _decision(entry, second, excerpt="Widget Server flaw exploited", rationale="the title says so",
              model="gemma", response_model="gemma-served")
    _decision(entry, other_queue)
    _decision(entry, shadow)

    assert deliver(collector_service.file_manager) == 2

    roots = {root.queue: root for root in _staged(collector_service)}
    assert set(roots) == {"default", "intel"}
    root = roots["default"]
    assert root.alert_type == ALERT_TYPE_FEED_WATCH
    assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
    assert root.description == "Vendor Security Advisories: Widget Server flaw exploited"
    assert root.submission_key == submission_key(feed.id, entry.identity_hash, "default")
    assert root.details["feed"]["publisher"] == "Vendor Security Advisories"
    assert root.details["entry"]["link"] == "https://vendor.example/urn:adv:1"
    matches = {match["watch"]: match for match in root.details["matches"]}
    assert set(matches) == {"exploitation", "widget products"}
    assert matches["exploitation"]["excerpt"] == "It is actively exploited."
    assert matches["exploitation"]["excerpt_source"] == "yara"
    assert matches["widget products"]["excerpt_source"] == "llm"
    assert matches["widget products"]["model"] == "gemma-served"
    assert matches["exploitation"]["watch_version"] == "v1:dddddddddddd"
    assert len(root.all_detection_points) == 2

    rows = get_db().execute(select(FeedDelivery)).scalars().all()
    assert {(row.queue, row.state) for row in rows} == {("default", "staged"), ("intel", "staged")}
    # the shadow watch delivered nothing
    assert get_db().execute(select(FeedDecision.delivery_id).where(FeedDecision.watch_id == shadow.id)).scalar() is None
    assert deliver(collector_service.file_manager) == 0


@pytest.mark.integration
def test_a_match_waits_for_the_other_watches_of_its_queue(collector_service, monkeypatch):
    monkeypatch.setattr(get_config().feeds, "delivery_wait_seconds", 600)
    feed = make_feed()
    entry = make_entry(feed)
    decided = make_watch(feed, "a")
    asking = make_watch(feed, "b")
    _decision(entry, decided)
    _decision(entry, asking, status="pending")

    assert deliver(collector_service.file_manager) == 0

    # it waited long enough
    get_db().execute(text("UPDATE feed_decisions SET created_at = NOW() - INTERVAL 601 SECOND"))
    get_db().commit()
    assert deliver(collector_service.file_manager) == 1


@pytest.mark.integration
def test_a_match_is_delivered_to_its_queue_after_the_watch_is_edited(collector_service):
    feed = make_feed()
    entry = make_entry(feed)
    watch = make_watch(feed, "a")
    _decision(entry, watch)
    # what saving the watch's form does, whatever it changed
    get_db().execute(text("UPDATE feed_watches SET version = 2, name = 'renamed', queue = 'intel'"))
    get_db().commit()
    assert deliver(collector_service.file_manager) == 1
    assert [root.queue for root in _staged(collector_service)] == ["default"]


@pytest.mark.integration
@pytest.mark.parametrize("change", ["mode = 'shadow'", "enabled = 0"])
def test_a_watch_switched_off_since_it_decided_delivers_nothing(collector_service, change):
    feed = make_feed()
    entry = make_entry(feed)
    _decision(entry, make_watch(feed, "a"))
    get_db().execute(text(f"UPDATE feed_watches SET version = 2, {change}"))
    get_db().commit()
    assert deliver(collector_service.file_manager) == 0


@pytest.mark.integration
def test_a_second_match_of_an_alerted_entry_is_ignored(collector_service):
    feed = make_feed()
    entry = make_entry(feed)
    watch = make_watch(feed, "a")
    _decision(entry, watch)
    deliver(collector_service.file_manager)

    update = make_entry(feed, identity=entry.identity, content="edited", content_hash="e" * 64)
    late = _decision(update, watch)
    assert deliver(collector_service.file_manager) == 0
    existing = get_db().execute(select(FeedDelivery.id)).scalar_one()
    get_db().expire_all()
    assert get_db().get(FeedDecision, late.id).delivery_id == existing
    assert len(_staged(collector_service)) == 1


@pytest.mark.integration
def test_a_delivery_interrupted_before_staging_is_staged_again(collector_service, monkeypatch, caplog):
    feed = make_feed()
    entry = make_entry(feed)
    _decision(entry, make_watch(feed, "a"))

    def crash(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(delivery, "build_root", crash)
    with caplog.at_level(logging.ERROR):
        assert deliver(collector_service.file_manager) == 0
    row = get_db().execute(select(FeedDelivery)).scalar_one()
    assert row.state == "pending"
    root_uuid = row.root_uuid
    (record,) = [record for record in caplog.records if record.levelname == "ERROR"]
    assert record.exc_info and record.feed_delivery_id == row.id and record.root_uuid == root_uuid

    monkeypatch.undo()
    assert deliver(collector_service.file_manager) == 1
    assert [root.uuid for root in _staged(collector_service)] == [root_uuid]


@pytest.mark.integration
def test_a_delivery_that_fails_again_does_not_hold_up_the_others(collector_service, monkeypatch, caplog):
    feed = make_feed()
    watch = make_watch(feed, "a")
    gone = make_entry(feed, identity="gone")
    _decision(gone, watch)
    monkeypatch.setattr(delivery, "build_root", _crash)
    deliver(collector_service.file_manager)
    monkeypatch.undo()
    stuck = get_db().execute(select(FeedDelivery)).scalar_one()
    # the entry expired while its delivery was pending
    get_db().execute(delete(FeedEntry).where(FeedEntry.id == gone.id))
    get_db().commit()
    _decision(make_entry(feed, identity="new"), watch)

    caplog.clear()
    with caplog.at_level(logging.ERROR):
        assert deliver(collector_service.file_manager) == 1

    get_db().expire_all()
    assert get_db().get(FeedDelivery, stuck.id).state == "pending"
    assert [root.details["entry"]["identity"] for root in _staged(collector_service)] == ["new"]
    (record,) = [record for record in caplog.records if record.levelname == "ERROR"]
    assert "has no entry left" in record.getMessage() and record.exc_info and record.feed_delivery_id == stuck.id


@pytest.mark.integration
def test_a_stop_ends_the_delivery_pass(collector_service, monkeypatch):
    feed = make_feed()
    watch = make_watch(feed, "a")
    _decision(make_entry(feed, identity="pending"), watch)
    monkeypatch.setattr(delivery, "build_root", _crash)
    deliver(collector_service.file_manager)
    monkeypatch.undo()
    _decision(make_entry(feed, identity="ready"), watch)

    assert deliver(collector_service.file_manager, should_stop=lambda: True) == 0
    assert get_db().execute(select(FeedDelivery.state)).scalars().all() == ["pending"]
    # the first stop is after the pending deliveries
    stops = iter([False, True])
    assert deliver(collector_service.file_manager, should_stop=lambda: next(stops)) == 1
    get_db().expire_all()
    assert get_db().execute(select(FeedDelivery.state)).scalars().all() == ["staged"]
    assert _staged(collector_service)[0].details["entry"]["identity"] == "pending"


@pytest.mark.integration
def test_a_staged_root_whose_state_was_lost_is_not_staged_twice(collector_service, monkeypatch):
    feed = make_feed()
    entry = make_entry(feed)
    _decision(entry, make_watch(feed, "a"))
    deliver(collector_service.file_manager)
    # the process died after staging, before the state was written
    get_db().execute(text("UPDATE feed_deliveries SET state = 'pending'"))
    get_db().commit()

    assert deliver(collector_service.file_manager) == 1
    assert len(_staged(collector_service)) == 1


@pytest.mark.integration
def test_a_restarted_collector_schedules_each_alert_once(collector_service):
    feed = make_feed()
    entry = make_entry(feed)
    _decision(entry, make_watch(feed, "a"))
    deliver(collector_service.file_manager)
    staged = _staged(collector_service)[0]

    # a retry that staged the same delivery again under another uuid (its key is the same)
    copy = RootAnalysis(storage_dir=collector_service.file_manager.get_staging_tmp_path("0" * 36), uuid="0" * 36,
                        desc=staged.description, alert_type=ALERT_TYPE_FEED_WATCH, queue="default",
                        analysis_mode=ANALYSIS_MODE_CORRELATION)
    copy.initialize_storage()
    copy.submission_key = staged.submission_key
    collector_service.file_manager.stage_submission(Submission(copy))

    # what a new process of the service finds
    restarted = CollectorService(FeedWatchCollector(collector_service.file_manager), config=service_config())
    assert restarted.execute_collection_loop() == (2, 1)
    assert get_db().execute(select(func.count()).select_from(IncomingWorkload)).scalar() == 1
    assert restarted.file_manager.list_staged_submissions() == []
