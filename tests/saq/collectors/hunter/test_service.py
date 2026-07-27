from datetime import datetime
from queue import Queue
from uuid import uuid4

import pytest

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.hunter.service import MAX_SUBMISSIONS_PER_COLLECTION, HunterCollector


def create_submission(tmpdir) -> Submission:
    root_uuid = str(uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        storage_dir=str(tmpdir / root_uuid),
        desc='test_description',
        analysis_mode='analysis',
        tool='unittest_tool',
        tool_instance='unittest_tool_instance',
        alert_type='unittest_type',
        event_time=datetime.now())
    root.initialize_storage()
    return Submission(root)


@pytest.mark.unit
def test_collect_drains_queue(tmpdir):
    """a single call to collect() returns everything already queued

    the collection loop processes one collect() call per iteration, so yielding a single
    submission per call made a burst of hunt results drain one-per-loop-iteration"""
    submission_queue = Queue()
    submissions = [create_submission(tmpdir) for _ in range(5)]
    for submission in submissions:
        submission_queue.put(submission)

    collector = HunterCollector(submission_queue)
    assert list(collector.collect()) == submissions
    assert submission_queue.empty()


@pytest.mark.unit
def test_collect_stops_at_maximum(tmpdir):
    """collect() yields at most MAX_SUBMISSIONS_PER_COLLECTION so the collection loop
    keeps coming back around to report status and check for shutdown"""
    submission_queue = Queue()
    for _ in range(MAX_SUBMISSIONS_PER_COLLECTION + 5):
        submission_queue.put(create_submission(tmpdir))

    collector = HunterCollector(submission_queue)
    assert len(list(collector.collect())) == MAX_SUBMISSIONS_PER_COLLECTION
    assert submission_queue.qsize() == 5


@pytest.mark.unit
def test_collect_empty_queue():
    """an empty queue yields nothing (and still blocks briefly so an idle collector
    polls at the same rate it always did)"""
    collector = HunterCollector(Queue())
    assert list(collector.collect()) == []
