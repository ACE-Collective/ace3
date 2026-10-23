import logging
import os
import shutil

import pytest

from saq.collectors.hunter import service as service_module
from saq.collectors.hunter.query_hunter import dedup_key_hunt_uuid
from saq.collectors.hunter.service import MAX_SUBMISSIONS_PER_COLLECTION, HunterCollector
from tests.saq.helpers import create_staged_submission, create_submission_file_manager, log_count


@pytest.fixture
def file_manager(tmpdir):
    return create_submission_file_manager(tmpdir)


@pytest.mark.unit
def test_collect_drains_staged_submissions(file_manager):
    """a single call to collect() returns everything already staged

    the collection loop processes one collect() call per iteration, so yielding a single
    submission per call made a burst of hunt results drain one-per-loop-iteration"""
    staged = [create_staged_submission(file_manager) for _ in range(5)]

    collector = HunterCollector(file_manager)
    collected = list(collector.collect())

    assert sorted(_.root.uuid for _ in collected) == sorted(staged)


@pytest.mark.unit
def test_collect_stops_at_maximum(file_manager):
    """collect() yields at most MAX_SUBMISSIONS_PER_COLLECTION so the collection loop
    keeps coming back around to report status and check for shutdown"""
    for _ in range(MAX_SUBMISSIONS_PER_COLLECTION + 5):
        create_staged_submission(file_manager)

    collector = HunterCollector(file_manager)
    assert len(list(collector.collect())) == MAX_SUBMISSIONS_PER_COLLECTION

    # nothing is consumed by collecting - a submission leaves the staging directory only when it
    # reaches a terminal outcome, which is what makes it survive a crash mid-processing
    assert len(file_manager.list_staged_submissions()) == MAX_SUBMISSIONS_PER_COLLECTION + 5

    # and because a pass leaves work behind, the collection loop must run again immediately
    # rather than waiting collection_frequency
    assert collector.collect_until_empty


@pytest.mark.unit
def test_collect_empty_staging(file_manager):
    """an empty staging directory yields nothing"""
    collector = HunterCollector(file_manager)
    assert list(collector.collect()) == []


@pytest.mark.unit
def test_staged_submission_round_trips_metadata(file_manager):
    """key, group_assignments, group_value and queued_at survive the trip through disk

    these live on Submission in memory but must be read back after a restart, so they are
    stored on the root where they get serialized"""
    root_uuid = create_staged_submission(
        file_manager, key="dedup-key", group_value="1.2.3.4", group_assignments=["group_a"])

    collector = HunterCollector(file_manager)
    collected = list(collector.collect())

    assert len(collected) == 1
    submission = collected[0]
    assert submission.root.uuid == root_uuid
    assert submission.key == "dedup-key"
    assert submission.group_value == "1.2.3.4"
    assert submission.group_assignments == ["group_a"]
    assert submission.queued_time is not None
    assert submission.queue_age >= 0


@pytest.mark.unit
def test_incomplete_submissions_are_never_collected(file_manager):
    """a submission still being built is invisible until the rename commits it"""
    incomplete_dir = file_manager.get_staging_tmp_path("incomplete-uuid")
    os.makedirs(incomplete_dir)

    collector = HunterCollector(file_manager)
    assert list(collector.collect()) == []

    # and it is cleaned up at startup rather than accumulating
    assert file_manager.purge_incomplete_staging() == 1
    assert not os.path.exists(incomplete_dir)


@pytest.mark.unit
def test_unloadable_submission_is_quarantined(file_manager):
    """a corrupt staged submission is moved aside instead of wedging collection

    without this it would fail to load on every pass forever, and because collect() yields in
    directory order it would block everything behind it"""
    good_uuid = create_staged_submission(file_manager)

    # a directory that looks staged but has no readable root
    bad_uuid = "00000000-0000-0000-0000-000000000000"
    os.makedirs(file_manager.get_staging_path(bad_uuid))

    collector = HunterCollector(file_manager)
    collected = list(collector.collect())

    assert [_.root.uuid for _ in collected] == [good_uuid]
    assert file_manager.list_staged_submissions() == [good_uuid]
    assert os.path.isdir(os.path.join(file_manager.error_dir, bad_uuid))


@pytest.mark.unit
def test_listing_survives_a_submission_disappearing_mid_scan(file_manager, monkeypatch):
    """a submission removed between scandir() and stat() drops out of the listing

    the stat() is a second syscall, so it can always lose a race with whatever removes the
    submission. sorting on the stat directly turned that into a FileNotFoundError that escaped
    the generator and aborted the entire collection pass, not just the one submission"""
    survivor = create_staged_submission(file_manager)

    class VanishedEntry:
        """a submission that is still in the scan result but gone by the time it is stat()ed"""
        name = "00000000-0000-0000-0000-000000000000"

        def is_dir(self):
            return True

        def stat(self):
            raise FileNotFoundError(2, "No such file or directory")

    real_scandir = os.scandir
    monkeypatch.setattr(os, "scandir", lambda path: [*real_scandir(path), VanishedEntry()])

    assert file_manager.list_staged_submissions() == [survivor]


@pytest.mark.unit
def test_vanished_submission_is_skipped_not_quarantined(file_manager):
    """a submission that disappears after being listed is nothing to review

    unlike a corrupt submission there is no evidence left to move aside, and treating it as one
    produced a pair of ERRORs per occurrence - "unable to load staged submission" immediately
    followed by "unable to quarantine staged submission" for the same uuid"""
    survivor = create_staged_submission(file_manager)
    doomed = create_staged_submission(file_manager)

    listed = file_manager.list_staged_submissions()
    assert sorted(listed) == sorted([survivor, doomed])

    real_list = file_manager.list_staged_submissions

    def list_then_remove(*args, **kwargs):
        result = real_list(*args, **kwargs)
        shutil.rmtree(file_manager.get_staging_path(doomed))
        return result

    file_manager.list_staged_submissions = list_then_remove

    collected = list(file_manager.iter_staged_submissions())

    assert [_.root.uuid for _ in collected] == [survivor]
    assert os.listdir(file_manager.error_dir) == []
    assert log_count("unable to load staged submission") == 0
    assert log_count("unable to quarantine staged submission") == 0


@pytest.mark.unit
def test_discard_removes_staged_submission(file_manager):
    """terminal outcomes that never reach the incoming dir must still leave staging

    duplicate submissions are dropped by process_submission; without an explicit
    discard they would be collected again on every pass"""
    root_uuid = create_staged_submission(file_manager)
    assert file_manager.list_staged_submissions() == [root_uuid]

    assert file_manager.discard_staged_submission(root_uuid)
    assert file_manager.list_staged_submissions() == []


HUNT_UUID = "11111111-aaaa-4aaa-8aaa-111111111111"
OTHER_HUNT_UUID = "22222222-bbbb-4bbb-8bbb-222222222222"


def _duplicates(file_manager, *keys) -> list:
    for key in keys:
        create_staged_submission(file_manager, key=key, group_value="win10-01" if key else None)
    return list(HunterCollector(file_manager).collect())


@pytest.mark.unit
def test_dedup_key_hunt_uuid():
    assert dedup_key_hunt_uuid(f"{HUNT_UUID}:alice:bob") == HUNT_UUID
    assert dedup_key_hunt_uuid("no-prefix") is None
    assert dedup_key_hunt_uuid(":value") is None
    assert dedup_key_hunt_uuid(None) is None


@pytest.mark.unit
def test_duplicates_are_recorded_per_hunt(file_manager, monkeypatch):
    """each hunt's duplicates go to svs together, as duplicates; a key no hunt made is skipped"""
    calls = []
    monkeypatch.setattr(service_module, "record_suppressed_matches",
                        lambda hunt_uuid, matches, duplicate: calls.append(
                            (hunt_uuid, sorted(value for _, value in matches), duplicate)))
    submissions = _duplicates(file_manager, f"{HUNT_UUID}:a", f"{OTHER_HUNT_UUID}:b", f"{HUNT_UUID}:c", "no-prefix")

    HunterCollector(file_manager).duplicates_dropped(submissions)
    assert sorted(calls) == [(HUNT_UUID, ["win10-01", "win10-01"], True), (OTHER_HUNT_UUID, ["win10-01"], True)]


@pytest.mark.unit
def test_a_failure_to_record_duplicates_is_logged_per_hunt(file_manager, monkeypatch, caplog):
    """one hunt's failure is logged at ERROR with its keys, and the next hunt is still recorded"""
    recorded = []

    def record(hunt_uuid, matches, duplicate):
        if hunt_uuid == HUNT_UUID:
            raise RuntimeError("database is gone")
        recorded.append(hunt_uuid)

    monkeypatch.setattr(service_module, "record_suppressed_matches", record)
    submissions = _duplicates(file_manager, f"{HUNT_UUID}:a", f"{OTHER_HUNT_UUID}:b")

    with caplog.at_level(logging.ERROR):
        HunterCollector(file_manager).duplicates_dropped(submissions)

    assert recorded == [OTHER_HUNT_UUID]
    (record_,) = [r for r in caplog.records if "unable to record the duplicate matches" in r.getMessage()]
    assert record_.levelno == logging.ERROR and record_.exc_info is not None
    assert (record_.hunt_uuid, record_.dedup_keys) == (HUNT_UUID, [f"{HUNT_UUID}:a"])
