"""The qa spool: what a scanning worker writes, and what the qa recorder makes of it."""

import errno
import json
import os
from typing import Optional

import pytest
from sqlalchemy.exc import OperationalError

from saq.cas import get_cas
from saq.yara_scanning.match_record import serialize_match_record
from saq.yara_scanning import protocol, qa
from saq.yara_scanning.qa import (
    CLAIMED_SUFFIX,
    FILE_SUFFIX,
    JOB_SUFFIX,
    MAX_ATTEMPTS,
    QARecorder,
    QASpooler,
    count_jobs,
    select_qa_matches,
)
from tests.saq.yara_qa.conftest import QA_UUID, counter_row, match_rows, qa_match_result

OTHER_UUID = "6b1d8f2a-2d54-4b4a-9e7c-3a2c4d5e6f70"


@pytest.fixture
def spool_dir(tmp_path) -> str:
    result = tmp_path / "spool"
    result.mkdir()
    return str(result)


@pytest.fixture
def scanned(tmp_path) -> str:
    """A file the engine asked to have scanned."""
    result = tmp_path / "storage" / "sample.bin"
    result.parent.mkdir()
    result.write_bytes(b"qa sample bytes")
    return str(result)


def _qa_context(file_observable=None, root_uuid: Optional[str] = None) -> dict:
    if file_observable is None:
        return {"root_uuid": "0c8a1d5e-7b2f-4c1e-9a3d-5f6e7d8c9b0a",
                "observable_uuid": "1d9b2e6f-8c3a-4d2f-ab4e-6a7f8e9d0c1b",
                "file_name": "sample.bin", "file_size": 15, "sha256": "0" * 64}

    return {"root_uuid": root_uuid, "observable_uuid": file_observable.uuid,
            "file_name": file_observable.file_name, "file_size": file_observable.size,
            "sha256": file_observable.value}


def _spool(spool_dir: str, path: str, matches: list[dict], qa_context: Optional[dict] = None, max_jobs: int = 0):
    """Spools a scan the way a worker does: begin before the response, commit after it."""
    spooler = QASpooler(spool_dir, max_jobs)
    request = {"op": protocol.OP_SCAN_FILE, "path": path, "qa": qa_context or _qa_context()}
    job = spooler.begin(request, {"status": protocol.STATUS_OK, "matches": protocol.encode_matches(matches)})
    if job:
        spooler.commit(job)

    return job


def _names(spool_dir: str, suffix: str) -> list[str]:
    return sorted(name for name in os.listdir(spool_dir) if name.endswith(suffix))


def _not_stopping() -> bool:
    return False


#
# worker side
#

@pytest.mark.unit
def test_select_qa_matches():
    qa_match = qa_match_result()
    not_qa = {**qa_match_result(), "meta": {"uuid": QA_UUID}}
    disabled = {**qa_match_result(), "meta": {**qa_match["meta"], "enabled": "false"}}
    no_uuid = qa_match_result(signature_uuid=None)
    assert select_qa_matches([qa_match, not_qa, disabled, no_uuid]) == [qa_match]


@pytest.mark.unit
def test_spooler_links_the_file_before_the_response(spool_dir, scanned):
    spooler = QASpooler(spool_dir, 0)
    match = qa_match_result()
    request = {"op": protocol.OP_SCAN_FILE, "path": scanned, "qa": _qa_context()}
    job = spooler.begin(request, {"status": protocol.STATUS_OK, "matches": protocol.encode_matches([match])})

    # the file is pinned, the job not written yet
    (file_name,) = _names(spool_dir, FILE_SUFFIX)
    assert os.stat(os.path.join(spool_dir, file_name)).st_ino == os.stat(scanned).st_ino
    assert _names(spool_dir, JOB_SUFFIX) == []

    spooler.commit(job)
    (job_name,) = _names(spool_dir, JOB_SUFFIX)
    assert job_name == file_name[:-len(FILE_SUFFIX)] + JOB_SUFFIX
    with open(os.path.join(spool_dir, job_name)) as fp:
        assert json.load(fp) == {"v": 1, "qa": _qa_context(), "matches": protocol.encode_matches([match]), "attempts": 0}

    assert sorted(os.listdir(spool_dir)) == sorted([file_name, job_name])


@pytest.mark.unit
@pytest.mark.parametrize("request_qa, status, matches", [
    (None, protocol.STATUS_OK, [qa_match_result()]),
    (_qa_context(), protocol.STATUS_TIMEOUT, [qa_match_result()]),
    (_qa_context(), protocol.STATUS_OK, [{**qa_match_result(), "meta": {"uuid": QA_UUID}}]),
    (_qa_context(), protocol.STATUS_OK, []),
])
def test_spooler_ignores_scans_without_qa_matches(spool_dir, scanned, request_qa, status, matches):
    spooler = QASpooler(spool_dir, 0)
    request = {"op": protocol.OP_SCAN_FILE, "path": scanned}
    if request_qa:
        request["qa"] = request_qa

    assert spooler.begin(request, {"status": status, "matches": protocol.encode_matches(matches)}) is None
    assert os.listdir(spool_dir) == []


@pytest.mark.unit
def test_spooler_copies_a_file_it_cannot_link(spool_dir, scanned, monkeypatch):
    def cross_device(src, dst, **kwargs):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(qa.os, "link", cross_device)
    spooler = QASpooler(spool_dir, 0)
    request = {"op": protocol.OP_SCAN_FILE, "path": scanned, "qa": _qa_context()}
    job = spooler.begin(request, {"status": protocol.STATUS_OK, "matches": protocol.encode_matches([qa_match_result()])})
    assert job.fd is not None

    # the engine deletes its file once it has the answer; the open file still has the bytes
    os.remove(scanned)
    spooler.commit(job)
    assert job.fd is None

    (file_name,) = _names(spool_dir, FILE_SUFFIX)
    with open(os.path.join(spool_dir, file_name), "rb") as fp:
        assert fp.read() == b"qa sample bytes"

    assert len(_names(spool_dir, JOB_SUFFIX)) == 1


@pytest.mark.unit
def test_spooler_bound(spool_dir, scanned):
    spooler = QASpooler(spool_dir, 2)
    request = {"op": protocol.OP_SCAN_FILE, "path": scanned, "qa": _qa_context()}
    response = {"status": protocol.STATUS_OK, "matches": protocol.encode_matches([qa_match_result()])}

    for _ in range(3):
        job = spooler.begin(request, response)
        if job:
            spooler.commit(job)

    assert count_jobs(spool_dir) == 2
    assert len(_names(spool_dir, FILE_SUFFIX)) == 2


@pytest.mark.unit
def test_spooler_never_raises(spool_dir, scanned):
    request = {"op": protocol.OP_SCAN_FILE, "path": scanned, "qa": _qa_context()}
    response = {"status": protocol.STATUS_OK, "matches": protocol.encode_matches([qa_match_result()])}
    assert QASpooler(os.path.join(spool_dir, "does_not_exist"), 0).begin(request, response) is None

    # the spool goes away between the link and the job
    spooler = QASpooler(spool_dir, 0)
    job = spooler.begin(request, response)
    for name in os.listdir(spool_dir):
        os.remove(os.path.join(spool_dir, name))

    os.rmdir(spool_dir)
    spooler.commit(job)
    assert not os.path.exists(spool_dir)


#
# recorder side
#

@pytest.fixture
def file_observable(root_analysis, tmp_path):
    path = tmp_path / "observable.bin"
    path.write_bytes(b"a file a qa rule matched")
    return root_analysis.add_file_observable(str(path))


@pytest.mark.integration
def test_recorder_records_a_spooled_job(spool_dir, file_observable, root_analysis):
    match = qa_match_result()
    _spool(spool_dir, file_observable.full_path, [match], _qa_context(file_observable, root_analysis.uuid))
    original = open(file_observable.full_path, "rb").read()

    # the engine is done with the file before the recorder gets to it
    os.remove(file_observable.full_path)

    assert QARecorder(spool_dir).process_once(_not_stopping)
    assert os.listdir(spool_dir) == []

    (row,) = match_rows()
    assert row.sha256 == file_observable.value
    assert row.file_name == file_observable.file_name
    assert row.file_size == len(original)
    assert row.root_uuid == root_analysis.uuid
    assert row.observable_uuid == file_observable.uuid

    pool = get_cas().pool("yara_qa")
    with pool.open(row.sha256) as fp:
        assert fp.read() == original

    # the same record the engine used to store: the strings come back as (offset, identifier,
    # bytes) tuples, and target is still the engine's path, not the spool's
    with pool.open(row.match_digest) as fp:
        assert fp.read() == serialize_match_record(match)


@pytest.mark.integration
def test_unreachable_database_keeps_what_is_left_of_the_job(spool_dir, file_observable, root_analysis, monkeypatch):
    matches = [qa_match_result(), qa_match_result(signature_uuid=OTHER_UUID, rule="other_qa_rule")]
    _spool(spool_dir, file_observable.full_path, matches, _qa_context(file_observable, root_analysis.uuid))

    original = qa.record_qa_match_or_raise
    calls = []

    def second_call_fails(match_result, target):
        calls.append(match_result["rule"])
        if len(calls) == 2:
            raise OperationalError("INSERT ...", {}, Exception("Lost connection to MySQL server"))

        return original(match_result, target)

    monkeypatch.setattr(qa, "record_qa_match_or_raise", second_call_fails)
    assert not QARecorder(spool_dir).process_once(_not_stopping)

    # the first match is recorded; the second is put back with the file, ready for the next try
    assert len(match_rows(QA_UUID)) == 1
    assert _names(spool_dir, CLAIMED_SUFFIX) == []
    (job_name,) = _names(spool_dir, JOB_SUFFIX)
    with open(os.path.join(spool_dir, job_name)) as fp:
        job = json.load(fp)

    assert job["attempts"] == 1
    assert [match["rule"] for match in job["matches"]] == ["other_qa_rule"]
    assert len(_names(spool_dir, FILE_SUFFIX)) == 1

    monkeypatch.setattr(qa, "record_qa_match_or_raise", original)
    assert QARecorder(spool_dir).process_once(_not_stopping)
    assert os.listdir(spool_dir) == []
    assert len(match_rows(OTHER_UUID)) == 1
    assert counter_row().match_count == 1


@pytest.mark.integration
def test_a_job_out_of_attempts_is_dropped(spool_dir, file_observable, root_analysis, monkeypatch):
    _spool(spool_dir, file_observable.full_path, [qa_match_result()], _qa_context(file_observable, root_analysis.uuid))
    (job_name,) = _names(spool_dir, JOB_SUFFIX)
    job_path = os.path.join(spool_dir, job_name)
    with open(job_path) as fp:
        job = json.load(fp)

    with open(job_path, "w") as fp:
        json.dump({**job, "attempts": MAX_ATTEMPTS - 1}, fp)

    def unreachable(match_result, target):
        raise OperationalError("SELECT 1", {}, Exception("Can't connect to MySQL server"))

    monkeypatch.setattr(qa, "record_qa_match_or_raise", unreachable)
    assert not QARecorder(spool_dir).process_once(_not_stopping)
    assert os.listdir(spool_dir) == []


@pytest.mark.unit
def test_an_interrupted_job_is_dropped(spool_dir, scanned):
    _spool(spool_dir, scanned, [qa_match_result()])
    _spool(spool_dir, scanned, [qa_match_result()])
    interrupted, put_back = _names(spool_dir, JOB_SUFFIX)

    # a recorder died recording the first job
    os.rename(os.path.join(spool_dir, interrupted),
              os.path.join(spool_dir, interrupted[:-len(JOB_SUFFIX)] + CLAIMED_SUFFIX))
    # and another one died after it put the second job back, before it removed its claim
    claimed_copy = os.path.join(spool_dir, put_back[:-len(JOB_SUFFIX)] + CLAIMED_SUFFIX)
    with open(claimed_copy, "w") as fp:
        fp.write("{}")

    QARecorder(spool_dir).drop_interrupted()
    name = put_back[:-len(JOB_SUFFIX)]
    assert sorted(os.listdir(spool_dir)) == [name + FILE_SUFFIX, name + JOB_SUFFIX]


@pytest.mark.integration
def test_an_invalid_job_is_dropped(spool_dir, scanned):
    _spool(spool_dir, scanned, [qa_match_result()])
    (job_name,) = _names(spool_dir, JOB_SUFFIX)
    with open(os.path.join(spool_dir, job_name), "w") as fp:
        fp.write("not json")

    assert QARecorder(spool_dir).process_once(_not_stopping)
    assert os.listdir(spool_dir) == []
    assert match_rows() == []


@pytest.mark.unit
def test_orphans_are_swept(spool_dir, scanned, monkeypatch):
    _spool(spool_dir, scanned, [qa_match_result()])
    kept = sorted(os.listdir(spool_dir))
    for name in ("1-2-3" + FILE_SUFFIX, "1-2-4" + JOB_SUFFIX + qa.TMP_SUFFIX):
        with open(os.path.join(spool_dir, name), "w") as fp:
            fp.write("left behind")

    # too new to be an orphan
    QARecorder(spool_dir).sweep_orphans()
    assert len(os.listdir(spool_dir)) == len(kept) + 2

    monkeypatch.setattr(qa, "ORPHAN_AGE_SECONDS", -10)
    QARecorder(spool_dir).sweep_orphans()
    assert sorted(os.listdir(spool_dir)) == kept
