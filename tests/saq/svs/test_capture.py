import json
import logging
import os

import pytest
from sqlalchemy import update

from saq.cas import CASPool
from saq.database.model import SVSYaraCapture
from saq.modules.file_analysis.yara import YaraScanResults_v3_4
from saq.svs.capture import (
    CaptureState,
    CaptureStatus,
    MissingReason,
    candidates_from_root,
    capture,
    capture_hold,
)
from saq.database.private_session import private_transaction
from tests.saq.svs.conftest import (
    COMMIT,
    OTHER_RULE_UUID,
    RULE_UUID,
    add_file,
    add_yara_match,
    capture_rows,
)


def _extras(caplog, message: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.ERROR and message in r.getMessage()]


#
# candidates
#

@pytest.mark.unit
def test_a_yara_detection_is_a_candidate(root_analysis):
    _file = add_file(root_analysis, "dir/invoice.doc")
    _file.add_directive("yara_meta:source=email")
    add_yara_match(_file)

    (candidate,) = candidates_from_root(root_analysis)

    assert candidate.sha256 == _file.value
    assert candidate.rule_uuid == RULE_UUID
    assert candidate.rule_name == "svs_rule"
    assert candidate.namespace == "unittest"
    assert candidate.signature_version == COMMIT
    assert candidate.observable_uuid == _file.uuid
    assert candidate.file_path == "dir/invoice.doc"
    assert candidate.full_path == _file.full_path
    assert candidate.yara_meta_tags == ("source=email",)
    assert candidate.match_record["rule"] == "svs_rule"
    assert candidate.match_record["meta"]["uuid"] == RULE_UUID


@pytest.mark.unit
def test_rules_without_a_uuid_and_legacy_detections_are_not_candidates(root_analysis):
    _file = add_file(root_analysis)
    add_yara_match(_file, rule="no_uuid_rule", rule_uuid=None)
    # a detection from before the structured details existed (D-3)
    _file.add_detection_point(f"{_file} matched yara rule old_rule")
    # and a detection that is not on a file
    root_analysis.add_detection_point("hunt", details={"sha256": "0" * 64, "rule": "r", "namespace": "n",
                                                       "rule_uuid": RULE_UUID})

    assert candidates_from_root(root_analysis) == []


@pytest.mark.unit
def test_one_candidate_per_file_and_rule(root_analysis):
    content = b"the same bytes twice"
    first = add_file(root_analysis, "first.bin", content)
    second = add_file(root_analysis, "second.bin", content)
    add_yara_match(first)
    add_yara_match(first, rule="other_rule", rule_uuid=OTHER_RULE_UUID)
    add_yara_match(second)

    candidates = candidates_from_root(root_analysis)

    assert sorted((c.rule_uuid, c.file_path) for c in candidates) == sorted(
        [(RULE_UUID, "first.bin"), (OTHER_RULE_UUID, "first.bin")])
    # each candidate carries its own rule's record
    assert {c.rule_uuid: c.match_record["rule"] for c in candidates} == {
        RULE_UUID: "svs_rule", OTHER_RULE_UUID: "other_rule"}


@pytest.mark.unit
def test_a_candidate_without_its_analysis_has_no_record(root_analysis):
    _file = add_file(root_analysis)
    add_yara_match(_file)
    # what archive() leaves: the analysis without its details
    _file.get_and_load_analysis(YaraScanResults_v3_4).details = None

    (candidate,) = candidates_from_root(root_analysis)

    assert candidate.match_record is None


#
# capture
#


def _candidate(root_analysis, **kwargs):
    _file = add_file(root_analysis, kwargs.pop("name", "sample.bin"), kwargs.pop("content", None))
    add_yara_match(_file, **kwargs)
    (candidate,) = candidates_from_root(root_analysis)
    return _file, candidate


@pytest.mark.integration
def test_capture_stores_the_file_and_the_record(root_analysis, svs_pool: CASPool):
    _file, candidate = _candidate(root_analysis, name="dir/invoice.doc")

    result = capture(svs_pool, root_analysis.uuid, candidate)

    assert result.status == CaptureStatus.STORED
    (row,) = capture_rows()
    assert row.id == result.capture_id
    assert row.alert_uuid == root_analysis.uuid
    assert row.observable_uuid == _file.uuid
    assert row.sha256 == _file.value
    assert row.rule_uuid == RULE_UUID
    assert row.rule_name == "svs_rule"
    assert row.namespace == "unittest"
    assert row.signature_version == COMMIT
    assert row.file_path == "dir/invoice.doc"
    assert row.file_size == os.path.getsize(_file.full_path)
    assert json.loads(row.yara_meta_tags) == []
    assert row.state == CaptureState.STORED
    assert row.missing_reason is None
    assert row.stored_at is not None
    assert row.yara_python_version and row.yara_scanner_version
    assert json.loads(row.match_summary)["string_match_count"] == 3

    hold = capture_hold(row.id)
    assert hold in svs_pool.holds(row.sha256)
    assert hold in svs_pool.holds(row.record_digest)
    with svs_pool.open(row.sha256) as fp:
        assert fp.read() == open(_file.full_path, "rb").read()
    with svs_pool.open(row.record_digest) as fp:
        assert json.loads(fp.read())["rule"] == "svs_rule"


@pytest.mark.integration
def test_capture_is_idempotent(root_analysis, svs_pool):
    _, candidate = _candidate(root_analysis)

    first = capture(svs_pool, root_analysis.uuid, candidate)
    second = capture(svs_pool, root_analysis.uuid, candidate)

    assert second.status == CaptureStatus.ALREADY
    assert second.capture_id == first.capture_id
    (row,) = capture_rows()
    assert svs_pool.holds(row.sha256) == [capture_hold(row.id)]


@pytest.mark.integration
def test_a_file_already_in_the_pool_is_captured_without_its_file(root_analysis, svs_pool):
    _file, candidate = _candidate(root_analysis)
    assert capture(svs_pool, root_analysis.uuid, candidate).status == CaptureStatus.STORED

    # the first capture was stored on another node
    with private_transaction() as session:
        session.execute(update(SVSYaraCapture).values(node="other_node"))

    # another alert has the same bytes, but its copy is gone
    os.remove(_file.full_path)
    result = capture(svs_pool, "00000000-0000-0000-0000-000000000001", candidate)

    assert result.status == CaptureStatus.STORED
    assert capture_hold(result.capture_id) in svs_pool.holds(candidate.sha256)
    # only a hold was taken, so the bytes are where the first capture put them
    assert capture_rows("00000000-0000-0000-0000-000000000001")[0].node == "other_node"


@pytest.mark.integration
def test_a_missing_file_is_recorded_and_reported_once(root_analysis, svs_pool, caplog):
    _file, candidate = _candidate(root_analysis)
    os.remove(_file.full_path)

    result = capture(svs_pool, root_analysis.uuid, candidate)

    assert result.status == CaptureStatus.MISSING
    (row,) = capture_rows()
    assert row.state == CaptureState.MISSING
    assert row.missing_reason == MissingReason.FILE
    (record,) = _extras(caplog, "its file is gone")
    assert record.alert_uuid == root_analysis.uuid
    assert record.sha256 == candidate.sha256
    assert record.rule_uuid == RULE_UUID
    assert record.missing_reason == "file"

    # the next pass tries again, and does not report it again
    caplog.clear()
    assert capture(svs_pool, root_analysis.uuid, candidate).status == CaptureStatus.MISSING
    assert _extras(caplog, "its file is gone") == []
    assert len(capture_rows()) == 1


@pytest.mark.integration
def test_a_capture_without_its_record_keeps_the_file(root_analysis, svs_pool, caplog):
    _file, candidate = _candidate(root_analysis, record=False)
    assert candidate.match_record is None

    result = capture(svs_pool, root_analysis.uuid, candidate)

    assert result.status == CaptureStatus.STORED
    (row,) = capture_rows()
    assert row.state == CaptureState.STORED
    assert row.missing_reason == MissingReason.MATCH_RECORD
    assert row.record_digest is None
    assert capture_hold(row.id) in svs_pool.holds(row.sha256)
    (record,) = _extras(caplog, "without its match record")
    assert record.missing_reason == "match_record"

    # a later pass that has the record adds it
    add_yara_match(_file)
    (candidate,) = candidates_from_root(root_analysis)
    assert capture(svs_pool, root_analysis.uuid, candidate).status == CaptureStatus.STORED
    (row,) = capture_rows()
    assert row.missing_reason is None
    assert capture_hold(row.id) in svs_pool.holds(row.record_digest)


@pytest.mark.integration
def test_a_storage_failure_releases_the_holds_and_is_retried(root_analysis, svs_pool, monkeypatch, caplog):
    _, candidate = _candidate(root_analysis)
    original_put = CASPool.put
    calls = []

    def failing_put(self, src, **kwargs):
        calls.append(src)
        if len(calls) == 2:
            # the file went in; the record does not
            raise RuntimeError("the backend is down")
        return original_put(self, src, **kwargs)

    monkeypatch.setattr(CASPool, "put", failing_put)
    result = capture(svs_pool, root_analysis.uuid, candidate)

    assert result.status == CaptureStatus.MISSING
    (row,) = capture_rows()
    assert row.state == CaptureState.MISSING
    assert row.missing_reason == MissingReason.STORAGE
    assert svs_pool.holds(candidate.sha256) == []
    (record,) = _extras(caplog, "unable to store svs capture")
    assert record.missing_reason == "storage"

    monkeypatch.setattr(CASPool, "put", original_put)
    assert capture(svs_pool, root_analysis.uuid, candidate).status == CaptureStatus.STORED
    (row,) = capture_rows()
    assert row.state == CaptureState.STORED
    assert row.missing_reason is None


@pytest.mark.integration
def test_an_unknown_signature_version_is_reported(root_analysis, svs_pool, caplog):
    _, candidate = _candidate(root_analysis, commit=None)
    assert candidate.signature_version == "unknown"

    capture(svs_pool, root_analysis.uuid, candidate)

    (record,) = _extras(caplog, "unknown signature version")
    assert record.alert_uuid == root_analysis.uuid
    assert record.sha256 == candidate.sha256
    assert record.rule_uuid == RULE_UUID

    # reported when it is stored, not on every pass
    caplog.clear()
    capture(svs_pool, root_analysis.uuid, candidate)
    assert _extras(caplog, "unknown signature version") == []


@pytest.mark.integration
def test_a_known_signature_version_is_not_reported(root_analysis, svs_pool, caplog):
    _, candidate = _candidate(root_analysis)

    capture(svs_pool, root_analysis.uuid, candidate)

    assert _extras(caplog, "unknown signature version") == []
