"""Reading samples (saq.svs.samples): the aggregate rows, where the bytes are, and what is missing."""

import uuid
from datetime import datetime, timedelta

import pytest

from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.svs.constants import CaptureState, MissingReason
from saq.svs.samples import bytes_nodes, contributing_detections, get_captures, get_sample, missing_by_rule
from tests.saq.svs.conftest import OTHER_RULE_UUID, RULE_UUID, graded_alert, insert_capture

SHA256 = "ab" * 32


def _alert_uuid() -> str:
    return str(uuid.uuid4())


@pytest.mark.integration
def test_a_sample_aggregates_its_captures():
    now = datetime.now().replace(microsecond=0)
    first = insert_capture(_alert_uuid(), SHA256, created_at=now - timedelta(days=2), file_path="old.bin",
                           rule_name="old_name")
    insert_capture(_alert_uuid(), SHA256, created_at=now - timedelta(days=1), state=CaptureState.MISSING,
                   missing_reason=MissingReason.FILE, stored_at=None)
    latest = insert_capture(_alert_uuid(), SHA256, created_at=now, file_path="dir/new.bin", rule_name="new_name",
                            file_size=99, missing_reason=MissingReason.MATCH_RECORD,
                            signature_version=SIGNATURE_VERSION_UNKNOWN)
    # another rule's sample of the same file is its own sample
    insert_capture(_alert_uuid(), SHA256, OTHER_RULE_UUID)

    sample = get_sample(SHA256, RULE_UUID)
    assert sample["capture_count"] == 3
    assert sample["stored"] == 2
    assert sample["missing"] == 1
    assert sample["missing_data"] == 2
    assert sample["unknown_version"] == 1
    assert sample["first_captured"] == now - timedelta(days=2)
    assert sample["last_captured"] == now
    assert sample["latest_capture_id"] == latest
    assert (sample["rule_name"], sample["file_path"], sample["file_size"]) == ("new_name", "dir/new.bin", 99)
    assert sample["label"] is None

    assert [row.id for row in get_captures(SHA256, RULE_UUID)][-1] == first
    assert get_sample(SHA256, OTHER_RULE_UUID)["capture_count"] == 1
    assert get_sample(SHA256, "no-such-rule") is None


@pytest.mark.integration
def test_the_bytes_are_where_the_first_stored_capture_put_them():
    insert_capture(_alert_uuid(), SHA256, state=CaptureState.MISSING, missing_reason=MissingReason.FILE, node="node-0")
    insert_capture(_alert_uuid(), SHA256, node="node-1")
    insert_capture(_alert_uuid(), SHA256, OTHER_RULE_UUID, node="node-2")
    assert bytes_nodes([SHA256, "cd" * 32]) == {SHA256: "node-1"}
    assert bytes_nodes([]) == {}


@pytest.mark.integration
def test_missing_by_rule():
    for reason in (MissingReason.FILE, MissingReason.FILE, MissingReason.STORAGE):
        insert_capture(_alert_uuid(), SHA256, state=CaptureState.MISSING, missing_reason=reason)
    insert_capture(_alert_uuid(), SHA256, OTHER_RULE_UUID, missing_reason=MissingReason.MATCH_RECORD,
                   rule_name="other_rule")
    insert_capture(_alert_uuid(), SHA256)

    assert missing_by_rule() == [
        {"rule_uuid": RULE_UUID, "rule_name": "svs_rule", "reason": "file", "count": 2},
        {"rule_uuid": OTHER_RULE_UUID, "rule_name": "other_rule", "reason": "match_record", "count": 1},
        {"rule_uuid": RULE_UUID, "rule_name": "svs_rule", "reason": "storage", "count": 1},
    ]


@pytest.mark.integration
def test_contributing_detections_of_each_capture():
    alert, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]})
    sha256 = files["a.bin"].value.lower()
    (capture,) = get_captures(sha256, RULE_UUID)
    orphan = insert_capture(_alert_uuid(), sha256)

    detections = contributing_detections([capture.id, orphan])
    (detection,) = detections[capture.id]
    assert detection["alert_uuid"] == alert.uuid
    assert detection["signature_uuid"] == RULE_UUID
    assert (detection["verdict"], detection["verdict_source"]) == ("fp", "inherited_single")
    assert detections[orphan] == []
    assert contributing_detections([]) == {}
