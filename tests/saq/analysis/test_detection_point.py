import uuid as uuidlib

import pytest

from saq.analysis.detection_point import DetectionPoint
from saq.signatures.builtin import (
    BUILTIN_SIGNATURE_UUID,
    BUILTIN_SIGNATURES,
    LEGACY_SIGNATURE_UUID,
    LEGACY_SIGNATURE_VERSION,
    SIGNATURE_VERSION_UNKNOWN,
    get_builtin_signature_version,
)


@pytest.mark.unit
def test_queue_round_trips_through_json():
    dp = DetectionPoint("matched a rule", details={"k": "v"}, queue="experimental")
    restored = DetectionPoint.from_json(dp.json)

    assert restored.description == "matched a rule"
    assert restored.details == {"k": "v"}
    assert restored.queue == "experimental"


@pytest.mark.unit
def test_queue_defaults_to_none():
    dp = DetectionPoint("matched a rule")
    assert dp.queue is None
    assert DetectionPoint.from_json(dp.json).queue is None


@pytest.mark.unit
def test_equality_considers_queue():
    a = DetectionPoint("same", queue="alpha")
    b = DetectionPoint("same", queue="bravo")
    c = DetectionPoint("same", queue="alpha")

    assert a != b
    assert a == c


@pytest.mark.unit
def test_signature_defaults_to_builtin():
    dp = DetectionPoint("matched a rule")
    assert dp.signature_uuid == BUILTIN_SIGNATURE_UUID
    assert dp.signature_version == get_builtin_signature_version()


@pytest.mark.unit
def test_signature_version_from_ace_version_env(monkeypatch):
    monkeypatch.setenv("ACE_VERSION", "9.9.9")
    dp = DetectionPoint("matched a rule")
    assert dp.signature_version == "9.9.9"


@pytest.mark.unit
def test_signature_version_falls_back_when_env_unset(monkeypatch):
    monkeypatch.delenv("ACE_VERSION", raising=False)
    dp = DetectionPoint("matched a rule")
    assert dp.signature_version == SIGNATURE_VERSION_UNKNOWN


@pytest.mark.unit
def test_explicit_signature_round_trips_through_json():
    dp = DetectionPoint("matched a rule", signature_uuid="abc-123", signature_version="deadbeef")
    restored = DetectionPoint.from_json(dp.json)
    assert restored.signature_uuid == "abc-123"
    assert restored.signature_version == "deadbeef"


@pytest.mark.unit
def test_old_serialized_form_backfills_legacy(monkeypatch):
    monkeypatch.setenv("ACE_VERSION", "1.2.3")
    # a detection point serialized before signature attribution existed gets the
    # special legacy identity (NOT the generic built-in / current ACE version), so
    # it stays distinguishable from freshly-created un-attributed detections
    restored = DetectionPoint.from_json({"description": "old"})
    assert restored.signature_uuid == LEGACY_SIGNATURE_UUID
    assert restored.signature_version == LEGACY_SIGNATURE_VERSION
    # an explicit null also backfills the legacy identity
    restored = DetectionPoint.from_json({"description": "old", "signature_uuid": None, "signature_version": None})
    assert restored.signature_uuid == LEGACY_SIGNATURE_UUID
    assert restored.signature_version == LEGACY_SIGNATURE_VERSION
    # the legacy identity is distinct from the generic built-in
    assert LEGACY_SIGNATURE_UUID != BUILTIN_SIGNATURE_UUID


@pytest.mark.unit
def test_equality_considers_signature():
    a = DetectionPoint("same", signature_uuid="u1", signature_version="v1")
    b = DetectionPoint("same", signature_uuid="u2", signature_version="v1")
    c = DetectionPoint("same", signature_uuid="u1", signature_version="v2")
    d = DetectionPoint("same", signature_uuid="u1", signature_version="v1")

    assert a != b
    assert a != c
    assert a == d


@pytest.mark.unit
def test_builtin_detections_still_equal_for_dedup():
    # unmigrated callers all share the generic built-in -> dedup still works
    a = DetectionPoint("same description")
    b = DetectionPoint("same description")
    assert a == b


@pytest.mark.unit
def test_id_unchanged_by_signature():
    # id is the UI/DOM display identity; signature attribution must not change it
    a = DetectionPoint("same", signature_uuid="zzz", signature_version="1")
    b = DetectionPoint("same", signature_uuid="yyy", signature_version="2")
    assert a.id == b.id
    assert str(a) == str(b)


@pytest.mark.unit
def test_content_hash_stable_and_sensitive():
    a = DetectionPoint("d", details={"b": 1, "a": 2}, signature_uuid="u")
    # insensitive to details key order (canonical JSON)
    b = DetectionPoint("d", details={"a": 2, "b": 1}, signature_uuid="u")
    assert a.content_hash == b.content_hash
    # differs when signature_uuid changes
    assert a.content_hash != DetectionPoint("d", details={"a": 2, "b": 1}, signature_uuid="v").content_hash
    # differs when description changes
    assert a.content_hash != DetectionPoint("d2", details={"a": 2, "b": 1}, signature_uuid="u").content_hash
    # differs when details change
    assert a.content_hash != DetectionPoint("d", details={"a": 2, "b": 9}, signature_uuid="u").content_hash


@pytest.mark.unit
def test_builtin_signatures_are_unique_valid_uuids():
    uuids = [sig.uuid for sig in BUILTIN_SIGNATURES.values()]
    assert len(uuids) == len(set(uuids))
    for u in uuids:
        uuidlib.UUID(u)  # raises if not a valid uuid


@pytest.mark.unit
def test_detection_identity_unchanged_by_signature():
    # the cache/diff identity (snapshot._detection_identity) keys on
    # (description, str(details)) and must NOT change with signature fields
    from saq.analysis.snapshot import _detection_identity
    a = DetectionPoint("d", details={"k": 1}, signature_uuid="u1", signature_version="v1")
    b = DetectionPoint("d", details={"k": 1}, signature_uuid="u2", signature_version="v2")
    assert _detection_identity(a) == _detection_identity(b)
