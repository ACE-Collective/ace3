"""Pins the detection identity formula (saq.analysis.detection_identity).

Every analyst verdict is keyed on the content hash these tests pin. If one of the literal hashes
below stops matching, the change re-keys every detection and orphans every verdict: it is a data
migration, not a refactor, and the test must not simply be updated to the new value.
"""

import hashlib
import os

import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.detection_identity import (
    NODE_KIND_ANALYSIS,
    NODE_KIND_OBSERVABLE,
    NODE_KIND_ROOT,
    NodeIdentity,
    detection_content_hash,
    node_identity,
)
from saq.analysis.detection_point import DetectionPoint
from saq.analysis.root import RootAnalysis
from saq.constants import F_IPV4
from saq.database.util.index import build_desired_index

SIGNATURE_UUID = "11111111-1111-1111-1111-111111111111"
IPV4_VALUE_SHA256 = "f5047344122f0dee9974ba6761e61c6b8649e1f3968d13a635ebbf7be53a3a0d"  # sha256("10.0.0.1")


class IdentityTestAnalysis(Analysis):
    pass


def _detection():
    return DetectionPoint("matched", details={"b": 1, "a": "ü"},
                          signature_uuid=SIGNATURE_UUID, signature_version="v")


# --- the formula, pinned with literal values -------------------------------------------------

@pytest.mark.unit
def test_node_keys_are_pinned():
    assert NodeIdentity(kind=NODE_KIND_ROOT).key == '["root"]'
    assert NodeIdentity(kind=NODE_KIND_OBSERVABLE, type="ipv4", value_sha256=IPV4_VALUE_SHA256).key == \
        '["observable","ipv4","' + IPV4_VALUE_SHA256 + '"]'
    assert NodeIdentity(kind=NODE_KIND_ANALYSIS, type="ipv4", value_sha256=IPV4_VALUE_SHA256,
                        module_path="saq.modules.example:ExampleAnalyzer").key == \
        '["analysis","saq.modules.example:ExampleAnalyzer","ipv4","' + IPV4_VALUE_SHA256 + '"]'


@pytest.mark.unit
def test_content_hash_on_root_is_pinned():
    assert detection_content_hash(NodeIdentity(kind=NODE_KIND_ROOT), _detection()) == \
        "f71e639a7680ee158e00aadcb34c12dd8684007f0a87f8d826fbabd8436a239c"


@pytest.mark.unit
def test_content_hash_on_observable_is_pinned():
    identity = NodeIdentity(kind=NODE_KIND_OBSERVABLE, type="ipv4", value_sha256=IPV4_VALUE_SHA256)
    assert detection_content_hash(identity, _detection()) == \
        "200ced2296cf3fae2f381780d95898a952d0239a2ecad1b58127e431d1eff395"


@pytest.mark.unit
def test_content_hash_on_analysis_is_pinned():
    identity = NodeIdentity(kind=NODE_KIND_ANALYSIS, type="ipv4", value_sha256=IPV4_VALUE_SHA256,
                            module_path="saq.modules.example:ExampleAnalyzer")
    assert detection_content_hash(identity, _detection()) == \
        "d43e33d75df46464af82745497bcb82f2a42cca122bbaa78e3b8446456e73cc7"


@pytest.mark.unit
def test_content_hash_with_unicode_description_is_pinned():
    dp = DetectionPoint("détection ✓", signature_uuid=SIGNATURE_UUID, signature_version="v")
    assert detection_content_hash(NodeIdentity(kind=NODE_KIND_ROOT), dp) == \
        "e94cbcd9c59642687ee1f00d1a65f86321bf3596a70c6f76351aa666389d5f3b"


@pytest.mark.unit
def test_content_hash_ignores_metadata_and_details_key_order():
    root = NodeIdentity(kind=NODE_KIND_ROOT)
    a = _detection()
    # details key order, queue, signature_version and signature_family are not identity
    b = DetectionPoint("matched", details={"a": "ü", "b": 1}, queue="internal",
                       signature_uuid=SIGNATURE_UUID, signature_version="other", signature_family="yara")
    assert detection_content_hash(root, a) == detection_content_hash(root, b)


@pytest.mark.unit
def test_content_hash_is_sensitive_to_every_identity_field():
    root = NodeIdentity(kind=NODE_KIND_ROOT)
    observable = NodeIdentity(kind=NODE_KIND_OBSERVABLE, type="ipv4", value_sha256=IPV4_VALUE_SHA256)
    base = detection_content_hash(root, _detection())
    assert detection_content_hash(observable, _detection()) != base
    assert detection_content_hash(root, DetectionPoint(
        "matched", details={"b": 1, "a": "ü"}, signature_uuid="22222222-2222-2222-2222-222222222222")) != base
    assert detection_content_hash(root, DetectionPoint(
        "other", details={"b": 1, "a": "ü"}, signature_uuid=SIGNATURE_UUID)) != base
    assert detection_content_hash(root, DetectionPoint(
        "matched", details={"b": 2, "a": "ü"}, signature_uuid=SIGNATURE_UUID)) != base


# --- node_identity() on real tree nodes ------------------------------------------------------

@pytest.mark.unit
def test_node_identity_of_root(root_analysis: RootAnalysis):
    # RootAnalysis is an Analysis: it must still come out as the root
    assert node_identity(root_analysis) == NodeIdentity(kind=NODE_KIND_ROOT)


@pytest.mark.unit
def test_node_identity_of_observable(root_analysis: RootAnalysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "10.0.0.1")
    assert node_identity(observable) == NodeIdentity(
        kind=NODE_KIND_OBSERVABLE, type=F_IPV4, value_sha256=IPV4_VALUE_SHA256)


@pytest.mark.unit
def test_node_identity_of_analysis(root_analysis: RootAnalysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "10.0.0.1")
    analysis = observable.add_analysis(IdentityTestAnalysis())
    assert node_identity(analysis) == NodeIdentity(
        kind=NODE_KIND_ANALYSIS, type=F_IPV4, value_sha256=IPV4_VALUE_SHA256,
        module_path="tests.saq.analysis.test_detection_identity:IdentityTestAnalysis")


@pytest.mark.unit
def test_node_identity_of_file_uses_the_content_sha256(root_analysis: RootAnalysis, tmp_path):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"hello world")
    observable = root_analysis.add_file_observable(str(path))
    expected = hashlib.sha256(b"hello world").hexdigest()

    # the file's bytes are not needed: an archived alert has none
    os.remove(observable.full_path)

    identity = node_identity(observable)
    assert identity.value_sha256 == expected == observable.value
    # the same key the observables table uses, so detections join to observables(type, sha256)
    assert bytes.fromhex(identity.value_sha256) == observable.sha256_bytes


@pytest.mark.unit
def test_node_identity_does_not_depend_on_uuids(root_analysis: RootAnalysis):
    other = RootAnalysis()
    a = root_analysis.add_observable_by_spec(F_IPV4, "10.0.0.1")
    b = other.add_observable_by_spec(F_IPV4, "10.0.0.1")
    assert a.uuid != b.uuid
    assert node_identity(a) == node_identity(b)


# --- the desired index keys detections on the node -------------------------------------------

@pytest.mark.unit
def test_same_detection_on_different_nodes_is_different_rows(root_analysis: RootAnalysis):
    first = root_analysis.add_observable_by_spec(F_IPV4, "10.0.0.1")
    second = root_analysis.add_observable_by_spec(F_IPV4, "10.0.0.2")
    analysis = first.add_analysis(IdentityTestAnalysis())
    for node in (root_analysis, first, second, analysis):
        node.add_detection_point("URL has matches on Google Safe Browsing List")

    desired = build_desired_index(root_analysis)

    assert len(desired.detection_points) == 4
    kinds = sorted(d.identity.kind for d in desired.detection_points.values())
    assert kinds == [NODE_KIND_ANALYSIS, NODE_KIND_OBSERVABLE, NODE_KIND_OBSERVABLE, NODE_KIND_ROOT]
