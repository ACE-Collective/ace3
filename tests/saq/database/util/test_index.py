"""Unit tests for the pure (no-I/O) half of saq.database.util.index."""

import hashlib

import pytest

from saq.analysis.detection_point import DetectionPoint
from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST
from saq.database.util.index import (
    CHUNK_SIZE,
    IndexSyncResult,
    _placeholders,
    _row_placeholders,
    build_desired_index,
    chunked,
    observable_key,
    tag_key,
)


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


@pytest.mark.unit
def test_tag_key_folds_case():
    # tags.name is utf8mb4_unicode_520_ci, so these are the same catalog row. If the key
    # did not fold, a SELECT that returned 'foo' would look like a miss for 'Foo', the
    # follow-up INSERT IGNORE would silently do nothing and the tag would never index.
    assert tag_key("Foo") == tag_key("foo") == tag_key("FOO")
    assert tag_key("foo") != tag_key("bar")


@pytest.mark.unit
def test_observable_key_folds_type_but_not_hash():
    digest = _sha256("value")
    assert observable_key("IPV4", digest) == observable_key("ipv4", digest)
    # sha256 is VARBINARY and compares byte-exact
    assert observable_key("ipv4", digest) != observable_key("ipv4", _sha256("other"))


@pytest.mark.unit
@pytest.mark.parametrize("count,size,expected", [
    (0, 3, []),
    (3, 3, [[0, 1, 2]]),
    (4, 3, [[0, 1, 2], [3]]),
    (2, 1, [[0], [1]]),
])
def test_chunked(count, size, expected):
    assert list(chunked(list(range(count)), size)) == expected


@pytest.mark.unit
def test_chunked_defaults_to_chunk_size():
    assert len(list(chunked(list(range(CHUNK_SIZE + 1))))) == 2


@pytest.mark.unit
def test_placeholders():
    assert _placeholders(3) == "%s,%s,%s"
    assert _row_placeholders(2, 2) == "(%s,%s),(%s,%s)"
    assert _row_placeholders(1, 3) == "(%s,%s,%s)"


@pytest.mark.unit
def test_index_sync_result_changed():
    result = IndexSyncResult()
    assert not result.changed
    assert result.total_writes == 0

    # unresolved_* are diagnostics, not writes -- they must not report as a change
    result.unresolved_tags = 1
    assert not result.changed

    result.observable_mappings_added = 1
    assert result.changed
    assert result.total_writes == 1


@pytest.mark.unit
def test_build_desired_index_excludes_ignored_observables(root_analysis: RootAnalysis):
    kept = root_analysis.add_observable_by_spec(F_TEST, "kept")
    ignored = root_analysis.add_observable_by_spec(F_TEST, "ignored")
    ignored.ignored = True

    desired = build_desired_index(root_analysis)

    assert observable_key(kept.type, kept.sha256_bytes) in desired.observables
    assert observable_key(ignored.type, ignored.sha256_bytes) not in desired.observables


@pytest.mark.unit
def test_build_desired_index_collapses_duplicate_observables(root_analysis: RootAnalysis):
    # the same (type, value) added twice is one row in the observables catalog
    first = root_analysis.add_observable_by_spec(F_TEST, "same")
    second = root_analysis.add_observable_by_spec(F_TEST, "same")
    assert first.sha256_bytes == second.sha256_bytes

    desired = build_desired_index(root_analysis)

    assert len(desired.observables) == 1


@pytest.mark.unit
def test_build_desired_index_separates_root_tags_from_observable_tags(root_analysis: RootAnalysis):
    root_analysis.add_tag("root_only")
    observable = root_analysis.add_observable_by_spec(F_TEST, "tagged")
    observable.add_tag("on_observable")

    desired = build_desired_index(root_analysis)

    # all_tags spans the whole tree, so tag_mapping gets both
    assert tag_key("root_only") in desired.tags
    assert tag_key("on_observable") in desired.tags

    # but observable_tag_index only records tags actually attached to an observable
    key = observable_key(observable.type, observable.sha256_bytes)
    assert desired.observable_tags == {(key, tag_key("on_observable"))}


@pytest.mark.unit
def test_build_desired_index_keeps_original_tag_name_for_insert(root_analysis: RootAnalysis):
    root_analysis.add_tag("MixedCase")

    desired = build_desired_index(root_analysis)

    assert desired.tags[tag_key("MixedCase")] == "MixedCase"


@pytest.mark.unit
def test_build_desired_index_dedupes_detection_points_by_content_hash(root_analysis: RootAnalysis):
    observable = root_analysis.add_observable_by_spec(F_TEST, "detected")
    observable.add_detection_point("same detection")
    root_analysis.add_detection_point("same detection")
    root_analysis.add_detection_point("different detection")

    desired = build_desired_index(root_analysis)

    assert len(desired.detection_points) == 2
    expected = DetectionPoint(description="same detection").content_hash
    assert expected in desired.detection_points
