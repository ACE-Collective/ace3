"""Unit tests for the pure (no-I/O) half of saq.database.util.index."""

import hashlib

import pytest

from saq.analysis.analysis import Analysis, UnknownAnalysis
from saq.analysis.detection_point import DetectionPoint
from saq.analysis.presenter import analysis_presenter
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter
from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST
from saq.database.util.index import (
    CHUNK_SIZE,
    IndexSyncResult,
    _placeholders,
    _row_placeholders,
    analysis_type_label,
    build_desired_index,
    chunked,
    is_indexed_analysis,
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


class FoundTestAnalysis(Analysis):
    @property
    def display_name(self) -> str:
        return "Found Test Analysis"


class EmptyTestAnalysis(Analysis):
    pass


class ExtractorTestAnalysis(Analysis):
    pass


class HiddenTestAnalysis(Analysis):
    pass


class HiddenTestAnalysisPresenter(AnalysisPresenter):
    @property
    def should_render(self) -> bool:
        return False


def _found(summary: str = "found something") -> FoundTestAnalysis:
    analysis = FoundTestAnalysis()
    analysis.summary = summary
    return analysis


@pytest.mark.unit
def test_is_indexed_analysis_follows_what_the_tree_renders(root_analysis: RootAnalysis, monkeypatch):
    observable = root_analysis.add_observable_by_spec(F_TEST, "value")

    found = observable.add_analysis(_found())
    assert is_indexed_analysis(found)

    # ran and found nothing: the negative result QRCodeAnalyzer records for caching
    empty = observable.add_analysis(EmptyTestAnalysis())
    assert not is_indexed_analysis(empty)

    # no summary, but it produced observables (PDFAnalysis and the other extractors)
    extractor = observable.add_analysis(ExtractorTestAnalysis())
    extractor.add_observable_by_spec(F_TEST, "extracted")
    assert is_indexed_analysis(extractor)

    # a presenter that hides the analysis hides it from the index too
    hidden = observable.add_analysis(HiddenTestAnalysis())
    hidden.summary = "never shown"
    monkeypatch.setitem(analysis_presenter._ANALYSIS_PRESENTER_REGISTRY, HiddenTestAnalysis, HiddenTestAnalysisPresenter)
    assert not is_indexed_analysis(hidden)


@pytest.mark.unit
def test_analysis_type_label():
    assert analysis_type_label(_found()) == "Found Test Analysis"

    instanced = _found()
    instanced.instance = "o365_session_activity"
    assert analysis_type_label(instanced) == "Found Test Analysis (o365_session_activity)"

    # a class that no longer loads only has its module path to go on
    unknown = UnknownAnalysis("saq.modules.gone:RemovedAnalysis:some_instance")
    assert analysis_type_label(unknown) == "RemovedAnalysis (some_instance)"


@pytest.mark.unit
def test_build_desired_index_records_analysis_types_the_tree_shows(root_analysis: RootAnalysis):
    first = root_analysis.add_observable_by_spec(F_TEST, "first")
    first.add_analysis(_found())
    first.add_analysis(EmptyTestAnalysis())

    # the same type on a second observable is still one type
    second = root_analysis.add_observable_by_spec(F_TEST, "second")
    second.add_analysis(_found("found something else"))

    desired = build_desired_index(root_analysis)

    assert desired.analysis_types == {FoundTestAnalysis().module_path: "Found Test Analysis"}


@pytest.mark.unit
def test_build_desired_index_keeps_instances_apart(root_analysis: RootAnalysis):
    observable = root_analysis.add_observable_by_spec(F_TEST, "value")
    for instance in ("one", "two"):
        analysis = _found()
        analysis.instance = instance
        observable.add_analysis(analysis)

    desired = build_desired_index(root_analysis)

    assert set(desired.analysis_types.values()) == {"Found Test Analysis (one)", "Found Test Analysis (two)"}
    assert all(module_path.endswith((":one", ":two")) for module_path in desired.analysis_types)


@pytest.mark.unit
def test_build_desired_index_skips_analysis_of_ignored_observables(root_analysis: RootAnalysis):
    ignored = root_analysis.add_observable_by_spec(F_TEST, "ignored")
    ignored.add_analysis(_found())
    ignored.ignored = True

    assert build_desired_index(root_analysis).analysis_types == {}


@pytest.mark.unit
def test_index_sync_result_counts_analysis_writes():
    result = IndexSyncResult()
    result.unresolved_analysis_types = 1
    assert not result.changed

    result.analysis_types_created = 1
    result.analysis_mappings_added = 2
    result.analysis_mappings_removed = 3
    assert result.total_writes == 6
    assert "analysis_mapping +2/-3" in str(result)
