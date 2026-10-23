import logging

import pytest

from saq.analysis import Analysis, RootAnalysis
from saq.constants import F_FQDN, F_IP, AnalysisExecutionResult
from saq.database.util.tag_mapping import add_observable_tag_mapping
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.modules.tag import (
    ConfigurationDefinedTaggingAnalysis,
    ConfigurationDefinedTaggingAnalyzer,
    CorrelatedTagAnalyzer,
    CorrelatedTagAnalyzerConfig,
    UserDefinedTaggingAnalysis,
    UserDefinedTaggingAnalyzer,
)
from saq.signatures.builtin import ALERTABLE_TAG, CORRELATED_TAG_MATCH


class _TestAnalysis(Analysis):
    pass


def _config(config_class=AnalysisModuleConfig, **kwargs):
    return config_class(name="test_tagging", python_module="saq.modules.tag", python_class="Test", enabled=True,
                        **kwargs)


def _all_detections(root):
    return [(obj, d) for obj in root.all for d in obj.detections]


@pytest.fixture
def tree():
    """root -> c (with analysis) -> a, b; root -> d (with analysis) -> e"""
    root = RootAnalysis()
    c = root.add_observable_by_spec(F_FQDN, "c.example.com")
    c_analysis = c.add_analysis(_TestAnalysis())
    a = c_analysis.add_observable_by_spec(F_IP, "10.0.0.1")
    b = c_analysis.add_observable_by_spec(F_IP, "10.0.0.2")
    d = root.add_observable_by_spec(F_FQDN, "d.example.com")
    e = d.add_analysis(_TestAnalysis()).add_observable_by_spec(F_IP, "10.0.0.3")
    return root, a, b, e


def _correlated_analyzer(root, **definitions):
    # the engine gives modules the root itself, not an adapter
    return CorrelatedTagAnalyzer(context=AnalysisModuleContext(root=root),
                                 config=_config(CorrelatedTagAnalyzerConfig, **definitions))


@pytest.mark.unit
def test_correlated_tags_with_common_ancestor(tree):
    root, a, b, _ = tree
    a.add_tag("t1")
    b.add_tag("t2")
    analyzer = _correlated_analyzer(root, definition_001_rule="t1, t2", definition_001_text="t1 and t2")

    assert analyzer.execute_post_analysis() == AnalysisExecutionResult.COMPLETED

    detections = _all_detections(root)
    assert detections
    assert {d.description for _, d in detections} == {"Correlated Tag Match: t1 and t2"}
    assert {d.signature_uuid for _, d in detections} == {CORRELATED_TAG_MATCH.uuid}


@pytest.mark.unit
def test_correlated_tags_without_common_ancestor(tree):
    # a and e only share the root, which doesn't count
    root, a, _, e = tree
    a.add_tag("t1")
    e.add_tag("t2")
    analyzer = _correlated_analyzer(root, definition_001_rule="t1,t2", definition_001_text="t1 and t2")

    analyzer.execute_post_analysis()

    assert _all_detections(root) == []


@pytest.mark.unit
def test_correlated_tags_incomplete(tree):
    root, a, b, _ = tree
    a.add_tag("t1")
    b.add_tag("t2")
    analyzer = _correlated_analyzer(root, definition_001_rule="t1,t2,t3", definition_001_text="all three")

    analyzer.execute_post_analysis()

    assert _all_detections(root) == []


@pytest.mark.unit
def test_correlated_tag_definition_without_text(caplog):
    analyzer = _correlated_analyzer(RootAnalysis(), definition_001_rule="t1,t2", definition_002_rule="t3",
                                    definition_002_text="t3 alone")

    assert [(d.text, d.tags) for d in analyzer.definitions] == [("t3 alone", {"t3"})]
    assert any(r.levelno == logging.ERROR and "definition_001_rule" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_configuration_defined_tagging(tree, monkeypatch):
    root, a, b, e = tree
    monkeypatch.setattr("saq.modules.tag.get_config",
                        lambda: type("_Config", (), {"tags": {"phish": "alert", "internal": "hidden"}})())
    analyzer = ConfigurationDefinedTaggingAnalyzer(context=AnalysisModuleContext(root=root), config=_config())
    a.add_tag("phish")
    e.add_tag("phish")
    b.add_tag("internal")

    assert analyzer.generated_analysis_type is ConfigurationDefinedTaggingAnalysis
    assert analyzer.execute_analysis(a) == AnalysisExecutionResult.COMPLETED
    assert analyzer.execute_post_analysis() == AnalysisExecutionResult.COMPLETED

    # one detection point per alertable tag, however many objects carry it
    assert [(d.description, d.signature_uuid) for d in root.detections] == [
        ("tag phish is configured to be alertable", ALERTABLE_TAG.uuid)]
    assert analyzer.is_alertable_tag("phish")
    assert not analyzer.is_alertable_tag("internal")
    assert not analyzer.is_alertable_tag("unknown")


@pytest.mark.integration
def test_user_defined_tagging(root_analysis):
    tagged = root_analysis.add_observable_by_spec(F_IP, "10.0.0.1")
    add_observable_tag_mapping(tagged, "known-scanner")
    add_observable_tag_mapping(tagged, "vpn")
    untagged = root_analysis.add_observable_by_spec(F_IP, "10.0.0.2")
    analyzer = UserDefinedTaggingAnalyzer(context=AnalysisModuleContext(root=root_analysis), config=_config())

    assert analyzer.valid_observable_types is None
    assert analyzer.execute_analysis(tagged) == AnalysisExecutionResult.COMPLETED
    analysis = tagged.get_analysis(UserDefinedTaggingAnalysis)
    assert sorted(analysis.tags_added) == ["known-scanner", "vpn"]
    assert tagged.has_tag("known-scanner") and tagged.has_tag("vpn")
    assert analysis.generate_summary() == "User Defined Tagging: added 2 tags"

    analyzer.execute_analysis(untagged)
    analysis = untagged.get_analysis(UserDefinedTaggingAnalysis)
    assert analysis.tags_added == []
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_user_defined_tagging_database_error(monkeypatch, caplog):
    def _fail():
        raise RuntimeError("database is down")

    monkeypatch.setattr("saq.modules.tag.get_db_connection", _fail)
    root = RootAnalysis()
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")
    analyzer = UserDefinedTaggingAnalyzer(context=AnalysisModuleContext(root=root), config=_config())

    with pytest.raises(RuntimeError, match="database is down"):
        analyzer.execute_analysis(observable)

    assert any(r.levelno == logging.ERROR and "unable to fetch tags" in r.getMessage() for r in caplog.records)
