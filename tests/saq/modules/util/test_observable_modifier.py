import logging
import os
import re

import pytest
import yaml

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_OBSERVABLE_MODIFIER,
    F_FILE,
    F_FQDN,
    F_URL,
    AnalysisExecutionResult,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.util.observable_modifier import (
    ObservableModifierAnalysis,
    ObservableModifierAnalyzer,
    ObservableModifierConfig,
    Rule,
    RuleActions,
    RuleConditions,
    TreeCondition,
    get_nested_value,
    _get_ancestor_analyses,
)
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


def _create_analyzer_with_rules(root, rules_data):
    """Helper to create an analyzer with specific rules written to a temp YAML file."""
    yaml_path = os.path.join(root.storage_dir, "test_rules.yaml")
    with open(yaml_path, "w") as f:
        yaml.dump({"rules": rules_data}, f)

    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    config.rules_config_path = yaml_path
    analyzer = ObservableModifierAnalyzer(context=context, config=config)
    adapter = AnalysisModuleAdapter(analyzer)
    return adapter


def _add_file_observable(root, filename, content=""):
    """Helper to create a real file and add it as a file observable."""
    target_path = root.create_file_path(filename)
    with open(target_path, "w") as fp:
        fp.write(content)
    return root.add_file_observable(target_path)


# ============================================================
# Unit tests for helper functions
# ============================================================


@pytest.mark.unit
def test_get_nested_value_simple():
    data = {"email": {"from_address": "test@example.com", "subject": "Hello"}}
    assert get_nested_value(data, "email.from_address") == "test@example.com"
    assert get_nested_value(data, "email.subject") == "Hello"


@pytest.mark.unit
def test_get_nested_value_missing_key():
    data = {"email": {"from_address": "test@example.com"}}
    assert get_nested_value(data, "email.to_address") is None
    assert get_nested_value(data, "nonexistent.path") is None


@pytest.mark.unit
def test_get_nested_value_non_dict_intermediate():
    data = {"email": "not_a_dict"}
    assert get_nested_value(data, "email.from_address") is None


@pytest.mark.unit
def test_get_nested_value_top_level():
    data = {"status": "active"}
    assert get_nested_value(data, "status") == "active"


# ============================================================
# Analysis class tests
# ============================================================


@pytest.mark.unit
def test_analysis_display_name():
    analysis = ObservableModifierAnalysis()
    assert analysis.display_name == "Observable Modifier Analysis"


@pytest.mark.unit
def test_analysis_summary_no_matches():
    analysis = ObservableModifierAnalysis()
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_analysis_summary_with_matches():
    analysis = ObservableModifierAnalysis()
    analysis.details["matched_rules"] = [
        {"name": "rule1", "actions_applied": {}},
        {"name": "rule2", "actions_applied": {}},
    ]
    summary = analysis.generate_summary()
    assert "2 rule(s)" in summary
    assert "rule1" in summary
    assert "rule2" in summary


# ============================================================
# RuleConditions tests (using lightweight mocks)
# ============================================================


class MockObservable:
    """Minimal mock for condition testing."""

    def __init__(self, type="file", value="test.html", tags=None, directives=None):
        self.type = type
        self.value = value
        self._tags = tags or []
        self._directives = directives or []

    def has_tag(self, tag):
        return tag in self._tags

    def has_directive(self, directive):
        return directive in self._directives


class MockRoot:
    """Minimal mock for root analysis."""

    def __init__(self, tags=None, alert_type=None, queue="default", all_analysis=None):
        self._tags = tags or []
        self.alert_type = alert_type
        self.queue = queue
        self.all_analysis = all_analysis or []

    def has_tag(self, tag):
        return tag in self._tags


@pytest.mark.unit
def test_conditions_empty_matches_everything():
    """Empty conditions should match any observable."""
    cond = RuleConditions()
    obs = MockObservable()
    root = MockRoot()
    assert cond.evaluate(obs, root) is True


@pytest.mark.unit
def test_conditions_observable_types_match():
    cond = RuleConditions(observable_types=["file", "url"])
    assert cond.evaluate(MockObservable(type="file"), MockRoot()) is True
    assert cond.evaluate(MockObservable(type="url"), MockRoot()) is True
    assert cond.evaluate(MockObservable(type="ip"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_alert_tags():
    cond = RuleConditions(alert_tags=["phishing", "external"])
    assert cond.evaluate(MockObservable(), MockRoot(tags=["phishing", "external", "other"])) is True
    assert cond.evaluate(MockObservable(), MockRoot(tags=["phishing"])) is False
    assert cond.evaluate(MockObservable(), MockRoot(tags=[])) is False


@pytest.mark.unit
def test_conditions_alert_type():
    cond = RuleConditions(alert_type="splunk - threat_intel")
    assert cond.evaluate(MockObservable(), MockRoot(alert_type="splunk - threat_intel")) is True
    assert cond.evaluate(MockObservable(), MockRoot(alert_type="other")) is False


@pytest.mark.unit
def test_conditions_queue():
    cond = RuleConditions(queue="external")
    assert cond.evaluate(MockObservable(), MockRoot(queue="external")) is True
    assert cond.evaluate(MockObservable(), MockRoot(queue="internal")) is False


@pytest.mark.unit
def test_conditions_has_tags():
    cond = RuleConditions(has_tags=["suspicious"])
    assert cond.evaluate(MockObservable(tags=["suspicious", "other"]), MockRoot()) is True
    assert cond.evaluate(MockObservable(tags=[]), MockRoot()) is False


@pytest.mark.unit
def test_conditions_has_directives():
    cond = RuleConditions(has_directives=["sandbox"])
    assert cond.evaluate(MockObservable(directives=["sandbox"]), MockRoot()) is True
    assert cond.evaluate(MockObservable(directives=[]), MockRoot()) is False


@pytest.mark.unit
def test_conditions_value_pattern():
    cond = RuleConditions(value_pattern=re.compile(r".*\.html$"))
    assert cond.evaluate(MockObservable(value="body.html"), MockRoot()) is True
    assert cond.evaluate(MockObservable(value="doc.pdf"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_and_logic():
    """All conditions must match (AND logic)."""
    cond = RuleConditions(
        observable_types=["file"],
        alert_tags=["phishing"],
        value_pattern=re.compile(r".*\.html$"),
    )
    obs = MockObservable(type="file", value="body.html")
    root = MockRoot(tags=["phishing"])
    assert cond.evaluate(obs, root) is True

    # Fails if any one condition doesn't match
    assert cond.evaluate(MockObservable(type="url", value="body.html"), MockRoot(tags=["phishing"])) is False
    assert cond.evaluate(MockObservable(type="file", value="body.html"), MockRoot(tags=[])) is False
    assert cond.evaluate(MockObservable(type="file", value="body.pdf"), MockRoot(tags=["phishing"])) is False


# ============================================================
# RuleActions tests (using lightweight mocks)
# ============================================================


class ActionTracker:
    """Mock observable that tracks applied actions."""

    def __init__(self):
        self.directives = []
        self.tags = []
        self.detection_points = []
        self._excluded_analysis = []
        self._limited_analysis = []

    def add_directive(self, d):
        self.directives.append(d)

    def add_tag(self, t):
        self.tags.append(t)

    def add_detection_point(self, desc):
        self.detection_points.append(desc)


@pytest.mark.unit
def test_actions_add_directives():
    actions = RuleActions(add_directives=["extract_iocs", "sandbox"])
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert tracker.directives == ["extract_iocs", "sandbox"]
    assert applied["add_directives"] == ["extract_iocs", "sandbox"]


@pytest.mark.unit
def test_actions_add_tags():
    actions = RuleActions(add_tags=["suspicious", "escalation"])
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert tracker.tags == ["suspicious", "escalation"]
    assert applied["add_tags"] == ["suspicious", "escalation"]


@pytest.mark.unit
def test_actions_exclude_analysis():
    actions = RuleActions(exclude_analysis=["saq.modules.sandbox:SandboxAnalyzer"])
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert "saq.modules.sandbox:SandboxAnalyzer" in tracker._excluded_analysis
    assert applied["exclude_analysis"] == ["saq.modules.sandbox:SandboxAnalyzer"]


@pytest.mark.unit
def test_actions_limit_analysis():
    actions = RuleActions(limit_analysis=["saq.modules.file_analysis.ioc_extraction:IOCExtractionAnalyzer"])
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert "saq.modules.file_analysis.ioc_extraction:IOCExtractionAnalyzer" in tracker._limited_analysis
    assert applied["limit_analysis"] == ["saq.modules.file_analysis.ioc_extraction:IOCExtractionAnalyzer"]


@pytest.mark.unit
def test_actions_add_detection_points():
    actions = RuleActions(add_detection_points=["suspicious file detected", "known malware pattern"])
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert tracker.detection_points == ["suspicious file detected", "known malware pattern"]
    assert applied["add_detection_points"] == ["suspicious file detected", "known malware pattern"]


@pytest.mark.unit
def test_actions_empty():
    """Empty actions should return empty dict."""
    actions = RuleActions()
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert applied == {}


# ============================================================
# execute_analysis / execute_final_analysis behavior tests
# ============================================================


@pytest.mark.unit
def test_execute_analysis_returns_incomplete():
    """execute_analysis should return INCOMPLETE without creating any analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "test rule",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # No analysis should be created by execute_analysis
    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is None
    # No actions should be applied yet
    assert not observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_execute_final_analysis_evaluates_rules():
    """execute_final_analysis should evaluate rules and apply actions."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "test rule",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # First call execute_analysis to initialize the module
    adapter.execute_analysis(observable)

    # Then call final analysis which should evaluate rules
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("extract_iocs")


# ============================================================
# Integration tests using real analysis tree (final analysis path)
# ============================================================


@pytest.mark.unit
def test_no_rules_no_modification():
    """When there are no rules, no modification should happen."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, [])

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is None


@pytest.mark.unit
def test_matching_rule_adds_directive():
    """A matching rule should add the specified directive to the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [{
        "name": "test rule",
        "conditions": {
            "observable_types": ["url"],
            "value_pattern": r".*\.html$",
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("extract_iocs")

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert len(analysis.details["matched_rules"]) == 1
    assert analysis.details["matched_rules"][0]["name"] == "test rule"


@pytest.mark.unit
def test_non_matching_rule_no_modification():
    """A non-matching rule should not modify the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/document.pdf")
    rules = [{
        "name": "html only",
        "conditions": {
            "observable_types": ["url"],
            "value_pattern": r".*\.html$",
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("extract_iocs")

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is None


@pytest.mark.unit
def test_disabled_rule_skipped():
    """Disabled rules should not be evaluated."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "disabled rule",
        "enabled": False,
        "conditions": {
            "observable_types": ["url"],
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_multiple_rules_independent():
    """Multiple rules should be evaluated independently."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [
        {
            "name": "rule 1",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["crawl"]},
        },
        {
            "name": "rule 2",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_tags": ["processed"]},
        },
        {
            "name": "rule 3 (no match)",
            "conditions": {"observable_types": ["file"]},
            "actions": {"add_tags": ["should_not_appear"]},
        },
    ]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("crawl")
    assert observable.has_tag("processed")
    assert not observable.has_tag("should_not_appear")

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert len(analysis.details["matched_rules"]) == 2


@pytest.mark.unit
def test_alert_tag_condition():
    """Rule with alert_tags should only match when root has those tags."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    root.add_tag("phishing")

    observable = root.add_observable_by_spec(F_URL, "https://evil.com")
    rules = [{
        "name": "phishing rule",
        "conditions": {
            "alert_tags": ["phishing"],
            "observable_types": ["url"],
        },
        "actions": {
            "add_directives": ["sandbox"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("sandbox")


@pytest.mark.unit
def test_alert_tag_condition_no_match():
    """Rule should not match when root doesn't have required tags."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://evil.com")
    rules = [{
        "name": "phishing rule",
        "conditions": {
            "alert_tags": ["phishing"],
        },
        "actions": {
            "add_directives": ["sandbox"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("sandbox")


@pytest.mark.unit
def test_alert_type_condition():
    """Rule with alert_type should match when root alert_type matches."""
    root = create_root_analysis(analysis_mode="test_single", alert_type="splunk - threat_intel")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://evil.com")
    rules = [{
        "name": "threat intel URLs",
        "conditions": {
            "alert_type": "splunk - threat_intel",
            "observable_types": ["url"],
        },
        "actions": {
            "add_directives": ["crawl"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("crawl")


@pytest.mark.unit
def test_queue_condition():
    """Rule with queue should match when root queue matches."""
    root = create_root_analysis(analysis_mode="test_single", queue="external")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "external queue rule",
        "conditions": {
            "queue": "external",
        },
        "actions": {
            "add_tags": ["external_alert"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_tag("external_alert")


@pytest.mark.unit
def test_exclude_analysis_action():
    """Rule should add analysis exclusions to the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "skip sandbox",
        "conditions": {
            "observable_types": ["url"],
        },
        "actions": {
            "exclude_analysis": ["saq.modules.sandbox:SandboxAnalyzer"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert "saq.modules.sandbox:SandboxAnalyzer" in observable.excluded_analysis


@pytest.mark.unit
def test_limit_analysis_action():
    """Rule should add analysis limits to the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "limit to ioc extraction",
        "conditions": {
            "observable_types": ["url"],
        },
        "actions": {
            "limit_analysis": ["ioc_extraction"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert "ioc_extraction" in observable.limited_analysis


@pytest.mark.unit
def test_file_observable_matching():
    """Test that rules work correctly with real file observables.
    Note: FileObservable.value is the SHA256 hash, not the filename.
    Use observable_types to match file observables by type."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = _add_file_observable(root, "body.html", "<html><body>test</body></html>")
    rules = [{
        "name": "all files rule",
        "conditions": {
            "observable_types": ["file"],
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_file_name_pattern_match():
    """file_name_pattern should match against the file's name, not its SHA256 hash."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = _add_file_observable(root, "body.html", "<html>test</html>")
    rules = [{
        "name": "html files by name",
        "conditions": {
            "observable_types": ["file"],
            "file_name_pattern": r".*\.html$",
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_file_name_pattern_no_match():
    """file_name_pattern should not match when the file name doesn't match the pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = _add_file_observable(root, "document.pdf", "pdf content")
    rules = [{
        "name": "html files only",
        "conditions": {
            "observable_types": ["file"],
            "file_name_pattern": r".*\.html$",
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_file_name_pattern_skips_non_file_observables():
    """file_name_pattern should not match non-file observables (they have no file_name)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/body.html")
    rules = [{
        "name": "html files by name",
        "conditions": {
            "file_name_pattern": r".*\.html$",
        },
        "actions": {
            "add_directives": ["should_not_appear"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("should_not_appear")


@pytest.mark.unit
def test_invalid_regex_in_value_pattern(caplog):
    """Invalid regex in value_pattern should skip the rule with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "bad regex rule",
        "conditions": {
            "value_pattern": "[invalid regex(",
        },
        "actions": {
            "add_directives": ["should_not_appear"],
        },
    }]

    with caplog.at_level(logging.WARNING):
        adapter = _create_analyzer_with_rules(root, rules)
        adapter.execute_analysis(observable)
        result = adapter.analyze(observable, final_analysis=True)

    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("should_not_appear")
    assert any("invalid" in msg.lower() for msg in [r.message for r in caplog.records])


@pytest.mark.unit
def test_invalid_regex_in_details_match(caplog):
    """Invalid regex in details_match should skip the rule with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "bad details regex rule",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": "test:TestAnalysis",
                "details_match": {
                    "email.from": "[bad regex(",
                },
            }],
        },
        "actions": {
            "add_directives": ["should_not_appear"],
        },
    }]

    with caplog.at_level(logging.WARNING):
        adapter = _create_analyzer_with_rules(root, rules)
        adapter.execute_analysis(observable)
        result = adapter.analyze(observable, final_analysis=True)

    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("should_not_appear")
    assert any("invalid" in msg.lower() for msg in [r.message for r in caplog.records])


@pytest.mark.unit
def test_empty_config_handles_gracefully():
    """An empty YAML config file should not cause errors."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    yaml_path = os.path.join(root.storage_dir, "empty_rules.yaml")
    with open(yaml_path, "w") as f:
        f.write("")

    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    config.rules_config_path = yaml_path
    analyzer = ObservableModifierAnalyzer(context=context, config=config)
    adapter = AnalysisModuleAdapter(analyzer)

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.unit
def test_missing_config_handles_gracefully():
    """A missing config file should not crash — the module runs with no rules."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    config.rules_config_path = "/nonexistent/path/rules.yaml"
    analyzer = ObservableModifierAnalyzer(context=context, config=config)
    adapter = AnalysisModuleAdapter(analyzer)

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)

    assert result == AnalysisExecutionResult.COMPLETED
    # No rules loaded, so no analysis should be created
    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is None


@pytest.mark.unit
def test_tree_condition_ancestor_match():
    """Tree condition should find matching analysis in the observable's ancestor chain."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Create a parent observable with analysis in the tree
    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class TestEmailAnalysis(Analysis):
        pass

    email_analysis = TestEmailAnalysis()
    email_analysis.details = {"email": {"from_address": "soc@vendor.com", "subject": "ESCALATION alert"}}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    # Create the target observable (child of the email analysis)
    target_observable = email_analysis.add_observable_by_spec(F_URL, "https://example.com/page.html")

    # The tree condition should match the TestEmailAnalysis (it's an ancestor)
    module_path = f"{TestEmailAnalysis.__module__}:{TestEmailAnalysis.__name__}"
    rules = [{
        "name": "tree condition test",
        "conditions": {
            "observable_types": ["url"],
            "value_pattern": r".*\.html$",
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {
                    "email.from_address": r"soc@vendor\.com",
                },
            }],
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_observable)
    result = adapter.analyze(target_observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert target_observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_tree_condition_no_match():
    """Tree condition should not match when details don't match."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.other.com")

    class TestEmailAnalysis2(Analysis):
        pass

    email_analysis = TestEmailAnalysis2()
    email_analysis.details = {"email": {"from_address": "someone@other.com"}}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    target_observable = email_analysis.add_observable_by_spec(F_URL, "https://example.com/page.html")

    module_path = f"{TestEmailAnalysis2.__module__}:{TestEmailAnalysis2.__name__}"
    rules = [{
        "name": "tree condition no match",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {
                    "email.from_address": r"soc@vendor\.com",
                },
            }],
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_observable)
    result = adapter.analyze(target_observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not target_observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_tree_condition_deep_ancestor_chain():
    """Tree condition should find matching analysis multiple levels up the ancestor chain."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Create deeper chain: root -> obs1 -> analysis1 -> obs2 -> analysis2 -> target
    obs1 = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class AncestorAnalysis(Analysis):
        pass

    class MiddleAnalysis(Analysis):
        pass

    ancestor_analysis = AncestorAnalysis()
    ancestor_analysis.details = {"email": {"from_address": "soc@vendor.com"}}
    ancestor_analysis.details_modified = True
    obs1.add_analysis(ancestor_analysis)

    obs2 = ancestor_analysis.add_observable_by_spec(F_URL, "https://example.com/intermediate")

    middle_analysis = MiddleAnalysis()
    middle_analysis.details = {}
    middle_analysis.details_modified = True
    obs2.add_analysis(middle_analysis)

    target = middle_analysis.add_observable_by_spec(F_URL, "https://example.com/body.html")

    module_path = f"{AncestorAnalysis.__module__}:{AncestorAnalysis.__name__}"
    rules = [{
        "name": "deep ancestor test",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {
                    "email.from_address": r"soc@vendor\.com",
                },
            }],
        },
        "actions": {
            "add_directives": ["extract_iocs"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert target.has_directive("extract_iocs")


@pytest.mark.unit
def test_tree_condition_no_match_sibling_branch():
    """Tree condition with ancestors scope should NOT match analyses in sibling branches."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Branch 1: root -> obs1 -> analysis1 (has matching details)
    obs1 = root.add_observable_by_spec(F_FQDN, "email1.vendor.com")

    class SiblingAnalysis(Analysis):
        pass

    sibling_analysis = SiblingAnalysis()
    sibling_analysis.details = {"email": {"from_address": "soc@vendor.com"}}
    sibling_analysis.details_modified = True
    obs1.add_analysis(sibling_analysis)

    # Branch 2: root -> target (NOT a descendant of analysis1)
    target = root.add_observable_by_spec(F_URL, "https://other.com/file.html")

    module_path = f"{SiblingAnalysis.__module__}:{SiblingAnalysis.__name__}"
    rules = [{
        "name": "sibling branch test",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "ancestors",
                "details_match": {
                    "email.from_address": r"soc@vendor\.com",
                },
            }],
        },
        "actions": {
            "add_directives": ["should_not_appear"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not target.has_directive("should_not_appear")


@pytest.mark.unit
def test_tree_condition_global_scope_finds_sibling():
    """Tree condition with global scope SHOULD match analyses in sibling branches."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Branch 1: root -> obs1 -> analysis1 (has matching details)
    obs1 = root.add_observable_by_spec(F_FQDN, "email1.vendor.com")

    class GlobalSiblingAnalysis(Analysis):
        pass

    sibling_analysis = GlobalSiblingAnalysis()
    sibling_analysis.details = {"email": {"from_address": "soc@vendor.com"}}
    sibling_analysis.details_modified = True
    obs1.add_analysis(sibling_analysis)

    # Branch 2: root -> target (NOT a descendant of analysis1)
    target = root.add_observable_by_spec(F_URL, "https://other.com/file.html")

    module_path = f"{GlobalSiblingAnalysis.__module__}:{GlobalSiblingAnalysis.__name__}"
    rules = [{
        "name": "global sibling test",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "global",
                "details_match": {
                    "email.from_address": r"soc@vendor\.com",
                },
            }],
        },
        "actions": {
            "add_directives": ["found_via_global"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert target.has_directive("found_via_global")


@pytest.mark.unit
def test_tree_condition_global_scope():
    """Tree condition with global scope should search the entire analysis tree."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Create analysis deep in a different branch
    obs1 = root.add_observable_by_spec(F_FQDN, "deep.vendor.com")

    class DeepAnalysis(Analysis):
        pass

    class IntermediateAnalysis(Analysis):
        pass

    deep_analysis = DeepAnalysis()
    deep_analysis.details = {"status": "malicious"}
    deep_analysis.details_modified = True
    obs1.add_analysis(deep_analysis)

    obs2 = deep_analysis.add_observable_by_spec(F_FQDN, "nested.vendor.com")
    intermediate = IntermediateAnalysis()
    intermediate.details = {"threat_level": "high"}
    intermediate.details_modified = True
    obs2.add_analysis(intermediate)

    # Target is in a completely different branch
    target = root.add_observable_by_spec(F_URL, "https://example.com/target.html")

    module_path = f"{IntermediateAnalysis.__module__}:{IntermediateAnalysis.__name__}"
    rules = [{
        "name": "global scope deep search",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "global",
                "details_match": {
                    "threat_level": "high",
                },
            }],
        },
        "actions": {
            "add_tags": ["global_match"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert target.has_tag("global_match")


@pytest.mark.unit
def test_tree_condition_ancestors_scope_in_final_mode():
    """Tree condition with ancestors scope should still work correctly in final analysis mode."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class AncestorScopeAnalysis(Analysis):
        pass

    parent_analysis = AncestorScopeAnalysis()
    parent_analysis.details = {"email": {"from_address": "soc@vendor.com"}}
    parent_analysis.details_modified = True
    parent.add_analysis(parent_analysis)

    target = parent_analysis.add_observable_by_spec(F_URL, "https://example.com/page.html")

    module_path = f"{AncestorScopeAnalysis.__module__}:{AncestorScopeAnalysis.__name__}"
    rules = [{
        "name": "ancestors scope in final mode",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "ancestors",
                "details_match": {
                    "email.from_address": r"soc@vendor\.com",
                },
            }],
        },
        "actions": {
            "add_directives": ["ancestor_found"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert target.has_directive("ancestor_found")


@pytest.mark.unit
def test_tree_condition_without_details_match():
    """Tree condition that only checks analysis_type (no details_match) should match."""
    from saq.analysis.analysis import Analysis

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class TypeOnlyAnalysis(Analysis):
        pass

    analysis = TypeOnlyAnalysis()
    analysis.details = {}
    analysis.details_modified = True
    parent.add_analysis(analysis)

    target = analysis.add_observable_by_spec(F_URL, "https://example.com/attachment.html")

    module_path = f"{TypeOnlyAnalysis.__module__}:{TypeOnlyAnalysis.__name__}"
    rules = [{
        "name": "type-only tree condition",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": module_path,
            }],
        },
        "actions": {
            "add_tags": ["has_analysis"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert target.has_tag("has_analysis")


@pytest.mark.unit
def test_analysis_summary_set():
    """Analysis summary should be set when rules match."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "summary test rule",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_tags": ["tested"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert analysis.summary is not None
    assert "1 rule(s)" in analysis.summary
    assert "summary test rule" in analysis.summary


@pytest.mark.unit
def test_has_tags_on_observable():
    """Rule with has_tags condition should check tags on the observable being evaluated."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    observable.add_tag("needs_processing")

    rules = [{
        "name": "tag check rule",
        "conditions": {
            "has_tags": ["needs_processing"],
        },
        "actions": {
            "add_directives": ["process"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_directive("process")


@pytest.mark.unit
def test_has_directives_on_observable():
    """Rule with has_directives condition should check directives on the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    observable.add_directive("review")

    rules = [{
        "name": "directive check rule",
        "conditions": {
            "has_directives": ["review"],
        },
        "actions": {
            "add_tags": ["reviewed"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_tag("reviewed")


@pytest.mark.unit
def test_get_config_class():
    """Verify the module returns the correct config class."""
    assert ObservableModifierAnalyzer.get_config_class() == ObservableModifierConfig


@pytest.mark.unit
def test_generated_analysis_type():
    """Verify the module generates the correct analysis type."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    analyzer = ObservableModifierAnalyzer(context=context, config=config)
    assert analyzer.generated_analysis_type == ObservableModifierAnalysis


@pytest.mark.unit
def test_detection_point_action_integration():
    """Rule with add_detection_points should add detection points to the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://evil.com/malware.exe")
    rules = [{
        "name": "suspicious download",
        "conditions": {
            "observable_types": ["url"],
            "value_pattern": r"\.exe$",
        },
        "actions": {
            "add_detection_points": ["Matched observable modifier rule: suspicious executable URL"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.has_detection_points()

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert len(analysis.details["matched_rules"]) == 1
    assert "add_detection_points" in analysis.details["matched_rules"][0]["actions_applied"]
