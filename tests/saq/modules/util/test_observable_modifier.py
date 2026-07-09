import logging
import os
import re
import uuid as uuid_lib

import pytest
import yaml

from saq.analysis.analysis import Analysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_OBSERVABLE_MODIFIER,
    DIRECTIVE_EXCLUDE_ALL,
    DIRECTIVE_OCR,
    DIRECTIVE_YARA_META_PREFIX,
    F_EMAIL_ADDRESS,
    F_EMAIL_FROM,
    F_EMAIL_TO,
    F_FQDN,
    F_MESSAGE_ID,
    F_SIGNATURE_ID,
    F_URL,
    F_USER,
    AnalysisExecutionResult,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.ocr import OCRAnalyzer, OCRAnalyzerConfig
from saq.modules.util.observable_modifier import (
    ObservableModifierAnalysis,
    ObservableModifierAnalyzer,
    ObservableModifierConfig,
    RuleActions,
    RuleConditions,
    TreeCondition,
    _AnalysisTypeIndex,
    _load_details_for_match,
    get_nested_value,
)
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


def _create_analyzer_with_rules(root, rules_data, auto_uuid=True):
    """Helper to create an analyzer with specific rules written to a temp YAML file.

    By default, any rule dict without a `uuid` key gets a deterministic test uuid
    injected so existing tests don't need to be rewritten when the uuid field
    became required. Pass auto_uuid=False for tests that need to verify the
    loader's behavior when a uuid is missing.
    """
    if auto_uuid:
        rules_data = [
            {**rule, "uuid": rule.get("uuid") or str(uuid_lib.uuid4())}
            for rule in rules_data
        ]
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


@pytest.mark.unit
def test_get_nested_value_list_mid_path_single_element():
    # Single-row Splunk-style stats result.
    data = {"query_results": [{"message_id_seen": "0"}]}
    assert get_nested_value(data, "query_results.message_id_seen") == ["0"]


@pytest.mark.unit
def test_get_nested_value_list_mid_path_multiple_elements():
    # Multi-row result fans out; results are returned in input order.
    data = {"query_results": [{"x": "a"}, {"x": "b"}, {"x": "c"}]}
    assert get_nested_value(data, "query_results.x") == ["a", "b", "c"]


@pytest.mark.unit
def test_get_nested_value_list_mid_path_partial_matches():
    # Elements that don't have the requested key are silently skipped.
    data = {"query_results": [{"x": "a"}, {"y": "b"}, {"x": "c"}]}
    assert get_nested_value(data, "query_results.x") == ["a", "c"]


@pytest.mark.unit
def test_get_nested_value_list_mid_path_no_matches():
    # No element has the requested key — returns None, not [].
    data = {"query_results": [{"x": "a"}, {"x": "b"}]}
    assert get_nested_value(data, "query_results.y") is None


@pytest.mark.unit
def test_get_nested_value_terminal_list_returned_as_list():
    # Path that resolves to a list value returns the list as-is.
    data = {"tags": ["alpha", "beta"]}
    assert get_nested_value(data, "tags") == ["alpha", "beta"]


@pytest.mark.unit
def test_get_nested_value_nested_lists():
    # List of dicts containing lists of dicts — fan-out flattens to a single list.
    data = {"a": [{"b": [{"c": "1"}, {"c": "2"}]}, {"b": [{"c": "3"}]}]}
    assert get_nested_value(data, "a.b.c") == ["1", "2", "3"]


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

    def __init__(self, type="file", value="test.html", tags=None, directives=None, display_type=None, display_value=None):
        self.type = type
        self.value = value
        self._tags = tags or []
        self._directives = directives or []
        self._display_type = display_type
        self._display_value = display_value

    @property
    def display_type(self) -> str:
        if self._display_type is not None:
            return f"{self._display_type} ({self.type})"
        return self.type

    @display_type.setter
    def display_type(self, value: str):
        self._display_type = value

    @property
    def display_value(self) -> str:
        if self._display_value is not None:
            return f"{self._display_value} ({self.value})"
        return self.value

    @display_value.setter
    def display_value(self, value: str):
        self._display_value = value

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


@pytest.fixture
def hierarchy_with_synthetic_subtype():
    """Seed and restore a synthetic subtype relationship in the global hierarchy.

    Mirrors the snapshot/restore pattern used by
    tests/saq/modules/test_base_module_subtype_dispatch.py so the test stays
    hermetic regardless of what the YAML config has loaded into the registry.
    """
    from saq.observables.type_hierarchy import get_type_hierarchy
    h = get_type_hierarchy()
    parent_snapshot = dict(h._parent)
    h._parent["__pytest_child__"] = "__pytest_parent__"
    h._ancestors_cache.clear()
    try:
        yield h
    finally:
        h._parent = parent_snapshot
        h._ancestors_cache.clear()


@pytest.mark.unit
def test_conditions_observable_types_match_subtype(hierarchy_with_synthetic_subtype):
    """A rule targeting the parent type matches observables of any subtype."""
    cond = RuleConditions(observable_types=["__pytest_parent__"])
    assert cond.evaluate(MockObservable(type="__pytest_child__"), MockRoot()) is True
    assert cond.evaluate(MockObservable(type="__pytest_parent__"), MockRoot()) is True
    assert cond.evaluate(MockObservable(type="ip"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_evaluate_early_observable_types_match_subtype(hierarchy_with_synthetic_subtype):
    """The early-eval path also honors subtype matching."""
    cond = RuleConditions(observable_types=["__pytest_parent__"])
    assert cond.evaluate_early(MockObservable(type="__pytest_child__"), MockRoot()) is True
    assert cond.evaluate_early(MockObservable(type="__pytest_parent__"), MockRoot()) is True
    assert cond.evaluate_early(MockObservable(type="ip"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_observable_types_match_real_email_subtype():
    """A rule targeting email_address matches subtypes loaded from etc/observable_types.yaml.

    The dev/CI default config_path points at etc/observable_types.yaml which
    declares email_from -> email_address (and several other email subtypes).
    """
    from saq.observables.type_hierarchy import get_type_hierarchy
    if not get_type_hierarchy().is_subtype("email_from", "email_address"):
        pytest.skip("email_from -> email_address not loaded in this environment")

    cond = RuleConditions(observable_types=["email_address"])
    assert cond.evaluate(MockObservable(type="email_from"), MockRoot()) is True
    assert cond.evaluate(MockObservable(type="email_address"), MockRoot()) is True
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
def test_conditions_display_type_pattern():
    cond = RuleConditions(display_type_pattern=re.compile(r"Phishing"))
    # display_type with _display_type set returns "Phishing URL (url)"
    assert cond.evaluate(MockObservable(type="url", display_type="Phishing URL"), MockRoot()) is True
    # display_type without _display_type returns the raw type "url"
    assert cond.evaluate(MockObservable(type="url"), MockRoot()) is False
    # display_type "file" doesn't match "Phishing"
    assert cond.evaluate(MockObservable(type="file"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_display_value_pattern():
    cond = RuleConditions(display_value_pattern=re.compile(r"decoded"))
    # display_value with _display_value set returns "decoded payload (test.html)"
    assert cond.evaluate(MockObservable(display_value="decoded payload"), MockRoot()) is True
    # display_value without _display_value returns "test.html"
    assert cond.evaluate(MockObservable(value="test.html"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_display_type_pattern_early():
    """evaluate_early should also check display_type_pattern."""
    cond = RuleConditions(display_type_pattern=re.compile(r"Phishing"))
    assert cond.evaluate_early(MockObservable(type="url", display_type="Phishing URL"), MockRoot()) is True
    assert cond.evaluate_early(MockObservable(type="url"), MockRoot()) is False


@pytest.mark.unit
def test_conditions_display_value_pattern_early():
    """evaluate_early should also check display_value_pattern."""
    cond = RuleConditions(display_value_pattern=re.compile(r"decoded"))
    assert cond.evaluate_early(MockObservable(display_value="decoded payload"), MockRoot()) is True
    assert cond.evaluate_early(MockObservable(value="test.html"), MockRoot()) is False


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
        self._ignored = False
        self._display_type = None
        self._display_value = None

    @property
    def ignored(self):
        return self._ignored

    @ignored.setter
    def ignored(self, value):
        self._ignored = value

    @property
    def display_type(self):
        return self._display_type

    @display_type.setter
    def display_type(self, value):
        self._display_type = value

    @property
    def display_value(self):
        return self._display_value

    @display_value.setter
    def display_value(self, value):
        self._display_value = value

    def add_directive(self, d):
        self.directives.append(d)

    def add_tag(self, t):
        self.tags.append(t)

    def add_detection_point(self, desc, signature_uuid=None, signature_version=None):
        self.detection_points.append(desc)
        self.detection_signatures = getattr(self, "detection_signatures", [])
        self.detection_signatures.append((signature_uuid, signature_version))


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


@pytest.mark.unit
def test_actions_set_display_type():
    actions = RuleActions(set_display_type="Phishing URL")
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert tracker.display_type == "Phishing URL"
    assert applied["set_display_type"] == "Phishing URL"


@pytest.mark.unit
def test_actions_set_display_value():
    actions = RuleActions(set_display_value="decoded payload")
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert tracker.display_value == "decoded payload"
    assert applied["set_display_value"] == "decoded payload"


@pytest.mark.unit
def test_actions_set_display_type_and_value():
    actions = RuleActions(set_display_type="Phishing URL", set_display_value="decoded payload")
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert tracker.display_type == "Phishing URL"
    assert tracker.display_value == "decoded payload"
    assert applied["set_display_type"] == "Phishing URL"
    assert applied["set_display_value"] == "decoded payload"


# ============================================================
# execute_analysis / execute_final_analysis behavior tests
# ============================================================


@pytest.mark.unit
def test_execute_analysis_returns_incomplete_when_rules_might_match():
    """execute_analysis should return INCOMPLETE when immutable conditions pass."""
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
def test_invalid_regex_in_display_type_pattern(caplog):
    """Invalid regex in display_type_pattern should skip the rule with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "bad display_type regex rule",
        "conditions": {
            "display_type_pattern": "[invalid regex(",
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
def test_invalid_regex_in_display_value_pattern(caplog):
    """Invalid regex in display_value_pattern should skip the rule with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "bad display_value regex rule",
        "conditions": {
            "display_value_pattern": "[invalid regex(",
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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target_observable.has_directive("extract_iocs")


def _build_email_tree(produce_message_id=False, from_value="hr@bv.com", message_id_value="<abc@bv.com>"):
    """Build root -> target url observable with a TestEmailAnalysis (scope self) that
    produces typed observables (email_from, optionally message_id). Returns
    (root, target_observable, module_path)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    target = root.add_observable_by_spec(F_URL, "https://example.com/page.html")

    class TestEmailAnalysis(Analysis):
        pass

    analysis = TestEmailAnalysis()
    analysis.details = {}
    analysis.details_modified = True
    target.add_analysis(analysis)
    analysis.add_observable_by_spec(F_EMAIL_FROM, from_value)
    analysis.add_observable_by_spec(F_EMAIL_TO, "robertsd@bv.com")
    if produce_message_id:
        analysis.add_observable_by_spec(F_MESSAGE_ID, message_id_value)

    module_path = f"{TestEmailAnalysis.__module__}:{TestEmailAnalysis.__name__}"
    return root, target, module_path


def _produces_rule(module_path, produces_observable, negate=False):
    return [{
        "name": "produces_observable test",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "self",
                "negate": negate,
                "produces_observable": produces_observable,
            }],
        },
        "actions": {"add_directives": ["matched"]},
    }]


@pytest.mark.unit
def test_tree_condition_produces_observable_positive():
    """Matches when the analysis produced an observable of the given type (no value regex)."""
    root, target, module_path = _build_email_tree()
    adapter = _create_analyzer_with_rules(root, _produces_rule(module_path, {"type": "email_from"}))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert target.has_directive("matched")


@pytest.mark.unit
def test_tree_condition_produces_observable_value_match():
    """Matches when a produced observable's value matches the value regex."""
    root, target, module_path = _build_email_tree(from_value="hr@bv.com")
    adapter = _create_analyzer_with_rules(
        root, _produces_rule(module_path, {"type": "email_from", "value": r"(?i)@bv\.com>?$"}))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert target.has_directive("matched")


@pytest.mark.unit
def test_tree_condition_produces_observable_value_no_match():
    """Does not match when no produced observable's value matches the value regex."""
    root, target, module_path = _build_email_tree(from_value="attacker@evil.com")
    adapter = _create_analyzer_with_rules(
        root, _produces_rule(module_path, {"type": "email_from", "value": r"(?i)@bv\.com>?$"}))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert not target.has_directive("matched")


@pytest.mark.unit
def test_tree_condition_produces_observable_negate_absence():
    """Negated produces_observable matches when the analysis produced no such observable."""
    root, target, module_path = _build_email_tree(produce_message_id=False)
    adapter = _create_analyzer_with_rules(
        root, _produces_rule(module_path, {"type": "message_id"}, negate=True))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert target.has_directive("matched")


@pytest.mark.unit
def test_tree_condition_produces_observable_negate_present():
    """Negated produces_observable does NOT match when the analysis did produce the observable."""
    root, target, module_path = _build_email_tree(produce_message_id=True)
    adapter = _create_analyzer_with_rules(
        root, _produces_rule(module_path, {"type": "message_id"}, negate=True))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert not target.has_directive("matched")


@pytest.mark.unit
def test_tree_condition_produces_observable_malformed_message_id():
    """Negating a well-formed message_id (value regex) still matches a malformed one."""
    root, target, module_path = _build_email_tree(produce_message_id=True, message_id_value="unknown")
    adapter = _create_analyzer_with_rules(
        root, _produces_rule(module_path, {"type": "message_id", "value": r"<.+@.+>$"}, negate=True))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert target.has_directive("matched")


@pytest.mark.unit
def test_tree_condition_produces_observable_subtype_aware():
    """produces_observable is subtype-aware: type email_address matches a produced email_from."""
    from saq.observables.type_hierarchy import get_type_hierarchy
    if not get_type_hierarchy().is_subtype("email_from", "email_address"):
        pytest.skip("email_from -> email_address not loaded in this environment")

    # parent type matches the subtype observable
    root, target, module_path = _build_email_tree()
    adapter = _create_analyzer_with_rules(root, _produces_rule(module_path, {"type": "email_address"}))
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert target.has_directive("matched")

    # a sibling subtype (email_to) of the parent does NOT match the produced email_from
    root2, target2, module_path2 = _build_email_tree(from_value="hr@bv.com")
    adapter2 = _create_analyzer_with_rules(
        root2, _produces_rule(module_path2, {"type": "email_from", "value": r"(?i)^robertsd@"}))
    adapter2.execute_analysis(target2)
    adapter2.analyze(target2, final_analysis=True)
    # robertsd is the email_to value, not email_from -> no email_from matches that value
    assert not target2.has_directive("matched")


@pytest.mark.unit
def test_parse_produces_observable_invalid_value_regex(caplog):
    """Invalid value regex in produces_observable should skip the rule with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "bad produces_observable regex",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": "test:TestAnalysis",
                "produces_observable": {"type": "message_id", "value": "[bad("},
            }],
        },
        "actions": {"add_directives": ["should_not_appear"]},
    }]
    with caplog.at_level(logging.WARNING):
        adapter = _create_analyzer_with_rules(root, rules)
        adapter.execute_analysis(observable)
        result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("should_not_appear")
    assert any("invalid" in msg.lower() for msg in [r.message for r in caplog.records])


@pytest.mark.unit
def test_parse_produces_observable_missing_type(caplog):
    """produces_observable without a 'type' should skip the rule with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "produces_observable missing type",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": "test:TestAnalysis",
                "produces_observable": {"value": r"<.+@.+>$"},
            }],
        },
        "actions": {"add_directives": ["should_not_appear"]},
    }]
    with caplog.at_level(logging.WARNING):
        adapter = _create_analyzer_with_rules(root, rules)
        adapter.execute_analysis(observable)
        result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("should_not_appear")
    assert any("produces_observable" in r.message for r in caplog.records)


@pytest.mark.unit
def test_tree_condition_no_match():
    """Tree condition should not match when details don't match."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert not target_observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_tree_condition_deep_ancestor_chain():
    """Tree condition should find matching analysis multiple levels up the ancestor chain."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_directive("extract_iocs")


@pytest.mark.unit
def test_tree_condition_no_match_sibling_branch():
    """Tree condition with ancestors scope should NOT match analyses in sibling branches."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert not target.has_directive("should_not_appear")


@pytest.mark.unit
def test_tree_condition_global_scope_finds_sibling():
    """Tree condition with global scope SHOULD match analyses in sibling branches."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_directive("found_via_global")


@pytest.mark.unit
def test_tree_condition_global_scope():
    """Tree condition with global scope should search the entire analysis tree."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_tag("global_match")


@pytest.mark.unit
def test_tree_condition_ancestors_scope_in_final_mode():
    """Tree condition with ancestors scope should still work correctly in final analysis mode."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_directive("ancestor_found")


@pytest.mark.unit
def test_tree_condition_without_details_match():
    """Tree condition that only checks analysis_type (no details_match) should match."""

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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_tag("has_analysis")


@pytest.mark.unit
def test_tree_condition_without_analysis_type():
    """Tree condition without analysis_type should match any ancestor analysis based on observable_match."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent = root.add_observable_by_spec(F_FQDN, "office-document.example.com")
    parent.add_tag("microsoft_office")

    class AncestorAnalysis(Analysis):
        pass

    analysis = AncestorAnalysis()
    analysis.details = {}
    analysis.details_modified = True
    parent.add_analysis(analysis)

    target = analysis.add_observable_by_spec(F_URL, "https://example.com/image.qrcode")

    rules = [{
        "name": "no analysis_type tree condition",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "scope": "ancestors",
                "observable_match": {
                    "tags": "microsoft_office",
                },
            }],
        },
        "actions": {
            "add_detection_points": ["QR code found in Office document"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_detection_points


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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
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
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_detection_points()

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert len(analysis.details["matched_rules"]) == 1
    assert "add_detection_points" in analysis.details["matched_rules"][0]["actions_applied"]


# ============================================================
# TreeCondition negate tests
# ============================================================


@pytest.mark.unit
def test_tree_condition_details_match_walks_list_mid_path():
    """details_match should walk a mid-path list and match if any element satisfies the regex.

    Mirrors the SplunkAPIAnalysis shape: details = {"query_results": [{"message_id_seen": "0"}]}.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent = root.add_observable_by_spec(F_FQDN, "example.com")

    class ListResultAnalysis(Analysis):
        pass

    parent_analysis = ListResultAnalysis()
    parent_analysis.details = {"query_results": [{"message_id_seen": "0"}]}
    parent_analysis.details_modified = True
    parent.add_analysis(parent_analysis)

    target = parent_analysis.add_observable_by_spec(F_URL, "https://example.com/x")
    module_path = f"{ListResultAnalysis.__module__}:{ListResultAnalysis.__name__}"

    tc_match = TreeCondition(
        analysis_type=module_path,
        details_match={"query_results.message_id_seen": re.compile(r"^0$")},
    )
    assert tc_match.evaluate(target, root) is True

    tc_no_match = TreeCondition(
        analysis_type=module_path,
        details_match={"query_results.message_id_seen": re.compile(r"^99$")},
    )
    assert tc_no_match.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_negate():
    """When negate=True, TreeCondition.evaluate() should invert its result."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class NegateTestAnalysis(Analysis):
        pass

    parent_analysis = NegateTestAnalysis()
    parent_analysis.details = {"scan_type": "file"}
    parent_analysis.details_modified = True
    parent.add_analysis(parent_analysis)

    target = parent_analysis.add_observable_by_spec(F_URL, "https://example.com/page.html")
    module_path = f"{NegateTestAnalysis.__module__}:{NegateTestAnalysis.__name__}"

    # Without negate: condition matches (analysis exists with matching details)
    tc_normal = TreeCondition(
        analysis_type=module_path,
        details_match={
            "scan_type": re.compile("file"),
        },
    )
    assert tc_normal.evaluate(target, root) is True

    # With negate: same condition inverted
    tc_negated = TreeCondition(
        analysis_type=module_path,
        details_match={
            "scan_type": re.compile("file"),
        },
        negate=True,
    )
    assert tc_negated.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_negate_no_match_becomes_true():
    """When negate=True and the inner condition doesn't match, evaluate() returns True."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://example.com/page.html")

    # No ancestor analysis exists, so inner evaluate returns False -> negate makes it True
    tc_negated = TreeCondition(
        analysis_type="nonexistent.module:NonexistentAnalysis",
        negate=True,
    )
    assert tc_negated.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_negate_parsed_from_yaml():
    """negate field should be read correctly from YAML rule config."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rules = [{
        "name": "negate yaml test",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": "some.module:SomeAnalysis",
                "negate": True,
            }],
        },
        "actions": {
            "add_tags": ["negated"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # Since the analysis doesn't exist in the tree, the inner condition is False.
    # With negate=True, this becomes True -> rule matches.
    target = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_tag("negated")


# ============================================================
# TreeCondition match_count tests
# ============================================================


@pytest.mark.unit
def test_tree_condition_match_count_exact():
    """match_count=N requires exactly N matching analyses in the resolved scope."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Chain: root -> obs_a -> DeobfAnalysis -> obs_b -> DeobfAnalysis -> target
    # target has two DeobfAnalysis ancestors (simulates the nested-deobf explosion).
    obs_a = root.add_observable_by_spec(F_FQDN, "outer.example.com")

    class DeobfAnalysis(Analysis):
        pass

    outer = DeobfAnalysis()
    outer.details = {}
    outer.details_modified = True
    obs_a.add_analysis(outer)

    obs_b = outer.add_observable_by_spec(F_URL, "https://example.com/intermediate")
    inner = DeobfAnalysis()
    inner.details = {}
    inner.details_modified = True
    obs_b.add_analysis(inner)

    target = inner.add_observable_by_spec(F_URL, "https://example.com/nested")

    module_path = f"{DeobfAnalysis.__module__}:{DeobfAnalysis.__name__}"

    tc_top_level = TreeCondition(analysis_type=module_path, match_count=1)
    assert tc_top_level.evaluate(target, root) is False  # two ancestors, not one

    tc_nested = TreeCondition(analysis_type=module_path, match_count=2)
    assert tc_nested.evaluate(target, root) is True

    # sibling URL directly under the outer analysis: exactly one ancestor
    top_level_target = outer.add_observable_by_spec(F_URL, "https://example.com/top")
    assert tc_top_level.evaluate(top_level_target, root) is True
    assert tc_nested.evaluate(top_level_target, root) is False


@pytest.mark.unit
def test_tree_condition_match_count_zero_when_absent():
    """match_count=0 matches observables whose chain contains none of the target analyses."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://example.com/orphan")

    tc = TreeCondition(
        analysis_type="nonexistent.module:NonexistentAnalysis",
        match_count=0,
    )
    assert tc.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_match_count_default_at_least_one():
    """With match_count unset, the historical 'at least one match' semantic is preserved."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent = root.add_observable_by_spec(F_FQDN, "example.com")

    class SomeAnalysis(Analysis):
        pass

    a = SomeAnalysis()
    a.details = {}
    a.details_modified = True
    parent.add_analysis(a)

    target = a.add_observable_by_spec(F_URL, "https://example.com/page")
    module_path = f"{SomeAnalysis.__module__}:{SomeAnalysis.__name__}"

    # Adding a second ancestor of the same type — default semantic should still match
    mid = a.add_observable_by_spec(F_URL, "https://example.com/mid")
    a2 = SomeAnalysis()
    a2.details = {}
    a2.details_modified = True
    mid.add_analysis(a2)
    deep_target = a2.add_observable_by_spec(F_URL, "https://example.com/deep")

    tc = TreeCondition(analysis_type=module_path)
    assert tc.evaluate(target, root) is True
    assert tc.evaluate(deep_target, root) is True


@pytest.mark.unit
def test_tree_condition_match_count_parsed_from_yaml():
    """match_count should be read correctly from YAML rule config."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # two nested DeobfAnalysis ancestors, same chain as test_tree_condition_match_count_exact
    obs_a = root.add_observable_by_spec(F_FQDN, "outer.example.com")

    class DeobfAnalysis(Analysis):
        pass

    outer = DeobfAnalysis()
    outer.details = {}
    outer.details_modified = True
    obs_a.add_analysis(outer)

    obs_b = outer.add_observable_by_spec(F_URL, "https://example.com/intermediate")
    inner = DeobfAnalysis()
    inner.details = {}
    inner.details_modified = True
    obs_b.add_analysis(inner)

    nested_target = inner.add_observable_by_spec(F_URL, "https://example.com/nested")
    top_level_target = outer.add_observable_by_spec(F_URL, "https://example.com/top")

    module_path = f"{DeobfAnalysis.__module__}:{DeobfAnalysis.__name__}"
    rules = [{
        "name": "crawl only top-level deobf urls",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "ancestors",
                "match_count": 1,
            }],
        },
        "actions": {
            "add_directives": ["crawl"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(top_level_target)
    adapter.execute_analysis(nested_target)

    assert top_level_target.has_directive("crawl")
    assert not nested_target.has_directive("crawl")


@pytest.mark.unit
def test_tree_condition_ancestor_plus_negated_ancestor_scopes_top_level_deobf_urls():
    """The production "Crawl URLs from top-level JavaScript deobfuscation"
    rule combines a positive JS-deobf ancestor check with a negated
    Phishkit-ancestor check. A URL extracted directly from the top-level
    deobfuscation output has a JS-deobf ancestor but no Phishkit ancestor
    and matches. A URL extracted from Phishkit-downloaded content has both
    ancestors and is excluded by the negate condition."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    original_js = _add_file_observable(root, "original.js", content="//js")

    class DeobfAnalysis(Analysis):
        pass

    class PhishkitLikeAnalysis(Analysis):
        pass

    class URLExtractAnalysis(Analysis):
        pass

    deobf = DeobfAnalysis()
    deobf.details = {}
    deobf.details_modified = True
    original_js.add_analysis(deobf)

    deobf_file = _add_file_observable(root, "deobfuscated-original.js", content="//deobf")
    deobf.add_observable(deobf_file)

    # URL extraction on the deobf file produces the top-level URL.
    extract_top = URLExtractAnalysis()
    extract_top.details = {}
    extract_top.details_modified = True
    deobf_file.add_analysis(extract_top)

    top_level_url = extract_top.add_observable_by_spec(F_URL, "https://example.com/top")

    # Phishkit runs on the top-level URL and downloads an HTML file.
    phishkit = PhishkitLikeAnalysis()
    phishkit.details = {}
    phishkit.details_modified = True
    top_level_url.add_analysis(phishkit)

    downloaded_html = _add_file_observable(root, "payload.html", content="<html/>")
    phishkit.add_observable(downloaded_html)

    # URL extraction on the downloaded HTML produces a nested URL whose
    # ancestors include both JS-deobf and Phishkit.
    extract_nested = URLExtractAnalysis()
    extract_nested.details = {}
    extract_nested.details_modified = True
    downloaded_html.add_analysis(extract_nested)

    nested_url = extract_nested.add_observable_by_spec(F_URL, "https://cdn.example.com/jquery.js")

    deobf_path = f"{DeobfAnalysis.__module__}:{DeobfAnalysis.__name__}"
    phishkit_path = f"{PhishkitLikeAnalysis.__module__}:{PhishkitLikeAnalysis.__name__}"

    rules = [{
        "name": "crawl top-level deobf urls only",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [
                {"analysis_type": deobf_path, "scope": "ancestors"},
                {"analysis_type": phishkit_path, "scope": "ancestors", "negate": True},
            ],
        },
        "actions": {"add_directives": ["crawl"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(top_level_url)
    adapter.execute_analysis(nested_url)

    assert top_level_url.has_directive("crawl")
    # Nested URL has a Phishkit ancestor, so the negate condition rejects it.
    assert not nested_url.has_directive("crawl")


@pytest.mark.unit
def test_tree_condition_match_count_invalid_in_yaml(caplog):
    """Invalid match_count values in YAML should cause the rule to be dropped."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rules = [{
        "name": "invalid match_count",
        "conditions": {
            "tree_conditions": [{
                "analysis_type": "some.module:SomeAnalysis",
                "match_count": "not-a-number",
            }],
        },
        "actions": {"add_tags": ["should_not_apply"]},
    }]
    with caplog.at_level(logging.WARNING):
        adapter = _create_analyzer_with_rules(root, rules)

    # The rule should have been skipped entirely during parsing, so no tag
    # is added even to an observable that would otherwise satisfy the
    # observable-type/analysis-type filters.
    target = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter.execute_analysis(target)
    adapter.analyze(target, final_analysis=True)
    assert not target.has_tag("should_not_apply")
    assert "invalid match_count" in caplog.text


# ============================================================
# TreeCondition observable_match tests
# ============================================================


@pytest.mark.unit
def test_tree_condition_observable_match():
    """observable_match should match when ancestor analysis's observable has matching properties."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Create a file observable that the ancestor analysis was performed against
    parent_file = _add_file_observable(root, "body.unknown_text_html_000", content="<html>test</html>")

    class PhishkitLikeAnalysis(Analysis):
        pass

    parent_analysis = PhishkitLikeAnalysis()
    parent_analysis.details = {}
    parent_analysis.details_modified = True
    parent_file.add_analysis(parent_analysis)

    # Target: a screenshot produced by the phishkit analysis
    target = _add_file_observable(root, "screenshot.png", content="fake image")
    parent_analysis.add_observable(target)

    module_path = f"{PhishkitLikeAnalysis.__module__}:{PhishkitLikeAnalysis.__name__}"

    tc = TreeCondition(
        analysis_type=module_path,
        observable_match={
            "file_name": re.compile(r".*\.unknown_text_html_.*"),
        },
    )
    assert tc.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_observable_match_no_match():
    """observable_match should fail when observable properties don't match the pattern."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_file = _add_file_observable(root, "regular_document.pdf", content="pdf content")

    class PhishkitLikeAnalysis2(Analysis):
        pass

    parent_analysis = PhishkitLikeAnalysis2()
    parent_analysis.details = {}
    parent_analysis.details_modified = True
    parent_file.add_analysis(parent_analysis)

    target = _add_file_observable(root, "screenshot.png", content="fake image")
    parent_analysis.add_observable(target)

    module_path = f"{PhishkitLikeAnalysis2.__module__}:{PhishkitLikeAnalysis2.__name__}"

    tc = TreeCondition(
        analysis_type=module_path,
        observable_match={
            "file_name": re.compile(r".*\.unknown_text_html_.*"),
        },
    )
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_observable_match_file_name():
    """observable_match should work with file_name attribute on FileObservable."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_file = _add_file_observable(root, "email.unknown_text_html_001", content="<html>body</html>")

    class TestAnalysis(Analysis):
        pass

    parent_analysis = TestAnalysis()
    parent_analysis.details = {}
    parent_analysis.details_modified = True
    parent_file.add_analysis(parent_analysis)

    target = _add_file_observable(root, "output.png", content="img")
    parent_analysis.add_observable(target)

    module_path = f"{TestAnalysis.__module__}:{TestAnalysis.__name__}"

    # Match file_name
    tc = TreeCondition(
        analysis_type=module_path,
        observable_match={
            "file_name": re.compile(r".*\.unknown_text_html_\d+$"),
        },
    )
    assert tc.evaluate(target, root) is True

    # Non-matching file_name pattern
    tc_no = TreeCondition(
        analysis_type=module_path,
        observable_match={
            "file_name": re.compile(r".*\.docx$"),
        },
    )
    assert tc_no.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_observable_match_with_negate():
    """Combined observable_match + negate should invert correctly."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_file = _add_file_observable(root, "body.unknown_text_html_000", content="<html></html>")

    class PhishkitAnalysisNeg(Analysis):
        pass

    parent_analysis = PhishkitAnalysisNeg()
    parent_analysis.details = {}
    parent_analysis.details_modified = True
    parent_file.add_analysis(parent_analysis)

    target = _add_file_observable(root, "screenshot.png", content="img")
    parent_analysis.add_observable(target)

    module_path = f"{PhishkitAnalysisNeg.__module__}:{PhishkitAnalysisNeg.__name__}"

    # Without negate: inner matches (file_name matches pattern) -> True
    tc = TreeCondition(
        analysis_type=module_path,
        observable_match={"file_name": re.compile(r".*\.unknown_text_html_.*")},
    )
    assert tc.evaluate(target, root) is True

    # With negate: inner matches -> negated to False (OCR should NOT run)
    tc_neg = TreeCondition(
        analysis_type=module_path,
        observable_match={"file_name": re.compile(r".*\.unknown_text_html_.*")},
        negate=True,
    )
    assert tc_neg.evaluate(target, root) is False

    # Now test when file_name does NOT match the pattern
    root2 = create_root_analysis(analysis_mode="test_single")
    root2.initialize_storage()

    parent_url = root2.add_observable_by_spec(F_URL, "https://evil.com")

    class PhishkitAnalysisNeg2(Analysis):
        pass

    url_analysis = PhishkitAnalysisNeg2()
    url_analysis.details = {}
    url_analysis.details_modified = True
    parent_url.add_analysis(url_analysis)

    target2 = _add_file_observable(root2, "screenshot2.png", content="img")
    url_analysis.add_observable(target2)

    module_path2 = f"{PhishkitAnalysisNeg2.__module__}:{PhishkitAnalysisNeg2.__name__}"

    # With negate: inner doesn't match, because a url observable has no file_name
    # attribute at all -- so the property check fails and negate flips it to True.
    # This is the trap documented in docs/OBSERVABLE_MODIFIER_RULES.md: a negated
    # observable_match written for one observable type silently passes for every
    # other type the analyzer runs on. Rules that need to exclude all outputs of an
    # analyzer must scope on the analysis alone, not on its observable's file_name.
    tc_neg2 = TreeCondition(
        analysis_type=module_path2,
        observable_match={"file_name": re.compile(r".*\.unknown_text_html_.*")},
        negate=True,
    )
    assert tc_neg2.evaluate(target2, root2) is True


@pytest.mark.unit
def test_observable_match_parsed_from_yaml():
    """observable_match field should be read correctly from YAML rule config."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()


    parent_file = _add_file_observable(root, "body.unknown_text_html_000", content="<html></html>")

    class YamlTestAnalysis(Analysis):
        pass

    parent_analysis = YamlTestAnalysis()
    parent_analysis.details = {}
    parent_analysis.details_modified = True
    parent_file.add_analysis(parent_analysis)

    target = _add_file_observable(root, "screenshot.png", content="img")
    parent_analysis.add_observable(target)

    module_path = f"{YamlTestAnalysis.__module__}:{YamlTestAnalysis.__name__}"

    rules = [{
        "name": "observable_match yaml test",
        "conditions": {
            "observable_types": ["file"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "negate": True,
                "observable_match": {
                    "file_name": r".*\.unknown_text_html_.*",
                },
            }],
        },
        "actions": {
            "add_directives": ["ocr"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # The ancestor analysis's observable has file_name matching the pattern,
    # so inner condition is True. With negate, the rule should NOT match.
    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert not target.has_directive("ocr")


@pytest.mark.unit
def test_observable_match_parsed_from_yaml_no_ancestor():
    """observable_match rule should match (with negate) when no matching ancestor exists."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Target file with no phishkit ancestor at all
    target = _add_file_observable(root, "standalone_image.png", content="img")

    rules = [{
        "name": "observable_match yaml test",
        "conditions": {
            "observable_types": ["file"],
            "tree_conditions": [{
                "analysis_type": "some.module:NonexistentAnalysis",
                "negate": True,
                "observable_match": {
                    "file_name": r".*\.unknown_text_html_.*",
                },
            }],
        },
        "actions": {
            "add_directives": ["ocr"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_directive("ocr")


@pytest.mark.unit
def test_ocr_directive_required():
    """OCRAnalyzer.required_directives should return ['ocr']."""


    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    context = create_test_context(root=root)

    config = OCRAnalyzerConfig(
        name="test_ocr",
        python_module="saq.modules.file_analysis.ocr",
        python_class="OCRAnalyzer",
        enabled=True,
    )
    analyzer = OCRAnalyzer(context=context, config=config)
    assert analyzer.required_directives == [DIRECTIVE_OCR]
    assert DIRECTIVE_OCR == 'ocr'


# ============================================================
# Pre-phase / post-phase tests
# ============================================================


@pytest.mark.unit
def test_pre_phase_rule_evaluated_in_execute_analysis():
    """Pre-phase rules should apply their actions during execute_analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "pre-phase rule",
        "phase": "pre",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["pre_applied"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # The directive should already be applied after execute_analysis
    assert observable.has_directive("pre_applied")


@pytest.mark.unit
def test_post_phase_rule_not_evaluated_in_execute_analysis():
    """Post-phase rules should NOT apply their actions during execute_analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "post-phase rule",
        "phase": "post",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["post_applied"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # The directive should NOT be applied yet
    assert not observable.has_directive("post_applied")

    # Only after final analysis
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_directive("post_applied")


@pytest.mark.unit
def test_post_phase_rule_evaluated_in_execute_final_analysis():
    """Post-phase rules (default) should work as before in execute_final_analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "default post rule",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_tags": ["post_tag"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_tag("post_tag")


@pytest.mark.unit
def test_pre_and_post_phase_rules_merged_in_analysis():
    """Both pre and post phase matches should appear in the final analysis details."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [
        {
            "name": "pre rule",
            "phase": "pre",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["pre_dir"]},
        },
        {
            "name": "post rule",
            "phase": "post",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_tags": ["post_tag"]},
        },
    ]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    rule_names = [r["name"] for r in analysis.details["matched_rules"]]
    assert "pre rule" in rule_names
    assert "post rule" in rule_names
    assert len(analysis.details["matched_rules"]) == 2


@pytest.mark.unit
def test_pre_phase_exclude_analysis_applied_before_final():
    """Pre-phase exclude_analysis should be on the observable before final analysis runs."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "pre exclude",
        "phase": "pre",
        "conditions": {"observable_types": ["url"]},
        "actions": {"exclude_analysis": ["saq.modules.file_analysis.ocr:OCRAnalyzer"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # After execute_analysis, the exclusion should already be in place
    adapter.execute_analysis(observable)
    assert "saq.modules.file_analysis.ocr:OCRAnalyzer" in observable.excluded_analysis


@pytest.mark.unit
def test_pre_phase_match_does_not_block_final_analysis_acceptance():
    """A pre-phase rule match must not mark the ObservableModifierAnalysis as
    completed -- otherwise AnalysisModule.accepts() refuses to run the module
    again and execute_final_analysis (the post phase) never evaluates.

    Regression test: pre-phase _persist_matches created the analysis with the
    default completed=True, which silently disabled every post-phase rule for
    any observable that also matched a pre-phase rule.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "pre rule",
        "phase": "pre",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["pre_dir"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # the pre-phase created the analysis, but it must NOT be marked completed
    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert analysis.completed is False

    # ...so the engine's acceptance check still lets the post phase run
    assert adapter.accepts(observable) is True


@pytest.mark.unit
def test_post_phase_rule_fires_after_pre_phase_match_via_accepts():
    """End-to-end through accepts(): an observable matched by a pre-phase rule
    must still have post-phase rules evaluated. This mirrors the engine path
    (_check_module_acceptance -> accepts() -> analyze(final_analysis=True))."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    pre_uuid = "b1b2c3d4-0000-4000-8000-000000000001"
    post_uuid = "b1b2c3d4-0000-4000-8000-000000000002"
    rules = [
        {
            "name": "pre rule",
            "uuid": pre_uuid,
            "phase": "pre",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["pre_dir"]},
        },
        {
            "name": "post rule",
            "uuid": post_uuid,
            "phase": "post",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_tags": ["post_tag"]},
        },
    ]
    adapter = _create_analyzer_with_rules(root, rules)

    # pre phase
    assert adapter.execute_analysis(observable) == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_directive("pre_dir")

    # the engine would gate the final pass on accepts() -- it must pass
    assert adapter.accepts(observable) is True

    # post phase
    assert adapter.analyze(observable, final_analysis=True) == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_tag("post_tag")

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert analysis.completed is False
    rule_names = sorted(r["name"] for r in analysis.details["matched_rules"])
    assert rule_names == ["post rule", "pre rule"]


@pytest.mark.unit
def test_post_phase_only_match_leaves_analysis_reevaluable():
    """When only a post-phase rule matches, the analysis produced by
    execute_final_analysis must be completed=False so AnalysisModule.accepts()
    keeps the module re-runnable -- a post rule may need to re-evaluate against
    an analysis that only appears in a later analysis mode."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "post rule",
        "phase": "post",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_tags": ["post_tag"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert analysis.completed is False


# ============================================================
# is_excluded clean format test
# ============================================================


@pytest.mark.unit
def test_is_excluded_clean_format():
    """Observable.is_excluded() should match clean format strings like 'module:ClassName'."""


    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")

    # Simulate what the observable modifier does: append a clean format string
    observable._excluded_analysis.append("saq.modules.util.observable_modifier:ObservableModifierAnalyzer")

    # Create a real module instance to test is_excluded against
    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    analyzer = ObservableModifierAnalyzer(context=context, config=config)

    # The clean format should match
    assert observable.is_excluded(analyzer) is True


@pytest.mark.unit
def test_is_excluded_legacy_format_still_works():
    """Observable.is_excluded() should still match the legacy str(type(...)) format."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")

    # Use the legacy exclude_analysis method which writes the str(type(...)) format
    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    analyzer = ObservableModifierAnalyzer(context=context, config=config)

    observable.exclude_analysis(type(analyzer))
    assert observable.is_excluded(analyzer) is True


@pytest.mark.unit
def test_phase_field_defaults_to_post():
    """Rules without explicit phase should default to 'post'."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rules = [{
        "name": "no phase specified",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_tags": ["default_phase"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # The rule should NOT apply during execute_analysis (it's post-phase)
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter.execute_analysis(observable)
    assert not observable.has_tag("default_phase")

    # Should apply during final analysis
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_tag("default_phase")


@pytest.mark.unit
def test_invalid_phase_defaults_to_post(caplog):
    """Invalid phase value should default to 'post' with a warning."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rules = [{
        "name": "bad phase rule",
        "phase": "invalid",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_tags": ["bad_phase"]},
    }]

    with caplog.at_level(logging.WARNING):
        adapter = _create_analyzer_with_rules(root, rules)

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter.execute_analysis(observable)
    # Should not be applied in pre-phase
    assert not observable.has_tag("bad_phase")

    # Should work in final analysis (defaulted to post)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_tag("bad_phase")
    assert any("invalid phase" in msg.lower() for msg in [r.message for r in caplog.records])


# ============================================================
# evaluate_early() unit tests
# ============================================================


@pytest.mark.unit
def test_evaluate_early_empty_conditions():
    """Empty conditions should always return True (might match)."""
    cond = RuleConditions()
    assert cond.evaluate_early(MockObservable(), MockRoot()) is True


@pytest.mark.unit
def test_evaluate_early_observable_type_match():
    cond = RuleConditions(observable_types=["url", "file"])
    assert cond.evaluate_early(MockObservable(type="url"), MockRoot()) is True
    assert cond.evaluate_early(MockObservable(type="ip"), MockRoot()) is False


@pytest.mark.unit
def test_evaluate_early_alert_type_match():
    cond = RuleConditions(alert_type="splunk - threat_intel")
    assert cond.evaluate_early(MockObservable(), MockRoot(alert_type="splunk - threat_intel")) is True
    assert cond.evaluate_early(MockObservable(), MockRoot(alert_type="other")) is False


@pytest.mark.unit
def test_evaluate_early_queue_match():
    cond = RuleConditions(queue="external")
    assert cond.evaluate_early(MockObservable(), MockRoot(queue="external")) is True
    assert cond.evaluate_early(MockObservable(), MockRoot(queue="internal")) is False


@pytest.mark.unit
def test_evaluate_early_value_pattern_match():
    cond = RuleConditions(value_pattern=re.compile(r".*\.html$"))
    assert cond.evaluate_early(MockObservable(value="page.html"), MockRoot()) is True
    assert cond.evaluate_early(MockObservable(value="doc.pdf"), MockRoot()) is False


@pytest.mark.unit
def test_evaluate_early_file_name_pattern():
    """evaluate_early checks file_name_pattern against the observable's file_name attribute."""
    cond = RuleConditions(file_name_pattern=re.compile(r".*\.html$"))
    obs_with_name = MockObservable()
    obs_with_name.file_name = "body.html"
    assert cond.evaluate_early(obs_with_name, MockRoot()) is True

    obs_no_name = MockObservable()
    assert cond.evaluate_early(obs_no_name, MockRoot()) is False

    obs_wrong_name = MockObservable()
    obs_wrong_name.file_name = "doc.pdf"
    assert cond.evaluate_early(obs_wrong_name, MockRoot()) is False


@pytest.mark.unit
def test_evaluate_early_ignores_dynamic_conditions():
    """evaluate_early should return True even when dynamic conditions are set,
    since it cannot evaluate them."""
    cond = RuleConditions(
        alert_tags=["phishing"],
        has_tags=["suspicious"],
        has_directives=["sandbox"],
        tree_conditions=[TreeCondition(analysis_type="test:Test")],
    )
    # Dynamic conditions are not checked, so evaluate_early returns True
    assert cond.evaluate_early(MockObservable(), MockRoot()) is True


@pytest.mark.unit
def test_evaluate_early_mixed_passing_immutable_and_dynamic():
    """When immutable conditions pass and dynamic conditions are present, should return True."""
    cond = RuleConditions(
        observable_types=["url"],
        alert_tags=["phishing"],  # dynamic
    )
    assert cond.evaluate_early(MockObservable(type="url"), MockRoot()) is True


@pytest.mark.unit
def test_evaluate_early_mixed_failing_immutable_and_dynamic():
    """When any immutable condition fails, should return False even if dynamic conditions present."""
    cond = RuleConditions(
        observable_types=["file"],  # will fail for url observable
        alert_tags=["phishing"],  # dynamic, would be ignored
    )
    assert cond.evaluate_early(MockObservable(type="url"), MockRoot()) is False


# ============================================================
# Early exit in execute_analysis tests
# ============================================================


@pytest.mark.unit
def test_early_exit_by_observable_type():
    """execute_analysis should return COMPLETED when observable type doesn't match any rule."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "file-only rule",
        "conditions": {"observable_types": ["file"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.unit
def test_early_exit_by_alert_type():
    """execute_analysis should return COMPLETED when alert_type doesn't match any rule."""
    root = create_root_analysis(analysis_mode="test_single", alert_type="manual")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "threat intel only",
        "conditions": {"alert_type": "splunk - threat_intel"},
        "actions": {"add_directives": ["crawl"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.unit
def test_early_exit_by_queue():
    """execute_analysis should return COMPLETED when queue doesn't match any rule."""
    root = create_root_analysis(analysis_mode="test_single", queue="internal")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "external only",
        "conditions": {"queue": "external"},
        "actions": {"add_tags": ["external"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.unit
def test_early_exit_by_value_pattern():
    """execute_analysis should return COMPLETED when value doesn't match any rule's pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/doc.pdf")
    rules = [{
        "name": "html only",
        "conditions": {"value_pattern": r".*\.html$"},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.unit
def test_defers_when_only_dynamic_conditions():
    """execute_analysis should return INCOMPLETE when rules have only dynamic conditions,
    since evaluate_early cannot rule them out."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "tag-based rule",
        "conditions": {"alert_tags": ["phishing"]},
        "actions": {"add_directives": ["sandbox"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE


@pytest.mark.unit
def test_defers_when_mixed_with_passing_immutable():
    """execute_analysis should return INCOMPLETE when immutable conditions pass
    but dynamic conditions are also present."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "mixed rule",
        "conditions": {
            "observable_types": ["url"],  # immutable, passes
            "has_tags": ["needs_review"],  # dynamic, cannot be checked early
        },
        "actions": {"add_directives": ["review"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE


@pytest.mark.unit
def test_early_exit_mixed_with_failing_immutable():
    """execute_analysis should return COMPLETED when an immutable condition fails,
    even if dynamic conditions are present."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "mixed rule",
        "conditions": {
            "observable_types": ["file"],  # immutable, fails for url
            "has_tags": ["needs_review"],  # dynamic
        },
        "actions": {"add_directives": ["review"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.unit
def test_early_exit_disabled_rules_ignored():
    """Disabled rules should not prevent early exit."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [
        {
            "name": "disabled matching rule",
            "enabled": False,
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["extract_iocs"]},
        },
        {
            "name": "non-matching rule",
            "conditions": {"observable_types": ["file"]},
            "actions": {"add_tags": ["processed"]},
        },
    ]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED


# ============================================================
# execute_final_analysis fast path tests
# ============================================================


@pytest.mark.unit
def test_final_analysis_fast_path_no_match():
    """execute_final_analysis should return COMPLETED quickly when no rules can match."""
    root = create_root_analysis(analysis_mode="test_single", alert_type="manual")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "threat intel only",
        "conditions": {"alert_type": "splunk - threat_intel"},
        "actions": {"add_directives": ["crawl"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # Initialize module via execute_analysis (which also returns COMPLETED)
    adapter.execute_analysis(observable)

    # Final analysis should also bail out early
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.COMPLETED
    assert not observable.has_directive("crawl")
    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is None


# ============================================================
# TreeCondition siblings scope tests
# ============================================================


@pytest.mark.unit
def test_tree_condition_siblings_scope_match():
    """Siblings scope should find a peer analysis on the observable that produced this observable."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_file = _add_file_observable(root, "invite.ics", content="BEGIN:VCALENDAR")

    class FileTypeAnalysisStubSibMatch(Analysis):
        pass

    file_type_analysis = FileTypeAnalysisStubSibMatch()
    file_type_analysis.details = {"mime": "text/calendar"}
    file_type_analysis.details_modified = True
    parent_file.add_analysis(file_type_analysis)

    class URLExtractionAnalysisSibMatch(Analysis):
        pass

    producer = URLExtractionAnalysisSibMatch()
    producer.details_modified = True
    parent_file.add_analysis(producer)
    target = producer.add_observable_by_spec(F_URL, "https://example.com/x")

    module_path = f"{FileTypeAnalysisStubSibMatch.__module__}:{FileTypeAnalysisStubSibMatch.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="siblings",
        details_match={"mime": re.compile(r"^text/calendar$")},
    )
    assert tc.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_siblings_scope_no_match_when_details_differ():
    """Siblings scope should not match when the peer analysis's details don't match."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_file = _add_file_observable(root, "page.html", content="<html></html>")

    class FileTypeAnalysisStubSibNoMatch(Analysis):
        pass

    file_type_analysis = FileTypeAnalysisStubSibNoMatch()
    file_type_analysis.details = {"mime": "text/html"}
    file_type_analysis.details_modified = True
    parent_file.add_analysis(file_type_analysis)

    class URLExtractionAnalysisSibNoMatch(Analysis):
        pass

    producer = URLExtractionAnalysisSibNoMatch()
    producer.details_modified = True
    parent_file.add_analysis(producer)
    target = producer.add_observable_by_spec(F_URL, "https://example.com/y")

    module_path = f"{FileTypeAnalysisStubSibNoMatch.__module__}:{FileTypeAnalysisStubSibNoMatch.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="siblings",
        details_match={"mime": re.compile(r"^text/calendar$")},
    )
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_siblings_scope_does_not_walk_grandparents():
    """Siblings scope only inspects the direct parent's observable, not deeper ancestors."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    # Grandparent file has the FileTypeAnalysis we'd otherwise look for.
    grandparent_file = _add_file_observable(root, "outer.eml", content="From: a@b")

    class FileTypeAnalysisStubGrand(Analysis):
        pass

    grand_file_type = FileTypeAnalysisStubGrand()
    grand_file_type.details = {"mime": "text/calendar"}
    grand_file_type.details_modified = True
    grandparent_file.add_analysis(grand_file_type)

    # Direct parent is a different file (e.g. an extracted attachment) with no FileTypeAnalysis match.
    class ExtractAnalysis(Analysis):
        pass

    extract = ExtractAnalysis()
    extract.details_modified = True
    grandparent_file.add_analysis(extract)
    parent_file = extract.add_observable_by_spec(F_FQDN, "intermediate.example")

    class URLExtractionAnalysisGrand(Analysis):
        pass

    producer = URLExtractionAnalysisGrand()
    producer.details_modified = True
    parent_file.add_analysis(producer)
    target = producer.add_observable_by_spec(F_URL, "https://example.com/z")

    module_path = f"{FileTypeAnalysisStubGrand.__module__}:{FileTypeAnalysisStubGrand.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="siblings",
        details_match={"mime": re.compile(r"^text/calendar$")},
    )
    # Must be False — the matching analysis is on a grandparent observable, not a sibling.
    assert tc.evaluate(target, root) is False


# ============================================================
# TreeCondition self scope tests
# ============================================================


@pytest.mark.unit
def test_tree_condition_self_scope_match():
    """Self scope should find matching analysis performed directly on the target observable."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = _add_file_observable(root, "image.png", content="img")

    class FileTypeAnalysisStub(Analysis):
        pass

    file_type_analysis = FileTypeAnalysisStub()
    file_type_analysis.details = {"mime": "image/png"}
    file_type_analysis.details_modified = True
    target.add_analysis(file_type_analysis)

    module_path = f"{FileTypeAnalysisStub.__module__}:{FileTypeAnalysisStub.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="self",
        details_match={"mime": re.compile(r"^image/")},
    )
    assert tc.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_self_scope_no_match():
    """Self scope should fail when analysis exists but details don't match."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = _add_file_observable(root, "document.pdf", content="pdf")

    class FileTypeAnalysisStub2(Analysis):
        pass

    file_type_analysis = FileTypeAnalysisStub2()
    file_type_analysis.details = {"mime": "application/pdf"}
    file_type_analysis.details_modified = True
    target.add_analysis(file_type_analysis)

    module_path = f"{FileTypeAnalysisStub2.__module__}:{FileTypeAnalysisStub2.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="self",
        details_match={"mime": re.compile(r"^image/")},
    )
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_self_scope_no_analysis():
    """Self scope should fail when the analysis type doesn't exist on the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = _add_file_observable(root, "image.png", content="img")

    tc = TreeCondition(
        analysis_type="some.module:NonexistentAnalysis",
        scope="self",
        details_match={"mime": re.compile(r"^image/")},
    )
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_self_scope_parsed_from_yaml():
    """scope: 'self' should be read correctly from YAML rule config."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = _add_file_observable(root, "image.jpg", content="img")

    class SelfScopeYamlAnalysis(Analysis):
        pass

    analysis = SelfScopeYamlAnalysis()
    analysis.details = {"mime": "image/jpeg"}
    analysis.details_modified = True
    target.add_analysis(analysis)

    module_path = f"{SelfScopeYamlAnalysis.__module__}:{SelfScopeYamlAnalysis.__name__}"
    rules = [{
        "name": "self scope yaml test",
        "conditions": {
            "observable_types": ["file"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "self",
                "details_match": {
                    "mime": "^image/",
                },
            }],
        },
        "actions": {
            "add_directives": ["ocr"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_directive("ocr")


# ============================================================
# has_yara_meta_tags condition tests
# ============================================================


@pytest.mark.unit
def test_conditions_has_yara_meta_tags_match():
    """has_yara_meta_tags should match when observable has the corresponding yara_meta: directive."""
    cond = RuleConditions(has_yara_meta_tags=["type=doc"])
    obs = MockObservable(directives=[f"{DIRECTIVE_YARA_META_PREFIX}type=doc"])
    assert cond.evaluate(obs, MockRoot()) is True


@pytest.mark.unit
def test_conditions_has_yara_meta_tags_no_match():
    """has_yara_meta_tags should fail when the observable lacks the directive."""
    cond = RuleConditions(has_yara_meta_tags=["type=doc"])
    obs = MockObservable(directives=[])
    assert cond.evaluate(obs, MockRoot()) is False


@pytest.mark.unit
def test_conditions_has_yara_meta_tags_multiple():
    """has_yara_meta_tags with multiple tags should require ALL of them (AND logic)."""
    cond = RuleConditions(has_yara_meta_tags=["type=doc", "source=email"])
    obs_both = MockObservable(directives=[
        f"{DIRECTIVE_YARA_META_PREFIX}type=doc",
        f"{DIRECTIVE_YARA_META_PREFIX}source=email",
    ])
    assert cond.evaluate(obs_both, MockRoot()) is True

    obs_one = MockObservable(directives=[f"{DIRECTIVE_YARA_META_PREFIX}type=doc"])
    assert cond.evaluate(obs_one, MockRoot()) is False


@pytest.mark.unit
def test_has_yara_meta_tags_integration():
    """Integration test: a rule with has_yara_meta_tags should match a file with add_yara_meta()."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = _add_file_observable(root, "qrcode_image.png", content="img data")
    observable.add_yara_meta("type", "document.text.qrcode")

    rules = [{
        "name": "qrcode meta tag rule",
        "conditions": {
            "observable_types": ["file"],
            "has_yara_meta_tags": ["type=document.text.qrcode"],
        },
        "actions": {
            "add_directives": ["ocr"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert observable.has_directive("ocr")

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert len(analysis.details["matched_rules"]) == 1
    assert analysis.details["matched_rules"][0]["name"] == "qrcode meta tag rule"


@pytest.mark.unit
def test_has_yara_meta_tags_no_match_integration():
    """Integration test: rule with has_yara_meta_tags should not match when tag is absent."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = _add_file_observable(root, "regular.png", content="img data")

    rules = [{
        "name": "qrcode meta tag rule",
        "conditions": {
            "observable_types": ["file"],
            "has_yara_meta_tags": ["type=document.text.qrcode"],
        },
        "actions": {
            "add_directives": ["ocr"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert not observable.has_directive("ocr")


# ============================================================
# Tests for ignore action
# ============================================================


@pytest.mark.unit
def test_actions_ignore():
    """ignore: true should record 'ignore' in the applied dict."""
    actions = RuleActions(ignore=True)
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert applied["ignore"] is True


@pytest.mark.unit
def test_actions_ignore_default():
    """Default ignore=False should not add 'ignore' to applied dict."""
    actions = RuleActions()
    tracker = ActionTracker()
    applied = actions.apply(tracker)
    assert "ignore" not in applied


# ============================================================
# Tests for parent scope in tree conditions
# ============================================================


@pytest.mark.unit
def test_tree_condition_parent_scope_match():
    """Parent scope should match when the analysis type is a direct parent of the observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class ParentEmailAnalysis(Analysis):
        pass

    email_analysis = ParentEmailAnalysis()
    email_analysis.details = {}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    # target is a direct child of email_analysis
    target = email_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "user@example.com")

    module_path = f"{ParentEmailAnalysis.__module__}:{ParentEmailAnalysis.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="parent",
    )
    assert tc.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_parent_scope_no_match():
    """Parent scope should not match when the analysis type is an ancestor but not a direct parent."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class GrandparentAnalysis(Analysis):
        pass

    class ChildAnalysis(Analysis):
        pass

    grandparent_analysis = GrandparentAnalysis()
    grandparent_analysis.details = {}
    grandparent_analysis.details_modified = True
    parent_observable.add_analysis(grandparent_analysis)

    mid_observable = grandparent_analysis.add_observable_by_spec(F_FQDN, "mid.example.com")
    child_analysis = ChildAnalysis()
    child_analysis.details = {}
    child_analysis.details_modified = True
    mid_observable.add_analysis(child_analysis)

    # target is a child of child_analysis, NOT a direct child of grandparent_analysis
    target = child_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "user@example.com")

    module_path = f"{GrandparentAnalysis.__module__}:{GrandparentAnalysis.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="parent",
    )
    # grandparent_analysis is an ancestor but NOT a direct parent
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_parent_scope_parsed_from_yaml():
    """scope: 'parent' should be read correctly from YAML rule config."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class YAMLParentAnalysis(Analysis):
        pass

    email_analysis = YAMLParentAnalysis()
    email_analysis.details = {}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    target = email_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "user@example.com")

    module_path = f"{YAMLParentAnalysis.__module__}:{YAMLParentAnalysis.__name__}"
    rules = [{
        "name": "parent scope test",
        "conditions": {
            "observable_types": ["email_address"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "parent",
            }],
        },
        "actions": {
            "add_tags": ["matched_parent"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_tag("matched_parent")


# ============================================================
# Regression tests for the "Enable OCR for images" rule shape
#
# The rule enables OCR on image files but must exclude phishkit screenshots,
# whose page text phishkit already captures verbatim in dom.html. An earlier
# version narrowed the exclusion with observable_match on file_name, which only
# suppressed OCR when phishkit was pointed at a file -- screenshots from URL
# scans were OCR'd anyway. These tests pin the parent-scoped form.
# ============================================================


class _PhishkitAnalysisStub(Analysis):
    """Stands in for saq.modules.phishkit:PhishkitAnalysis."""
    pass


_PHISHKIT_STUB_PATH = f"{_PhishkitAnalysisStub.__module__}:{_PhishkitAnalysisStub.__name__}"

_OCR_RULE = {
    "name": "Enable OCR for images",
    "conditions": {
        "observable_types": ["file"],
        "has_yara_meta_tags": ["type=image"],
        "tree_conditions": [{
            "analysis_type": _PHISHKIT_STUB_PATH,
            "scope": "parent",
            "negate": True,
        }],
    },
    "actions": {"add_directives": [DIRECTIVE_OCR]},
}


def _add_phishkit_screenshot(root, scanned_observable, filename="screenshot.png"):
    """Attaches a phishkit analysis to scanned_observable and returns its screenshot."""
    phishkit = _PhishkitAnalysisStub()
    phishkit.details = {}
    phishkit.details_modified = True
    scanned_observable.add_analysis(phishkit)

    screenshot = _add_file_observable(root, filename, content="fake png")
    phishkit.add_observable(screenshot)
    screenshot.add_yara_meta("type", "image")
    return screenshot


@pytest.mark.unit
def test_ocr_rule_skips_phishkit_screenshot_of_url_scan():
    """A screenshot from a phishkit scan of a URL must not get the ocr directive.

    This is the regression: the scanned observable is a url, which has no
    file_name, so an observable_match-narrowed exclusion never fired.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    scanned_url = root.add_observable_by_spec(F_URL, "https://example.com/login/")
    screenshot = _add_phishkit_screenshot(root, scanned_url)

    adapter = _create_analyzer_with_rules(root, [_OCR_RULE])
    adapter.execute_analysis(screenshot)
    adapter.analyze(screenshot, final_analysis=True)

    assert not screenshot.has_directive(DIRECTIVE_OCR)


@pytest.mark.unit
def test_ocr_rule_skips_phishkit_screenshot_of_html_body_render():
    """A screenshot from a phishkit render of an email HTML body must not get the ocr directive."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    html_body = _add_file_observable(root, "email.rfc822.unknown_text_html_000.html", content="<html></html>")
    screenshot = _add_phishkit_screenshot(root, html_body)

    adapter = _create_analyzer_with_rules(root, [_OCR_RULE])
    adapter.execute_analysis(screenshot)
    adapter.analyze(screenshot, final_analysis=True)

    assert not screenshot.has_directive(DIRECTIVE_OCR)


@pytest.mark.unit
def test_ocr_rule_still_enables_ocr_for_non_phishkit_images():
    """An image that phishkit did not produce still gets the ocr directive."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    attachment = _add_file_observable(root, "invoice.png", content="fake png")
    attachment.add_yara_meta("type", "image")

    adapter = _create_analyzer_with_rules(root, [_OCR_RULE])
    adapter.execute_analysis(attachment)
    adapter.analyze(attachment, final_analysis=True)

    assert attachment.has_directive(DIRECTIVE_OCR)


# ============================================================
# Tests for descendants scope in tree conditions
# ============================================================


@pytest.mark.unit
def test_tree_condition_descendants_scope_match():
    """Descendants scope should match when the analysis type runs on a descendant observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://newdomain.example/login")

    class ParseURLAnalysisStub(Analysis):
        pass

    parse_url_analysis = ParseURLAnalysisStub()
    parse_url_analysis.details = {}
    parse_url_analysis.details_modified = True
    target.add_analysis(parse_url_analysis)

    child_fqdn = parse_url_analysis.add_observable_by_spec(F_FQDN, "newdomain.example")

    class RdapAnalysisStub(Analysis):
        pass

    rdap_analysis = RdapAnalysisStub()
    rdap_analysis.details = {"age_created_in_days": "3"}
    rdap_analysis.details_modified = True
    child_fqdn.add_analysis(rdap_analysis)

    module_path = f"{RdapAnalysisStub.__module__}:{RdapAnalysisStub.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="descendants",
        details_match={"age_created_in_days": re.compile(r"^[0-7]$")},
    )
    assert tc.evaluate(target, root) is True


@pytest.mark.unit
def test_tree_condition_descendants_scope_no_match_details():
    """Descendants scope should fail when descendant analysis details don't match."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://olddomain.example/login")

    class ParseURLAnalysisStub2(Analysis):
        pass

    parse_url_analysis = ParseURLAnalysisStub2()
    parse_url_analysis.details = {}
    parse_url_analysis.details_modified = True
    target.add_analysis(parse_url_analysis)

    child_fqdn = parse_url_analysis.add_observable_by_spec(F_FQDN, "olddomain.example")

    class RdapAnalysisStub2(Analysis):
        pass

    rdap_analysis = RdapAnalysisStub2()
    rdap_analysis.details = {"age_created_in_days": "500"}
    rdap_analysis.details_modified = True
    child_fqdn.add_analysis(rdap_analysis)

    module_path = f"{RdapAnalysisStub2.__module__}:{RdapAnalysisStub2.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="descendants",
        details_match={"age_created_in_days": re.compile(r"^[0-7]$")},
    )
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_descendants_scope_excludes_self():
    """Descendants scope must not match analyses performed directly on the target observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://example.test/x")

    class SelfOnlyAnalysis(Analysis):
        pass

    self_analysis = SelfOnlyAnalysis()
    self_analysis.details = {"flag": "yes"}
    self_analysis.details_modified = True
    target.add_analysis(self_analysis)

    module_path = f"{SelfOnlyAnalysis.__module__}:{SelfOnlyAnalysis.__name__}"
    tc = TreeCondition(
        analysis_type=module_path,
        scope="descendants",
        details_match={"flag": re.compile(r"^yes$")},
    )
    assert tc.evaluate(target, root) is False


@pytest.mark.unit
def test_tree_condition_descendants_observable_match_no_analysis_on_descendant():
    """A descendants + observable_match condition (no analysis_type) must match a
    descendant observable that has NO analysis of its own.

    Regression for the "Tag Crowdstrike hosts belonging to analysts" race: a user
    observable emitted by a Falcon analysis on the host is invisible to the
    analysis-centric descendant traversal until it acquires its own analysis, by
    which point the host is no longer re-queued for pre-phase re-evaluation. The
    observable-centric path must surface it immediately.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    host = root.add_observable_by_spec(F_URL, "https://host.example/")

    class HostEnrichmentStub(Analysis):
        pass

    enrichment = HostEnrichmentStub()
    enrichment.details = {}
    enrichment.details_modified = True
    host.add_analysis(enrichment)

    # descendant user observable with NO analysis of its own (the bug condition)
    user = enrichment.add_observable_by_spec(F_USER, "usr1234")
    assert not user.all_analysis

    tc = TreeCondition(
        analysis_type=None,
        scope="descendants",
        observable_match={
            "type": re.compile(r"^user$"),
            "value": re.compile(r"(?i)^usr1234$"),
        },
    )
    assert tc.evaluate(host, root) is True

    # sanity: the old analysis-centric traversal cannot see an analysis-less child
    from saq.modules.util.observable_modifier import _get_descendant_analyses
    assert all(a.observable is not user for a in _get_descendant_analyses(host))


@pytest.mark.unit
def test_tree_condition_descendants_observable_match_value_outside_pattern():
    """Descendants observable_match must not match when the descendant observable's
    value falls outside the allowlist pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    host = root.add_observable_by_spec(F_URL, "https://host.example/")

    class HostEnrichmentStub2(Analysis):
        pass

    enrichment = HostEnrichmentStub2()
    enrichment.details = {}
    enrichment.details_modified = True
    host.add_analysis(enrichment)

    # a non-allowlisted user
    enrichment.add_observable_by_spec(F_USER, "nottracked99")

    tc = TreeCondition(
        analysis_type=None,
        scope="descendants",
        observable_match={
            "type": re.compile(r"^user$"),
            "value": re.compile(r"(?i)^usr1234$"),
        },
    )
    assert tc.evaluate(host, root) is False


@pytest.mark.unit
def test_tree_condition_descendants_scope_parsed_from_yaml():
    """scope: 'descendants' should be read correctly from YAML rule config."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://fresh.example/q")

    class YAMLParseURL(Analysis):
        pass

    parse_url_analysis = YAMLParseURL()
    parse_url_analysis.details = {}
    parse_url_analysis.details_modified = True
    target.add_analysis(parse_url_analysis)

    child_fqdn = parse_url_analysis.add_observable_by_spec(F_FQDN, "fresh.example")

    class YAMLWhois(Analysis):
        pass

    whois_analysis = YAMLWhois()
    whois_analysis.details = {"age_created_in_days": "1"}
    whois_analysis.details_modified = True
    child_fqdn.add_analysis(whois_analysis)

    module_path = f"{YAMLWhois.__module__}:{YAMLWhois.__name__}"
    rules = [{
        "name": "descendants scope yaml test",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "descendants",
                "details_match": {
                    "age_created_in_days": "^[0-7]$",
                },
            }],
        },
        "actions": {
            "add_directives": ["crawl"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target.has_directive("crawl")


# ============================================================
# Tests for reset_analysis action
# ============================================================


@pytest.mark.unit
def test_reset_analysis_clears_no_analysis_sentinel():
    """reset_analysis should delete the False sentinel so the module can re-run."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://example.test/x")
    sentinel_key = "saq.modules.phishkit:PhishkitAnalysis"
    target._analysis[sentinel_key] = False  # simulate add_no_analysis()

    actions = RuleActions(
        reset_analysis=[sentinel_key],
        add_directives=["crawl"],
    )
    applied = actions.apply(target)

    assert applied.get("reset_analysis") == [sentinel_key]
    assert sentinel_key not in target._analysis
    assert target.has_directive("crawl")


@pytest.mark.unit
def test_reset_analysis_preserves_real_analysis():
    """reset_analysis must not delete an entry holding an actual Analysis object."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://example.test/y")

    class RealAnalysis(Analysis):
        pass

    real = RealAnalysis()
    real.details = {"ok": True}
    real.details_modified = True
    target.add_analysis(real)
    key = real.module_path

    actions = RuleActions(reset_analysis=[key])
    applied = actions.apply(target)

    assert "reset_analysis" not in applied
    assert target._analysis[key] is real


@pytest.mark.unit
def test_reset_analysis_missing_entry_is_noop():
    """reset_analysis should silently skip modules with no prior record."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    target = root.add_observable_by_spec(F_URL, "https://example.test/z")

    actions = RuleActions(reset_analysis=["saq.modules.never:RanAnalysis"])
    applied = actions.apply(target)

    assert "reset_analysis" not in applied


@pytest.mark.unit
def test_reset_analysis_parsed_from_yaml():
    """reset_analysis list should be read correctly from YAML rule config."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_URL, "https://example.test/yaml")
    sentinel_key = "saq.modules.phishkit:PhishkitAnalysis"
    target._analysis[sentinel_key] = False

    rules = [{
        "name": "reset analysis yaml test",
        "conditions": {"observable_types": ["url"]},
        "actions": {
            "add_directives": ["crawl"],
            "reset_analysis": [sentinel_key],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert sentinel_key not in target._analysis
    assert target.has_directive("crawl")


# ============================================================
# Integration tests for ignore action with parent removal
# ============================================================


@pytest.mark.unit
def test_ignore_removes_observable_from_matching_parent():
    """ignore action with parent scope should remove observable from the matching parent analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class EmailAnalysisStub(Analysis):
        pass

    email_analysis = EmailAnalysisStub()
    email_analysis.details = {}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    # Add email_address observable as child of email analysis (envelope recipient)
    target = email_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")
    assert target in email_analysis.observables

    module_path = f"{EmailAnalysisStub.__module__}:{EmailAnalysisStub.__name__}"
    rules = [{
        "name": "ignore team emails",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "parent",
            }],
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # Observable should be removed from email_analysis._observables
    assert target not in email_analysis.observables
    # Observable has no remaining parents, so it should be globally ignored
    assert target.ignored is True


@pytest.mark.unit
def test_ignore_preserves_observable_in_other_parents():
    """ignore action should only remove from matching parent, preserving other parent references."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class EmailAnalysisStub2(Analysis):
        pass

    class IOCExtractionStub(Analysis):
        pass

    email_analysis = EmailAnalysisStub2()
    email_analysis.details = {}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    # Add email as child of email_analysis (envelope recipient)
    target = email_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")

    # Also add the SAME observable as child of IOC extraction (simulating IOC extraction finding it too)
    ioc_parent = root.add_observable_by_spec(F_FQDN, "body.example.com")
    ioc_analysis = IOCExtractionStub()
    ioc_analysis.details = {}
    ioc_analysis.details_modified = True
    ioc_parent.add_analysis(ioc_analysis)
    ioc_analysis.add_observable_to_tree(target)

    assert target in email_analysis.observables
    assert target in ioc_analysis.observables

    email_module_path = f"{EmailAnalysisStub2.__module__}:{EmailAnalysisStub2.__name__}"
    rules = [{
        "name": "ignore team emails",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
            "tree_conditions": [{
                "analysis_type": email_module_path,
                "scope": "parent",
            }],
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # Observable should be removed from email_analysis
    assert target not in email_analysis.observables
    # But preserved in ioc_analysis
    assert target in ioc_analysis.observables
    # Should NOT be globally ignored since it still has a parent
    assert target.ignored is False


@pytest.mark.unit
def test_ignore_global_without_parent_scope():
    """ignore action without parent-scoped tree conditions should globally ignore the observable."""
    root = create_root_analysis(analysis_mode="test_single", alert_type="test_alert")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")

    rules = [{
        "name": "global ignore",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target)
    result = adapter.analyze(target, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # No parent-scoped tree conditions, so should be globally ignored
    assert target.ignored is True


# ============================================================
# ignore action in the pre phase
# ============================================================


@pytest.mark.unit
def test_ignore_pre_adds_exclude_all_directive():
    """A pre-phase ignore rule should install the exclude_all directive (so the
    engine skips all further analysis) and mark the observable ignored -- during
    execute_analysis, without waiting for the final pass."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")
    rules = [{
        "name": "ignore team emails (pre)",
        "phase": "pre",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(target)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # the pre phase actioned the ignore inline -- no final pass needed
    assert target.has_directive(DIRECTIVE_EXCLUDE_ALL)
    assert target.ignored is True


@pytest.mark.unit
def test_ignore_pre_removes_observable_from_matching_parent():
    """A pre-phase ignore rule with parent scope should remove the observable
    from the matching parent analysis during execute_analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class EmailAnalysisStubPre(Analysis):
        pass

    email_analysis = EmailAnalysisStubPre()
    email_analysis.details = {}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    target = email_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")
    assert target in email_analysis.observables

    module_path = f"{EmailAnalysisStubPre.__module__}:{EmailAnalysisStubPre.__name__}"
    rules = [{
        "name": "ignore team emails (pre)",
        "phase": "pre",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
            "tree_conditions": [{
                "analysis_type": module_path,
                "scope": "parent",
            }],
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # only the pre pass -- no final_analysis
    result = adapter.execute_analysis(target)
    assert result == AnalysisExecutionResult.INCOMPLETE

    assert target not in email_analysis.observables
    # no remaining parents -> globally ignored
    assert target.ignored is True
    assert target.has_directive(DIRECTIVE_EXCLUDE_ALL)


@pytest.mark.unit
def test_ignore_pre_preserves_observable_in_other_parents():
    """A pre-phase ignore rule should only remove from the matching parent,
    preserving other parent references (and not globally ignoring)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class EmailAnalysisStubPre2(Analysis):
        pass

    class IOCExtractionStubPre(Analysis):
        pass

    email_analysis = EmailAnalysisStubPre2()
    email_analysis.details = {}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)

    target = email_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")

    ioc_parent = root.add_observable_by_spec(F_FQDN, "body.example.com")
    ioc_analysis = IOCExtractionStubPre()
    ioc_analysis.details = {}
    ioc_analysis.details_modified = True
    ioc_parent.add_analysis(ioc_analysis)
    ioc_analysis.add_observable_to_tree(target)

    assert target in email_analysis.observables
    assert target in ioc_analysis.observables

    email_module_path = f"{EmailAnalysisStubPre2.__module__}:{EmailAnalysisStubPre2.__name__}"
    rules = [{
        "name": "ignore team emails (pre)",
        "phase": "pre",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
            "tree_conditions": [{
                "analysis_type": email_module_path,
                "scope": "parent",
            }],
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    result = adapter.execute_analysis(target)
    assert result == AnalysisExecutionResult.INCOMPLETE

    assert target not in email_analysis.observables
    assert target in ioc_analysis.observables
    # still has a parent -> not globally ignored
    assert target.ignored is False
    # but still excluded from further analysis
    assert target.has_directive(DIRECTIVE_EXCLUDE_ALL)


@pytest.mark.unit
def test_ignore_pre_idempotent_across_repeated_execute_analysis():
    """The pre phase's execute_analysis is re-invoked as the tree grows; a
    pre-phase ignore rule must be safe to apply repeatedly."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    target = root.add_observable_by_spec(F_EMAIL_ADDRESS, "team@example.com")
    rules = [{
        "name": "ignore team emails (pre)",
        "uuid": "c1c2c3c4-0000-4000-8000-000000000001",
        "phase": "pre",
        "conditions": {
            "observable_types": ["email_address"],
            "value_pattern": r"team@example\.com",
        },
        "actions": {
            "ignore": True,
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # re-invoke several times -- must not raise and must converge
    for _ in range(3):
        assert adapter.execute_analysis(target) == AnalysisExecutionResult.INCOMPLETE

    assert target.ignored is True
    # add_directive dedups -- exactly one exclude_all directive
    assert target.directives.count(DIRECTIVE_EXCLUDE_ALL) == 1

    analysis = target.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    # matched_rules is rebuilt fresh each pass -- not accumulated
    assert len(analysis.details["matched_rules"]) == 1


@pytest.mark.unit
def test_accepts_returns_false_with_exclude_all_directive():
    """AnalysisModule.accepts() must refuse an observable carrying the
    exclude_all directive (consistent with the engine's exclusion check), so a
    directive installed mid-work-item gates the remaining modules immediately."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rules = [{
        "name": "noop",
        "conditions": {"observable_types": ["email_address"]},
        "actions": {"add_tags": ["noop"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    # control: a fresh observable is accepted
    control = root.add_observable_by_spec(F_EMAIL_ADDRESS, "control@example.com")
    assert adapter.accepts(control) is True

    # with exclude_all, the same module refuses it
    excluded = root.add_observable_by_spec(F_EMAIL_ADDRESS, "excluded@example.com")
    excluded.add_directive(DIRECTIVE_EXCLUDE_ALL)
    assert adapter.accepts(excluded) is False


# ============================================================
# uuid / signature_id observable tests
# ============================================================


@pytest.mark.unit
def test_rule_uuid_round_trips_through_parser():
    """A uuid declared in YAML should be loaded onto Rule.uuid."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rule_uuid = "3a1ddc4e-def5-439b-b3d3-d51352786d94"
    rules = [{
        "name": "uuid round-trip rule",
        "uuid": rule_uuid,
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)
    # Trigger lazy initialization
    adapter.execute_analysis(root.add_observable_by_spec(F_URL, "https://example.com"))

    loaded_rules = adapter._module._rules
    assert len(loaded_rules) == 1
    assert loaded_rules[0].uuid == rule_uuid


@pytest.mark.unit
def test_rule_without_uuid_is_rejected_at_load(caplog):
    """A rule missing the required uuid field should be dropped with an error."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    rules = [{
        "name": "missing uuid rule",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    with caplog.at_level(logging.ERROR):
        adapter = _create_analyzer_with_rules(root, rules, auto_uuid=False)
        # Trigger lazy load
        adapter.execute_analysis(root.add_observable_by_spec(F_URL, "https://example.com"))

    assert adapter._module._rules == []
    assert any(
        "missing required 'uuid'" in rec.message for rec in caplog.records
    )


@pytest.mark.unit
def test_matching_rule_emits_signature_id_observable():
    """When a rule matches, a signature_id observable with the rule's uuid is emitted."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rule_uuid = "48d96a47-b7a2-415b-bb6c-661675d2a87c"
    rules = [{
        "name": "sig test rule",
        "uuid": rule_uuid,
        "conditions": {
            "observable_types": ["url"],
            "value_pattern": r".*\.html$",
        },
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    # matched_rules record carries the uuid
    assert analysis.details["matched_rules"][0]["uuid"] == rule_uuid
    # signature_id observable attached as a child of the analysis
    sig_observables = [o for o in analysis.observables if o.type == F_SIGNATURE_ID]
    assert len(sig_observables) == 1
    assert sig_observables[0].value == rule_uuid


@pytest.mark.unit
def test_multiple_matching_rules_emit_distinct_signature_ids():
    """Two distinct matching rules should each yield their own signature_id observable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    uuid_a = "67efec83-6146-49b7-839a-02de5af92a20"
    uuid_b = "7fcbc3ef-cb8a-4433-8dbf-0753da7b4ac7"
    rules = [
        {
            "name": "rule a",
            "uuid": uuid_a,
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["extract_iocs"]},
        },
        {
            "name": "rule b",
            "uuid": uuid_b,
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_tags": ["tagged"]},
        },
    ]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    emitted = {o.value for o in analysis.observables if o.type == F_SIGNATURE_ID}
    assert emitted == {uuid_a, uuid_b}


@pytest.mark.unit
def test_pre_phase_signature_id_survives_worker_handoff():
    """A pre-phase rule's signature_id must be emitted even when execute_final_analysis
    runs on a fresh analyzer instance (simulating the root being resumed by a
    different worker process). Regression test for the bug where pre-phase matches
    were held only in in-memory module state and lost across worker hand-offs."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rule_uuid = "a1b2c3d4-0000-4000-8000-000000000001"
    rules = [{
        "name": "pre rule with sig",
        "uuid": rule_uuid,
        "phase": "pre",
        "conditions": {"observable_types": ["url"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]

    # Worker A: runs the pre-phase pass.
    adapter_a = _create_analyzer_with_rules(root, rules)
    result = adapter_a.execute_analysis(observable)
    assert result == AnalysisExecutionResult.INCOMPLETE

    # Worker B: completely fresh analyzer instance, simulating a different
    # process pulling the root off the workload queue between phases.
    adapter_b = _create_analyzer_with_rules(root, rules)
    result = adapter_b.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    rule_uuids = [r["uuid"] for r in analysis.details["matched_rules"]]
    assert rule_uuids == [rule_uuid]

    sig_observables = [o for o in analysis.observables if o.type == F_SIGNATURE_ID]
    assert [o.value for o in sig_observables] == [rule_uuid]


@pytest.mark.unit
def test_pre_and_post_phase_signature_ids_survive_worker_handoff():
    """Pre and post phase matches across separate analyzer instances must
    each contribute exactly one signature_id observable to the final analysis."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    pre_uuid = "a1b2c3d4-0000-4000-8000-000000000010"
    post_uuid = "a1b2c3d4-0000-4000-8000-000000000020"
    rules = [
        {
            "name": "pre rule",
            "uuid": pre_uuid,
            "phase": "pre",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["pre_dir"]},
        },
        {
            "name": "post rule",
            "uuid": post_uuid,
            "phase": "post",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_tags": ["post_tag"]},
        },
    ]

    # Worker A handles pre-phase only.
    adapter_a = _create_analyzer_with_rules(root, rules)
    adapter_a.execute_analysis(observable)

    # Worker B (fresh instance) handles post-phase.
    adapter_b = _create_analyzer_with_rules(root, rules)
    adapter_b.analyze(observable, final_analysis=True)

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    rule_uuids = sorted(r["uuid"] for r in analysis.details["matched_rules"])
    assert rule_uuids == sorted([pre_uuid, post_uuid])

    emitted = sorted(o.value for o in analysis.observables if o.type == F_SIGNATURE_ID)
    assert emitted == sorted([pre_uuid, post_uuid])


# ============================================================
# Crawl URLs from iCalendar files (analyst_data rule)
# ============================================================


@pytest.mark.unit
def test_crawl_url_extracted_from_ical_file():
    """URL whose ancestor file has FileTypeAnalysis mime=text/calendar should get crawl directive."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    ical_file = _add_file_observable(root, "invite.ics", content="BEGIN:VCALENDAR")

    class FileTypeAnalysisStubICal(Analysis):
        pass

    file_type_analysis = FileTypeAnalysisStubICal()
    file_type_analysis.details = {"mime": "text/calendar", "type": "iCalendar calendar file"}
    file_type_analysis.details_modified = True
    ical_file.add_analysis(file_type_analysis)

    class URLExtractionAnalysisStub(Analysis):
        pass

    url_extraction = URLExtractionAnalysisStub()
    url_extraction.details_modified = True
    ical_file.add_analysis(url_extraction)
    target_url = url_extraction.add_observable_by_spec(F_URL, "https://calendly.com/d/cx4j-xpc-9b5")

    file_type_module_path = f"{FileTypeAnalysisStubICal.__module__}:{FileTypeAnalysisStubICal.__name__}"
    rules = [{
        "name": "Crawl URLs extracted from iCalendar files",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": file_type_module_path,
                "scope": "siblings",
                "details_match": {"mime": r"^text/calendar$"},
            }],
        },
        "actions": {
            "add_directives": ["crawl"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_url)
    result = adapter.analyze(target_url, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert target_url.has_directive("crawl")


@pytest.mark.unit
def test_crawl_ical_rule_does_not_match_non_ical_ancestor():
    """URL whose ancestor file has a non-calendar mime type should NOT get the crawl directive."""

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    html_file = _add_file_observable(root, "page.html", content="<html></html>")

    class FileTypeAnalysisStubHTML(Analysis):
        pass

    file_type_analysis = FileTypeAnalysisStubHTML()
    file_type_analysis.details = {"mime": "text/html", "type": "HTML document"}
    file_type_analysis.details_modified = True
    html_file.add_analysis(file_type_analysis)

    class URLExtractionAnalysisStub2(Analysis):
        pass

    url_extraction = URLExtractionAnalysisStub2()
    url_extraction.details_modified = True
    html_file.add_analysis(url_extraction)
    target_url = url_extraction.add_observable_by_spec(F_URL, "https://example.com/page")

    file_type_module_path = f"{FileTypeAnalysisStubHTML.__module__}:{FileTypeAnalysisStubHTML.__name__}"
    rules = [{
        "name": "Crawl URLs extracted from iCalendar files",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": file_type_module_path,
                "scope": "siblings",
                "details_match": {"mime": r"^text/calendar$"},
            }],
        },
        "actions": {
            "add_directives": ["crawl"],
        },
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_url)
    result = adapter.analyze(target_url, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert not target_url.has_directive("crawl")


# ============================================================
# Rule evaluation cost metrics tests
# ============================================================


def _cost_rules(*uuids, enabled=True):
    """Build simple url-matching post-phase rules with explicit uuids."""
    return [
        {
            "name": f"cost rule {u}",
            "uuid": u,
            "enabled": enabled,
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["extract_iocs"]},
        }
        for u in uuids
    ]


@pytest.mark.unit
def test_rule_eval_cost_accumulates():
    """A rule that is evaluated records count and timing in the accumulator."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, _cost_rules("cost-uuid-1"))

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    stats = adapter.wrapped_module._rule_eval_stats
    assert root.uuid in stats
    rule_stats = stats[root.uuid]["cost-uuid-1"]
    assert rule_stats["count"] >= 1
    assert rule_stats["total_seconds"] >= 0.0
    assert rule_stats["max_seconds"] >= 0.0
    assert rule_stats["name"] == "cost rule cost-uuid-1"


@pytest.mark.unit
def test_rule_eval_cost_emitted_on_post_analysis(caplog):
    """execute_post_analysis emits one cost log line per evaluated rule."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, _cost_rules("cost-uuid-1"))

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    with caplog.at_level(logging.INFO):
        result = adapter.execute_post_analysis()

    assert result == AnalysisExecutionResult.COMPLETED
    cost_lines = [
        r.getMessage() for r in caplog.records
        if "observable_modifier rule cost" in r.getMessage()
    ]
    assert len(cost_lines) == 1
    assert "rule_uuid=cost-uuid-1" in cost_lines[0]
    assert f"root={root.uuid}" in cost_lines[0]
    assert "count=" in cost_lines[0]
    assert "total_seconds=" in cost_lines[0]


@pytest.mark.unit
def test_rule_eval_cost_dict_popped_after_emit():
    """The root's accumulator entry is removed once metrics are emitted."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, _cost_rules("cost-uuid-1"))

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)
    assert root.uuid in adapter.wrapped_module._rule_eval_stats

    adapter.execute_post_analysis()
    assert root.uuid not in adapter.wrapped_module._rule_eval_stats


@pytest.mark.unit
def test_rule_eval_cost_post_analysis_idempotent(caplog):
    """A second execute_post_analysis call emits nothing and does not raise."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, _cost_rules("cost-uuid-1"))

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    with caplog.at_level(logging.INFO):
        adapter.execute_post_analysis()
        caplog.clear()
        result = adapter.execute_post_analysis()

    assert result == AnalysisExecutionResult.COMPLETED
    assert not [
        r for r in caplog.records
        if "observable_modifier rule cost" in r.getMessage()
    ]


@pytest.mark.unit
def test_rule_eval_cost_counts_per_rule(caplog):
    """Each evaluated rule gets its own accumulator entry and log line."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, _cost_rules("cost-uuid-1", "cost-uuid-2"))

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    root_stats = adapter.wrapped_module._rule_eval_stats[root.uuid]
    assert set(root_stats) == {"cost-uuid-1", "cost-uuid-2"}

    with caplog.at_level(logging.INFO):
        adapter.execute_post_analysis()

    cost_lines = [
        r.getMessage() for r in caplog.records
        if "observable_modifier rule cost" in r.getMessage()
    ]
    assert len(cost_lines) == 2


@pytest.mark.unit
def test_rule_eval_cost_disabled_rule_not_counted():
    """A disabled rule is skipped before evaluation and is not counted."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = _cost_rules("enabled-uuid") + _cost_rules("disabled-uuid", enabled=False)
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    root_stats = adapter.wrapped_module._rule_eval_stats[root.uuid]
    assert "enabled-uuid" in root_stats
    assert "disabled-uuid" not in root_stats


@pytest.mark.unit
def test_rule_eval_cost_no_rules_no_emission(caplog):
    """With no rules, execute_post_analysis emits no cost lines."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, [])

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    with caplog.at_level(logging.INFO):
        result = adapter.execute_post_analysis()

    assert result == AnalysisExecutionResult.COMPLETED
    assert not [
        r for r in caplog.records
        if "observable_modifier rule cost" in r.getMessage()
    ]


# ============================================================
# Post-phase re-evaluation across analysis modes
# ============================================================


@pytest.mark.unit
def test_post_phase_reevaluated_in_later_mode_after_delayed_analysis():
    """Regression: a post-phase rule whose tree_condition depends on an analysis
    produced only in a later analysis mode must still fire -- even when an
    earlier-phase rule already created the ObservableModifierAnalysis in the
    first mode. The module must not seal the analysis completed, or
    AnalysisModule.accepts() blocks the re-evaluation and the post rule never
    sees the analysis it waits for."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")

    # Stand-in for a delayed analysis module (e.g. a Splunk query) whose module
    # group only runs in a later analysis mode.
    class DeferredAnalysis(Analysis):
        pass

    module_path = f"{DeferredAnalysis.__module__}:{DeferredAnalysis.__name__}"
    pre_uuid = "c0ffee00-0000-4000-8000-000000000001"
    post_uuid = "c0ffee00-0000-4000-8000-000000000002"
    rules = [
        {
            # matches in mode 1 -> creates the ObservableModifierAnalysis
            "name": "pre rule",
            "uuid": pre_uuid,
            "phase": "pre",
            "conditions": {"observable_types": ["url"]},
            "actions": {"add_directives": ["pre_dir"]},
        },
        {
            "name": "post rule depending on deferred analysis",
            "uuid": post_uuid,
            "phase": "post",
            "conditions": {
                "observable_types": ["url"],
                "tree_conditions": [{
                    "analysis_type": module_path,
                    "scope": "self",
                    "details_match": {"query_results.message_id_seen": "^0$"},
                }],
            },
            "actions": {"add_detection_points": ["deferred analysis detection"]},
        },
    ]

    # Mode 1: the pre rule matches; the deferred analysis has not run yet, so
    # the post rule cannot match.
    adapter1 = _create_analyzer_with_rules(root, rules)
    adapter1.execute_analysis(observable)
    assert adapter1.analyze(observable, final_analysis=True) == AnalysisExecutionResult.INCOMPLETE
    assert not observable.has_detection_points()

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    # the analysis must NOT be sealed completed -- otherwise accepts() blocks
    # the post phase from re-running in the later mode.
    assert analysis.completed is False
    assert adapter1.accepts(observable) is True

    # The deferred analysis now appears (it ran in the later mode).
    deferred = DeferredAnalysis()
    deferred.details = {"query_results": [{"message_id_seen": "0"}]}
    deferred.details_modified = True
    observable.add_analysis(deferred)

    # Mode 2: the root has moved to a later analysis mode and a fresh analyzer
    # instance (a different worker process) resumes it.
    root.analysis_mode = "test_groups"
    adapter2 = _create_analyzer_with_rules(root, rules)
    assert adapter2.accepts(observable) is True
    adapter2.execute_analysis(observable)
    adapter2.analyze(observable, final_analysis=True)

    # the post rule now sees the deferred analysis and fires
    assert observable.has_detection_points()
    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert sorted(r["uuid"] for r in analysis.details["matched_rules"]) == sorted(
        [pre_uuid, post_uuid]
    )


@pytest.mark.unit
def test_post_phase_idempotent_across_modes():
    """Re-running the module (as happens across analysis modes) must not
    duplicate a matched rule's effects: matched_rules entries, detection
    points, signature_id observables, or appended exclude_analysis entries."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    post_uuid = "d0d0d0d0-0000-4000-8000-000000000001"
    rules = [{
        "name": "post rule",
        "uuid": post_uuid,
        "phase": "post",
        "conditions": {"observable_types": ["url"]},
        "actions": {
            "add_detection_points": ["dup check detection"],
            "add_tags": ["dup_tag"],
            "exclude_analysis": ["some.module:SomeAnalysis"],
        },
    }]

    # Run the full pre + final-analysis cycle three times, each on a fresh
    # analyzer instance (simulating re-runs in successive analysis modes).
    for _ in range(3):
        adapter = _create_analyzer_with_rules(root, rules)
        adapter.execute_analysis(observable)
        adapter.analyze(observable, final_analysis=True)

    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    assert analysis is not None
    assert [r["uuid"] for r in analysis.details["matched_rules"]] == [post_uuid]
    assert len(observable.detections) == 1
    assert observable.has_tag("dup_tag")
    assert observable._excluded_analysis.count("some.module:SomeAnalysis") == 1
    sig_observables = [o for o in analysis.observables if o.type == F_SIGNATURE_ID]
    assert [o.value for o in sig_observables] == [post_uuid]


@pytest.mark.unit
def test_no_match_observable_sealed_completed():
    """An observable that no rule's immutable conditions can match takes the
    fast path: both execute_analysis and execute_final_analysis return
    COMPLETED (sealing it) and no ObservableModifierAnalysis is created."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()

    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "fqdn-only rule",
        "phase": "post",
        "conditions": {"observable_types": ["fqdn"]},
        "actions": {"add_tags": ["nope"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    assert adapter.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert adapter.analyze(observable, final_analysis=True) == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(ObservableModifierAnalysis) is None


# ============================================================
# Per-root analysis-details cache (_load_details_for_match)
# ============================================================


class _StubDetailsAnalysis:
    """Minimal stand-in for an Analysis exposing only what
    _load_details_for_match touches, with a load_details() that counts disk
    reads and repopulates details from a simulated on-disk copy."""

    def __init__(self, external_details_path, details_size, disk_details):
        self.external_details_path = external_details_path
        self.details_size = details_size
        self.details = {}
        self._disk_details = disk_details
        self.load_count = 0

    def load_details(self):
        self.load_count += 1
        self.details = self._disk_details
        return True


@pytest.mark.unit
def test_load_details_for_match_caches_within_root():
    """A saved analysis is read from disk once; later sweeps (even after the
    engine flushes details back to {}) are served from the cache."""
    cache = {}
    analysis = _StubDetailsAnalysis("EmailAnalysis_abc.json", 100, {"email": {"from_address": "x@y.com"}})

    first = _load_details_for_match(analysis, cache)
    assert first == {"email": {"from_address": "x@y.com"}}
    assert analysis.load_count == 1

    # simulate the engine flushing details between observable_modifier sweeps
    analysis.details = {}
    second = _load_details_for_match(analysis, cache)
    assert second == {"email": {"from_address": "x@y.com"}}
    assert analysis.load_count == 1  # served from cache, no second disk read


@pytest.mark.unit
def test_load_details_for_match_invalidates_on_size_change():
    """A deferred analysis that re-saves with new content (new details_size)
    must be reloaded, not served stale from the cache (e.g. RdapAnalysis filling
    in age_created_in_days on a later pass)."""
    cache = {}
    analysis = _StubDetailsAnalysis("RdapAnalysis_abc.json", 100, {"age_created_in_days": "30"})

    assert _load_details_for_match(analysis, cache)["age_created_in_days"] == "30"
    assert analysis.load_count == 1

    # deferred re-save: details change, size changes, disk copy updated
    analysis.details = {}
    analysis.details_size = 140
    analysis._disk_details = {"age_created_in_days": "3"}

    refreshed = _load_details_for_match(analysis, cache)
    assert refreshed["age_created_in_days"] == "3"  # reloaded, not stale
    assert analysis.load_count == 2


@pytest.mark.unit
def test_load_details_for_match_no_cache_loads_every_time():
    """With details_cache=None the legacy behavior is preserved: load every call."""
    analysis = _StubDetailsAnalysis("EmailAnalysis_abc.json", 100, {"k": "v"})
    _load_details_for_match(analysis, None)
    analysis.details = {}
    _load_details_for_match(analysis, None)
    assert analysis.load_count == 2


@pytest.mark.unit
def test_load_details_for_match_unsaved_analysis_not_cached():
    """An analysis whose details were never saved (external_details_path is None)
    is never cached -- there is no stable disk key to invalidate against."""
    cache = {}
    analysis = _StubDetailsAnalysis(None, None, {"k": "v"})
    _load_details_for_match(analysis, cache)
    analysis.details = {}
    _load_details_for_match(analysis, cache)
    assert analysis.load_count == 2
    assert cache == {}


def _build_root_with_flushed_email_analysis(from_address="soc@vendor.com"):
    """Build a root with a target URL observable under an EmailAnalysis whose
    details have been flushed to disk (so external_details_path / details_size are
    set and access goes through the disk-read path). Returns
    (root, target_observable, email_analysis, module_path)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    parent_observable = root.add_observable_by_spec(F_FQDN, "email.vendor.com")

    class TestEmailAnalysis(Analysis):
        pass

    email_analysis = TestEmailAnalysis()
    email_analysis.details = {"email": {"from_address": from_address}}
    email_analysis.details_modified = True
    parent_observable.add_analysis(email_analysis)
    target_observable = email_analysis.add_observable_by_spec(F_URL, "https://example.com/page.html")

    # flush to disk: sets external_details_path + details_size and clears details
    root.analysis_tree_manager.flush_analysis_details(email_analysis)
    assert email_analysis.external_details_path is not None
    assert email_analysis.details == {}

    module_path = f"{TestEmailAnalysis.__module__}:{TestEmailAnalysis.__name__}"
    return root, target_observable, email_analysis, module_path


@pytest.mark.integration
def test_details_cache_loads_once_across_resweeps():
    """A non-matching details_match rule re-evaluates on every sweep (it never
    enters emitted_uuids), but the cache means its EmailAnalysis details are read
    from disk only once across many evaluations."""
    root, target_observable, email_analysis, module_path = _build_root_with_flushed_email_analysis()

    calls = {"n": 0}
    real_load = email_analysis.load_details

    def counting_load():
        calls["n"] += 1
        return real_load()

    email_analysis.load_details = counting_load

    rules = [{
        "name": "non-matching details rule",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {"email.from_address": r"NOMATCH@nowhere\.com"},
            }],
        },
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    for _ in range(5):
        adapter.execute_analysis(target_observable)

    # rule never matches -> no directive; details loaded from disk exactly once
    assert not target_observable.has_directive("extract_iocs")
    assert calls["n"] == 1


@pytest.mark.integration
def test_details_cache_matching_rule_parity():
    """A matching details_match rule still fires correctly when served via the cache."""
    root, target_observable, email_analysis, module_path = _build_root_with_flushed_email_analysis(
        from_address="soc@vendor.com"
    )
    rules = [{
        "name": "matching details rule",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {"email.from_address": r"soc@vendor\.com"},
            }],
        },
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_observable)
    assert target_observable.has_directive("extract_iocs")


@pytest.mark.integration
def test_details_cache_cleared_in_post_analysis():
    """The per-root details cache is populated during evaluation and dropped in
    execute_post_analysis so it stays bounded to a single root."""
    root, target_observable, email_analysis, module_path = _build_root_with_flushed_email_analysis()
    rules = [{
        "name": "details rule",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {"email.from_address": r"NOMATCH@nowhere\.com"},
            }],
        },
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_observable)

    analyzer = adapter._module
    # cache was populated for this root (the flushed EmailAnalysis details got cached)
    assert root.uuid in analyzer._details_cache
    assert analyzer._details_cache[root.uuid]  # non-empty: a path was cached

    adapter.execute_post_analysis()
    assert root.uuid not in analyzer._details_cache


# ============================================================
# git_dir / signature_version attribution tests
# ============================================================

def _init_git_repo_at(path):
    """init a git repo at path with one commit, returns the HEAD sha"""
    import subprocess
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    with open(os.path.join(str(path), ".keep"), "w") as fp:
        fp.write("x")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True, capture_output=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-m", "init"], check=True, capture_output=True, env=env)
    out = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    return out.stdout.strip()


@pytest.mark.unit
def test_observable_modifier_no_git_dir_yields_unknown():
    from saq.signatures import SIGNATURE_VERSION_UNKNOWN
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://evil.com/malware.exe")
    rules = [{
        "name": "suspicious download",
        "uuid": "11111111-1111-1111-1111-111111111111",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_detection_points": ["matched"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)
    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)
    dp = observable.detections[0]
    assert dp.signature_uuid == "11111111-1111-1111-1111-111111111111"
    assert dp.signature_version == SIGNATURE_VERSION_UNKNOWN


@pytest.mark.unit
def test_observable_modifier_git_dir_stamps_commit(tmpdir):
    # the rules file lives inside the git repo, so git_dir contains it
    git_dir = str(tmpdir)
    sha = _init_git_repo_at(git_dir)
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://evil.com/malware.exe")
    rules = [{
        "name": "suspicious download",
        "uuid": "22222222-2222-2222-2222-222222222222",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_detection_points": ["matched"]},
    }]
    # write rules into the git repo and point the analyzer's config there
    yaml_path = os.path.join(git_dir, "rules.yaml")
    with open(yaml_path, "w") as f:
        yaml.dump({"rules": rules}, f)

    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    config.rules_config_path = yaml_path
    config.git_dir = git_dir
    analyzer = ObservableModifierAnalyzer(context=context, config=config)
    adapter = AnalysisModuleAdapter(analyzer)

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)
    dp = observable.detections[0]
    assert dp.signature_uuid == "22222222-2222-2222-2222-222222222222"
    assert dp.signature_version == sha


@pytest.mark.unit
def test_observable_modifier_git_dir_not_containing_rules_logs_error(tmpdir, caplog):
    from saq.signatures import SIGNATURE_VERSION_UNKNOWN
    git_dir = str(tmpdir.mkdir("repo"))
    _init_git_repo_at(git_dir)
    # rules file lives OUTSIDE the git_dir -> validation fails -> unknown
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://evil.com/malware.exe")
    rules = [{
        "name": "suspicious download",
        "uuid": "33333333-3333-3333-3333-333333333333",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_detection_points": ["matched"]},
    }]
    yaml_path = os.path.join(str(tmpdir.mkdir("elsewhere")), "rules.yaml")
    with open(yaml_path, "w") as f:
        yaml.dump({"rules": rules}, f)

    context = create_test_context(root=root)
    config = get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    config.rules_config_path = yaml_path
    config.git_dir = git_dir
    analyzer = ObservableModifierAnalyzer(context=context, config=config)
    adapter = AnalysisModuleAdapter(analyzer)

    with caplog.at_level(logging.ERROR):
        adapter.execute_analysis(observable)
        adapter.analyze(observable, final_analysis=True)
    dp = observable.detections[0]
    assert dp.signature_version == SIGNATURE_VERSION_UNKNOWN
    assert any("does not contain rules file" in r.message for r in caplog.records)


# ============================================================
# analysis-type presence index tests
# ============================================================

def _absent_type_rule(scope, negate=False, match_count=None, extra_conditions=None):
    """Build a rule whose single tree_condition targets an analysis type that
    exists nowhere in the root."""
    tc = {"analysis_type": "tests.nonexistent:NoSuchAnalysis", "scope": scope}
    if negate:
        tc["negate"] = True
    if match_count is not None:
        tc["match_count"] = match_count
    conditions = {"observable_types": ["url"], "tree_conditions": [tc]}
    if extra_conditions:
        conditions.update(extra_conditions)
    return [{
        "name": f"absent type rule {scope}",
        "phase": "pre",
        "conditions": conditions,
        "actions": {"add_directives": ["extract_iocs"]},
    }]


@pytest.mark.unit
@pytest.mark.parametrize("scope", ["ancestors", "descendants", "global", "self", "parent", "siblings"])
def test_type_index_absent_type_no_match(scope):
    """When no analysis of the condition's type exists in the root, the rule
    does not match, for every scope."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    adapter = _create_analyzer_with_rules(root, _absent_type_rule(scope))

    adapter.execute_analysis(observable)
    assert not observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_type_index_absent_type_negate_matches():
    """negate: true on an absent analysis type resolves to True instantly (the
    'no PhishkitAnalysis ancestor' pattern) -- the rule matches."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    adapter = _create_analyzer_with_rules(root, _absent_type_rule("ancestors", negate=True))

    adapter.execute_analysis(observable)
    assert observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_type_index_absent_type_match_count_zero():
    """match_count: 0 means 'require exactly zero matches', so an absent
    analysis type satisfies the condition -- the fast path must not return
    an unconditional False."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    adapter = _create_analyzer_with_rules(root, _absent_type_rule("ancestors", match_count=0))

    adapter.execute_analysis(observable)
    assert observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_type_index_absent_type_match_count_zero_negated():
    """match_count: 0 + negate: true on an absent type is inner True -> negated
    False -- the rule does not match."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    adapter = _create_analyzer_with_rules(root, _absent_type_rule("ancestors", negate=True, match_count=0))

    adapter.execute_analysis(observable)
    assert not observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_analysis_type_index_lazy_and_frozen():
    """The index is resolved lazily on first lookup and frozen thereafter; a
    fresh instance over the same root sees analyses added since."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    parent_observable = root.add_observable_by_spec(F_FQDN, "example.com")

    class TestMarkerAnalysis(Analysis):
        pass

    module_path = f"{TestMarkerAnalysis.__module__}:{TestMarkerAnalysis.__name__}"

    index = _AnalysisTypeIndex(root)
    assert module_path not in index

    marker = TestMarkerAnalysis()
    marker.details = {}
    marker.details_modified = True
    parent_observable.add_analysis(marker)

    # already-resolved instance is frozen (safe: it never outlives one invocation)
    assert module_path not in index
    # a fresh per-invocation instance sees the new analysis
    assert module_path in _AnalysisTypeIndex(root)


@pytest.mark.unit
def test_analysis_type_index_cross_invocation_cache():
    """The shared cache reuses the type set while the real-analysis count is
    unchanged and rebuilds when it grows."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    parent_observable = root.add_observable_by_spec(F_FQDN, "example.com")

    class TestMarkerAnalysis(Analysis):
        pass

    module_path = f"{TestMarkerAnalysis.__module__}:{TestMarkerAnalysis.__name__}"

    cache = {}
    assert module_path not in _AnalysisTypeIndex(root, cache)
    assert root.uuid in cache
    first_set = cache[root.uuid][1]

    # same count -> a fresh instance reuses the exact same set object
    index2 = _AnalysisTypeIndex(root, cache)
    assert module_path not in index2
    assert cache[root.uuid][1] is first_set

    # count grows -> rebuild picks up the new type
    marker = TestMarkerAnalysis()
    marker.details = {}
    marker.details_modified = True
    parent_observable.add_analysis(marker)
    assert module_path in _AnalysisTypeIndex(root, cache)
    assert cache[root.uuid][1] is not first_set


@pytest.mark.integration
def test_type_index_rebuilt_per_invocation():
    """A tree-condition rule that finds nothing on the first invocation still
    matches on a later invocation after the analysis type appears -- proving
    the index is rebuilt per module invocation, never cached across calls."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    parent_observable = root.add_observable_by_spec(F_FQDN, "example.com")

    class TestMarkerAnalysis(Analysis):
        pass

    module_path = f"{TestMarkerAnalysis.__module__}:{TestMarkerAnalysis.__name__}"
    rules = [{
        "name": "global marker rule",
        "phase": "post",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{"analysis_type": module_path, "scope": "global"}],
        },
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    result = adapter.analyze(observable, final_analysis=True)
    assert result == AnalysisExecutionResult.INCOMPLETE
    assert not observable.has_directive("extract_iocs")

    marker = TestMarkerAnalysis()
    marker.details = {}
    marker.details_modified = True
    parent_observable.add_analysis(marker)

    adapter.analyze(observable, final_analysis=True)
    assert observable.has_directive("extract_iocs")


@pytest.mark.integration
def test_type_index_present_type_parity():
    """When the analysis type IS present, the walk still runs and details_match
    still discriminates -- the gate only fast-paths absence."""
    root, target_observable, email_analysis, module_path = _build_root_with_flushed_email_analysis(
        from_address="soc@vendor.com"
    )
    rules = [{
        "name": "matching details rule",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {"email.from_address": r"soc@vendor\.com"},
            }],
        },
        "actions": {"add_directives": ["extract_iocs"]},
    }, {
        "name": "non-matching details rule",
        "phase": "pre",
        "conditions": {
            "observable_types": ["url"],
            "tree_conditions": [{
                "analysis_type": module_path,
                "details_match": {"email.from_address": r"NOMATCH@nowhere\.com"},
            }],
        },
        "actions": {"add_tags": ["should-not-appear"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(target_observable)
    assert target_observable.has_directive("extract_iocs")
    assert not target_observable.has_tag("should-not-appear")


# ============================================================
# immutable-rule verdict memoization tests
# ============================================================

def _keeper_rule():
    """A mutable rule (has_tags never satisfied) that passes evaluate_early for
    url observables, keeping the observable past _any_rule_could_match so the
    rule loop actually runs. Mirrors the production shape where tree-condition
    rules keep candidacy alive while cheap immutable rules get re-checked."""
    return {
        "name": "keeper",
        "uuid": "keeper-uuid",
        "conditions": {"observable_types": ["url"], "has_tags": ["never-set"]},
        "actions": {"add_tags": ["keeper-matched"]},
        "phase": "pre",
    }


@pytest.mark.unit
@pytest.mark.parametrize("mutable_field,value", [
    ("alert_tags", ["t"]),
    ("has_tags", ["t"]),
    ("has_directives", ["d"]),
    ("has_yara_meta_tags", ["y"]),
    ("tree_conditions", [TreeCondition(analysis_type="x:Y")]),
])
def test_rule_conditions_mutable_fields_not_immutable(mutable_field, value):
    conditions = RuleConditions(**{mutable_field: value})
    assert conditions.is_immutable is False


@pytest.mark.unit
def test_rule_conditions_early_only_fields_immutable():
    assert RuleConditions().is_immutable is True
    assert RuleConditions(
        observable_types=["url"],
        alert_type="mailbox",
        queue="default",
        value_pattern=re.compile(r"x"),
        file_name_pattern=re.compile(r"x"),
        display_type_pattern=re.compile(r"x"),
        display_value_pattern=re.compile(r"x"),
    ).is_immutable is True


@pytest.mark.unit
def test_rule_is_immutable_round_trips_through_parser():
    """Rule.is_immutable is derived from the parsed conditions."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    rules = [{
        "name": "immutable rule",
        "uuid": "imm-uuid",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_tags": ["t"]},
    }, {
        "name": "mutable rule",
        "uuid": "mut-uuid",
        "conditions": {"observable_types": ["url"], "has_tags": ["t"]},
        "actions": {"add_tags": ["t"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)
    adapter.execute_analysis(root.add_observable_by_spec(F_URL, "https://example.com"))

    by_uuid = {r.uuid: r for r in adapter.wrapped_module._rules}
    assert by_uuid["imm-uuid"].is_immutable is True
    assert by_uuid["mut-uuid"].is_immutable is False


@pytest.mark.unit
def test_immutable_rule_evaluated_once_across_invocations():
    """An immutable rule that fails is evaluated exactly once per observable;
    a mutable rule of the same shape keeps being re-evaluated."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [_keeper_rule(), {
        "name": "immutable exe rule",
        "uuid": "imm-exe-uuid",
        "phase": "pre",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_tags": ["exe"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    for _ in range(3):
        adapter.execute_analysis(observable)

    stats = adapter.wrapped_module._rule_eval_stats[root.uuid]
    assert stats["imm-exe-uuid"]["count"] == 1
    assert stats["keeper-uuid"]["count"] == 3


@pytest.mark.integration
def test_mutable_rule_can_newly_match_later():
    """A mutable rule must keep re-evaluating: a tag added between invocations
    lets a has_tags rule match on a later pass."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [{
        "name": "tag reactor",
        "uuid": "tag-reactor-uuid",
        "phase": "post",
        "conditions": {"observable_types": ["url"], "has_tags": ["hot"]},
        "actions": {"add_directives": ["extract_iocs"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)
    assert not observable.has_directive("extract_iocs")

    observable.add_tag("hot")
    adapter.analyze(observable, final_analysis=True)
    assert observable.has_directive("extract_iocs")


@pytest.mark.unit
def test_immutable_memo_snapshot_invalidation_on_display_change():
    """Mutating a display field re-opens memoized verdicts: the rule is
    re-evaluated against the new snapshot and can now match."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [_keeper_rule(), {
        "name": "display type rule",
        "uuid": "display-uuid",
        "phase": "pre",
        # the display_type getter renders a set value as "special (url)"
        "conditions": {"observable_types": ["url"], "display_type_pattern": r"^special \(url\)$"},
        "actions": {"add_tags": ["special-display"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    assert not observable.has_tag("special-display")
    # verdict memoized
    assert "display-uuid" in adapter.wrapped_module._immutable_false_cache[root.uuid][observable.uuid][1]

    observable.display_type = "special"
    adapter.execute_analysis(observable)
    assert observable.has_tag("special-display")


@pytest.mark.unit
def test_immutable_memo_cleared_on_rule_reload():
    """_load_config clears all memoized verdicts: a reloaded rule with the same
    uuid but changed conditions is re-evaluated and can match."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [_keeper_rule(), {
        "name": "pattern rule",
        "uuid": "reload-uuid",
        "phase": "pre",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_tags": ["pattern-hit"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    assert not observable.has_tag("pattern-hit")
    assert adapter.wrapped_module._immutable_false_cache

    # same uuid, widened pattern -- rewrite the rules file and reload
    rules[1]["conditions"]["value_pattern"] = r"\.html$"
    yaml_path = os.path.join(root.storage_dir, "test_rules.yaml")
    with open(yaml_path, "w") as f:
        yaml.dump({"rules": rules}, f)
    adapter.wrapped_module._load_config()
    assert adapter.wrapped_module._immutable_false_cache == {}

    adapter.execute_analysis(observable)
    assert observable.has_tag("pattern-hit")


@pytest.mark.unit
def test_immutable_memo_popped_in_post_analysis():
    """The per-root verdict memo is dropped in execute_post_analysis so it
    stays bounded to a single root."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [_keeper_rule(), {
        "name": "immutable exe rule",
        "uuid": "imm-exe-uuid",
        "phase": "pre",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_tags": ["exe"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    assert root.uuid in adapter.wrapped_module._immutable_false_cache

    adapter.execute_post_analysis()
    assert root.uuid not in adapter.wrapped_module._immutable_false_cache
    assert root.uuid not in adapter.wrapped_module._type_index_cache
    # idempotent
    adapter.execute_post_analysis()
    assert root.uuid not in adapter.wrapped_module._immutable_false_cache


@pytest.mark.unit
def test_unmatched_immutable_rule_no_accidental_settle():
    """Memoizing a False verdict must not seal the module: both phases still
    return INCOMPLETE while any rule passes evaluate_early."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com/page.html")
    rules = [_keeper_rule(), {
        "name": "immutable exe rule",
        "uuid": "imm-exe-uuid",
        "phase": "pre",
        "conditions": {"observable_types": ["url"], "value_pattern": r"\.exe$"},
        "actions": {"add_tags": ["exe"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    assert adapter.execute_analysis(observable) == AnalysisExecutionResult.INCOMPLETE
    assert adapter.execute_analysis(observable) == AnalysisExecutionResult.INCOMPLETE
    assert adapter.analyze(observable, final_analysis=True) == AnalysisExecutionResult.INCOMPLETE


# ============================================================
# pre/final eval-split counter tests
# ============================================================

@pytest.mark.unit
def test_rule_eval_split_counters():
    """eval_calls_pre / eval_calls_final split the count by phase method: a pre
    rule only accrues pre calls, a post rule only final calls."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    rules = [{
        "name": "pre split rule",
        "uuid": "split-pre-uuid",
        "phase": "pre",
        "conditions": {"observable_types": ["url"], "has_tags": ["never"]},
        "actions": {"add_tags": ["t"]},
    }, {
        "name": "post split rule",
        "uuid": "split-post-uuid",
        "phase": "post",
        "conditions": {"observable_types": ["url"], "has_tags": ["never"]},
        "actions": {"add_tags": ["t"]},
    }]
    adapter = _create_analyzer_with_rules(root, rules)

    adapter.execute_analysis(observable)
    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    stats = adapter.wrapped_module._rule_eval_stats[root.uuid]
    assert stats["split-pre-uuid"]["eval_calls_pre"] == 2
    assert stats["split-pre-uuid"]["eval_calls_final"] == 0
    assert stats["split-pre-uuid"]["count"] == 2
    assert stats["split-post-uuid"]["eval_calls_pre"] == 0
    assert stats["split-post-uuid"]["eval_calls_final"] == 1
    assert stats["split-post-uuid"]["count"] == 1


@pytest.mark.unit
def test_rule_eval_cost_line_contains_phase_split(caplog):
    """The emitted cost line carries the new split fields, with rule_name still
    the terminal field (the downstream rex captures it to end-of-line)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://example.com")
    adapter = _create_analyzer_with_rules(root, _cost_rules("cost-uuid-1"))

    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)

    with caplog.at_level(logging.INFO):
        adapter.execute_post_analysis()

    cost_lines = [
        r.getMessage() for r in caplog.records
        if "observable_modifier rule cost" in r.getMessage()
    ]
    assert len(cost_lines) == 1
    assert "eval_calls_pre=0" in cost_lines[0]
    assert "eval_calls_final=1" in cost_lines[0]
    match = re.search(r"rule_name=(?P<rule_name>.+)$", cost_lines[0])
    assert match is not None
    assert match.group("rule_name") == "cost rule cost-uuid-1"
