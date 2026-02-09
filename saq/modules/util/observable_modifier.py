import logging
import os
import re
from dataclasses import dataclass, field
from typing import Generator, Optional, Type, override

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
import yaml
from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig


class ObservableModifierConfig(AnalysisModuleConfig):
    rules_config_path: str = Field(
        default="etc/observable_modifier_rules.yaml",
        description="Path to YAML rules config file, relative to SAQ_HOME",
    )


class ObservableModifierAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "matched_rules": [],
        }

    @override
    @property
    def display_name(self) -> str:
        return "Observable Modifier Analysis"

    def generate_summary(self):
        matched = self.details.get("matched_rules", [])
        if not matched:
            return None
        names = [r["name"] for r in matched]
        return f"Applied {len(matched)} rule(s): {', '.join(names)}"


def get_nested_value(data: dict, dot_path: str):
    """Traverse nested dicts using dot notation."""
    keys = dot_path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


@dataclass
class TreeCondition:
    analysis_type: str
    scope: str = "ancestors"  # "ancestors" or "global"
    details_match: dict[str, re.Pattern] = field(default_factory=dict)

    def evaluate(self, observable: Observable, root: RootAnalysis) -> bool:
        if self.scope == "ancestors":
            analyses = _get_ancestor_analyses(observable)
        else:
            analyses = (a for a in root.all_analysis if a)

        for analysis in analyses:
            if analysis.module_path != self.analysis_type:
                continue
            if not self.details_match:
                return True
            analysis.load_details()
            if self._check_details(analysis.details):
                return True
        return False

    def _check_details(self, details: dict) -> bool:
        if not details:
            return False
        for dot_path, pattern in self.details_match.items():
            value = get_nested_value(details, dot_path)
            if value is None:
                return False
            if not pattern.search(str(value)):
                return False
        return True


def _get_ancestor_analyses(observable: Observable) -> Generator[Analysis, None, None]:
    """Yield all Analysis objects that are ancestors of this observable."""
    visited = set()
    stack = list(observable.parents)
    while stack:
        analysis = stack.pop()
        if id(analysis) in visited:
            continue
        visited.add(id(analysis))
        yield analysis
        if analysis.observable:
            stack.extend(analysis.observable.parents)


@dataclass
class RuleConditions:
    alert_tags: list[str] = field(default_factory=list)
    alert_type: Optional[str] = None
    queue: Optional[str] = None
    observable_types: list[str] = field(default_factory=list)
    value_pattern: Optional[re.Pattern] = None
    file_name_pattern: Optional[re.Pattern] = None
    has_tags: list[str] = field(default_factory=list)
    has_directives: list[str] = field(default_factory=list)
    tree_conditions: list[TreeCondition] = field(default_factory=list)

    def evaluate(self, observable: Observable, root: RootAnalysis) -> bool:
        # Cheapest checks first for short-circuit efficiency

        # Observable type check
        if self.observable_types:
            if observable.type not in self.observable_types:
                return False

        # Alert-level checks
        if self.alert_tags:
            for tag in self.alert_tags:
                if not root.has_tag(tag):
                    return False

        if self.alert_type is not None:
            if root.alert_type != self.alert_type:
                return False

        if self.queue is not None:
            if root.queue != self.queue:
                return False

        # Observable-level checks
        if self.has_tags:
            for tag in self.has_tags:
                if not observable.has_tag(tag):
                    return False

        if self.has_directives:
            for directive in self.has_directives:
                if not observable.has_directive(directive):
                    return False

        # Value pattern (regex)
        if self.value_pattern is not None:
            if not self.value_pattern.search(str(observable.value)):
                return False

        # File name pattern (regex, only applies to FileObservable)
        if self.file_name_pattern is not None:
            file_name = getattr(observable, "file_name", None)
            if file_name is None or not self.file_name_pattern.search(file_name):
                return False

        # Tree conditions (most expensive — disk I/O)
        for tc in self.tree_conditions:
            if not tc.evaluate(observable, root):
                return False

        return True


@dataclass
class RuleActions:
    add_directives: list[str] = field(default_factory=list)
    add_tags: list[str] = field(default_factory=list)
    add_detection_points: list[str] = field(default_factory=list)
    exclude_analysis: list[str] = field(default_factory=list)
    limit_analysis: list[str] = field(default_factory=list)

    def apply(self, observable: Observable) -> dict:
        applied = {}
        if self.add_directives:
            for d in self.add_directives:
                observable.add_directive(d)
            applied["add_directives"] = self.add_directives

        if self.add_tags:
            for t in self.add_tags:
                observable.add_tag(t)
            applied["add_tags"] = self.add_tags

        if self.add_detection_points:
            for desc in self.add_detection_points:
                observable.add_detection_point(desc)
            applied["add_detection_points"] = self.add_detection_points

        if self.exclude_analysis:
            for module_name in self.exclude_analysis:
                observable._excluded_analysis.append(module_name)
            applied["exclude_analysis"] = self.exclude_analysis

        if self.limit_analysis:
            for module_name in self.limit_analysis:
                observable._limited_analysis.append(module_name)
            applied["limit_analysis"] = self.limit_analysis

        return applied


@dataclass
class Rule:
    name: str
    description: str
    enabled: bool
    conditions: RuleConditions
    actions: RuleActions


class ObservableModifierAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = False
        self._rules: list[Rule] = []

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ObservableModifierConfig

    @property
    def generated_analysis_type(self):
        return ObservableModifierAnalysis

    def _load_config(self):
        """Load rules from YAML config file."""
        self._rules = []

        yaml_path = os.path.join(
            get_base_dir(),
            self.config.rules_config_path,
        )

        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            logging.warning(f"failed to load observable modifier rules YAML {yaml_path}: {e}")
            return

        for rule_data in data.get("rules", []) or []:
            try:
                rule = self._parse_rule(rule_data)
                if rule:
                    self._rules.append(rule)
            except Exception as e:
                logging.warning(f"failed to parse observable modifier rule: {e}")

        logging.debug(f"loaded {len(self._rules)} observable modifier rules from {yaml_path}")

    def _parse_rule(self, rule_data: dict) -> Optional[Rule]:
        name = rule_data.get("name", "unnamed")
        description = rule_data.get("description", "")
        enabled = rule_data.get("enabled", True)

        conditions_data = rule_data.get("conditions", {}) or {}
        actions_data = rule_data.get("actions", {}) or {}

        # Parse conditions
        value_pattern = None
        raw_pattern = conditions_data.get("value_pattern")
        if raw_pattern:
            try:
                value_pattern = re.compile(raw_pattern)
            except re.error as e:
                logging.warning(f"invalid value_pattern regex '{raw_pattern}' in rule '{name}': {e}")
                return None

        file_name_pattern = None
        raw_fn_pattern = conditions_data.get("file_name_pattern")
        if raw_fn_pattern:
            try:
                file_name_pattern = re.compile(raw_fn_pattern)
            except re.error as e:
                logging.warning(f"invalid file_name_pattern regex '{raw_fn_pattern}' in rule '{name}': {e}")
                return None

        tree_conditions = []
        for tc_data in conditions_data.get("tree_conditions", []) or []:
            tc = self._parse_tree_condition(tc_data, name)
            if tc is None:
                return None
            tree_conditions.append(tc)

        conditions = RuleConditions(
            alert_tags=conditions_data.get("alert_tags", []) or [],
            alert_type=conditions_data.get("alert_type"),
            queue=conditions_data.get("queue"),
            observable_types=conditions_data.get("observable_types", []) or [],
            value_pattern=value_pattern,
            file_name_pattern=file_name_pattern,
            has_tags=conditions_data.get("has_tags", []) or [],
            has_directives=conditions_data.get("has_directives", []) or [],
            tree_conditions=tree_conditions,
        )

        actions = RuleActions(
            add_directives=actions_data.get("add_directives", []) or [],
            add_tags=actions_data.get("add_tags", []) or [],
            add_detection_points=actions_data.get("add_detection_points", []) or [],
            exclude_analysis=actions_data.get("exclude_analysis", []) or [],
            limit_analysis=actions_data.get("limit_analysis", []) or [],
        )

        return Rule(
            name=name,
            description=description,
            enabled=enabled,
            conditions=conditions,
            actions=actions,
        )

    def _parse_tree_condition(self, tc_data: dict, rule_name: str) -> Optional[TreeCondition]:
        analysis_type = tc_data.get("analysis_type", "")
        scope = tc_data.get("scope", "ancestors")
        if scope not in ("ancestors", "global"):
            logging.warning(f"invalid scope '{scope}' in tree_condition for rule '{rule_name}', defaulting to 'ancestors'")
            scope = "ancestors"
        details_match_raw = tc_data.get("details_match", {}) or {}

        compiled_details_match = {}
        for dot_path, pattern_str in details_match_raw.items():
            try:
                compiled_details_match[dot_path] = re.compile(str(pattern_str))
            except re.error as e:
                logging.warning(
                    f"invalid details_match regex '{pattern_str}' for path '{dot_path}' in rule '{rule_name}': {e}"
                )
                return None

        return TreeCondition(
            analysis_type=analysis_type,
            scope=scope,
            details_match=compiled_details_match,
        )

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        if not self._initialized:
            yaml_path = os.path.join(
                get_base_dir(),
                self.config.rules_config_path,
            )
            self.watch_file(yaml_path, self._load_config)
            self._initialized = True

        # Defer all rule evaluation to final analysis mode so the full
        # analysis tree is available for global-scope tree conditions.
        # Returning INCOMPLETE without creating analysis means the engine
        # won't call add_no_analysis (executor.py:939-949), allowing
        # execute_final_analysis to run later.
        return AnalysisExecutionResult.INCOMPLETE

    def execute_final_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        if not self._initialized:
            yaml_path = os.path.join(
                get_base_dir(),
                self.config.rules_config_path,
            )
            self.watch_file(yaml_path, self._load_config)
            self._initialized = True

        root = self.get_root()
        matched_rules = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            if rule.conditions.evaluate(observable, root):
                applied = rule.actions.apply(observable)
                matched_rules.append({
                    "name": rule.name,
                    "actions_applied": applied,
                })
                logging.info(f"observable modifier rule '{rule.name}' matched {observable}")

        if matched_rules:
            analysis = self.create_analysis(observable)
            analysis.details["matched_rules"] = matched_rules
            analysis.summary = analysis.generate_summary()

        return AnalysisExecutionResult.COMPLETED
