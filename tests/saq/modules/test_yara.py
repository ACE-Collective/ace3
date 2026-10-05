import os

import pytest
import yara
import yara_scanner

from saq.configuration.config import get_analysis_module_config, get_service_config
from saq.constants import (
    ANALYSIS_MODULE_YARA_SCANNER_V3_4,
    DIRECTIVE_NO_SCAN,
    F_SIGNATURE_ID,
    F_YARA_RULE,
    SERVICE_YARA_SCANNER,
    AnalysisExecutionResult,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.yara import YaraScanResults_v3_4, YaraScanner_v3_4
from saq.signatures.builtin import YARA_RULE_MATCH
from saq.util.filesystem import abs_path
from saq.yara_scanning import client as yara_client
from saq.yara_scanning.client import YaraScanCrashed, YaraScanTimeout, YaraServiceUnavailable
from tests.saq.test_util import create_test_context


# ---------------------------------------------------------------------------
# Unit tests — mock the yara scanner to verify meta_tags plumbing
# ---------------------------------------------------------------------------
class TestYaraScannerMetaTagsUnit:
    """Verify that execute_analysis passes meta_tags through to the scanner."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    @pytest.mark.unit
    def test_meta_tags_passed_to_scanner(self, monkeypatch, root_analysis):
        """FileObservable with yara_meta directives passes meta_tags to scan_file."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")
        observable.add_yara_meta("source", "imap")

        captured = {}

        def mock_scan_file(path, meta_tags=None, qa=None):
            captured["meta_tags"] = meta_tags
            return []

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert sorted(captured["meta_tags"]) == ["content_type=email_body", "source=imap"]

    @pytest.mark.unit
    def test_no_meta_tags_passes_none(self, monkeypatch, root_analysis):
        """FileObservable with no yara_meta directives passes meta_tags=None."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        captured = {}

        def mock_scan_file(path, meta_tags=None, qa=None):
            captured["meta_tags"] = meta_tags
            return []

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert captured["meta_tags"] is None

    @pytest.mark.unit
    def test_meta_tags_passed_to_local_scanner_when_service_unavailable(self, monkeypatch, root_analysis):
        """When the yara scanner service is unavailable, local scanner fallback receives meta_tags."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")

        def mock_scan_file(path, meta_tags=None, qa=None):
            raise YaraServiceUnavailable("connection refused")

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        captured = {}

        class MockLocalScanner:
            scan_results = []

            def scan(self, path, meta_tags=None):
                captured["meta_tags"] = meta_tags
                return False

        def mock_initialize_local_scanner(self):
            self.scanner = MockLocalScanner()

        monkeypatch.setattr(YaraScanner_v3_4, "initialize_local_scanner", mock_initialize_local_scanner)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert captured["meta_tags"] == ["content_type=email_body"]

    @pytest.mark.unit
    def test_no_scan_directive_skips_scanning(self, monkeypatch, root_analysis):
        """FileObservable with DIRECTIVE_NO_SCAN skips scanning entirely."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_directive(DIRECTIVE_NO_SCAN)
        observable.add_yara_meta("content_type", "email_body")

        scan_called = {"called": False}

        def mock_scan_file(path, meta_tags=None, qa=None):
            scan_called["called"] = True
            return []

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert scan_called["called"] is False


# ---------------------------------------------------------------------------
# Unit tests — scan timeouts must be swallowed and logged as warnings
# ---------------------------------------------------------------------------
class TestYaraScannerServiceFailures:
    """How execute_analysis handles each way the yara scanner service can fail."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    @pytest.mark.unit
    def test_yara_timeout_is_caught(self, monkeypatch, caplog, root_analysis):
        """YaraScanTimeout from scan_file is handled by the timeout handler, not the
        generic error handler.

        The generic `except Exception` handler also swallows the exception and returns
        COMPLETED, so the meaningful distinction is that the timeout is handled by the
        dedicated handler — which logs the specific timeout warning and does NOT call
        report_exception (i.e. it does not generate an error report).
        """
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        def mock_scan_file(path, meta_tags=None, qa=None):
            raise YaraScanTimeout("scanning timed out")

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        report_exception_called = {"called": False}

        def mock_report_exception(*args, **kwargs):
            report_exception_called["called"] = True
            return ""

        monkeypatch.setattr(
            "saq.modules.file_analysis.yara.report_exception", mock_report_exception
        )

        adapter = self._create_module(root_analysis)
        with caplog.at_level("WARNING"):
            result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        # the timeout must be handled by the dedicated handler, not reported as an error
        assert report_exception_called["called"] is False
        assert any(
            "yara scanner service timed out" in record.message for record in caplog.records
        )


    @pytest.mark.unit
    def test_crashed_scan_is_a_scan_failure_without_local_fallback(self, monkeypatch, root_analysis):
        """A scanner that died on the file is reported as a scan failure; the file is not
        rescanned in-process, where it could take the engine worker down the same way."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        def mock_scan_file(path, meta_tags=None, qa=None):
            raise YaraScanCrashed("the yara scanner closed the connection without answering")

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        report_exception_called = {"called": False}

        def mock_report_exception(*args, **kwargs):
            report_exception_called["called"] = True
            return ""

        monkeypatch.setattr("saq.modules.file_analysis.yara.report_exception", mock_report_exception)

        def fail_initialize_local_scanner(self):
            raise AssertionError("the local scanner must not be used")

        monkeypatch.setattr(YaraScanner_v3_4, "initialize_local_scanner", fail_initialize_local_scanner)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert report_exception_called["called"] is True
        assert observable.get_analysis(YaraScanResults_v3_4) is None

    @pytest.mark.unit
    def test_local_scanner_timeout_is_caught(self, monkeypatch, caplog, root_analysis):
        """yara.TimeoutError from the local fallback scanner is a timeout, not a scan failure."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        def mock_scan_file(path, meta_tags=None, qa=None):
            raise YaraServiceUnavailable("connection refused")

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        class TimingOutLocalScanner:
            scan_results = []

            def scan(self, path, meta_tags=None):
                raise yara.TimeoutError("scanning timed out")

        def mock_initialize_local_scanner(self):
            self.scanner = TimingOutLocalScanner()

        monkeypatch.setattr(YaraScanner_v3_4, "initialize_local_scanner", mock_initialize_local_scanner)

        report_exception_called = {"called": False}

        def mock_report_exception(*args, **kwargs):
            report_exception_called["called"] = True
            return ""

        monkeypatch.setattr("saq.modules.file_analysis.yara.report_exception", mock_report_exception)

        adapter = self._create_module(root_analysis)
        with caplog.at_level("WARNING"):
            result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert report_exception_called["called"] is False
        assert any("local yara scanner timed out" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Integration tests — use a real YaraScanner with test rules
# ---------------------------------------------------------------------------
class TestYaraScannerMetaTagsIntegration:
    """Verify that yara_scanner actually filters rules based on meta_tags."""

    @pytest.fixture
    def scanner(self, datadir):
        s = yara_scanner.YaraScanner(signature_dir=str(datadir / "yara_rules"))
        s.load_rules()
        return s

    @pytest.fixture
    def target(self, datadir):
        return str(datadir / "sample.target")

    def _rule_names(self, scanner):
        return [r["rule"] for r in scanner.scan_results]

    @pytest.mark.integration
    def test_no_meta_tags_skips_tagged_rules(self, scanner, target):
        """With no meta_tags, only untagged rules match."""
        scanner.scan(target, meta_tags=None)
        names = self._rule_names(scanner)
        assert "always_match" in names
        assert "meta_tagged_email_body" not in names
        assert "meta_tagged_source_imap" not in names

    @pytest.mark.integration
    def test_matching_meta_tag_enables_rule(self, scanner, target):
        """Providing content_type=email_body enables that rule."""
        scanner.scan(target, meta_tags=["content_type=email_body"])
        names = self._rule_names(scanner)
        assert "always_match" in names
        assert "meta_tagged_email_body" in names
        assert "meta_tagged_source_imap" not in names

    @pytest.mark.integration
    def test_non_matching_meta_tag_skips_rule(self, scanner, target):
        """A tag that doesn't match any rule's meta_tags won't enable it."""
        scanner.scan(target, meta_tags=["source=something_else"])
        names = self._rule_names(scanner)
        assert "always_match" in names
        assert "meta_tagged_email_body" not in names

    @pytest.mark.integration
    def test_multiple_tags_match_multiple_rules(self, scanner, target):
        """Multiple tags enable multiple rules (but not rules whose strings don't match)."""
        scanner.scan(target, meta_tags=["content_type=email_body", "source=imap"])
        names = self._rule_names(scanner)
        assert "always_match" in names
        assert "meta_tagged_email_body" in names
        assert "meta_tagged_source_imap" in names
        assert "meta_tagged_no_match_content" not in names

    @pytest.mark.integration
    def test_meta_tag_match_but_string_mismatch(self, scanner, target):
        """Tag matches the rule but the string condition fails — no match."""
        scanner.scan(target, meta_tags=["content_type=email_body"])
        names = self._rule_names(scanner)
        assert "meta_tagged_no_match_content" not in names


# ---------------------------------------------------------------------------
# Unit tests — verify signature_id observable is emitted from rule.meta.uuid
# ---------------------------------------------------------------------------
class TestYaraSignatureIdEmission:
    """When a yara rule matches and has a `uuid` meta field, a signature_id observable
    should be attached to the resulting YaraScanResults_v3_4 analysis."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    def _match(self, rule_name, rule_uuid=None, modifiers=None):
        meta = {}
        if rule_uuid is not None:
            meta["uuid"] = rule_uuid
        if modifiers is not None:
            meta["modifiers"] = modifiers
        return {
            "rule": rule_name,
            "meta": meta,
            "tags": [],
            "strings": [],
        }

    @pytest.mark.unit
    def test_rule_with_uuid_emits_signature_id(self, monkeypatch, root_analysis):
        """A matching rule carrying a uuid meta field emits a signature_id observable."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        rule_uuid = "da44c9b8-24f5-472f-acab-1907f4ce4ad9"
        matches = [self._match("test_rule_with_uuid", rule_uuid=rule_uuid)]

        def mock_scan_file(path, meta_tags=None, qa=None):
            return matches

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        sig_observables = [o for o in analysis.observables if o.type == F_SIGNATURE_ID]
        assert len(sig_observables) == 1
        assert sig_observables[0].value == rule_uuid

    @pytest.mark.unit
    def test_rule_without_uuid_does_not_emit(self, monkeypatch, root_analysis):
        """A matching rule whose meta lacks a uuid must NOT emit a signature_id."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        matches = [self._match("test_rule_no_uuid")]

        def mock_scan_file(path, meta_tags=None, qa=None):
            return matches

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        sig_observables = [o for o in analysis.observables if o.type == F_SIGNATURE_ID]
        assert sig_observables == []

    @pytest.mark.unit
    def test_multiple_rules_emit_distinct_signature_ids(self, monkeypatch, root_analysis):
        """Two matching rules with different uuids emit two signature_id observables."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        uuid_a = "da44c9b8-24f5-472f-acab-1907f4ce4ad9"
        uuid_b = "3a1ddc4e-def5-439b-b3d3-d51352786d94"
        matches = [
            self._match("rule_a", rule_uuid=uuid_a),
            self._match("rule_b", rule_uuid=uuid_b),
        ]

        def mock_scan_file(path, meta_tags=None, qa=None):
            return matches

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        emitted = {o.value for o in analysis.observables if o.type == F_SIGNATURE_ID}
        assert emitted == {uuid_a, uuid_b}

    @pytest.mark.unit
    def test_duplicate_uuid_across_matches_dedups(self, monkeypatch, root_analysis):
        """If two rule matches share the same uuid, only one signature_id observable is emitted."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        rule_uuid = "da44c9b8-24f5-472f-acab-1907f4ce4ad9"
        matches = [
            self._match("rule_a", rule_uuid=rule_uuid),
            self._match("rule_b", rule_uuid=rule_uuid),
        ]

        def mock_scan_file(path, meta_tags=None, qa=None):
            return matches

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        sig_observables = [o for o in analysis.observables if o.type == F_SIGNATURE_ID]
        assert len(sig_observables) == 1
        assert sig_observables[0].value == rule_uuid


def _yara_match(rule_name, meta=None, strings=None, tags=None):
    """Build a yara scan result dict as returned by the scanner."""
    return {
        "rule": rule_name,
        "meta": meta or {},
        "tags": tags or [],
        "strings": strings or [],
    }


class TestYaraEnabledMeta:
    """A rule whose `enabled` meta is falsy is ignored as if it never matched."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    def _run(self, monkeypatch, root_analysis, matches):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")
        observable = root_analysis.add_file_observable(file_path)

        monkeypatch.setattr(
            yara_client, "scan_file",
            lambda path, meta_tags=None, qa=None: matches,
        )

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)
        assert result == AnalysisExecutionResult.COMPLETED
        return observable

    @pytest.mark.unit
    @pytest.mark.parametrize("enabled_value", [False, "false", "False", "no", "off", "disabled", 0])
    def test_disabled_rule_produces_no_analysis(self, monkeypatch, root_analysis, enabled_value):
        """A file matching only a disabled rule behaves exactly like no match: no analysis."""
        matches = [_yara_match("disabled_rule", meta={"enabled": enabled_value})]
        observable = self._run(monkeypatch, root_analysis, matches)

        assert observable.get_and_load_analysis(YaraScanResults_v3_4) is None
        assert not root_analysis.has_detections()

    @pytest.mark.unit
    @pytest.mark.parametrize("enabled_value", [True, "true", "yes", 1])
    def test_enabled_rule_is_processed(self, monkeypatch, root_analysis, enabled_value):
        """An explicitly-enabled rule (or one with no `enabled` meta) is processed normally."""
        matches = [_yara_match("enabled_rule", meta={"enabled": enabled_value})]
        observable = self._run(monkeypatch, root_analysis, matches)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        assert root_analysis.has_detections()

    @pytest.mark.unit
    def test_missing_enabled_meta_defaults_to_enabled(self, monkeypatch, root_analysis):
        matches = [_yara_match("default_rule")]
        observable = self._run(monkeypatch, root_analysis, matches)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        assert root_analysis.has_detections()

    @pytest.mark.unit
    def test_mixed_enabled_and_disabled(self, monkeypatch, root_analysis):
        """Only the enabled rule survives filtering; the disabled one yields nothing."""
        matches = [
            _yara_match("disabled_rule", meta={"enabled": False}),
            _yara_match("enabled_rule"),
        ]
        observable = self._run(monkeypatch, root_analysis, matches)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        assert [r["rule"] for r in analysis.scan_results] == ["enabled_rule"]
        rule_values = {o.value for o in analysis.observables if o.type == F_YARA_RULE}
        assert rule_values == {"enabled_rule"}


class TestYaraQueueMeta:
    """A rule's `queue` meta rides along on the detection point it creates."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    def _run(self, monkeypatch, root_analysis, matches):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")
        observable = root_analysis.add_file_observable(file_path)

        monkeypatch.setattr(
            yara_client, "scan_file",
            lambda path, meta_tags=None, qa=None: matches,
        )

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)
        assert result == AnalysisExecutionResult.COMPLETED
        return observable

    @pytest.mark.unit
    def test_queue_meta_attached_to_detection_point(self, monkeypatch, root_analysis):
        matches = [_yara_match("routed_rule", meta={"queue": "experimental"})]
        self._run(monkeypatch, root_analysis, matches)

        detection_points = root_analysis.all_detection_points
        assert len(detection_points) == 1
        assert detection_points[0].queue == "experimental"

    @pytest.mark.unit
    def test_no_queue_meta_leaves_detection_unrouted(self, monkeypatch, root_analysis):
        matches = [_yara_match("plain_rule")]
        self._run(monkeypatch, root_analysis, matches)

        detection_points = root_analysis.all_detection_points
        assert len(detection_points) == 1
        assert detection_points[0].queue is None

    @pytest.mark.unit
    def test_no_alert_rule_with_queue_creates_no_detection(self, monkeypatch, root_analysis):
        """A no_alert rule adds no detection point, so its queue meta is moot."""
        matches = [_yara_match("quiet_rule", meta={"modifiers": "no_alert", "queue": "experimental"})]
        self._run(monkeypatch, root_analysis, matches)

        assert root_analysis.all_detection_points == []
        assert not root_analysis.has_detections()


class TestYaraDetectionOnFile:
    """A match puts its detection on the file it matched, with structured details (docs/SVS.md,
    Part 1, D-20), not on the yara_rule observable every file matching the rule shares."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    def _run(self, monkeypatch, root_analysis, matches, content=b"Hello, world!\n", name="test.txt"):
        file_path = root_analysis.create_file_path(name)
        with open(file_path, "wb") as fp:
            fp.write(content)
        observable = root_analysis.add_file_observable(file_path)

        monkeypatch.setattr(
            yara_client, "scan_file",
            lambda path, meta_tags=None, qa=None: matches,
        )

        adapter = self._create_module(root_analysis)
        assert adapter.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
        return observable

    @pytest.mark.unit
    def test_detection_sits_on_the_file_with_details(self, monkeypatch, root_analysis):
        signature_dir = abs_path(get_service_config(SERVICE_YARA_SCANNER).signature_dir)
        rule_uuid = "da44c9b8-24f5-472f-acab-1907f4ce4ad9"
        match = _yara_match("phish_rule", meta={"uuid": rule_uuid})
        match["namespace"] = os.path.join(signature_dir, "phish")
        observable = self._run(monkeypatch, root_analysis, [match])

        assert len(observable.detections) == 1
        detection = observable.detections[0]
        assert detection.description == f"{observable} matched yara rule phish_rule"
        assert detection.details == {
            "sha256": observable.value,
            "rule": "phish_rule",
            "namespace": "phish",
            "rule_uuid": rule_uuid,
        }
        assert detection.signature_uuid == rule_uuid
        assert detection.signature_family == "yara"

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)[0]
        assert not yara_rule.detections
        # the rules and their strings stay in the pruned alert view
        assert analysis.always_visible()

    @pytest.mark.unit
    def test_rule_without_uuid_has_no_rule_uuid_and_the_builtin_family(self, monkeypatch, root_analysis):
        observable = self._run(monkeypatch, root_analysis, [_yara_match("no_uuid_rule")])

        detection = observable.detections[0]
        assert detection.details["rule_uuid"] is None
        # the scanner's default namespace, or none, is kept as it is
        assert detection.details["namespace"] is None
        assert detection.signature_uuid == YARA_RULE_MATCH.uuid
        assert detection.signature_family == "builtin"

    @pytest.mark.unit
    def test_one_rule_matching_two_files_is_two_detections(self, monkeypatch, root_analysis):
        first = self._run(monkeypatch, root_analysis, [_yara_match("shared_rule")], b"one", "one.txt")
        second = self._run(monkeypatch, root_analysis, [_yara_match("shared_rule")], b"two", "two.txt")

        assert [d.details["sha256"] for d in first.detections] == [first.value]
        assert [d.details["sha256"] for d in second.detections] == [second.value]
        assert len(root_analysis.all_detection_points) == 2

    @pytest.mark.unit
    def test_no_alert_rule_leaves_the_analysis_prunable(self, monkeypatch, root_analysis):
        observable = self._run(
            monkeypatch, root_analysis, [_yara_match("quiet_rule", meta={"modifiers": "no_alert"})])

        assert not observable.detections
        assert not observable.get_and_load_analysis(YaraScanResults_v3_4).always_visible()

class TestYaraQAMatches:
    """QA matches are recorded by the yara scanner service, never by the module (docs/YARA_QA.md)."""

    QA_META = {"modifiers": "qa", "uuid": "7f3c1c2e-5b7e-4f7a-9a51-0c1d2e3f4a5b"}

    def _create_module(self, root):
        return YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )

    def _observable(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        return root_analysis.add_file_observable(file_path)

    @pytest.mark.unit
    def test_service_is_told_where_the_file_came_from(self, monkeypatch, root_analysis):
        observable = self._observable(root_analysis)
        captured = {}

        def mock_scan_file(path, meta_tags=None, qa=None):
            captured["qa"] = qa
            return [_yara_match("qa_rule", meta=self.QA_META)]

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)
        result = AnalysisModuleAdapter(self._create_module(root_analysis)).execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert captured["qa"] == {
            "root_uuid": root_analysis.uuid,
            "observable_uuid": observable.uuid,
            "file_name": "test.txt",
            "file_size": 14,
            "sha256": observable.value,
        }
        # a qa rule never alerts
        assert not root_analysis.has_detections()

    @pytest.mark.unit
    def test_no_qa_context_when_qa_results_are_not_saved(self, monkeypatch, root_analysis):
        observable = self._observable(root_analysis)
        captured = {}

        def mock_scan_file(path, meta_tags=None, qa=None):
            captured["qa"] = qa
            return []

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)
        module = self._create_module(root_analysis)
        monkeypatch.setattr(module.config, "save_qa_scan_results", False)
        AnalysisModuleAdapter(module).execute_analysis(observable)

        assert captured["qa"] is None

    @pytest.mark.unit
    def test_local_scanner_qa_matches_are_logged_and_dropped(self, monkeypatch, caplog, root_analysis):
        observable = self._observable(root_analysis)

        def mock_scan_file(path, meta_tags=None, qa=None):
            raise YaraServiceUnavailable("connection refused")

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        class QAMatchingLocalScanner:
            scan_results = [_yara_match("qa_rule", meta=TestYaraQAMatches.QA_META)]

            def scan(self, path, meta_tags=None):
                return True

        def mock_initialize_local_scanner(self):
            self.scanner = QAMatchingLocalScanner()

        monkeypatch.setattr(YaraScanner_v3_4, "initialize_local_scanner", mock_initialize_local_scanner)

        with caplog.at_level("WARNING"):
            result = AnalysisModuleAdapter(self._create_module(root_analysis)).execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert observable.get_and_load_analysis(YaraScanResults_v3_4) is not None
        assert not root_analysis.has_detections()
        assert any("with the local yara scanner: the match is not recorded" in record.message for record in caplog.records)
