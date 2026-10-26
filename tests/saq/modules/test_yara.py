import logging
import os
import shutil
import subprocess
import tempfile
from unittest.mock import Mock

import pytest
import yara
import yara_scanner

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config, get_service_config
from saq.constants import (
    ANALYSIS_MODULE_YARA_SCANNER_V3_4,
    DIRECTIVE_NO_SCAN,
    DIRECTIVE_SANDBOX,
    F_SIGNATURE_ID,
    F_YARA_RULE,
    SERVICE_YARA_SCANNER,
    AnalysisExecutionResult,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.yara import YaraScanResults_v3_4, YaraScanner_v3_4, highlight_hexdump, visible_match_value
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN, YARA_RULE_MATCH
from saq.svs.marker_rule import MARKER_RULE_NAME, marker_rule_path
from saq.svs.markers import find_markers_in_match, new_marker
from saq.util.uuid import get_storage_dir
from saq.yara_scanning import client as yara_client
from saq.yara_scanning.client import YaraScanCrashed, YaraScanTimeout, YaraServiceUnavailable
from saq.yara_scanning.server import ScannerSettings, YaraScannerServer
from tests.saq.test_util import create_test_context


def _meta_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return f'"{value}"'


def _rule(name: str, meta: dict | None = None, tags: list[str] | None = None,
          strings: str = '$a = "Hello, world!"', condition: str = "any of them") -> str:
    meta_block = ""
    if meta:
        meta_block = "    meta:\n" + "".join(f"        {key} = {_meta_value(value)}\n" for key, value in meta.items())

    tag_list = f" : {' '.join(tags)}" if tags else ""
    return f"rule {name}{tag_list}\n{{\n{meta_block}    strings:\n        {strings}\n    condition:\n        {condition}\n}}\n"


@pytest.fixture
def signature_dir(tmp_path, monkeypatch) -> str:
    result = str(tmp_path / "signatures")
    os.mkdir(result)
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", result)
    return result


@pytest.fixture
def write_rules(signature_dir):
    def _write(*rules: str, subdir: str = "rules"):
        rule_dir = os.path.join(signature_dir, subdir)
        os.makedirs(rule_dir, exist_ok=True)
        with open(os.path.join(rule_dir, "test.yar"), "w") as fp:
            fp.write("\n".join(rules))

        return rule_dir

    return _write


@pytest.fixture
def socket_dir(monkeypatch):
    # AF_UNIX paths are limited to 108 bytes, which a tmp_path under xdist can come close to.
    # nothing serves this directory until yara_service starts a server in it, so until then the
    # module finds the service unavailable and scans with its local scanner
    result = tempfile.mkdtemp(prefix="yss-")
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "socket_dir", result)
    yield result
    shutil.rmtree(result, ignore_errors=True)


@pytest.fixture
def yara_service(signature_dir, socket_dir, write_rules):
    """Starts a real yara scanner service over the given rules, at the socket the module uses."""
    servers = []

    def _start(*rules: str, git_repo_dirs: tuple[str, ...] = ()) -> YaraScannerServer:
        if rules:
            write_rules(*rules)

        server = YaraScannerServer(ScannerSettings(
            socket_dir=socket_dir, signature_dir=signature_dir, git_repo_dirs=git_repo_dirs, worker_count=1,
            update_frequency=60, default_timeout=5, compile_timeout=60, io_timeout=5,
            max_data_bytes=1024 * 1024, max_requests_per_worker=0, backlog=50))
        servers.append(server)
        server.start()
        assert server.wait_for_start(30)
        return server

    yield _start

    for server in servers:
        server.stop()


def _git_commit(repo_dir: str) -> str:
    for args in (["init", "-q"], ["add", "."], ["-c", "user.name=test", "-c", "user.email=test@localhost", "commit", "-q", "-m", "rules"]):
        subprocess.run(["git", *args], cwd=repo_dir, check=True)

    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True).stdout.strip()


# ---------------------------------------------------------------------------
# meta_tags plumbing, against a real yara scanner service and the real local scanner
# ---------------------------------------------------------------------------
META_TAGGED_RULES = (
    _rule("always_match"),
    _rule("meta_tagged_email_body", meta={"meta_tags": "content_type=email_body"}),
    _rule("meta_tagged_source_imap", meta={"meta_tags": "source=imap"}),
)


class TestYaraScannerMetaTags:
    """Verify that execute_analysis passes meta_tags through to the scanner."""

    def _create_module(self, root):
        module = YaraScanner_v3_4(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        return AnalysisModuleAdapter(module)

    def _matched_rules(self, observable) -> set[str]:
        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        return {r["rule"] for r in analysis.scan_results}

    @pytest.mark.integration
    def test_meta_tags_passed_to_scanner(self, yara_service, root_analysis):
        """FileObservable with yara_meta directives enables the rules tagged with them."""
        yara_service(*META_TAGGED_RULES)
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")
        observable.add_yara_meta("source", "imap")

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert self._matched_rules(observable) == {"always_match", "meta_tagged_email_body", "meta_tagged_source_imap"}

    @pytest.mark.integration
    def test_no_meta_tags_passes_none(self, yara_service, root_analysis):
        """FileObservable with no yara_meta directives matches only the untagged rules."""
        yara_service(*META_TAGGED_RULES)
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert self._matched_rules(observable) == {"always_match"}

    @pytest.mark.integration
    def test_meta_tags_passed_to_local_scanner_when_service_unavailable(self, socket_dir, write_rules, root_analysis):
        """When the yara scanner service is unavailable, local scanner fallback receives meta_tags."""
        write_rules(*META_TAGGED_RULES)
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert self._matched_rules(observable) == {"always_match", "meta_tagged_email_body"}

    @pytest.mark.integration
    def test_no_scan_directive_skips_scanning(self, yara_service, root_analysis):
        """FileObservable with DIRECTIVE_NO_SCAN skips scanning entirely."""
        yara_service(*META_TAGGED_RULES)
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_directive(DIRECTIVE_NO_SCAN)
        observable.add_yara_meta("content_type", "email_body")

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert observable.get_analysis(YaraScanResults_v3_4) is None


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
        dedicated handler — which logs the specific timeout warning and does not
        generate an error report.
        """
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)

        def mock_scan_file(path, meta_tags=None, qa=None):
            raise YaraScanTimeout("scanning timed out")

        monkeypatch.setattr(yara_client, "scan_file", mock_scan_file)

        write_error_report_called = {"called": False}

        def mock_write_error_report(*args, **kwargs):
            write_error_report_called["called"] = True
            return ""

        monkeypatch.setattr(
            "saq.error.reporting.write_error_report", mock_write_error_report
        )

        adapter = self._create_module(root_analysis)
        with caplog.at_level("WARNING"):
            result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        # the timeout must be handled by the dedicated handler, not reported as an error
        assert write_error_report_called["called"] is False
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

        write_error_report_called = {"called": False}

        def mock_write_error_report(*args, **kwargs):
            write_error_report_called["called"] = True
            return ""

        monkeypatch.setattr("saq.error.reporting.write_error_report", mock_write_error_report)

        def fail_initialize_local_scanner(self):
            raise AssertionError("the local scanner must not be used")

        monkeypatch.setattr(YaraScanner_v3_4, "initialize_local_scanner", fail_initialize_local_scanner)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert write_error_report_called["called"] is True
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

        write_error_report_called = {"called": False}

        def mock_write_error_report(*args, **kwargs):
            write_error_report_called["called"] = True
            return ""

        monkeypatch.setattr("saq.error.reporting.write_error_report", mock_write_error_report)

        adapter = self._create_module(root_analysis)
        with caplog.at_level("WARNING"):
            result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert write_error_report_called["called"] is False
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
# signature_id observables are emitted from rule.meta.uuid
# ---------------------------------------------------------------------------
UUID_A = "da44c9b8-24f5-472f-acab-1907f4ce4ad9"
UUID_B = "3a1ddc4e-def5-439b-b3d3-d51352786d94"


def _create_module(root):
    module = YaraScanner_v3_4(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
    )
    return AnalysisModuleAdapter(module)


def _scan(root_analysis, content=b"Hello, world!\n", name="test.txt"):
    file_path = root_analysis.create_file_path(name)
    with open(file_path, "wb") as fp:
        fp.write(content)
    observable = root_analysis.add_file_observable(file_path)

    assert _create_module(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    return observable


class TestYaraSignatureIdEmission:
    """When a yara rule matches and has a `uuid` meta field, a signature_id observable
    should be attached to the resulting YaraScanResults_v3_4 analysis."""

    def _signature_ids(self, observable) -> list[str]:
        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        return [o.value for o in analysis.observables if o.type == F_SIGNATURE_ID]

    @pytest.mark.integration
    def test_rule_with_uuid_emits_signature_id(self, yara_service, root_analysis):
        """A matching rule carrying a uuid meta field emits a signature_id observable."""
        yara_service(_rule("test_rule_with_uuid", meta={"uuid": UUID_A}))
        assert self._signature_ids(_scan(root_analysis)) == [UUID_A]

    @pytest.mark.integration
    def test_rule_without_uuid_does_not_emit(self, yara_service, root_analysis):
        """A matching rule whose meta lacks a uuid must NOT emit a signature_id."""
        yara_service(_rule("test_rule_no_uuid"))
        assert self._signature_ids(_scan(root_analysis)) == []

    @pytest.mark.integration
    def test_multiple_rules_emit_distinct_signature_ids(self, yara_service, root_analysis):
        """Two matching rules with different uuids emit two signature_id observables."""
        yara_service(_rule("rule_a", meta={"uuid": UUID_A}), _rule("rule_b", meta={"uuid": UUID_B}))
        assert set(self._signature_ids(_scan(root_analysis))) == {UUID_A, UUID_B}

    @pytest.mark.integration
    def test_duplicate_uuid_across_matches_dedups(self, yara_service, root_analysis):
        """If two rule matches share the same uuid, only one signature_id observable is emitted."""
        yara_service(_rule("rule_a", meta={"uuid": UUID_A}), _rule("rule_b", meta={"uuid": UUID_A}))
        assert self._signature_ids(_scan(root_analysis)) == [UUID_A]


@pytest.mark.integration
def test_disassembly_failure_is_reported_and_analysis_continues(yara_service, monkeypatch, caplog, root_analysis):
    yara_service(_rule("asm_rule", tags=["asm"], strings='$code_x86 = "world"'))

    def failing_disassemble(*args, **kwargs):
        raise ValueError("bad instruction stream")

    monkeypatch.setattr("saq.modules.file_analysis.yara.disassemble", failing_disassemble)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    with caplog.at_level(logging.ERROR):
        observable = _scan(root_analysis)

    analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis.scan_results[0]["context"][0][4] == "Failed to disassemble"
    records = [r for r in caplog.records if r.getMessage().startswith("unable to disassemble $code_x86 at 7")]
    assert len(records) == 1
    write_error_report.assert_called_once()


class TestYaraEnabledMeta:
    """A rule whose `enabled` meta is falsy is ignored as if it never matched."""

    @pytest.mark.integration
    @pytest.mark.parametrize("enabled_value", [False, "false", "False", "no", "off", "disabled", 0])
    def test_disabled_rule_produces_no_analysis(self, yara_service, root_analysis, enabled_value):
        """A file matching only a disabled rule behaves exactly like no match: no analysis."""
        yara_service(_rule("disabled_rule", meta={"enabled": enabled_value}))
        observable = _scan(root_analysis)

        assert observable.get_and_load_analysis(YaraScanResults_v3_4) is None
        assert not root_analysis.has_detections()

    @pytest.mark.integration
    @pytest.mark.parametrize("enabled_value", [True, "true", "yes", 1])
    def test_enabled_rule_is_processed(self, yara_service, root_analysis, enabled_value):
        """An explicitly-enabled rule (or one with no `enabled` meta) is processed normally."""
        yara_service(_rule("enabled_rule", meta={"enabled": enabled_value}))
        observable = _scan(root_analysis)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        assert root_analysis.has_detections()

    @pytest.mark.integration
    def test_missing_enabled_meta_defaults_to_enabled(self, yara_service, root_analysis):
        yara_service(_rule("default_rule"))
        observable = _scan(root_analysis)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        assert root_analysis.has_detections()

    @pytest.mark.integration
    def test_mixed_enabled_and_disabled(self, yara_service, root_analysis):
        """Only the enabled rule survives filtering; the disabled one yields nothing."""
        yara_service(_rule("disabled_rule", meta={"enabled": False}), _rule("enabled_rule"))
        observable = _scan(root_analysis)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None
        assert [r["rule"] for r in analysis.scan_results] == ["enabled_rule"]
        rule_values = {o.value for o in analysis.observables if o.type == F_YARA_RULE}
        assert rule_values == {"enabled_rule"}


class TestYaraQueueMeta:
    """A rule's `queue` meta rides along on the detection point it creates."""

    @pytest.mark.integration
    def test_queue_meta_attached_to_detection_point(self, yara_service, root_analysis):
        yara_service(_rule("routed_rule", meta={"queue": "experimental"}))
        _scan(root_analysis)

        detection_points = root_analysis.all_detection_points
        assert len(detection_points) == 1
        assert detection_points[0].queue == "experimental"

    @pytest.mark.integration
    def test_no_queue_meta_leaves_detection_unrouted(self, yara_service, root_analysis):
        yara_service(_rule("plain_rule"))
        _scan(root_analysis)

        detection_points = root_analysis.all_detection_points
        assert len(detection_points) == 1
        assert detection_points[0].queue is None

    @pytest.mark.integration
    def test_no_alert_rule_with_queue_creates_no_detection(self, yara_service, root_analysis):
        """A no_alert rule adds no detection point, so its queue meta is moot."""
        yara_service(_rule("quiet_rule", meta={"modifiers": "no_alert", "queue": "experimental"}))
        _scan(root_analysis)

        assert root_analysis.all_detection_points == []
        assert not root_analysis.has_detections()


class TestYaraDetectionOnFile:
    """A match puts its detection on the file it matched, with structured details (docs/SVS.md,
    Part 1, D-20), not on the yara_rule observable every file matching the rule shares."""

    @pytest.mark.integration
    def test_detection_sits_on_the_file_with_details(self, yara_service, write_rules, root_analysis):
        # the rule comes from a git repository, so the detection carries the commit as its version
        commit = _git_commit(write_rules(_rule("phish_rule", meta={"uuid": UUID_A}), subdir="phish"))
        yara_service(git_repo_dirs=("phish",))
        observable = _scan(root_analysis)

        assert len(observable.detections) == 1
        detection = observable.detections[0]
        assert detection.description == f"{observable} matched yara rule phish_rule"
        assert detection.details == {
            "sha256": observable.value,
            "rule": "phish_rule",
            "namespace": "phish",
            "rule_uuid": UUID_A,
        }
        assert detection.signature_uuid == UUID_A
        assert detection.signature_version == commit
        assert detection.signature_family == "yara"

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)[0]
        assert not yara_rule.detections
        # the rules and their strings stay in the pruned alert view
        assert analysis.always_visible()

    @pytest.mark.integration
    def test_rule_without_uuid_has_no_rule_uuid_and_the_builtin_family(self, yara_service, root_analysis):
        yara_service(_rule("no_uuid_rule"))
        observable = _scan(root_analysis)

        detection = observable.detections[0]
        assert detection.details["rule_uuid"] is None
        # the namespace is the rule directory, relative to the signature directory
        assert detection.details["namespace"] == "rules"
        assert detection.signature_uuid == YARA_RULE_MATCH.uuid
        assert detection.signature_version == SIGNATURE_VERSION_UNKNOWN
        assert detection.signature_family == "builtin"

    @pytest.mark.integration
    def test_one_rule_matching_two_files_is_two_detections(self, yara_service, root_analysis):
        yara_service(_rule("shared_rule", strings='$a = "one"\n        $b = "two"'))
        first = _scan(root_analysis, b"one", "one.txt")
        second = _scan(root_analysis, b"two", "two.txt")

        assert [d.details["sha256"] for d in first.detections] == [first.value]
        assert [d.details["sha256"] for d in second.detections] == [second.value]
        assert len(root_analysis.all_detection_points) == 2

    @pytest.mark.integration
    def test_no_alert_rule_leaves_the_analysis_prunable(self, yara_service, root_analysis):
        yara_service(_rule("quiet_rule", meta={"modifiers": "no_alert"}))
        observable = _scan(root_analysis)

        assert not observable.detections
        assert not observable.get_and_load_analysis(YaraScanResults_v3_4).always_visible()


class TestYaraQAMatches:
    """QA matches are recorded by the yara scanner service, never by the module (docs/YARA_QA.md)."""

    QA_RULE = _rule("qa_rule", meta={"modifiers": "qa", "uuid": "7f3c1c2e-5b7e-4f7a-9a51-0c1d2e3f4a5b"})

    def _observable(self, root_analysis):
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        return root_analysis.add_file_observable(file_path)

    @pytest.mark.integration
    def test_service_is_told_where_the_file_came_from(self, yara_service, monkeypatch, root_analysis):
        yara_service(self.QA_RULE)
        observable = self._observable(root_analysis)
        scan_file = Mock(wraps=yara_client.scan_file)
        monkeypatch.setattr(yara_client, "scan_file", scan_file)

        result = _create_module(root_analysis).execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert scan_file.call_args.kwargs["qa"] == {
            "root_uuid": root_analysis.uuid,
            "observable_uuid": observable.uuid,
            "file_name": "test.txt",
            "file_size": 14,
            "sha256": observable.value,
        }
        assert [r["rule"] for r in observable.get_and_load_analysis(YaraScanResults_v3_4).scan_results] == ["qa_rule"]
        # a qa rule never alerts
        assert not root_analysis.has_detections()

    @pytest.mark.integration
    def test_no_qa_context_when_qa_results_are_not_saved(self, yara_service, monkeypatch, root_analysis):
        yara_service(self.QA_RULE)
        observable = self._observable(root_analysis)
        scan_file = Mock(wraps=yara_client.scan_file)
        monkeypatch.setattr(yara_client, "scan_file", scan_file)

        module = YaraScanner_v3_4(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_YARA_SCANNER_V3_4),
        )
        monkeypatch.setattr(module.config, "save_qa_scan_results", False)
        AnalysisModuleAdapter(module).execute_analysis(observable)

        assert scan_file.call_args.kwargs["qa"] is None

    @pytest.mark.integration
    def test_local_scanner_qa_matches_are_logged_and_dropped(self, socket_dir, write_rules, caplog, root_analysis):
        write_rules(self.QA_RULE)
        observable = self._observable(root_analysis)

        with caplog.at_level("WARNING"):
            result = _create_module(root_analysis).execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert any("yara scanner service unavailable, scanning locally" in record.message for record in caplog.records)
        assert observable.get_and_load_analysis(YaraScanResults_v3_4) is not None
        assert not root_analysis.has_detections()
        assert any("with the local yara scanner: the match is not recorded" in record.message for record in caplog.records)


class TestYaraMarkerRule:
    """The svs marker rule (saq/svs/marker_rule.py) reaches the module's fallback scanner too, and
    its matches are kept in the file's YaraScanResults, strings included, without a detection
    (docs/SVS.md, Part 3, FR-20 and FR-25)."""

    @pytest.mark.integration
    def test_fallback_scanner_records_markers(self, monkeypatch, tmp_path, root_analysis):
        signature_dir = tmp_path / "yara"
        signature_dir.mkdir()
        monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(signature_dir))

        def unavailable(path, meta_tags=None, qa=None):
            raise YaraServiceUnavailable("connection refused")

        monkeypatch.setattr(yara_client, "scan_file", unavailable)

        marker = new_marker()
        file_path = root_analysis.create_file_path("dropped.ps1")
        with open(file_path, "wb") as fp:
            fp.write(f"Write-Host 'hello' <# {marker} #>".encode("utf-16-le"))

        root_analysis.analysis_mode = "test_groups"
        observable = root_analysis.add_file_observable(file_path)
        root_analysis.save()
        root_analysis.schedule()

        engine = Engine()
        engine.configuration_manager.enable_module(ANALYSIS_MODULE_YARA_SCANNER_V3_4, "test_groups")
        engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

        assert os.path.exists(marker_rule_path(str(signature_dir)))

        root_analysis = load_root(get_storage_dir(root_analysis.uuid))
        observable = root_analysis.get_observable(observable.uuid)
        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis is not None

        (result,) = analysis.scan_results
        assert result["rule"] == MARKER_RULE_NAME
        assert [m for (_, _, data) in result["strings"] for m in find_markers_in_match(data)] == [marker]

        assert not observable.detections
        assert not observable.has_directive(DIRECTIVE_SANDBOX)


class TestYaraStringPatterns:
    """The pattern of each string that matched is stored with the match, for the GUI."""

    @pytest.mark.integration
    def test_patterns_of_matched_strings_are_stored(self, yara_service, root_analysis):
        yara_service(_rule("pattern_rule", strings='$a = "Hello" nocase\n        $b = { 77 6F 72 6C 64 }\n        $c = "not in the file"'))
        observable = _scan(root_analysis)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        # $c did not match, so its pattern is not kept
        assert analysis.scan_results[0]["string_patterns"] == {"$a": '"Hello" nocase', "$b": "{ 77 6F 72 6C 64 }"}

    @pytest.mark.integration
    def test_patterns_are_stored_by_the_local_scanner(self, socket_dir, write_rules, root_analysis):
        write_rules(_rule("local_rule"))
        observable = _scan(root_analysis)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis.scan_results[0]["string_patterns"] == {"$a": '"Hello, world!"'}

    @pytest.mark.integration
    def test_pattern_lookup_failure_is_reported_and_analysis_continues(self, yara_service, monkeypatch, caplog, root_analysis):
        yara_service(_rule("pattern_rule"))

        def failing_lookup(namespace, rule_name):
            raise RuntimeError("lookup failed")

        monkeypatch.setattr("saq.modules.file_analysis.yara.rule_string_patterns", failing_lookup)
        write_error_report = Mock()
        monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

        with caplog.at_level(logging.ERROR):
            observable = _scan(root_analysis)

        analysis = observable.get_and_load_analysis(YaraScanResults_v3_4)
        assert analysis.scan_results[0]["string_patterns"] == {}
        assert root_analysis.has_detections()
        records = [r for r in caplog.records if r.getMessage() == "unable to read the string patterns of yara rule pattern_rule"]
        assert len(records) == 1
        assert records[0].yara_rule == "pattern_rule"
        write_error_report.assert_called_once()



# ---------------------------------------------------------------------------
# how a string match is drawn in the GUI
# ---------------------------------------------------------------------------
def _hexdump(data: bytes) -> str:
    return subprocess.run(["hexdump", "-C"], input=data, capture_output=True, check=True).stdout.decode()


@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("plain", "plain"),
    # the space itself stays, so find in page and copy see it; css draws the dot
    ("a b", 'a<span class="yara-sp"> </span>b'),
    ("\n\n", '<span class="yara-ws">\u240a</span><span class="yara-ws">\u240a</span>'),
    ("\t\r\x00\x7f", '<span class="yara-ws">\u2409</span><span class="yara-ws">\u240d</span>'
                     '<span class="yara-ws">\u2400</span><span class="yara-ws">\u2421</span>'),
    ("\x85\u200b", '<span class="yara-ws">\\x85</span><span class="yara-ws">\\u200b</span>'),
    ("<b>&", "&lt;b&gt;&amp;"),
    ("caf\u00e9", "caf\u00e9"),
])
def test_visible_match_value(value, expected):
    assert str(visible_match_value(value)) == expected


@pytest.mark.unit
def test_highlight_hexdump_marks_a_match_across_lines():
    data = b"A" * 10 + b"needle-that-spans-two-lines" + b"B" * 10
    html = str(highlight_hexdump([10, "$a", "needle-that-spans-two-lines", _hexdump(data)], 64))

    assert html.splitlines() == [
        "00000000  41 41 41 41 41 41 41 41  41 41 <mark>6e 65 65 64 6c 65</mark>  |AAAAAAAAAA<mark>needle</mark>|",
        "00000010  <mark>2d 74 68 61 74 2d 73 70  61 6e 73 2d 74 77 6f 2d</mark>  |<mark>-that-spans-two-</mark>|",
        "00000020  <mark>6c 69 6e 65 73</mark> 42 42 42  42 42 42 42 42 42 42     |<mark>lines</mark>BBBBBBBBBB|",
        "0000002f",
    ]


@pytest.mark.unit
def test_highlight_hexdump_match_after_leading_context():
    """The dump starts context_bytes before the match, so the match is context_bytes in."""
    data = b"x" * 70 + b"needle" + b"y" * 20
    context = data[70 - 16:]
    html = str(highlight_hexdump([70, "$a", "needle", _hexdump(context)], 16))
    assert "00000010  <mark>6e 65 65 64 6c 65</mark> 79 79" in html
    assert html.count("<mark>") == 2


@pytest.mark.unit
def test_highlight_hexdump_finds_a_unique_match_when_context_bytes_changed():
    context = b"x" * 32 + b"needle" + b"y" * 32
    html = str(highlight_hexdump([500, "$a", "needle", _hexdump(context)], 64))
    assert "|<mark>needle</mark>yyyyyyyyyy|" in html


@pytest.mark.unit
def test_highlight_hexdump_marks_a_match_partly_behind_a_repeat():
    """hexdump replaces repeated lines with *; the bytes it still shows are marked."""
    data = b"\x00" * 48 + b"tail"
    html = str(highlight_hexdump([0, "$zeros", "\x00" * 40, _hexdump(data)], 64))
    lines = html.splitlines()
    assert lines[0].startswith("00000000  <mark>00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00</mark>")
    assert lines[1] == "*"


@pytest.mark.unit
@pytest.mark.parametrize("value", ["not there", "\\n", "\u4e2d"])
def test_highlight_hexdump_leaves_an_unlocatable_match_unmarked(value):
    dump = _hexdump(b"Hello, world!\n")
    assert str(highlight_hexdump([7, "$a", value, dump], 64)) + "\n" == dump


@pytest.mark.unit
def test_highlight_hexdump_escapes_and_accepts_bytes():
    dump = _hexdump(b"<script>")
    html = str(highlight_hexdump([0, "$a", "<script>", dump.encode()], 64))
    assert "|<mark>&lt;script&gt;</mark>|" in html
