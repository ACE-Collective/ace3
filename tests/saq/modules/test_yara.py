import socket

import pytest
import yara_scanner

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_YARA_SCANNER_V3_4,
    DIRECTIVE_NO_SCAN,
    AnalysisExecutionResult,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.yara import YaraScanner_v3_4
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

        def mock_scan_file(path, base_dir=None, socket_dir=None, meta_tags=None):
            captured["meta_tags"] = meta_tags
            return []

        monkeypatch.setattr(yara_scanner, "scan_file", mock_scan_file)

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

        def mock_scan_file(path, base_dir=None, socket_dir=None, meta_tags=None):
            captured["meta_tags"] = meta_tags
            return []

        monkeypatch.setattr(yara_scanner, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert captured["meta_tags"] is None

    @pytest.mark.unit
    def test_meta_tags_passed_to_local_scanner_on_socket_error(self, monkeypatch, root_analysis):
        """When scan_file raises socket.error, local scanner fallback receives meta_tags."""
        file_path = root_analysis.create_file_path("test.txt")
        with open(file_path, "wb") as fp:
            fp.write(b"Hello, world!\n")

        observable = root_analysis.add_file_observable(file_path)
        observable.add_yara_meta("content_type", "email_body")

        def mock_scan_file(path, base_dir=None, socket_dir=None, meta_tags=None):
            raise socket.error("connection refused")

        monkeypatch.setattr(yara_scanner, "scan_file", mock_scan_file)

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

        def mock_scan_file(path, base_dir=None, socket_dir=None, meta_tags=None):
            scan_called["called"] = True
            return []

        monkeypatch.setattr(yara_scanner, "scan_file", mock_scan_file)

        adapter = self._create_module(root_analysis)
        result = adapter.execute_analysis(observable)

        assert result == AnalysisExecutionResult.COMPLETED
        assert scan_called["called"] is False


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
