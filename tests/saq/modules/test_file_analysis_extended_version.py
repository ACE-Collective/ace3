"""Unit tests for OCR/QR extended_version (Phase 4 cache-key invalidation
tied to external tool versions and the QR filter file)."""
import hashlib
from importlib.metadata import PackageNotFoundError
import os

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_OCR, ANALYSIS_MODULE_QRCODE
from saq.modules.file_analysis.ocr import OCRAnalyzer
from saq.modules.file_analysis.qrcode import QRCodeAnalyzer


def _make_ocr(test_context):
    return OCRAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR),
    )


def _make_qr(test_context):
    return QRCodeAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE),
    )


class TestOCRExtendedVersion:

    @pytest.mark.unit
    def test_includes_tesseract_version(self, test_context, monkeypatch):
        monkeypatch.setattr(
            "saq.modules.file_analysis.ocr.probe_binary_version",
            lambda name, args=None: "tesseract 5.3.0" if name == "tesseract" else None,
        )
        assert _make_ocr(test_context).extended_version == {"tesseract": "tesseract 5.3.0"}

    @pytest.mark.unit
    def test_omits_key_on_probe_failure(self, test_context, monkeypatch):
        """A transient probe failure must not poison the cache key — the
        tool's key is omitted (accepting staleness across an upgrade)."""
        monkeypatch.setattr(
            "saq.modules.file_analysis.ocr.probe_binary_version",
            lambda name, args=None: None,
        )
        assert _make_ocr(test_context).extended_version == {}


class TestQRCodeExtendedVersion:

    @pytest.mark.unit
    def test_includes_tool_versions_and_filter_fingerprint(self, test_context, monkeypatch, tmp_path):
        versions = {"zbarimg": "0.23", "gs": "10.0", "pdfinfo": "poppler 22.x"}
        monkeypatch.setattr(
            "saq.modules.file_analysis.qrcode.probe_binary_version",
            lambda name, args=None: versions.get(name),
        )
        monkeypatch.setattr(
            "saq.modules.file_analysis.qrcode.package_version",
            lambda name: {"opencv-python": "9.9.9"}[name],
        )
        filter_file = tmp_path / "qrcode.filter"
        filter_file.write_text("example\\.com\n")
        monkeypatch.setattr(
            QRCodeAnalyzer, "qrcode_filter_path",
            property(lambda _self: str(filter_file)),
        )
        ev = _make_qr(test_context).extended_version
        assert ev["zbarimg"] == "0.23"
        assert ev["gs"] == "10.0"
        assert ev["pdfinfo"] == "poppler 22.x"
        assert ev["opencv"] == "9.9.9"
        # the filter fingerprint is a content sha256, not an mtime+size string
        expected = hashlib.sha256(filter_file.read_bytes()).hexdigest()
        assert ev["qrcode_filter_version"] == expected

    @pytest.mark.unit
    def test_filter_edit_changes_fingerprint(self, test_context, monkeypatch, tmp_path):
        """An analyst edit to the filter file must shift the cache key —
        the filter's contents change output but only its path is in the
        config hash."""
        monkeypatch.setattr(
            "saq.modules.file_analysis.qrcode.probe_binary_version",
            lambda name, args=None: None,
        )
        filter_file = tmp_path / "qrcode.filter"
        filter_file.write_text("one\n")
        monkeypatch.setattr(
            QRCodeAnalyzer, "qrcode_filter_path",
            property(lambda _self: str(filter_file)),
        )
        analyzer = _make_qr(test_context)
        first = analyzer.extended_version["qrcode_filter_version"]
        filter_file.write_text("one\ntwo - longer content\n")
        second = analyzer.extended_version["qrcode_filter_version"]
        assert first != second

    @pytest.mark.unit
    def test_identical_content_same_fingerprint_across_mtime(self, test_context, monkeypatch, tmp_path):
        """Regression: the filter ships from a git repo, so its mtime is set
        per host at checkout. Identical content must yield an identical
        fingerprint regardless of mtime — a content hash, not mtime+size."""
        monkeypatch.setattr(
            "saq.modules.file_analysis.qrcode.probe_binary_version",
            lambda name, args=None: None,
        )
        content = "example\\.com\n"
        file_a = tmp_path / "a.filter"
        file_b = tmp_path / "b.filter"
        file_a.write_text(content)
        file_b.write_text(content)
        # force distinct mtimes — what differs across hosts after a checkout
        os.utime(file_a, (1000, 1000))
        os.utime(file_b, (2000, 2000))

        monkeypatch.setattr(
            QRCodeAnalyzer, "qrcode_filter_path",
            property(lambda _self: str(file_a)),
        )
        first = _make_qr(test_context).extended_version["qrcode_filter_version"]
        monkeypatch.setattr(
            QRCodeAnalyzer, "qrcode_filter_path",
            property(lambda _self: str(file_b)),
        )
        second = _make_qr(test_context).extended_version["qrcode_filter_version"]
        assert first == second

    @pytest.mark.unit
    def test_missing_tools_and_filter_yield_empty(self, test_context, monkeypatch):
        monkeypatch.setattr(
            "saq.modules.file_analysis.qrcode.probe_binary_version",
            lambda name, args=None: None,
        )
        def not_installed(name):
            raise PackageNotFoundError(name)
        monkeypatch.setattr("saq.modules.file_analysis.qrcode.package_version", not_installed)
        monkeypatch.setattr(
            QRCodeAnalyzer, "qrcode_filter_path", property(lambda _self: None),
        )
        assert _make_qr(test_context).extended_version == {}
