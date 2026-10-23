import base64
import logging
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_EXTRACT_URLS, F_FILE, R_EXTRACTED_FROM
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.html import HTMLDataURLAnalysis, MHTMLAnalysis
from saq.util.uuid import get_storage_dir

GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00"
       b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
SCRIPT = b"location='https://landing.example.com/x'"


def _analyze(root_analysis, path: Path, module: str, directive: str = None):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    if directive:
        file_observable.add_directive(directive)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


def _data_url(mime_type: bytes, data: bytes) -> bytes:
    return b"data:" + mime_type + b";base64," + base64.b64encode(data)


@pytest.mark.integration
def test_data_urls_extracted(root_analysis, tmp_path):
    path = tmp_path / "page.html"
    path.write_bytes(b"<html><img src=\"" + _data_url(b"image/gif", GIF) + b"\">"
                     b"<script src=\"" + _data_url(b"text/javascript", SCRIPT) + b"\"></script></html>")

    observable = _analyze(root_analysis, path, "html_data_url_extraction")

    analysis = observable.get_and_load_analysis(HTMLDataURLAnalysis)
    assert analysis.count == 2
    assert analysis.generate_summary() == "HTML Data URL Analysis: Extracted 2 Data URLs"
    files = {o.file_name: o for o in analysis.get_observables_by_type(F_FILE)}
    assert sorted(files) == ["page.html_embed_0.gif", "page.html_embed_1.js"]
    with open(files["page.html_embed_0.gif"].full_path, "rb") as fp:
        assert fp.read() == GIF
    with open(files["page.html_embed_1.js"].full_path, "rb") as fp:
        assert fp.read() == SCRIPT
    for extracted in files.values():
        assert extracted.get_relationship_by_type(R_EXTRACTED_FROM).target == observable
        # an extracted file is not scanned for data URLs again
        assert extracted.get_and_load_analysis(HTMLDataURLAnalysis) is None


@pytest.mark.integration
def test_data_url_bad_mime_type_and_base64(root_analysis, tmp_path, caplog):
    # a mime type that isn't utf-8 used to raise UnicodeDecodeError out of the module
    path = tmp_path / "page.html"
    path.write_bytes(b"<img src=\"" + _data_url(b"image\xff/x\xfe", GIF) + b"\">"
                     b"<img src=\"data:image/png;base64,AAAAA\">")

    observable = _analyze(root_analysis, path, "html_data_url_extraction")

    analysis = observable.get_and_load_analysis(HTMLDataURLAnalysis)
    assert analysis.count == 1
    (extracted,) = analysis.get_observables_by_type(F_FILE)
    assert extracted.file_name == "page.html_embed_0.bin"
    assert any("unable to decode base64" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_data_url_max_bytes(root_analysis, tmp_path, monkeypatch):
    monkeypatch.setattr(get_analysis_module_config("html_data_url_extraction"), "max_bytes", 100)
    path = tmp_path / "page.html"
    path.write_bytes(b"<img src=\"" + _data_url(b"image/gif", GIF) + b"\">" + b" " * 200
                     + b"<img src=\"" + _data_url(b"image/gif", GIF) + b"\">")

    observable = _analyze(root_analysis, path, "html_data_url_extraction")

    assert observable.get_and_load_analysis(HTMLDataURLAnalysis).count == 1


@pytest.mark.integration
@pytest.mark.parametrize("content", [b"", b"<html>no data urls here</html>"])
def test_data_url_nothing_to_extract(root_analysis, tmp_path, content):
    path = tmp_path / "page.html"
    path.write_bytes(content)

    observable = _analyze(root_analysis, path, "html_data_url_extraction")

    assert not observable.get_and_load_analysis(HTMLDataURLAnalysis)


MHTML = (b"From: <Saved by Blink>\r\n"
         b"Snapshot-Content-Location: https://landing.example.com/\r\n"
         b"Subject: Invoice\r\n"
         b"MIME-Version: 1.0\r\n"
         b"Content-Type: multipart/related; type=\"text/html\"; boundary=\"----boundary\"\r\n"
         b"\r\n"
         b"------boundary\r\n"
         b"Content-Type: text/html\r\n"
         b"Content-Transfer-Encoding: quoted-printable\r\n"
         b"Content-Location: https://landing.example.com/\r\n"
         b"\r\n"
         b"<html><a href=3D\"https://landing.example.com/pay\">pay</a></html>\r\n"
         b"------boundary\r\n"
         b"Content-Type: image/gif\r\n"
         b"Content-Transfer-Encoding: base64\r\n"
         b"\r\n"
         + base64.b64encode(GIF) + b"\r\n"
         b"------boundary\r\n"
         b"Content-Type: text/plain\r\n"
         b"\r\n"
         b"\r\n"
         b"------boundary--\r\n")


@pytest.mark.integration
def test_mhtml_parts_extracted(root_analysis, tmp_path):
    # anything before the first header line is skipped
    path = tmp_path / "invoice.MHT"
    path.write_bytes(b"\xef\xbb\xbf\r\n<!-- saved page -->\r\n" + MHTML)

    observable = _analyze(root_analysis, path, "mhtml", directive=DIRECTIVE_EXTRACT_URLS)

    analysis = observable.get_and_load_analysis(MHTMLAnalysis)
    files = {o.file_name: o for o in analysis.get_observables_by_type(F_FILE)}
    # the empty text/plain part is skipped
    assert sorted(files) == ["file_0", "file_1"]
    with open(files["file_0"].full_path, "rb") as fp:
        assert fp.read() == b"<html><a href=\"https://landing.example.com/pay\">pay</a></html>"
    with open(files["file_1"].full_path, "rb") as fp:
        assert fp.read() == GIF
    assert all(f.has_directive(DIRECTIVE_EXTRACT_URLS) for f in files.values())
    assert sorted(analysis.extracted_files) == sorted(f.value for f in files.values())
    assert analysis.generate_summary().startswith("MHTML Analysis: ")


@pytest.mark.integration
def test_mhtml_needs_mhtml_extension(root_analysis, tmp_path):
    path = tmp_path / "invoice.eml"
    path.write_bytes(MHTML)

    observable = _analyze(root_analysis, path, "mhtml")

    assert not observable.get_and_load_analysis(MHTMLAnalysis)


@pytest.mark.integration
def test_mhtml_without_parts(root_analysis, tmp_path):
    path = tmp_path / "empty.mhtml"
    path.write_bytes(b"no headers in this file at all\r\n")

    observable = _analyze(root_analysis, path, "mhtml")

    analysis = observable.get_and_load_analysis(MHTMLAnalysis)
    assert analysis.extracted_files == []
    assert analysis.generate_summary() is None
