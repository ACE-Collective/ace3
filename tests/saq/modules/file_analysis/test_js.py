"""Unit tests for the JavaScript deobfuscation analyzer.

The production path dispatches through celery to a docker-in-docker
manager that spawns scanner containers. None of that is available in the
unit test environment, so we monkeypatch
``saq.modules.file_analysis.js.deobfuscate_file`` with a local shim that
runs the harness directly via ``node``. This keeps the tests fast and
faithful to the real harness output while skipping the container plumbing.

That fidelity covers the dynamic sandbox pass only. webcrack is installed
into the scanner image by Dockerfile.js_deobfuscator and is deliberately
absent from a checkout, so under the shim the static pre-pass always reports
"skipped" -- its "applied" and "failed" branches are exercised only inside
that image, and the tests below stub the report when they need to cover how
the module handles them.
"""

import json
import os
import subprocess

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_JAVASCRIPT_DEOBFUSCATION,
    DIRECTIVE_CRAWL_EXTRACTED_URLS,
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_YARA_META_PREFIX,
    F_FILE,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.js import (
    DEOBFUSCATED_PREFIX,
    JavaScriptDeobfuscationAnalysis,
    JavaScriptDeobfuscationAnalyzer,
)
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context

YARA_META_JS = f"{DIRECTIVE_YARA_META_PREFIX}type=script.javascript"

HARNESS_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "..",
        "js_deobfuscator", "harness.js",
    )
)


def _local_deobfuscate_file(file_path, output_dir, is_async=False, timeout=60, scanner_timeout=30):
    """Stand-in for saq.js_deobfuscator.deobfuscate_file that runs the
    harness directly via node."""
    os.makedirs(output_dir, exist_ok=True)
    out_js = os.path.join(output_dir, "deobfuscated.js")
    proc = subprocess.run(
        ["node", HARNESS_PATH, file_path, out_js],
        capture_output=True,
        text=True,
        timeout=scanner_timeout,
    )
    stdout, stderr = proc.stdout or "", proc.stderr or ""

    with open(os.path.join(output_dir, "std.out"), "w") as fp:
        fp.write(stdout)
    with open(os.path.join(output_dir, "std.err"), "w") as fp:
        fp.write(stderr)
    with open(os.path.join(output_dir, "exit.code"), "w") as fp:
        fp.write(str(proc.returncode))
    try:
        report = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        report = {"status": "parse_error", "raw_stdout": stdout}
    with open(os.path.join(output_dir, "report.json"), "w") as fp:
        json.dump(report, fp)

    fixed_names = ("deobfuscated.js", "std.out", "std.err", "exit.code", "report.json")
    blob_names = sorted(
        n for n in os.listdir(output_dir)
        if n.startswith("blob_") and n.endswith((".html", ".svg", ".js"))
    )
    return [
        os.path.join(output_dir, name)
        for name in (*fixed_names, *blob_names)
        if os.path.exists(os.path.join(output_dir, name))
    ]


@pytest.fixture
def patched_deobfuscate(monkeypatch):
    """Replace the celery client with the local node shim for every test."""
    monkeypatch.setattr(
        "saq.modules.file_analysis.js.deobfuscate_file",
        _local_deobfuscate_file,
    )


def _build_analyzer(root):
    """Build the analyzer wired to a root."""
    raw_analyzer = JavaScriptDeobfuscationAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_JAVASCRIPT_DEOBFUSCATION),
    )
    return AnalysisModuleAdapter(raw_analyzer)


@pytest.mark.unit
def test_obfuscated_sample_is_deobfuscated(datadir, monkeypatch, patched_deobfuscate):
    """Feeding the canonical obfuscator.io sample should produce a
    deobfuscated sibling file marked for URL extraction. The crawl-scope
    directive is applied downstream by the observable_modifier rule, not by
    this analyzer, so we assert that the analyzer does NOT add it here."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "sample_obsfucated_javascript.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert isinstance(analysis, JavaScriptDeobfuscationAnalysis)
    assert analysis.exit_code == 0
    assert analysis.event_count > 0
    assert len(analysis.extracted_files) == 1
    assert os.path.basename(analysis.extracted_files[0]).startswith(DEOBFUSCATED_PREFIX)

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    assert emitted_obs.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert not emitted_obs.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    assert emitted_obs.has_relationship(R_EXTRACTED_FROM)
    assert observable.has_tag("js")

    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "in loop" in body


@pytest.mark.unit
def test_plain_js_emits_url_to_extracted_file(datadir, monkeypatch, patched_deobfuscate):
    """A trivial but real JS file should still produce a deobfuscated
    file containing the assigned URL in clear text."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "plain.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    assert emitted_obs.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert not emitted_obs.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com/plain-target" in body


@pytest.mark.unit
def test_acrobat_pdf_bracket_notation_js(datadir, monkeypatch, patched_deobfuscate):
    """A PDF-extracted sample that uses only bracket-notation calls on
    Acrobat globals (app, util, SOAP, getField)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "acrobat_pdf.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0
    assert analysis.event_count > 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "getField" in body
    assert "SOAP" in body or "streamDecode" in body


@pytest.mark.unit
def test_window_property_is_resolved_in_url(datadir, monkeypatch, patched_deobfuscate):
    """Values written to `window.<prop>` must be resolved when read back and
    concatenated into a later redirect URL — otherwise the sandbox emits a
    bogus URL like `https://host/[window.prop]` from Proxy stringification."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "window_property_substitution.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://evil.com/?e=user@example.com" in body
    assert "[window.abcd]" not in body


@pytest.mark.unit
def test_blob_redirect_records_decoded_html(datadir, monkeypatch, patched_deobfuscate):
    """SVG-style redirect via `new Blob([decoded_html], {type:'text/html'})`
    + `URL.createObjectURL` + `document.location.replace`. The harness's
    Blob recorder both records the construct event AND materializes the
    decoded HTML payload as a sibling .html file so html_js_extraction can
    recurse into the inner script."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "svg_blob_redirect.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0
    assert analysis.error is None

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    # one for the deobfuscated trace, one for the extracted blob payload
    assert len(file_observables) == 2

    deob_obs = next(o for o in file_observables if o.file_name.startswith(DEOBFUSCATED_PREFIX))
    blob_obs = next(o for o in file_observables if o.file_name.endswith(".blob_0.html"))

    with open(deob_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "new Blob(" in body
    assert "https://evil.example.com/login" in body

    # The blob payload must be the raw decoded HTML — html_js_extraction
    # gates on extension (.html / .svg / .htm), so the trailing `.html`
    # part of the filename is what makes the recursion work end-to-end.
    assert blob_obs.file_name.endswith(".html")
    with open(blob_obs.full_path, "r", encoding="utf-8") as fp:
        blob_body = fp.read()
    assert blob_body == '<a href="https://evil.example.com/login">click</a>'
    assert blob_obs.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert blob_obs.has_relationship(R_EXTRACTED_FROM)


@pytest.mark.unit
def test_blob_extracts_svg_and_js_mime_types(tmpdir, monkeypatch, patched_deobfuscate):
    """Beyond text/html, image/svg+xml and text/javascript blobs should be
    materialized too — those are the next-most-common MIME types in
    SVG-redirect and Function-ctor staging samples."""
    sample_path = tmpdir / "multi_blob.js"
    sample_path.write(
        "var _svg = new Blob(['<svg><script>x=1</script></svg>'], {type:'image/svg+xml'});\n"
        "var _js = new Blob(['document.location.href=\"https://evil.example.org/p\"'], {type:'text/javascript'});\n"
    )
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    blob_names = sorted(o.file_name for o in file_observables if ".blob_" in o.file_name)
    assert any(name.endswith(".blob_0.svg") for name in blob_names)
    assert any(name.endswith(".blob_1.js") for name in blob_names)


@pytest.mark.unit
def test_harness_crash_still_emits_observable(tmpdir, monkeypatch):
    """When the sandbox harness crashes partway through, the analyzer should
    still emit the deobfuscated-<name> observable carrying analysis.error."""
    import json as _json

    def _crashing_shim(file_path, output_dir, is_async=False, timeout=60, scanner_timeout=30):
        os.makedirs(output_dir, exist_ok=True)
        out_js = os.path.join(output_dir, "deobfuscated.js")
        with open(out_js, "w") as fp:
            fp.write(
                "// ACE3 javascript deobfuscator -- reconstructed from sandbox trace\n"
                "// partial capture before crash\n"
                "// run error: TypeError: this[<obfuscated>] is not a function\n"
            )
        with open(os.path.join(output_dir, "std.out"), "w") as fp:
            fp.write("")
        with open(os.path.join(output_dir, "std.err"), "w") as fp:
            fp.write("")
        with open(os.path.join(output_dir, "exit.code"), "w") as fp:
            fp.write("0")
        with open(os.path.join(output_dir, "report.json"), "w") as fp:
            _json.dump({
                "status": "error_during_run",
                "event_count": 0,
                "secondary_script_count": 0,
                "error": "TypeError: this[<obfuscated>] is not a function at evalmachine.<anonymous>:1:639",
            }, fp)
        return [
            os.path.join(output_dir, name)
            for name in ("deobfuscated.js", "std.out", "std.err", "exit.code", "report.json")
        ]

    monkeypatch.setattr(
        "saq.modules.file_analysis.js.deobfuscate_file",
        _crashing_shim,
    )

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    crash_src = tmpdir / "harness_crash_sample.js"
    crash_src.write('var x = 1; app.unknown_method();')
    observable = root.add_file_observable(str(crash_src))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error and "not a function" in analysis.error
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    assert emitted_obs.has_directive(DIRECTIVE_EXTRACT_URLS)


@pytest.mark.unit
def test_deobfuscator_error_does_not_crash(datadir, monkeypatch):
    """If the celery client raises, the analyzer should record the error
    and return COMPLETED without a derived file observable."""
    def _exploding(*args, **kwargs):
        raise RuntimeError("simulated manager unavailable")
    monkeypatch.setattr("saq.modules.file_analysis.js.deobfuscate_file", _exploding)

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "plain.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error and "simulated manager unavailable" in analysis.error
    assert [o for o in analysis.observables if o.type == F_FILE] == []


@pytest.mark.unit
def test_js_extension_triggers_without_yara_tag(tmpdir, monkeypatch, patched_deobfuscate):
    """A .js file without the yara meta tag (e.g. manually uploaded) should
    still be deobfuscated, and the tag should be added to the source
    observable on success."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    manual_upload = tmpdir / "uploaded_sample.js"
    manual_upload.write('window.location.href = "https://example.com/manual";')
    observable = root.add_file_observable(str(manual_upload))
    # deliberately NOT adding the yara meta directive — .js extension is enough

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0
    # the source observable should now have the yara meta tag applied
    assert observable.has_directive(YARA_META_JS)


@pytest.mark.unit
def test_skipped_without_tag_or_js_extension(tmpdir, monkeypatch, patched_deobfuscate):
    """Files without the yara meta tag AND without a .js extension should be
    skipped entirely — no analysis created."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    txt_path = tmpdir / "notes.txt"
    txt_path.write("just some plain text")
    observable = root.add_file_observable(str(txt_path))

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis) is None


@pytest.mark.unit
def test_empty_file_is_skipped(tmpdir, monkeypatch, patched_deobfuscate):
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    empty_path = tmpdir / "empty.js"
    empty_path.write("")
    observable = root.add_file_observable(str(empty_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis) is None


@pytest.mark.unit
def test_own_output_is_not_reanalyzed(tmpdir, monkeypatch, patched_deobfuscate):
    """Files whose name already starts with the deobfuscated- prefix
    (i.e. our own output) must not recurse."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    out_path = tmpdir / f"{DEOBFUSCATED_PREFIX}already.js"
    out_path.write("const x = 1;")
    observable = root.add_file_observable(str(out_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis) is None


def _deobfuscated_body(analysis):
    """Read back the deobfuscated trace emitted for an analysis."""
    deob_obs = next(
        o for o in analysis.observables
        if o.type == F_FILE and o.file_name.startswith(DEOBFUSCATED_PREFIX)
    )
    with open(deob_obs.full_path, "r", encoding="utf-8") as fp:
        return fp.read()


@pytest.mark.unit
def test_textdecoder_xor_eval_payload_is_captured(datadir, monkeypatch, patched_deobfuscate):
    """atob -> XOR -> TextDecoder -> eval staging must reach the payload.

    TextDecoder is a REAL implementation in the sandbox, not a recorder, and
    this test pins both ways that can regress:

      - Removed entirely -> ReferenceError, analysis.error is set, no events.
      - Added to the recorder list instead -> .decode() returns a Proxy,
        eval() silently no-ops, and there is NO error -- just zero events and
        no URL. That failure is invisible unless we assert on the payload.

    The error assertion alone would not catch the recorder case, which is the
    more tempting fix. Both assertions are load-bearing.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "textdecoder_xor_eval.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0
    # catches TextDecoder missing (ReferenceError)
    assert analysis.error is None
    assert analysis.error_type is None
    # catches TextDecoder stubbed as a recorder (no error, but nothing decoded)
    assert analysis.event_count > 0
    assert "https://example.com/second-stage" in _deobfuscated_body(analysis)


@pytest.mark.unit
def test_textencoder_roundtrip_is_real(tmpdir, monkeypatch, patched_deobfuscate):
    """TextEncoder must return real bytes, not a recorder Proxy.

    The URL is assembled from the encoded byte LENGTH rather than written as a
    literal. That matters: a recorder Proxy records its arguments, so any URL
    passed straight into encode() would show up in the trace verbatim and the
    test would pass without a single byte being encoded. Deriving the host from
    _u8.length can only produce "7" if encode() really returned 7 bytes.
    """
    sample_path = tmpdir / "textencoder_roundtrip.js"
    sample_path.write(
        'var _u8 = new TextEncoder().encode("abcdefg");\n'
        'window.location.href = "https://example.com/" + _u8.length'
        ' + "/" + new TextDecoder().decode(_u8);\n'
    )
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert "https://example.com/7/abcdefg" in _deobfuscated_body(analysis)


@pytest.mark.unit
def test_domready_deferred_payload_is_fired(datadir, monkeypatch, patched_deobfuscate):
    """A payload deferred to DOMContentLoaded must still execute.

    There is no event loop in the sandbox, so the harness fires DOM-ready
    listeners itself once the main script finishes. Without that the listener
    body never runs and its URL never reaches the trace -- and, like the
    recorder case above, it fails silently with no error.

    The fixture defines the URL AFTER registering the handler, which also pins
    the ordering: firing at registration time instead of after the script would
    read an undefined binding.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "domready_deferred_payload.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert "https://example.com/deferred-stage.js" in _deobfuscated_body(analysis)


@pytest.mark.unit
def test_jquery_ready_payload_is_fired(datadir, monkeypatch, patched_deobfuscate):
    """A payload wrapped in `$(document).ready(...)` must execute.

    jQuery is not loaded in the sandbox, so an undefined `$` throws
    "ReferenceError: $ is not defined" at the top of the payload and the run
    dies with zero events -- the exact production failure this pins. `$` is a
    REAL implementation, not a recorder: a recorder would record the .ready()
    call but never fire the handler, so the payload would vanish with no error.

    Both assertions are load-bearing, mirroring the TextDecoder/DOM-ready tests:
      - error is None catches the ReferenceError regression (`$` undefined).
      - the URLs catch the ready handler not firing (recorder-only regression):
        the POST target, the harvested form `action`, and the deferred redirect
        must all reach the trace.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "jquery_ready_payload.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    # catches the "ReferenceError: $ is not defined" regression
    assert analysis.error is None
    assert analysis.error_type is None
    # catches the ready handler not firing (jQuery stubbed as a bare recorder)
    body = _deobfuscated_body(analysis)
    assert "https://example.com/jquery-collect" in body
    assert "https://example.com/jquery-harvest" in body
    assert "https://example.com/jquery-ready-stage.js" in body


@pytest.mark.unit
def test_async_ready_handler_rejection_does_not_discard_output(datadir, monkeypatch, patched_deobfuscate):
    """An async `$(document).ready` handler that throws after an await must not
    crash the harness.

    The handler's rejected continuation is an unhandled promise rejection;
    Node's default terminates the process with a non-zero exit AFTER the trace
    and report are written, and the client (js.py) discards any result whose
    exit code is non-zero. So a rejecting async payload would silently throw
    away an otherwise-complete deobfuscation. Both assertions are load-bearing:

      - exit_code == 0 catches the process-crash regression (output discarded).
      - the post-await URL catches the event-loop drain not running, which is
        the only reason a payload staged after `await` reaches the trace.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "jquery_async_ready_payload.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    # the async rejection must not surface as a harness failure
    assert analysis.exit_code == 0
    assert analysis.error is None
    # a derived observable must be emitted (not discarded)
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    body = _deobfuscated_body(analysis)
    # pre-await exfil call
    assert "https://example.com/async-c2-pre" in body
    # post-await exfil call -- only present if the event loop was drained
    assert "https://example.com/async-c2-post" in body


@pytest.mark.unit
def test_bare_global_addeventlistener_is_defined(datadir, monkeypatch, patched_deobfuscate):
    """`addEventListener(...)` as a bare global, not `window.addEventListener`.

    The window recorder does not provide the bare global form -- it is its own
    global -- so without it the sample dies on ReferenceError before reaching its
    payload, the same failure mode as a missing TextDecoder. Obfuscated samples
    use the bare form routinely, sometimes alongside the qualified one.

    The DOM-ready hook must fire for the bare form too, or the deferred payload
    never runs and its URL never reaches the trace.
    """
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "bare_addeventlistener.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    # catches the ReferenceError regression
    assert analysis.error is None
    assert analysis.error_type is None
    # catches the DOM-ready hook not being wired to the bare form
    assert "https://example.com/bare-global-stage.js" in _deobfuscated_body(analysis)


@pytest.mark.unit
def test_runtime_error_still_tags_source_as_javascript(tmpdir, monkeypatch, patched_deobfuscate):
    """A sample that parses and then dies mid-run is still JavaScript.

    error_type == "runtime" means the source compiled, so the js tag must be
    applied -- that is precisely when we want downstream extraction to run.
    """
    sample_path = tmpdir / "runtime_error.js"
    # parses fine; blows up on a global the sandbox deliberately doesn't stub
    sample_path.write('var x = SomeUndefinedGlobal.doThing();\n')
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error is not None
    assert analysis.error_type == "runtime"
    assert observable.has_directive(YARA_META_JS)


@pytest.mark.unit
def test_parse_error_does_not_tag_source_as_javascript(tmpdir, monkeypatch, patched_deobfuscate):
    """A source that never parsed is NOT JavaScript and must not be tagged.

    This is the counterweight to the test above: the two failures are only
    distinguishable because the harness compiles and runs as separate steps.
    """
    sample_path = tmpdir / "not_really.js"
    sample_path.write("This is prose, not JavaScript <<< >>>\n")
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error is not None
    assert analysis.error_type == "compile"
    assert not observable.has_directive(YARA_META_JS)


@pytest.mark.unit
def test_legacy_report_without_error_type_does_not_tag(tmpdir, monkeypatch):
    """An errored report with no error_type must not tag the source.

    A scanner image predating error_type reporting (version skew mid-rollout)
    gives us no way to tell a parse failure from a runtime one, so the
    conservative pre-existing behavior has to hold rather than defaulting to
    "tag it".
    """
    import json as _json

    def _legacy_shim(file_path, output_dir, is_async=False, timeout=60, scanner_timeout=30):
        os.makedirs(output_dir, exist_ok=True)
        out_js = os.path.join(output_dir, "deobfuscated.js")
        with open(out_js, "w") as fp:
            fp.write("// trace\n")
        # note: no error_type key at all, as an older harness would emit
        report = {"status": "error_during_run", "event_count": 0, "error": "boom"}
        with open(os.path.join(output_dir, "report.json"), "w") as fp:
            _json.dump(report, fp)
        with open(os.path.join(output_dir, "exit.code"), "w") as fp:
            fp.write("0")
        return [out_js, os.path.join(output_dir, "report.json"), os.path.join(output_dir, "exit.code")]

    monkeypatch.setattr("saq.modules.file_analysis.js.deobfuscate_file", _legacy_shim)

    sample_path = tmpdir / "legacy_report.js"
    sample_path.write("var x = 1;\n")
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error_type is None
    assert not observable.has_directive(YARA_META_JS)


@pytest.mark.unit
def test_webcrack_status_is_surfaced(tmpdir, monkeypatch, patched_deobfuscate):
    """webcrack's static-pass status must reach the analysis.

    The dynamic sandbox does the real work, so a failing static pass degrades
    the result rather than invalidating it -- but it was previously dropped on
    the floor entirely, making a systematically failing pre-pass invisible.

    Note: every test here shares one root storage directory and the suite runs
    in random order, so this uses its own uniquely-named source. Reusing
    another test's fixture name makes whichever test runs second collide on
    the deobfuscated- output path and emit nothing.
    """
    # name deliberately free of the word "webcrack": the summary echoes the
    # emitted filename, which would satisfy the assertion below for free.
    sample_path = tmpdir / "static_pass_skipped.js"
    sample_path.write('window.location.href = "https://example.com/wc";\n')
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    # webcrack ships only in the scanner image, so under the node shim the
    # static pass never runs and reports "skipped". A pass that did not run is
    # not a pass that failed -- the harness must not conflate the two, and a
    # missing dependency must not surface to the analyst as a per-sample fault.
    assert analysis.webcrack_status is not None
    assert not analysis.webcrack_failed
    assert analysis.webcrack_error is None
    # a healthy pass must not clutter the analyst-facing summary
    assert "webcrack" not in (analysis.generate_summary() or "")


@pytest.mark.unit
def test_webcrack_failure_is_reported_in_summary(tmpdir, monkeypatch, patched_deobfuscate):
    """A failing static pass must be visible to the analyst.

    Driving a real webcrack failure needs a specific obfuscator variant, so
    this stubs the report instead -- the point under test is the module's
    handling, not webcrack's matchers.
    """
    import json as _json

    def _webcrack_failed_shim(file_path, output_dir, is_async=False, timeout=60, scanner_timeout=30):
        os.makedirs(output_dir, exist_ok=True)
        out_js = os.path.join(output_dir, "deobfuscated.js")
        with open(out_js, "w") as fp:
            fp.write('// trace\nwindow.location.href = "https://example.com/wcf";\n')
        report = {
            "status": "ok",
            "event_count": 1,
            "secondary_script_count": 0,
            "error": None,
            "error_type": None,
            "webcrack_status": "failed: _0xabcd is not defined",
            "webcrack_error": "_0xabcd is not defined",
            "blob_files": [],
        }
        with open(os.path.join(output_dir, "report.json"), "w") as fp:
            _json.dump(report, fp)
        with open(os.path.join(output_dir, "exit.code"), "w") as fp:
            fp.write("0")
        return [out_js, os.path.join(output_dir, "report.json"), os.path.join(output_dir, "exit.code")]

    monkeypatch.setattr("saq.modules.file_analysis.js.deobfuscate_file", _webcrack_failed_shim)

    sample_path = tmpdir / "webcrack_failed.js"
    sample_path.write('window.location.href = "https://example.com/wcf";\n')
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.webcrack_failed
    assert analysis.webcrack_error == "_0xabcd is not defined"
    # the dynamic pass still did its job, so this stays a success summary --
    # just one that admits the static pass degraded
    summary = analysis.generate_summary()
    assert "webcrack failed" in summary
    assert "extracted" in summary


# ---------------------------------------------------------------------------
# DOM snapshot sidecar -- resolving document lookups against real element data.
#
# html_js_extraction writes a `<script>.dom.json` snapshot beside each extracted
# script; the harness discovers it at `INPUT_PATH + '.dom.json'`. Because the
# node shim above runs the harness on the observable's full_path, these tests
# just drop the sidecar next to it and let the convention resolve.
# ---------------------------------------------------------------------------

def _charcode_snapshot(url, token):
    """A snapshot modeling the SVG phish: a <metadata> element whose data-*
    attributes encode the URL (comma-separated char codes) and an appended
    base64 token, plus the button the click handler is registered on."""
    codes = ",".join(str(ord(c)) for c in url)
    return {
        "version": 1,
        "truncated": False,
        "elements": [
            {"tag": "metadata", "attrs": {"id": "cb0705c", "data-u7fb": codes, "data-token": token}},
            {"tag": "button", "attrs": {"id": "b47c467", "type": "button"}, "text": "View Document"},
        ],
    }


def _write_sidecar(observable, snapshot):
    with open(observable.full_path + ".dom.json", "w", encoding="utf-8") as fp:
        json.dump(snapshot, fp, separators=(",", ":"))


@pytest.mark.unit
def test_dom_snapshot_recovers_charcode_click_url(datadir, monkeypatch, patched_deobfuscate):
    """With the snapshot present, the click-gated redirect built from data-*
    attributes must decode to the real URL in the trace -- the whole point of
    the fix. Without it (next test) the URL is structurally unreachable."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "svg_charcode_click.js")
    observable.add_directive(YARA_META_JS)
    _write_sidecar(observable, _charcode_snapshot("https://example.com", "dG9rZW4="))

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error_type is None
    assert analysis.dom_snapshot is True

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    with open(file_observables[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    # the decoded URL with the appended token, in clear text for URL extraction
    assert "https://example.com/dG9rZW4=" in body
    # and NOT the recorder placeholder that proves the lookup returned a stub
    assert "[document.getElementById" not in body


@pytest.mark.unit
def test_charcode_click_without_snapshot_loses_url(datadir, tmpdir, monkeypatch, patched_deobfuscate):
    """The same script with no snapshot: the run must not crash, but the URL is
    unreachable. This pins that the snapshot is load-bearing, not incidental."""
    # Uniquely-named copy: every test shares one root storage dir, so reusing the
    # recovery test's fixture name would collide on the deobfuscated- output path
    # (see the note on test_webcrack_status_is_surfaced).
    with open(datadir / "svg_charcode_click.js", "r", encoding="utf-8") as fp:
        source = fp.read()
    sample_path = tmpdir / "svg_charcode_noshot.js"
    sample_path.write(source)
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)
    # deliberately no sidecar

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error_type is None  # no crash
    assert analysis.dom_snapshot is False

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    with open(file_observables[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com" not in body


@pytest.mark.unit
def test_dom_snapshot_onclick_property_assignment_fires(tmpdir, monkeypatch, patched_deobfuscate):
    """`el.onclick = fn` handler assignment (no addEventListener) must also fire
    against the snapshot-backed element."""
    sample_path = tmpdir / "onclick_assign.js"
    sample_path.write(
        'var el = document.getElementById("cta");\n'
        'el.onclick = function () { top.location = el.getAttribute("data-dest"); };\n'
    )
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)
    _write_sidecar(observable, {
        "version": 1, "truncated": False,
        "elements": [{"tag": "a", "attrs": {"id": "cta", "data-dest": "https://example.com/onclick"}}],
    })

    analyzer = _build_analyzer(root)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    with open(file_observables[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com/onclick" in body


@pytest.mark.unit
def test_dom_snapshot_dataset_and_queryselector(tmpdir, monkeypatch, patched_deobfuscate):
    """dataset access and querySelector('#id') must both resolve to real values
    from the snapshot."""
    sample_path = tmpdir / "dataset_qs.js"
    sample_path.write(
        'var el = document.querySelector("#host");\n'
        'top.location = "https://" + el.dataset.host + "/p";\n'
    )
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)
    _write_sidecar(observable, {
        "version": 1, "truncated": False,
        "elements": [{"tag": "span", "attrs": {"id": "host", "data-host": "example.com"}}],
    })

    analyzer = _build_analyzer(root)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    with open(file_observables[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com/p" in body


@pytest.mark.unit
def test_dom_snapshot_template_content_split_url(datadir, monkeypatch, patched_deobfuscate):
    """The HTML-attachment variant of the split-URL phish: scheme and host
    prefix in a hidden div's data-* attributes, one piece of the host inside a
    <template>, the rest in a hidden <span>, joined on click. The script reads
    each text piece through `el.content ? el.content.textContent : el.textContent`,
    so `.content` must be a real fragment on the <template> and falsy on the
    <span> -- a recorder for either leaves a `[#id.content.textContent]`
    placeholder in the middle of the URL."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "template_content_split_url.js")
    observable.add_directive(YARA_META_JS)
    _write_sidecar(observable, {
        "version": 1, "truncated": False,
        "elements": [
            {"tag": "div", "attrs": {"id": "cf7be89", "hidden": "", "data-pce": "http", "data-q8e": "s:",
                                     "data-rbb": "//exam", "data-token": "#dG9rZW4="}},
            {"tag": "template", "attrs": {"id": "tb3360d"}, "text": "ple"},
            {"tag": "span", "attrs": {"id": "nbd0085", "hidden": ""}, "text": ".com"},
            {"tag": "button", "attrs": {"id": "b5453af", "type": "button"}, "text": "Open File"},
        ],
    })

    analyzer = _build_analyzer(root)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis.error_type is None
    assert analysis.dom_snapshot is True
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    with open(file_observables[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert 'href = "https://example.com#dG9rZW4="' in body
    assert ".content.textContent]" not in body


@pytest.mark.unit
def test_malformed_dom_snapshot_is_ignored(tmpdir, monkeypatch, patched_deobfuscate):
    """A corrupt sidecar must not fail the run; the harness falls back to
    recorder behavior (dom_snapshot False)."""
    sample_path = tmpdir / "malformed_sidecar.js"
    sample_path.write('window.location.href = "https://example.com/ok";\n')
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(str(sample_path))
    observable.add_directive(YARA_META_JS)
    with open(observable.full_path + ".dom.json", "w", encoding="utf-8") as fp:
        fp.write("{ this is not json")

    analyzer = _build_analyzer(root)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error_type is None
    assert analysis.dom_snapshot is False
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    with open(file_observables[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com/ok" in body


@pytest.mark.unit
def test_html_extraction_to_deobfuscation_chain(tmpdir, monkeypatch, patched_deobfuscate):
    """End-to-end: the extractor writes the sidecar and the deobfuscator consumes
    it, with no manual sidecar placement. Proves the two halves agree on the
    `<script>.dom.json` convention."""
    from saq.configuration.config import get_analysis_module_config as _gc
    from saq.constants import ANALYSIS_MODULE_HTML_JS_EXTRACTION
    from saq.modules.file_analysis.html_js_extraction import (
        HTMLJavaScriptExtractionAnalysis,
        HTMLJavaScriptExtractor,
    )

    codes = ",".join(str(ord(c)) for c in "https://example.com")
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<button id="b47c467" type="button">Open</button>'
        f'<metadata id="cb0705c" data-u7fb="{codes}" data-token="dG9rZW4="></metadata>'
        '<script type="text/javascript"><![CDATA['
        'function go(){var el=document.getElementById("cb0705c");'
        'var raw=el.getAttribute("data-u7fb").split(","),o="",i;'
        'for(i=0;i<raw.length;i++)o+=String.fromCharCode(+raw[i]);'
        'top.location=o.replace(/\\/$/,"")+"/"+el.getAttribute("data-token");}'
        'var b=document.getElementById("b47c467");b.addEventListener("click",go);'
        ']]></script></svg>'
    )
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    svg_path = root.create_file_path("chain.svg")
    with open(svg_path, "w") as fp:
        fp.write(svg)
    svg_obs = root.add_file_observable(svg_path)

    extractor = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=create_test_context(root=root),
        config=_gc(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    extractor.root = root
    assert extractor.execute_analysis(svg_obs) == AnalysisExecutionResult.COMPLETED

    ext_analysis = svg_obs.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    extracted_js = [o for o in ext_analysis.observables if o.type == F_FILE]
    assert len(extracted_js) == 1
    js_obs = extracted_js[0]
    assert os.path.exists(js_obs.full_path + ".dom.json")

    deob = _build_analyzer(root)
    assert deob.execute_analysis(js_obs) == AnalysisExecutionResult.COMPLETED
    deob_analysis = js_obs.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert deob_analysis.dom_snapshot is True

    emitted = [o for o in deob_analysis.observables if o.type == F_FILE]
    with open(emitted[0].full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com/dG9rZW4=" in body
