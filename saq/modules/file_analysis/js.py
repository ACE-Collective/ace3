import json
import logging
import os
import shutil

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import (
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_YARA_META_PREFIX,
    F_FILE,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.js_deobfuscator import deobfuscate_file
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable
from saq.util.filesystem import create_temporary_directory
from saq.util.strings import format_item_list_for_summary

DEOBFUSCATED_PREFIX = "deobfuscated-"


class JavaScriptDeobfuscationAnalysis(Analysis):

    KEY_EXTRACTED_FILES = "extracted_files"
    KEY_STDOUT = "stdout"
    KEY_STDERR = "stderr"
    KEY_EXIT_CODE = "exit_code"
    KEY_EVENT_COUNT = "event_count"
    KEY_SECONDARY_SCRIPT_COUNT = "secondary_script_count"
    KEY_ERROR = "error"
    # "compile" (the source never parsed, so it is not JavaScript), "runtime"
    # (it parsed and failed mid-execution, so it IS JavaScript), or None.
    KEY_ERROR_TYPE = "error_type"
    KEY_WEBCRACK_STATUS = "webcrack_status"
    KEY_WEBCRACK_ERROR = "webcrack_error"
    # True when a DOM snapshot sidecar was present and used to back document
    # lookups during the run (see html_js_extraction). Useful when triaging why
    # a data-* attribute payload did or did not decode.
    KEY_DOM_SNAPSHOT = "dom_snapshot"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            JavaScriptDeobfuscationAnalysis.KEY_EXTRACTED_FILES: [],
            JavaScriptDeobfuscationAnalysis.KEY_STDOUT: None,
            JavaScriptDeobfuscationAnalysis.KEY_STDERR: None,
            JavaScriptDeobfuscationAnalysis.KEY_EXIT_CODE: None,
            JavaScriptDeobfuscationAnalysis.KEY_EVENT_COUNT: 0,
            JavaScriptDeobfuscationAnalysis.KEY_SECONDARY_SCRIPT_COUNT: 0,
            JavaScriptDeobfuscationAnalysis.KEY_ERROR: None,
            JavaScriptDeobfuscationAnalysis.KEY_ERROR_TYPE: None,
            JavaScriptDeobfuscationAnalysis.KEY_WEBCRACK_STATUS: None,
            JavaScriptDeobfuscationAnalysis.KEY_WEBCRACK_ERROR: None,
            JavaScriptDeobfuscationAnalysis.KEY_DOM_SNAPSHOT: False,
        }

    @property
    def extracted_files(self):
        if self.details is None:
            return []
        return self.details.get(JavaScriptDeobfuscationAnalysis.KEY_EXTRACTED_FILES, [])

    @property
    def stdout(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_STDOUT)

    @stdout.setter
    def stdout(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_STDOUT] = value

    @property
    def stderr(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_STDERR)

    @stderr.setter
    def stderr(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_STDERR] = value

    @property
    def exit_code(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_EXIT_CODE)

    @exit_code.setter
    def exit_code(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_EXIT_CODE] = value

    @property
    def event_count(self):
        return 0 if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_EVENT_COUNT, 0)

    @event_count.setter
    def event_count(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_EVENT_COUNT] = value

    @property
    def secondary_script_count(self):
        return 0 if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_SECONDARY_SCRIPT_COUNT, 0)

    @secondary_script_count.setter
    def secondary_script_count(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_SECONDARY_SCRIPT_COUNT] = value

    @property
    def error(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_ERROR)

    @error.setter
    def error(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_ERROR] = value

    @property
    def error_type(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_ERROR_TYPE)

    @error_type.setter
    def error_type(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_ERROR_TYPE] = value

    @property
    def webcrack_status(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_WEBCRACK_STATUS)

    @webcrack_status.setter
    def webcrack_status(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_WEBCRACK_STATUS] = value

    @property
    def webcrack_error(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_WEBCRACK_ERROR)

    @webcrack_error.setter
    def webcrack_error(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_WEBCRACK_ERROR] = value

    @property
    def dom_snapshot(self):
        return False if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_DOM_SNAPSHOT, False)

    @dom_snapshot.setter
    def dom_snapshot(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_DOM_SNAPSHOT] = value

    @property
    def webcrack_failed(self) -> bool:
        """True when the static pre-pass errored out. The dynamic sandbox still
        runs and does the real work, so this degrades the result rather than
        invalidating it -- but it is otherwise invisible to an analyst."""
        return (self.webcrack_status or "").startswith("failed")

    def generate_summary(self) -> str:
        if not self.details:
            return None
        if self.error:
            return f"JavaScript Deobfuscation: failed: {self.error}"
        if self.exit_code != 0 or not self.extracted_files:
            return None
        summary = (
            "JavaScript Deobfuscation: extracted "
            + format_item_list_for_summary(self.extracted_files)
            + f" ({self.event_count} events, {self.secondary_script_count} secondary scripts)"
        )
        # only mentioned when it failed -- a working static pass is unremarkable
        # and shouldn't cost the analyst any summary width.
        if self.webcrack_failed:
            summary += f" (webcrack {self.webcrack_status})"
        return summary


class JavaScriptDeobfuscationAnalyzerConfig(AnalysisModuleConfig):
    scanner_timeout: int = Field(
        default=30,
        description="Wall-clock limit (seconds) for a single scanner container invocation.",
    )
    celery_timeout: int = Field(
        default=60,
        description="Wall-clock limit (seconds) to wait on the celery manager for a result.",
    )


class JavaScriptDeobfuscationAnalyzer(AnalysisModule):
    """Runs obfuscated JavaScript in a throwaway scanner container whose
    sandbox harness traces every write to a browser global, and emits a
    reconstructed file observable marked for URL extraction and crawling.

    The actual execution happens in the ``js-deobfuscator`` service, which
    spawns a sibling ``js-deobfuscator`` image per scan via
    ``docker run --rm --network none``. This module is just a client.
    """

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return JavaScriptDeobfuscationAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return JavaScriptDeobfuscationAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path

        # run on files tagged as JavaScript by upstream extraction modules
        # (html_js_extraction, pdf, ole, etc.) OR files with a .js extension
        # (covers manually uploaded JS files that have no upstream tagger)
        has_js_tag = _file.has_directive(f"{DIRECTIVE_YARA_META_PREFIX}type=script.javascript")
        if not has_js_tag and not _file.file_name.endswith(".js"):
            return AnalysisExecutionResult.COMPLETED

        # don't re-analyze our own output
        if _file.file_name.startswith(DEOBFUSCATED_PREFIX):
            return AnalysisExecutionResult.COMPLETED

        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag("js")

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, JavaScriptDeobfuscationAnalysis)

        # temp directory on the ACE side where result files will be copied
        # back from the shared ace-js-deobfuscator volume
        scratch_dir = create_temporary_directory()

        try:
            result_files = deobfuscate_file(
                local_file_path,
                scratch_dir,
                is_async=False,
                timeout=self.config.celery_timeout,
                scanner_timeout=self.config.scanner_timeout,
            )
        except Exception as e:
            analysis.error = f"js deobfuscator call failed: {e}"
            logging.warning(f"js deobfuscator failed for {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        # parse std.out / std.err / exit.code / report.json and pick out
        # the deobfuscated.js file
        deobfuscated_src = None
        blob_filenames: list[str] = []
        result_by_basename = {os.path.basename(p): p for p in result_files}
        for result_file in result_files:
            basename = os.path.basename(result_file)
            if basename == "std.out":
                with open(result_file, "r", errors="replace") as fp:
                    analysis.stdout = fp.read()
            elif basename == "std.err":
                with open(result_file, "r", errors="replace") as fp:
                    analysis.stderr = fp.read()
            elif basename == "exit.code":
                try:
                    with open(result_file, "r") as fp:
                        analysis.exit_code = int(fp.read().strip() or "0")
                except ValueError:
                    analysis.exit_code = None
            elif basename == "report.json":
                try:
                    with open(result_file, "r") as fp:
                        report = json.load(fp)
                    analysis.event_count = int(report.get("event_count", 0) or 0)
                    analysis.secondary_script_count = int(report.get("secondary_script_count", 0) or 0)
                    if report.get("error"):
                        analysis.error = report["error"]
                    analysis.error_type = report.get("error_type")
                    analysis.webcrack_status = report.get("webcrack_status")
                    analysis.webcrack_error = report.get("webcrack_error")
                    analysis.dom_snapshot = bool(report.get("dom_snapshot", False))
                    if analysis.webcrack_failed:
                        logging.info(
                            f"js deobfuscator webcrack static pass failed for "
                            f"{local_file_path}: {analysis.webcrack_error}"
                        )
                    blob_filenames = [
                        b for b in (report.get("blob_files") or [])
                        if isinstance(b, str)
                    ]
                except (OSError, json.JSONDecodeError) as e:
                    logging.debug(f"failed to read report.json from deobfuscator: {e}")
            elif basename == "deobfuscated.js":
                deobfuscated_src = result_file

        # tag the source as JavaScript so downstream modules (yara rules, url
        # extractor text/plain override) see it. a run error does not mean the
        # file isn't JavaScript: only a *parse* failure proves that. a sample
        # that parsed and then died mid-execution (e.g. ReferenceError on a
        # global the sandbox doesn't stub) is still JavaScript, and that is
        # exactly when we most want downstream extraction to run on it.
        #
        # an errored report with no error_type comes from a harness predating
        # that field (version skew mid-rollout), where we can't tell the two
        # apart -- stay conservative and don't tag.
        source_parsed = not analysis.error or analysis.error_type == "runtime"
        if analysis.exit_code == 0 and source_parsed and not has_js_tag:
            _file.add_yara_meta("type", "script.javascript")

        if analysis.exit_code != 0:
            logging.warning(
                f"js deobfuscator exit {analysis.exit_code} for {local_file_path}; stderr={analysis.stderr!r}"
            )
            return AnalysisExecutionResult.COMPLETED

        if not deobfuscated_src or not os.path.exists(deobfuscated_src):
            logging.debug(f"js deobfuscator produced no output file for {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # skip emission only when the harness finished cleanly with nothing to
        # show. if the sandbox crashed partway through we still want the
        # observable (and its analysis.error) so the analyst can see what
        # happened and any partial captures get URL-extracted.
        if os.path.getsize(deobfuscated_src) == 0:
            logging.debug(f"js deobfuscator produced empty output for {local_file_path}")
            return AnalysisExecutionResult.COMPLETED
        if analysis.event_count == 0 and not analysis.error:
            logging.debug(f"js deobfuscator produced no events for {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # rename into place next to the source file so the ACE file manager
        # picks up the new observable with a meaningful name
        target_dir = os.path.dirname(local_file_path)
        target_path = os.path.join(target_dir, f"{DEOBFUSCATED_PREFIX}{_file.file_name}")
        if os.path.exists(target_path):
            logging.warning(f"target file {target_path} already exists")
            return AnalysisExecutionResult.COMPLETED

        shutil.move(deobfuscated_src, target_path)

        o_file = analysis.add_file_observable(target_path, volatile=True)
        if o_file:
            o_file.add_relationship(R_EXTRACTED_FROM, _file)
            o_file.exclude_analysis(self)
            o_file.add_yara_meta("type", "script.javascript")
            o_file.add_directive(DIRECTIVE_EXTRACT_URLS)
            analysis.extracted_files.append(o_file.file_path)

        # Materialize any side-channel Blob payloads the harness wrote out
        # (text/html, image/svg+xml, text/javascript). Naming preserves the
        # blob's MIME-derived extension at the tail so html_js_extraction's
        # extension gate picks up .html / .svg blobs and JS deob recurses
        # into .js blobs naturally — no recursion limits needed beyond
        # ACE's existing analysis-tree depth.
        for blob_filename in blob_filenames:
            blob_src = result_by_basename.get(blob_filename)
            if not blob_src or not os.path.exists(blob_src):
                continue
            blob_target = os.path.join(target_dir, f"{_file.file_name}.{blob_filename}")
            if os.path.exists(blob_target):
                logging.debug(f"blob target {blob_target} already exists; skipping")
                continue
            shutil.move(blob_src, blob_target)
            blob_obs = analysis.add_file_observable(blob_target, volatile=True)
            if blob_obs:
                blob_obs.add_relationship(R_EXTRACTED_FROM, _file)
                blob_obs.add_directive(DIRECTIVE_EXTRACT_URLS)
                analysis.extracted_files.append(blob_obs.file_path)

        return AnalysisExecutionResult.COMPLETED
