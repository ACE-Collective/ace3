import json
import logging
import os
import re
import subprocess
from typing import Optional, List, Type, override
from urlfinderlib.url import URL

import yaml
from fluent import sender
from pydantic import Field
from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import ANALYSIS_MODE_CORRELATION, DIRECTIVE_CRAWL, DIRECTIVE_RENDER, F_URL, F_FILE, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis import FileTypeAnalysis, OCRAnalyzer
from saq.modules.tool_version import file_content_version
from saq.observables.file import FileObservable
from saq.phishkit import get_async_scan_result, get_phishkit_scanner_version, scan_file, scan_url
from saq.proxy import proxy_string_for_seleniumbase
from saq.util.filesystem import create_temporary_directory
from saq.util.strings import format_item_list_for_summary

FIELD_OUTPUT_DIR = "output_dir"
FIELD_JOB_ID = "job_id"
FIELD_SCAN_TYPE = "scan_type"
FIELD_SCAN_RESULT = "scan_result"
FIELD_OUTPUT_FILES = "output_files"
FIELD_ERROR = "error"
FIELD_EXIT_CODE = "exit_code"
FIELD_STDOUT = "stdout"
FIELD_STDERR = "stderr"
FIELD_METRICS = "metrics"
FIELD_PROXY_STATUS = "proxy_status"

SCAN_TYPE_URL = "url"
SCAN_TYPE_FILE = "file"

# Content types whose bodies we already capture verbatim (dom.html / requests.json). A screenshot
# of Chrome's plain-text rendering of these carries no information the raw body doesn't already
# have, so OCR of it can only add transcription error. Worse, running domain extraction over source
# code manufactures observables like "b.call" and "n.map" out of JavaScript method calls -- no OCR
# error required, since ".call" and ".map" are real gTLDs. This is a denylist rather than an
# allowlist: an unknown or missing content type falls back to running OCR.
OCR_SKIP_CONTENT_TYPES = frozenset([
    "application/javascript",
    "application/json",
    "application/x-javascript",
    "application/xml",
    "text/css",
    "text/javascript",
    "text/plain",
    "text/xml",
])

# scanner.py writes screenshot.png, pre_bypass_screenshot.png and pre_bypass_screenshot_iter{n}.png
SCREENSHOT_PREFIXES = ("screenshot.png", "pre_bypass_screenshot")


class PhishkitAnalysis(Analysis):
    """Analysis results from Phishkit scanning of URLs and files."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            FIELD_EXIT_CODE: None,
            FIELD_STDOUT: None,
            FIELD_STDERR: None,
            FIELD_OUTPUT_DIR: None,  # output directory for the scan
            FIELD_JOB_ID: None, # job ID for the scan
            FIELD_SCAN_TYPE: None,  # SCAN_TYPE_URL or SCAN_TYPE_FILE
            FIELD_SCAN_RESULT: None,  # result from phishkit scan
            FIELD_OUTPUT_FILES: [],  # list of output file paths
            FIELD_ERROR: None,  # error message if scan failed
            FIELD_METRICS: None,  # scan metrics (bytes downloaded, domain breakdown, etc.)
            FIELD_PROXY_STATUS: None,  # proxy usage / fallback info from the scanner worker
        }

    @override
    @property
    def display_name(self) -> str:
        return "Phishkit Analysis"

    @property
    def exit_code(self) -> Optional[int]:
        return self.details.get(FIELD_EXIT_CODE)
    
    @exit_code.setter
    def exit_code(self, value: int):
        self.details[FIELD_EXIT_CODE] = value
    
    @property
    def stdout(self) -> Optional[str]:
        return self.details.get(FIELD_STDOUT)
    
    @stdout.setter
    def stdout(self, value: str):
        self.details[FIELD_STDOUT] = value
    
    @property
    def stderr(self) -> Optional[str]:
        return self.details.get(FIELD_STDERR)
    
    @stderr.setter
    def stderr(self, value: str):
        self.details[FIELD_STDERR] = value

    @property
    def output_dir(self) -> Optional[str]:
        return self.details.get(FIELD_OUTPUT_DIR)

    @output_dir.setter
    def output_dir(self, value: str):
        self.details[FIELD_OUTPUT_DIR] = value

    @property
    def job_id(self) -> Optional[str]:
        return self.details.get(FIELD_JOB_ID)

    @job_id.setter
    def job_id(self, value: str):
        self.details[FIELD_JOB_ID] = value

    @property
    def scan_type(self) -> Optional[str]:
        return self.details.get(FIELD_SCAN_TYPE)

    @scan_type.setter
    def scan_type(self, value: str):
        self.details[FIELD_SCAN_TYPE] = value

    @property
    def scan_result(self) -> Optional[str]:
        return self.details.get(FIELD_SCAN_RESULT)

    @scan_result.setter
    def scan_result(self, value: str):
        self.details[FIELD_SCAN_RESULT] = value

    @property
    def output_files(self) -> List[str]:
        return self.details.get(FIELD_OUTPUT_FILES, [])

    @output_files.setter
    def output_files(self, value: List[str]):
        self.details[FIELD_OUTPUT_FILES] = value

    @property
    def error(self) -> Optional[str]:
        return self.details.get(FIELD_ERROR)

    @error.setter
    def error(self, value: str):
        self.details[FIELD_ERROR] = value

    @property
    def metrics(self) -> Optional[dict]:
        return self.details.get(FIELD_METRICS)

    @metrics.setter
    def metrics(self, value: dict):
        self.details[FIELD_METRICS] = value

    @property
    def proxy_status(self) -> Optional[dict]:
        return self.details.get(FIELD_PROXY_STATUS)

    @proxy_status.setter
    def proxy_status(self, value: dict):
        self.details[FIELD_PROXY_STATUS] = value

    def _is_unfinished(self) -> bool:
        # Job dispatched (scan_type + job_id set) but no result ever flowed back:
        # neither success fields nor an explicit error are populated. The engine's
        # delayed_analysis deadline fires asynchronously from the analyzer's POV
        # and never lets continue_analysis set error, so this is the only signal
        # an analyst gets that the scan was abandoned.
        return (
            self.job_id is not None
            and self.scan_type in (SCAN_TYPE_URL, SCAN_TYPE_FILE)
            and self.scan_result is None
            and self.exit_code is None
            and not self.output_files
            and not self.error
        )

    def generate_summary(self):
        if self.error:
            return f"{self.display_name}: failed: {self.error}"

        if self._is_unfinished():
            return f"{self.display_name}: scan timed out — no content captured"

        if self.scan_type == SCAN_TYPE_URL or self.scan_type == SCAN_TYPE_FILE:
            summary = f"{self.display_name}: output files created (" + format_item_list_for_summary(self.output_files) + ")"
            if (self.metrics and self.metrics.get("interrupted")) or self.exit_code == 143:
                summary += " - PARTIAL (scanner timed out)"
            if self.metrics and self.metrics.get("total_bytes_downloaded"):
                mb = self.metrics["total_bytes_downloaded"] / (1024 * 1024)
                summary += f" - {mb:.2f} MB downloaded"
            if self.proxy_status:
                route = self.proxy_status.get("final_route")
                if route == "proxy":
                    summary += " - fetched via proxy"
                elif route == "direct" and self.proxy_status.get("configured"):
                    reason = self.proxy_status.get("fallback_reason") or "unknown"
                    summary += f" - proxy failed ({reason}), fetched direct"
            return summary
        else:
            return f"{self.display_name}: completed"


class PhishkitAnalyzerConfig(AnalysisModuleConfig):
    valid_file_extensions: list[str] = Field(..., description="List of file extensions to enable for scanning.")
    valid_mime_types: list[str] = Field(..., description="List of mime types to enable for scanning.")
    fluent_bit_metrics_enabled: bool = Field(default=False, description="Whether to forward scan metrics to fluent-bit.")
    fluent_bit_hostname: str = Field(default="fluent-bit", description="Hostname of the fluent-bit server.")
    fluent_bit_port: int = Field(default=24224, description="Port of the fluent-bit forward input.")
    fluent_bit_metrics_tag: str = Field(default="phishkit-metrics", description="Tag for phishkit metrics events.")
    scanner_timeout: int = Field(default=15, description="Timeout in seconds for the phishkit scanner process.")
    proxy: Optional[str] = Field(default=None, description="Named proxy config to route scanner traffic through.")
    proxy_fallback_to_direct: bool = Field(default=True, description="If true, retry scan without proxy on proxy-related failures.")
    config_path: str = Field(default="etc/phishkit_config.yaml", description="Path to phishkit YAML config file, relative to SAQ_HOME.")

class PhishkitAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return PhishkitAnalyzerConfig

    """Analyzes URLs and files using Phishkit for phishing detection."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fluent_bit_metrics_sender: Optional[sender.FluentSender] = None
        if self.config.fluent_bit_metrics_enabled:
            self.fluent_bit_metrics_sender = sender.FluentSender(
                self.config.fluent_bit_metrics_tag,
                host=self.config.fluent_bit_hostname,
                port=self.config.fluent_bit_port,
            )

        # resolve named proxy config to a SeleniumBase-compatible proxy string
        self._proxy_string: Optional[str] = None
        if self.config.proxy:
            self._proxy_string = proxy_string_for_seleniumbase(self.config.proxy)
            if self._proxy_string:
                logging.info(f"phishkit analyzer using proxy: {self.config.proxy}")

        self._deny_crawl_patterns: list[str] = []
        self._yaml_config_path = os.path.join(get_base_dir(), self.config.config_path)
        self._load_deny_patterns()
        self.watch_file(self._yaml_config_path, self._load_deny_patterns)

    def _load_deny_patterns(self):
        """Load deny_crawl_url_patterns from the phishkit YAML config."""
        try:
            with open(self._yaml_config_path, "r") as fp:
                data = yaml.safe_load(fp) or {}
        except Exception as e:
            logging.warning(
                f"failed to load phishkit YAML config {self._yaml_config_path}: {e}"
            )
            self._deny_crawl_patterns = []
            return

        raw = data.get("deny_crawl_url_patterns", []) or []
        if not isinstance(raw, list):
            logging.error(
                f"invalid deny_crawl_url_patterns type in {self._yaml_config_path}: "
                f"expected list, got {type(raw).__name__}"
            )
            raw = []
        self._deny_crawl_patterns = [p.lower() for p in raw if isinstance(p, str) and p]
        logging.debug(
            f"loaded {len(self._deny_crawl_patterns)} phishkit deny_crawl_url_patterns"
        )

    @property
    def generated_analysis_type(self):
        return PhishkitAnalysis

    @property
    def valid_observable_types(self):
        return [F_URL, F_FILE]

    @property
    def extended_version(self) -> dict[str, str]:
        """Inputs (besides the observable value) that change scanner output,
        mixed into the cache key so a change invalidates stale entries.

        Two signals:
        - ``phishkit_config``: content hash of the scanner YAML (bypasses, deny
          patterns, body-skip rules, waits) — an analyst edit re-keys without a
          redeploy.
        - ``scanner_image``: the running scanner image's content id (``{{.Id}}``
          via ``scanner_image_id`` worker task).
        Each key is omitted on probe failure (accept staleness, bounded by the
        short ``cache_ttl``, over poisoning the key with a transient failure).
        The key is computed before the scan, so both inputs are statically
        derivable from local state — never from a scan result.
        """
        result: dict[str, str] = {}
        config_version = file_content_version(self._yaml_config_path)
        if config_version is not None:
            result["phishkit_config"] = config_version
        scanner = get_phishkit_scanner_version()
        if scanner.get("image_id"):
            result["scanner_image"] = scanner["image_id"]
        return result

    def custom_requirement(self, observable: Observable) -> bool:
        """Custom requirement for phishkit analysis.

        Note that the crawl/render directive gating lives here on purpose to
        allow observables to gain the crawl/render directives by other modules.
        """
        if observable.type == F_URL:
            # urls require crawl directives
            if not observable.has_directive(DIRECTIVE_CRAWL):
                return False
            url_lc = observable.value.lower()
            for pattern in self._deny_crawl_patterns:
                if pattern in url_lc:
                    logging.info(
                        f"phishkit refusing to scan {observable.value} - "
                        f"matched deny pattern {pattern!r}"
                    )
                    return False
            return True
        elif observable.type == F_FILE:
            # files require render directives
            if not observable.has_directive(DIRECTIVE_RENDER):
                return False
            # phishkit file rendering only meaningful in correlation mode
            if self.get_root().analysis_mode != ANALYSIS_MODE_CORRELATION:
                return False

            assert isinstance(observable, FileObservable)
            local_file_path = observable.full_path
            if not os.path.exists(local_file_path) or os.path.getsize(local_file_path) == 0:
                return False

            return self._file_scan_enabled(observable)
        else:
            return False

    def _file_scan_enabled(self, observable: FileObservable) -> bool:
        """True if this file's extension or (declared-dependency) FileTypeAnalysis
        mime type is enabled for phishkit scanning."""
        file_extension = os.path.splitext(observable.file_name)[1].lower()
        if file_extension in self.config.valid_file_extensions:
            return True

        file_type_analysis = observable.get_and_load_analysis(FileTypeAnalysis)
        return (
            file_type_analysis is not None
            and file_type_analysis.mime_type in self.config.valid_mime_types
        )

    def _redact_proxy_credentials(self, text: str) -> str:
        """Remove proxy credentials from text to prevent storage in analysis details."""
        if not text or not self._proxy_string or '@' not in self._proxy_string:
            return text
        before_at = self._proxy_string.rsplit('@', 1)[0]
        # strip scheme prefix (e.g. socks5://) to get raw user:pass
        if '://' in before_at:
            creds = before_at.split('://', 1)[1]
        else:
            creds = before_at
        if creds:
            return text.replace(creds, "****:****")
        return text

    def _emit_scan_outcome(self, observable: Observable, analysis: "PhishkitAnalysis", outcome: str) -> None:
        """Emit a scan-level outcome event to fluent-bit for proxy-reliability dashboards.

        outcome: "success" | "failed" | "scan_timeout"
        """
        if not self.fluent_bit_metrics_sender:
            return
        try:
            proxy_status = analysis.proxy_status or {}
            self.fluent_bit_metrics_sender.emit(None, {
                "event": "scan_outcome",
                "job_id": analysis.job_id,
                "scan_type": analysis.scan_type,
                "observable_value": observable.value,
                "outcome": outcome,
                "error": analysis.error,
                "exit_code": analysis.exit_code,
                "proxy_configured": proxy_status.get("configured"),
                "proxy_fallback_enabled": proxy_status.get("fallback_enabled"),
                "proxy_fallback_triggered": proxy_status.get("fallback_triggered"),
                "proxy_fallback_reason": proxy_status.get("fallback_reason"),
                "proxy_final_route": proxy_status.get("final_route"),
                "scan_duration_seconds": (analysis.metrics or {}).get("scan_duration_seconds"),
                "total_bytes_downloaded": (analysis.metrics or {}).get("total_bytes_downloaded"),
            })
        except Exception as e:
            logging.error(f"failed to send scan_outcome to fluent-bit for {observable}: {e}")

    def on_cache_hit(self, root, observable: Observable) -> None:
        """A cached PhishkitAnalysis was replayed instead of running a live scan.
        The replayed analysis carries the original scan's metrics, so emit a
        dedicated ``cache_served`` event recording exactly the bytes and scan
        time this cache hit avoided."""
        if not self.fluent_bit_metrics_sender:
            return

        analysis = observable.get_analysis(PhishkitAnalysis)
        if analysis is None:
            return

        metrics = analysis.metrics or {}
        try:
            self.fluent_bit_metrics_sender.emit(None, {
                "event": "cache_served",
                "job_id": analysis.job_id,
                "scan_type": analysis.scan_type,
                "observable_value": observable.value,
                "saved_bytes": metrics.get("total_bytes_downloaded"),
                "saved_duration_seconds": metrics.get("scan_duration_seconds"),
            })
        except Exception as e:
            logging.error(f"failed to send cache_served to fluent-bit for {observable}: {e}")

    def _emit_scan_dispatched(self, observable: Observable, analysis: "PhishkitAnalysis") -> None:
        """Emit a scan-dispatch event to fluent-bit. Pair with _emit_scan_outcome.

        Splunk can join scan_dispatched against scan_outcome on job_id; unmatched
        dispatched events imply the engine's delayed_analysis deadline fired before
        the scan completed (hard timeout, no analyzer-side callback).
        """
        if not self.fluent_bit_metrics_sender:
            return
        try:
            self.fluent_bit_metrics_sender.emit(None, {
                "event": "scan_dispatched",
                "job_id": analysis.job_id,
                "scan_type": analysis.scan_type,
                "observable_value": observable.value,
                "proxy_configured": bool(self._proxy_string),
                "proxy_fallback_enabled": self.config.proxy_fallback_to_direct,
            })
        except Exception as e:
            logging.error(f"failed to send scan_dispatched to fluent-bit for {observable}: {e}")

    def _top_level_content_type(self, output_dir: str) -> Optional[str]:
        """Returns the lowercased content type of the top-level response, or None if unknown.

        The screenshot is a rendering of the top-level document, which is the first non-redirect
        response logged in requests.json. Subresource responses follow it.
        """
        requests_path = os.path.join(output_dir, "requests.json")
        if not os.path.exists(requests_path):
            return None

        try:
            with open(requests_path, "r", errors="ignore") as fp:
                entries = json.load(fp)
        except Exception as e:
            logging.warning(f"failed to read requests.json at {requests_path}: {e}")
            return None

        if not isinstance(entries, list):
            return None

        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") != "response":
                continue

            # skip redirect hops -- the document is the response they land on
            status_code = entry.get("status_code")
            if isinstance(status_code, int) and 300 <= status_code < 400:
                continue

            headers = entry.get("headers")
            if not isinstance(headers, dict):
                return None

            # header casing varies between scanner versions and origins
            for name, value in headers.items():
                if name.lower() == "content-type" and isinstance(value, str):
                    # "application/javascript; charset=utf-8" -> "application/javascript"
                    return value.split(";", 1)[0].strip().lower()

            return None

        return None

    def continue_analysis(self, observable: Observable, analysis: PhishkitAnalysis) -> AnalysisExecutionResult:
        """Completes an existing analysis."""
        if not analysis.job_id:
            logging.error(f"no job ID for analysis {analysis}")
            return AnalysisExecutionResult.COMPLETED

        # wait for the job to complete
        logging.info(f"checking for phishkit scan results for {observable} job ID {analysis.job_id}")
        try:
            scan_results = get_async_scan_result(analysis.job_id, analysis.output_dir, timeout=1)
        except (subprocess.TimeoutExpired, TimeoutError) as e:
            error_msg = f"phishkit scan timed out for {observable} job ID {analysis.job_id}: {e}"
            logging.warning(error_msg)
            analysis.error = error_msg
            self._emit_scan_outcome(observable, analysis, "scan_timeout")
            return AnalysisExecutionResult.COMPLETED
        except Exception as e:
            error_msg = f"phishkit scan failed for {observable} job ID {analysis.job_id}: {e}"
            logging.error(error_msg)
            report_exception()
            analysis.error = error_msg
            self._emit_scan_outcome(observable, analysis, "failed")
            return AnalysisExecutionResult.COMPLETED

        if scan_results is None:
            logging.info(f"scan results not ready yet for {observable} job ID {analysis.job_id}")
            return self.delay_analysis(observable, analysis, seconds=3, timeout_seconds=max(self.config.scanner_timeout, 60) * 2 + 30)

        # if we get this far then the scan results are ready (possibly partial —
        # the worker now returns the output dir even when the scan timed out, so
        # we can still harvest captured-traffic observables). The success vs.
        # partial scan_result label is decided after we've read metrics/exit code.
        analysis.error = None

        # a screenshot of Chrome rendering source text (JS, CSS, JSON) as plain text tells us
        # nothing the captured body doesn't already, so don't hand it to OCR
        skip_screenshot_ocr = self._top_level_content_type(analysis.output_dir) in OCR_SKIP_CONTENT_TYPES

        for file_path in scan_results:
            if not os.path.exists(file_path):
                logging.error(f"file {file_path} does not exist for {observable} job ID {analysis.job_id}")
                continue

            if os.path.basename(file_path) == "exit.code":
                with open(file_path, "r") as fp:
                    raw_exit_code = fp.read().strip()
                try:
                    analysis.exit_code = int(raw_exit_code)
                except ValueError:
                    # a hard-killed container can leave a non-numeric payload
                    # (e.g. "None"); don't let it abort result processing
                    logging.warning(f"non-integer exit.code {raw_exit_code!r} for {observable} job ID {analysis.job_id}")
            elif os.path.basename(file_path) == "std.out":
                with open(file_path, "r") as fp:
                    analysis.stdout = self._redact_proxy_credentials(fp.read())
            elif os.path.basename(file_path) == "std.err":
                with open(file_path, "r") as fp:
                    analysis.stderr = self._redact_proxy_credentials(fp.read())
            elif os.path.basename(file_path) == "metrics.json":
                try:
                    with open(file_path, "r") as fp:
                        analysis.metrics = json.load(fp)
                    logging.info(f"loaded scan metrics for {observable} job ID {analysis.job_id}: "
                                 f"{analysis.metrics.get('total_bytes_downloaded', 0)} bytes downloaded")
                    if self.fluent_bit_metrics_sender:
                        try:
                            # send one message per domain with all stats
                            for domain, stats in analysis.metrics.get("domain_stats", {}).items():
                                self.fluent_bit_metrics_sender.emit(None, {
                                    "timestamp": analysis.metrics.get("timestamp"),
                                    "job_id": analysis.job_id,
                                    "url_scanned": analysis.metrics.get("url_scanned"),
                                    "total_bytes_downloaded": analysis.metrics.get("total_bytes_downloaded"),
                                    "scan_duration_seconds": analysis.metrics.get("scan_duration_seconds"),
                                    "domain": domain,
                                    **stats,
                                })
                        except Exception as e:
                            logging.error(f"failed to send metrics to fluent-bit for {observable}: {e}")
                except Exception as e:
                    logging.error(f"failed to read metrics.json for {observable}: {e}")
            elif os.path.basename(file_path) == "proxy.json":
                try:
                    with open(file_path, "r") as fp:
                        proxy_status = json.load(fp)
                    # defense in depth — worker already sanitizes host, but redact again
                    # in case an older worker version slipped credentials through
                    host = proxy_status.get("host")
                    if isinstance(host, str):
                        proxy_status["host"] = self._redact_proxy_credentials(host)
                    analysis.proxy_status = proxy_status
                except Exception as e:
                    logging.error(f"failed to read proxy.json for {observable}: {e}")
            else:
                relative_path = os.path.join("phishkit", analysis.job_id, os.path.relpath(file_path, analysis.output_dir))
                file_observable = analysis.add_file_observable(file_path, relative_path)
                if file_observable:
                    from saq.modules.file_analysis.pdf import PDFAnalyzer
                    # do not send phishkit output to phishkit
                    file_observable.add_yara_meta("type", "document.html.phishkit")
                    file_observable.exclude_analysis(self)
                    file_observable.exclude_analysis(PDFAnalyzer)
                    #file_observable.add_directive(DIRECTIVE_EXCLUDE_ALL)
                    if skip_screenshot_ocr and os.path.basename(file_path).startswith(SCREENSHOT_PREFIXES):
                        logging.debug(f"skipping ocr for {file_path}: top level response is not a rendered page")
                        file_observable.exclude_analysis(OCRAnalyzer)
                    analysis.output_files.append(file_observable.file_path)


                # TODO follow the logic of the existing crawlphish module here

        # A scan that was interrupted mid-crawl still flushes partial
        # requests.json/dom.html/metrics.json (interrupted=True) and exits 143.
        # Label it honestly so analysts know the capture is incomplete, while
        # the extraction below still promotes whatever traffic was captured
        # (e.g. redirect/CDN domains) to observables.
        interrupted = bool(analysis.metrics and analysis.metrics.get("interrupted")) or analysis.exit_code == 143
        if interrupted:
            analysis.scan_result = f"partial scan of {observable}: scanner timed out"
        else:
            analysis.scan_result = f"successfully scanned {observable}"

        # The scanned input URL is omitted from both promotion passes because
        # re-adding it from dom.html or requests.json would make it a descendant
        # of its own PhishkitAnalysis and create a spurious ancestor, which
        # would break observable-modifier crawl rules that require no
        # PhishkitAnalysis ancestor above the URL.
        scanned_url_value = URL(observable.value).value if observable.type == F_URL else None

        # extract URL observables from MARKER URL entries in dom.html
        dom_path = os.path.join(analysis.output_dir, "dom.html")
        if os.path.exists(dom_path):
            try:
                with open(dom_path, "r", errors="ignore") as fp:
                    for line in fp:
                        match = re.match(r"MARKER URL: (.+)$", line.strip())
                        if match:
                            url = URL(match.group(1).strip())
                            if url.value and url.value != scanned_url_value and not url.value.startswith("file:///"):
                                obs = analysis.add_observable_by_spec(F_URL, url.value)
                                if obs:
                                    obs.display_type = "Phishkit Request URL"
            except Exception as e:
                logging.error(f"failed to extract MARKER URLs from dom.html for {observable}: {e}")

        # extract URL observables from every request entry in requests.json.
        # The MARKER URL pass above only covers URLs whose response bodies
        # were captured into dom.html, which skips anything filtered by
        # skip_body_ext / skip_body_url_patterns and anything that failed
        # outright. Parsing requests.json catches those too — including
        # errored URLs like the second-stage challenge endpoints that get
        # blocked by upstream origin checks. add_observable_by_spec dedupes
        # by value, so overlap with the MARKER URL pass is a no-op.
        requests_path = os.path.join(analysis.output_dir, "requests.json")
        if os.path.exists(requests_path):
            try:
                with open(requests_path, "r", errors="ignore") as fp:
                    entries = json.load(fp)
                for entry in entries:
                    if entry.get("type") != "request":
                        continue
                    raw_url = entry.get("url")
                    if not raw_url:
                        continue
                    if raw_url.startswith(("file:///", "data:", "blob:")):
                        continue
                    url = URL(raw_url)
                    if not url.value or url.value == scanned_url_value:
                        continue
                    obs = analysis.add_observable_by_spec(F_URL, url.value)
                    if obs:
                        obs.display_type = "Phishkit Request URL"
            except Exception as e:
                logging.error(f"failed to extract URLs from requests.json for {observable}: {e}")

        self._emit_scan_outcome(
            observable, analysis, "failed" if analysis.error else "success"
        )
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        # The crawl (URL) and render (FILE) directive gates live in
        # custom_requirement so we never record a permanent "no analysis"
        # sentinel before the directive lands. See custom_requirement above.

        # if the observable is a file, we need to check if the file type is enabled for scanning.
        # custom_requirement already gates on this via the file_type declared dependency; this is
        # a defensive backstop for direct invocation.
        if observable.type == F_FILE:
            assert isinstance(observable, FileObservable)
            if not self._file_scan_enabled(observable):
                logging.debug(f"file {observable} not accepted for phishkit analysis")
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, PhishkitAnalysis)

        # create a temporary directory to store the output files
        analysis.output_dir = create_temporary_directory()

        if observable.type == F_URL:
            logging.info(f"executing phishkit URL scan for {observable}")
            analysis.scan_type = SCAN_TYPE_URL

            try:
                analysis.job_id = scan_url(observable.value, analysis.output_dir, is_async=True, scanner_timeout=self.config.scanner_timeout, proxy=self._proxy_string, proxy_fallback_to_direct=self.config.proxy_fallback_to_direct, config_path=self.config.config_path)
                self._emit_scan_dispatched(observable, analysis)
                # return the INCOMPLETE result so the executor sees the module as
                # delayed on this cycle (matches the F_FILE branch below). The
                # delay is already registered by delay_analysis regardless, but
                # returning COMPLETED here triggers a redundant cycle-1 cache
                # write attempt that put_cached_delta then refuses.
                return self.delay_analysis(observable, analysis, seconds=5, timeout_seconds=max(self.config.scanner_timeout, 60) * 2 + 30)

            except Exception as e:
                error_msg = f"failed to scan URL {observable.value}: {str(e)}"
                logging.error(error_msg)
                analysis.error = error_msg
                self._emit_scan_outcome(observable, analysis, "failed")
                return AnalysisExecutionResult.COMPLETED

        elif observable.type == F_FILE:
            logging.info(f"executing phishkit file scan for {observable.value}")
            analysis.scan_type = SCAN_TYPE_FILE

            try:
                analysis.job_id = scan_file(observable.full_path, analysis.output_dir, is_async=True, scanner_timeout=self.config.scanner_timeout, proxy=self._proxy_string, proxy_fallback_to_direct=self.config.proxy_fallback_to_direct, config_path=self.config.config_path)
                self._emit_scan_dispatched(observable, analysis)
                return self.delay_analysis(observable, analysis, seconds=5, timeout_seconds=max(self.config.scanner_timeout, 60) * 2 + 30)

            except Exception as e:
                error_msg = f"Failed to scan file {observable.value}: {str(e)}"
                logging.error(error_msg)
                report_exception()
                analysis.error = error_msg
                self._emit_scan_outcome(observable, analysis, "failed")
                return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED
