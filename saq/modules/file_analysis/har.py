"""Extracts the pages and scripts recorded in an HTTP archive (.har).

A HAR is the JSON a browser's developer tools export for a browsing session:
every request the browser made, each with its response body. An analyst who
detonates a link in a VM can export one and add it to the alert.

Every response body sits inside a JSON string, so the file can't be analyzed
as it is. libmagic calls it text/html, and parsing it as HTML pulls scripts out
with their JSON escapes still in them (html_js_extraction skips JSON files for
that reason). This module writes each page and script out as its own file, so
html_js_extraction, the JS deobfuscator and the rest of file analysis see them
as they would see a crawled page:

- a page is linked to the URL it was loaded from (downloaded_from), which
  html_js_extraction hands to the page's inline scripts as their location;
- a script a page loads with <script src> runs inside that page in a browser,
  so it gets the page's DOM snapshot as a sidecar (`<script>.dom.json`), which
  is where the JS deobfuscator looks for one.
"""

import base64
import binascii
import hashlib
import json
import logging
import os
import re
from urllib.parse import unquote, urljoin, urlsplit

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, F_URL, R_DOWNLOADED_FROM, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.html_js_extraction import (
    build_dom_snapshot,
    get_script_source,
    parse_document,
    write_dom_snapshot,
)
from saq.observables.file import FileObservable

# Every HAR exporter writes the single top-level "log" key first.
RE_HAR_HEADER = re.compile(rb'^\s*\{\s*"log"\s*:')
HAR_HEADER_PEEK_BYTES = 4096

# The responses worth a file, by MIME type, with the extension that gets them
# past the downstream extension gates (html_js_extraction: .html/.svg, the JS
# deobfuscator: .js).
DOCUMENT_EXTENSIONS = {
    "text/html": ".html",
    "application/xhtml+xml": ".html",
    "image/svg+xml": ".svg",
}
SCRIPT_EXTENSIONS = {
    "application/javascript": ".js",
    "application/x-javascript": ".js",
    "application/ecmascript": ".js",
    "text/javascript": ".js",
    "text/ecmascript": ".js",
}

MAX_FILE_NAME_LENGTH = 100


class HARResponse:
    """One response body worth extracting."""

    def __init__(self, index: int, url: str, mime_type: str, status, body: bytes, truncated: bool):
        self.index = index
        self.url = url
        self.mime_type = mime_type
        self.status = status
        self.body = body
        self.truncated = truncated

    @property
    def is_document(self) -> bool:
        return self.mime_type in DOCUMENT_EXTENSIONS

    @property
    def extension(self) -> str:
        return DOCUMENT_EXTENSIONS.get(self.mime_type) or SCRIPT_EXTENSIONS[self.mime_type]

    @property
    def file_name(self) -> str:
        """`<entry index>_<last path segment><extension>`, e.g. 012_module.js. The
        index keeps two responses from the same path (a GET and the POST back to it)
        apart and sorts the files in the order the browser requested them."""
        parts = urlsplit(self.url)
        name = unquote(parts.path.rstrip("/").rsplit("/", 1)[-1]) or parts.hostname or "response"
        name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:MAX_FILE_NAME_LENGTH].strip("._") or "response"
        if not name.lower().endswith(self.extension):
            name += self.extension

        return f"{self.index:03d}_{name}"


def is_har_header(head: bytes) -> bool:
    return RE_HAR_HEADER.match(head) is not None


def _as_dict(value) -> dict:
    """A HAR is input like any other: a member that should be an object may not be."""
    return value if isinstance(value, dict) else {}


def get_har_entries(har) -> list | None:
    entries = _as_dict(_as_dict(har).get("log")).get("entries")
    return entries if isinstance(entries, list) else None


def get_har_responses(har) -> list[HARResponse]:
    """The page and script responses in a parsed HAR, in request order, one per
    distinct body. A data: URL is skipped: its content is part of the document
    that holds it, not something the browser fetched."""
    result = []
    seen_hashes = set()
    for index, entry in enumerate(get_har_entries(har) or []):
        entry = _as_dict(entry)
        url = _as_dict(entry.get("request")).get("url")
        response = _as_dict(entry.get("response"))
        content = _as_dict(response.get("content"))
        if not isinstance(url, str) or url.lower().startswith("data:"):
            continue

        mime_type = str(content.get("mimeType") or "").split(";", 1)[0].strip().lower()
        if mime_type not in DOCUMENT_EXTENSIONS and mime_type not in SCRIPT_EXTENSIONS:
            continue

        text = content.get("text")
        if not isinstance(text, str) or not text:
            continue

        if content.get("encoding") == "base64":
            try:
                body = base64.b64decode(text)
            except (binascii.Error, ValueError):
                logging.debug(f"invalid base64 body for {url} in har entry {index}")
                continue
        else:
            body = text.encode("utf-8", errors="replace")

        body_hash = hashlib.sha256(body).hexdigest()
        if body_hash in seen_hashes:
            continue
        seen_hashes.add(body_hash)

        # browsers cap the body they keep (Firefox at 1 MB) and record the real size
        size = content.get("size")
        truncated = isinstance(size, int) and size > len(body)

        result.append(HARResponse(index, url, mime_type, response.get("status"), body, truncated))

    return result


class HARAnalysis(Analysis):
    """The pages and scripts extracted from an HTTP archive."""

    KEY_CREATOR = "creator"
    KEY_ENTRY_COUNT = "entry_count"
    KEY_RESPONSES = "responses"
    KEY_SKIPPED_COUNT = "skipped_count"
    KEY_ERROR = "error"

    # keys of one KEY_RESPONSES item
    KEY_URL = "url"
    KEY_STATUS = "status"
    KEY_MIME_TYPE = "mime_type"
    KEY_FILE_PATH = "file_path"
    KEY_TRUNCATED = "truncated"
    # the page whose DOM snapshot a script runs against
    KEY_LOADED_BY = "loaded_by"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            HARAnalysis.KEY_CREATOR: None,
            HARAnalysis.KEY_ENTRY_COUNT: 0,
            HARAnalysis.KEY_RESPONSES: [],
            HARAnalysis.KEY_SKIPPED_COUNT: 0,
            HARAnalysis.KEY_ERROR: None,
        }

    @property
    def creator(self) -> str | None:
        return self.details.get(HARAnalysis.KEY_CREATOR)

    @creator.setter
    def creator(self, value: str | None):
        self.details[HARAnalysis.KEY_CREATOR] = value

    @property
    def entry_count(self) -> int:
        return self.details.get(HARAnalysis.KEY_ENTRY_COUNT, 0)

    @entry_count.setter
    def entry_count(self, value: int):
        self.details[HARAnalysis.KEY_ENTRY_COUNT] = value

    @property
    def responses(self) -> list[dict]:
        return self.details.get(HARAnalysis.KEY_RESPONSES, [])

    @property
    def skipped_count(self) -> int:
        return self.details.get(HARAnalysis.KEY_SKIPPED_COUNT, 0)

    @skipped_count.setter
    def skipped_count(self, value: int):
        self.details[HARAnalysis.KEY_SKIPPED_COUNT] = value

    @property
    def error(self) -> str | None:
        return self.details.get(HARAnalysis.KEY_ERROR)

    @error.setter
    def error(self, value: str | None):
        self.details[HARAnalysis.KEY_ERROR] = value

    def generate_summary(self) -> str | None:
        if not self.details:
            return None

        if self.error:
            return f"HTTP Archive: failed: {self.error}"

        pages = sum(1 for r in self.responses if r[HARAnalysis.KEY_MIME_TYPE] in DOCUMENT_EXTENSIONS)
        scripts = len(self.responses) - pages
        summary = f"HTTP Archive: extracted {pages} pages and {scripts} scripts from {self.entry_count} requests"
        if self.creator:
            summary += f" ({self.creator})"
        if self.skipped_count:
            summary += f", {self.skipped_count} more over the extraction limit"

        return summary


class HARExtractorConfig(AnalysisModuleConfig):
    max_file_size: int = Field(
        default=52428800,
        description="Largest .har file parsed, in bytes. The whole file is loaded as JSON.",
    )
    max_extracted_files: int = Field(
        default=50,
        description="Most response bodies extracted from one .har file, pages first, then scripts in request order.",
    )


class HARExtractor(AnalysisModule):
    """Writes the pages and scripts recorded in an HTTP archive out as files."""

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return HARExtractorConfig

    @property
    def generated_analysis_type(self):
        return HARAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path) or os.path.getsize(local_file_path) == 0:
            return AnalysisExecutionResult.COMPLETED

        # detected by content: an exported .har is renamed as easily as anything else
        with open(local_file_path, "rb") as fp:
            if not is_har_header(fp.read(HAR_HEADER_PEEK_BYTES)):
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, HARAnalysis)

        file_size = os.path.getsize(local_file_path)
        if file_size > self.config.max_file_size:
            analysis.error = f"{file_size} bytes exceeds max_file_size {self.config.max_file_size}"
            return AnalysisExecutionResult.COMPLETED

        try:
            with open(local_file_path, "rb") as fp:
                har = json.load(fp)
        except (ValueError, RecursionError) as e:
            analysis.error = f"not valid JSON: {e}"
            return AnalysisExecutionResult.COMPLETED

        entries = get_har_entries(har)
        if entries is None:
            analysis.error = "no log.entries list"
            return AnalysisExecutionResult.COMPLETED

        creator = _as_dict(har["log"].get("creator"))
        if creator.get("name"):
            analysis.creator = f"{creator['name']} {creator.get('version') or ''}".strip()
        analysis.entry_count = len(entries)

        responses = get_har_responses(har)
        # pages first: they are the navigation and they hold the scripts' DOM
        documents = [r for r in responses if r.is_document]
        scripts = [r for r in responses if not r.is_document]
        selected = (documents + scripts)[:self.config.max_extracted_files]
        analysis.skipped_count = len(responses) - len(selected)

        extracted_dir = f"{local_file_path}.extracted"
        os.makedirs(extracted_dir, exist_ok=True)

        # script URL -> (the snapshot of the page that loads it, that page's file path)
        page_snapshots: dict[str, tuple[dict, str]] = {}
        for response in selected:
            file_observable = self._extract_response(response, extracted_dir, _file, analysis)
            if file_observable is None:
                continue

            record = {
                HARAnalysis.KEY_URL: response.url,
                HARAnalysis.KEY_STATUS: response.status,
                HARAnalysis.KEY_MIME_TYPE: response.mime_type,
                HARAnalysis.KEY_FILE_PATH: file_observable.file_path,
                HARAnalysis.KEY_TRUNCATED: response.truncated,
            }

            if response.is_document:
                self._collect_page_snapshot(response, file_observable, page_snapshots)
            elif response.url in page_snapshots:
                snapshot, page_file_path = page_snapshots[response.url]
                if write_dom_snapshot(file_observable.full_path + ".dom.json", snapshot):
                    record[HARAnalysis.KEY_LOADED_BY] = page_file_path

            analysis.responses.append(record)

        return AnalysisExecutionResult.COMPLETED

    def _extract_response(self, response: HARResponse, extracted_dir: str, _file: FileObservable,
                          analysis: HARAnalysis) -> FileObservable | None:
        target_path = os.path.join(extracted_dir, response.file_name)
        try:
            with open(target_path, "wb") as fp:
                fp.write(response.body)
        except OSError as e:
            logging.warning(f"unable to write har response {response.url} to {target_path}: {e}")
            return None

        file_observable = analysis.add_file_observable(target_path, volatile=True)
        if file_observable is None:
            return None

        file_observable.add_relationship(R_EXTRACTED_FROM, _file)
        file_observable.exclude_analysis(self)

        if urlsplit(response.url).scheme.lower() in ("http", "https"):
            url_observable = analysis.add_observable_by_spec(F_URL, response.url)
            if url_observable is not None:
                file_observable.add_relationship(R_DOWNLOADED_FROM, url_observable)

        return file_observable

    def _collect_page_snapshot(self, response: HARResponse, file_observable: FileObservable,
                               page_snapshots: dict[str, tuple[dict, str]]):
        """Records this page's DOM snapshot under every script URL it loads. A
        script two pages load runs against the first page's."""
        try:
            soup = parse_document(response.body.decode("utf-8", errors="ignore"))
        except Exception as e:
            logging.warning(f"unable to parse har page {response.url}: {e}")
            return

        snapshot = None
        for script in soup.find_all("script"):
            source = get_script_source(script)
            if not source or not source.strip():
                continue

            script_url = urljoin(response.url, source.strip())
            if script_url in page_snapshots:
                continue

            if snapshot is None:
                snapshot = build_dom_snapshot(soup, url=response.url)
                if snapshot is None:
                    return

            page_snapshots[script_url] = (snapshot, file_observable.file_path)
