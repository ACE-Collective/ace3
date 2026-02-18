import email.parser
import hashlib
import logging
import os
import re
from typing import Type, override
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_CRAWL, DIRECTIVE_CRAWL_EXTRACTED_URLS, F_FILE, F_URL, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable


# Event attributes that can contain JavaScript code
EVENT_ATTRIBUTES = [
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmouseout',
    'onmousemove', 'onkeydown', 'onkeyup', 'onkeypress', 'onload', 'onunload',
    'onerror', 'onabort', 'onchange', 'onsubmit', 'onreset', 'onfocus', 'onblur',
    'onresize', 'onscroll', 'onselect', 'ondrag', 'ondrop', 'ondragstart', 'ondragend',
    'ondragenter', 'ondragleave', 'ondragover',
]


class HTMLJavaScriptExtractionAnalysis(Analysis):
    """Analysis results for JavaScript extracted from HTML files."""

    KEY_EXTRACTED_FILES = "extracted_files"
    KEY_EXTRACTED_URLS = "extracted_urls"
    KEY_INLINE_HANDLERS = "inline_handlers"
    KEY_SCRIPT_COUNT = "script_count"
    KEY_DUPLICATE_COUNT = "duplicate_count"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            self.KEY_EXTRACTED_FILES: [],
            self.KEY_EXTRACTED_URLS: [],
            self.KEY_INLINE_HANDLERS: [],
            self.KEY_SCRIPT_COUNT: 0,
            self.KEY_DUPLICATE_COUNT: 0,
        }

    @override
    @property
    def display_name(self) -> str:
        return "HTML JavaScript Extraction"

    @property
    def extracted_files(self):
        return self.details[self.KEY_EXTRACTED_FILES]

    @property
    def extracted_urls(self):
        return self.details[self.KEY_EXTRACTED_URLS]

    @property
    def inline_handlers(self):
        return self.details[self.KEY_INLINE_HANDLERS]

    @property
    def script_count(self):
        return self.details[self.KEY_SCRIPT_COUNT]

    @script_count.setter
    def script_count(self, value):
        self.details[self.KEY_SCRIPT_COUNT] = value

    @property
    def duplicate_count(self):
        return self.details[self.KEY_DUPLICATE_COUNT]

    @duplicate_count.setter
    def duplicate_count(self, value):
        self.details[self.KEY_DUPLICATE_COUNT] = value

    def generate_summary(self) -> str:
        if self.script_count == 0:
            return None

        parts = []
        if self.extracted_files:
            parts.append(f"{len(self.extracted_files)} inline script(s)")
        if self.extracted_urls:
            parts.append(f"{len(self.extracted_urls)} external URL(s)")
        if self.inline_handlers:
            parts.append(f"{len(self.inline_handlers)} event handler(s)")

        summary = f"{self.display_name}: {', '.join(parts)}"

        if self.duplicate_count > 0:
            summary += f" ({self.duplicate_count} duplicate(s) skipped)"

        return summary


class HTMLJavaScriptExtractionConfig(AnalysisModuleConfig):
    min_script_size: int = Field(
        default=10,
        description="Minimum size in bytes for a script to be extracted"
    )

    extract_event_handlers: bool = Field(
        default=True,
        description="Whether to extract inline event handlers (onclick, onload, etc.)"
    )

    max_event_handler_size: int = Field(
        default=8192,
        description="Maximum size in bytes for inline event handlers"
    )

    deduplicate: bool = Field(
        default=True,
        description="Skip extraction of duplicate scripts"
    )


class HTMLJavaScriptExtractor(AnalysisModule):
    """Extracts JavaScript code from HTML, MHTML, and SVG files."""

    # File extensions to check
    HTML_EXTENSIONS = ['.html', '.htm', '.svg']
    MHTML_EXTENSIONS = ['.mhtml', '.mht']

    # MIME types that indicate HTML content
    HTML_MIME_TYPES = ['text/html', 'application/xhtml+xml', 'image/svg+xml', 'message/rfc822']

    # Regex to detect MHTML header
    RE_HEADER = re.compile(b'^[a-zA-Z0-9-_]+:')

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return HTMLJavaScriptExtractionConfig

    @property
    def generated_analysis_type(self):
        return HTMLJavaScriptExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def min_script_size(self):
        return self.config.min_script_size

    @property
    def extract_event_handlers(self):
        return self.config.extract_event_handlers

    @property
    def max_event_handler_size(self):
        return self.config.max_event_handler_size

    @property
    def deduplicate(self):
        return self.config.deduplicate

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path

        # Validate file exists
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # Skip empty files
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        # Check if file should be analyzed based on extension or MIME type
        if not self._is_html_file(_file):
            return AnalysisExecutionResult.COMPLETED

        logging.info(f"extracting JavaScript from {_file.file_name}")

        # Try to get file type analysis for MIME type (optional)
        mime_type = None
        try:
            file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
            mime_type = file_type_analysis.mime_type if file_type_analysis else None
        except Exception:
            # File type analysis not available, continue with extension-based detection
            pass

        # Determine if this is an MHTML file
        is_mhtml = self._is_mhtml_file(_file, mime_type)

        if is_mhtml:
            html_content_list = self._parse_mhtml(local_file_path)
        else:
            html_content_list = [self._read_html_file(local_file_path)]

        analysis = self.create_analysis(_file)
        seen_hashes = set()

        # Process each HTML content block
        for html_content in html_content_list:
            if not html_content:
                continue

            try:
                self._extract_javascript_from_html(
                    html_content,
                    _file,
                    analysis,
                    seen_hashes
                )
            except Exception as e:
                logging.warning(f"failed to extract JavaScript from {_file.file_name}: {e}")

        return AnalysisExecutionResult.COMPLETED

    def _is_html_file(self, _file: FileObservable) -> bool:
        """Check if file should be analyzed based on extension."""
        filename = _file.file_name.lower()

        for ext in self.HTML_EXTENSIONS + self.MHTML_EXTENSIONS:
            if filename.endswith(ext):
                return True

        return False

    def _is_mhtml_file(self, _file: FileObservable, mime_type: str = None) -> bool:
        """Determine if file is MHTML format."""
        filename = _file.file_name.lower()

        # Check extension
        for ext in self.MHTML_EXTENSIONS:
            if filename.endswith(ext):
                return True

        # Check MIME type
        if mime_type == 'message/rfc822':
            return True

        return False

    def _read_html_file(self, file_path: str) -> bytes:
        """Read HTML file content."""
        try:
            with open(file_path, 'rb') as fp:
                return fp.read()
        except Exception as e:
            logging.error(f"failed to read {file_path}: {e}")
            return b''

    def _parse_mhtml(self, file_path: str) -> list:
        """Parse MHTML file and return list of HTML content parts."""
        html_parts = []

        try:
            parser = email.parser.BytesFeedParser()
            state_started_headers = False

            with open(file_path, 'rb') as fp:
                # Skip any garbage at the start of the file
                for line in fp:
                    if not state_started_headers:
                        if not self.RE_HEADER.search(line):
                            continue
                        else:
                            state_started_headers = True

                    parser.feed(line)

            parsed_file = parser.close()

            # Extract HTML parts
            for part in parsed_file.walk():
                if part.get_content_maintype() == 'multipart':
                    continue

                content_type = part.get_content_type()
                if content_type in ['text/html', 'application/xhtml+xml']:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_parts.append(payload)

        except Exception as e:
            logging.warning(f"failed to parse MHTML {file_path}: {e}")

        return html_parts

    def _extract_javascript_from_html(
        self,
        html_content: bytes,
        _file: FileObservable,
        analysis: HTMLJavaScriptExtractionAnalysis,
        seen_hashes: set
    ):
        """Extract JavaScript from HTML content using BeautifulSoup."""
        import bs4

        # NOTE this also extracts JS from SVG files, which uses bs4 as an XML parser
        # they emit a warning for that that we ignore here
        from bs4 import XMLParsedAsHTMLWarning
        import warnings

        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

        try:
            soup = bs4.BeautifulSoup(html_content.decode(errors='ignore'), 'lxml')
        except Exception as e:
            logging.warning(f"failed to parse HTML with BeautifulSoup: {e}")
            return

        # Extract inline scripts
        self._extract_inline_scripts(soup, _file, analysis, seen_hashes)

        # Extract external script URLs
        self._extract_external_scripts(soup, _file, analysis)

        # Extract event handlers if enabled
        if self.extract_event_handlers:
            self._extract_event_handlers(soup, _file, analysis, seen_hashes)

    def _extract_inline_scripts(
        self,
        soup,
        _file: FileObservable,
        analysis: HTMLJavaScriptExtractionAnalysis,
        seen_hashes: set
    ):
        """Extract inline <script> tags."""
        for script in soup.find_all('script'):
            # Skip scripts with src attribute (external scripts)
            if script.has_attr('src'):
                continue

            # Get script type attribute
            script_type = script.get('type', 'text/javascript').lower()

            # Skip non-JavaScript scripts (e.g., application/json)
            if script_type not in ['text/javascript', 'application/javascript', '']:
                continue

            # Get script content
            script_content = script.string
            if not script_content:
                continue

            script_content = script_content.strip()

            # Skip empty or too-small scripts
            if len(script_content) < self.min_script_size:
                continue

            analysis.script_count += 1

            # Deduplicate if enabled
            if self.deduplicate:
                script_hash = self._compute_hash(script_content)
                if script_hash in seen_hashes:
                    analysis.duplicate_count += 1
                    continue
                seen_hashes.add(script_hash)

            # Save script to file
            self._save_and_register_script(
                script_content,
                'inline',
                _file,
                analysis,
                analysis.extracted_files
            )

    def _extract_external_scripts(
        self,
        soup,
        _file: FileObservable,
        analysis: HTMLJavaScriptExtractionAnalysis
    ):
        """Extract external script URLs from src attributes."""
        for script in soup.find_all('script'):
            if not script.has_attr('src'):
                continue

            src_url = script['src'].strip()
            if not src_url:
                continue

            analysis.script_count += 1

            # Create URL observable
            url_observable = analysis.add_observable_by_spec(F_URL, src_url)
            if url_observable:
                if _file.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS):
                    url_observable.add_directive(DIRECTIVE_CRAWL)

                url_observable.add_relationship(R_EXTRACTED_FROM, _file)
                analysis.extracted_urls.append(src_url)
                logging.info(f"extracted external script URL {src_url} from {_file.file_name}")

    def _extract_event_handlers(
        self,
        soup,
        _file: FileObservable,
        analysis: HTMLJavaScriptExtractionAnalysis,
        seen_hashes: set
    ):
        """Extract inline event handlers from HTML elements."""
        for tag in soup.find_all():
            for attr in EVENT_ATTRIBUTES:
                if not tag.has_attr(attr):
                    continue

                handler_code = tag[attr].strip()

                # Skip empty or too-large handlers
                if not handler_code or len(handler_code) < self.min_script_size:
                    continue

                if len(handler_code) > self.max_event_handler_size:
                    logging.debug(f"skipping event handler larger than {self.max_event_handler_size} bytes")
                    continue

                analysis.script_count += 1

                # Deduplicate if enabled
                if self.deduplicate:
                    handler_hash = self._compute_hash(handler_code)
                    if handler_hash in seen_hashes:
                        analysis.duplicate_count += 1
                        continue
                    seen_hashes.add(handler_hash)

                # Save handler to file
                self._save_and_register_script(
                    handler_code,
                    f'event_{attr}',
                    _file,
                    analysis,
                    analysis.inline_handlers
                )

    def _save_and_register_script(
        self,
        script_content: str,
        script_type: str,
        _file: FileObservable,
        analysis: HTMLJavaScriptExtractionAnalysis,
        tracking_list: list
    ):
        """Save JavaScript content to file and register as observable."""
        # Compute hash for filename
        script_hash = self._compute_hash(script_content)
        hash_prefix = script_hash[:8]

        # Generate filename
        base_name = os.path.splitext(_file.file_name)[0]
        index = len(tracking_list)
        filename = f"{base_name}_js_{script_type}_{index}_{hash_prefix}.js"

        # Create target directory
        local_file_dir = os.path.dirname(_file.full_path)
        target_path = os.path.join(local_file_dir, filename)

        try:
            # Write script to file
            with open(target_path, 'w', encoding='utf-8') as fp:
                fp.write(script_content)

        except Exception as e:
            logging.error(f"failed to save script to {target_path}: {e}")
            return 

        file_observable = analysis.add_file_observable(target_path, volatile=True)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.exclude_analysis(self)  # Don't re-analyze our own output
            _file.copy_directives_to(file_observable)
            tracking_list.append(file_observable.file_path)
            logging.debug(f"extracted {script_type} JavaScript to {filename}")


    def _compute_hash(self, content: str) -> str:
        """Compute SHA256 hash of content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
