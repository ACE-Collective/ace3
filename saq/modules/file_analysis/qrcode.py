import glob
import logging
import os
import re
import tempfile
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Optional, Type, override
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.environment import get_global_runtime_settings
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_image, is_pdf_file
from saq.observables.file import FileObservable

from PIL import Image, ImageOps


class QRCodeAnalysis(Analysis):

    KEY_EXTRACTED_TEXT = "extracted_text"
    KEY_INVERTED = "inverted"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            QRCodeAnalysis.KEY_EXTRACTED_TEXT: None,
            QRCodeAnalysis.KEY_INVERTED: False,
        }

    @override
    @property
    def display_name(self) -> str:
        return "QR Code Analysis"

    @property
    def extracted_text(self):
        if self.details is None:
            return []

        return self.details.get(QRCodeAnalysis.KEY_EXTRACTED_TEXT, None)

    @extracted_text.setter
    def extracted_text(self, value):
        self.details[QRCodeAnalysis.KEY_EXTRACTED_TEXT] = value

    @property
    def inverted(self) -> bool:
        """Returns True if the QR code was pulled from the inverted version of the image, False otherwise."""
        if self.details is None:
            return False

        return self.details.get(QRCodeAnalysis.KEY_INVERTED, False)

    @inverted.setter
    def inverted(self, value: bool):
        self.details[QRCodeAnalysis.KEY_INVERTED] = value

    def generate_summary(self) -> str:
        if not self.extracted_text:
            return None

        result = f"{self.display_name}: "
        if self.inverted:
            result += "INVERTED: "

        result += self.extracted_text
        return result

class QRCodeFilter:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.url_filters = []

    def load(self):
        try:
            with open(self.file_path, "r") as fp:
                for line in fp:
                    if not line.strip():
                        continue

                    try:
                        self.url_filters.append(re.compile(line.strip(), re.I))
                        logging.debug(f"loaded regex {line.strip()}")
                    except Exception as e:
                        logging.error(f"unable to load qr code filter {line.strip()}: {e}")
        except Exception as e:
            logging.warning(f"unable to load qr code filters: {e}")

    def is_filtered(self, url: str):
        if not url:
            return False

        for url_filter in self.url_filters:
            m = url_filter.search(url)
            if m:
                return True

        return False

class QRCodeAnalyzerConfig(AnalysisModuleConfig):
    filter_path: Optional[str] = Field(default=None, description="Path to a list of strings to exclude from the results relative to ANALYST_DATA_DIR.")
    pdf_first_pages: int = Field(default=3, description="Number of pages to scan from the beginning of a PDF.")
    pdf_last_pages: int = Field(default=3, description="Number of pages to scan from the end of a PDF.")
    timeout: int = Field(default=30, description="Timeout in seconds for subprocess execution.")

class QRCodeAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return QRCodeAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return QRCodeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def qrcode_filter_path(self):
        return os.path.join(get_global_runtime_settings().analyst_data_dir, self.config.filter_path) if self.config.filter_path else None

    @property
    def pdf_first_pages(self):
        return self.config.pdf_first_pages

    @property
    def pdf_last_pages(self):
        return self.config.pdf_last_pages

    @property
    def timeout(self):
        return self.config.timeout

    def _get_pdf_page_count(self, pdf_path: str) -> Optional[int]:
        """Use pdfinfo to get the page count of a PDF."""
        try:
            process = Popen(["pdfinfo", pdf_path], stdout=PIPE, stderr=PIPE, text=True)
            stdout, _ = process.communicate(timeout=self.timeout)
            for line in stdout.split("\n"):
                if line.startswith("Pages:"):
                    return int(line.split(":")[1].strip())
        except TimeoutExpired:
            logging.warning(f"pdfinfo timed out on {pdf_path}")
            process.kill()
            process.communicate()
        except Exception as e:
            logging.warning(f"pdfinfo failed on {pdf_path}: {e}")
        return None

    def _render_pdf_pages(self, pdf_path: str, first_page: int, last_page: int, output_pattern: str) -> bool:
        """Render specific PDF pages to PNG using Ghostscript."""
        try:
            process = Popen(
                ["gs", "-sDEVICE=pngalpha", "-o", output_pattern, "-r144",
                 f"-dFirstPage={first_page}", f"-dLastPage={last_page}", pdf_path],
                stdout=PIPE, stderr=PIPE
            )
            process.communicate(timeout=self.timeout)
            return process.returncode == 0
        except TimeoutExpired:
            logging.warning(f"gs timed out rendering pages {first_page}-{last_page} of {pdf_path}")
            process.kill()
            process.communicate()
            return False

    def _scan_image(self, image_path: str) -> Optional[str]:
        """Run zbarimg on an image and return stdout, or None on failure/timeout."""
        try:
            process = Popen(["zbarimg", "-q", "--raw", "--nodbus", image_path], stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = process.communicate(timeout=self.timeout)
            if stderr:
                logging.debug(f"zbarimg stderr for {image_path}: {stderr}")
            return stdout if stdout else None
        except TimeoutExpired:
            logging.warning(f"zbarimg timed out on {image_path}")
            process.kill()
            process.communicate()
            return None

    def _scan_inverted_image(self, image_path: str) -> Optional[str]:
        """Invert the image and scan it for QR codes. Uses a temp file for the inverted image."""
        try:
            image = Image.open(image_path).convert("RGB")
            image_inverted = ImageOps.invert(image)
        except Exception as e:
            logging.warning(f"unable to invert image {image_path}: {e}")
            return None

        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            tmp.close()
            image_inverted.save(tmp.name)
            return self._scan_image(tmp.name)
        except Exception as e:
            logging.warning(f"unable to save/scan inverted image {image_path}: {e}")
            return None
        finally:
            if tmp and os.path.exists(tmp.name):
                try:
                    os.unlink(tmp.name)
                except Exception as e:
                    logging.error(f"unable to remove inverted temp file {tmp.name}: {e}")

    def _extract_valid_urls(self, stdout: str, qrcode_filter: Optional[QRCodeFilter]) -> list[str]:
        """Extract valid URLs from zbarimg output, applying filters."""
        urls = []
        for line in stdout.split("\n"):
            if not line:
                continue
            if qrcode_filter and qrcode_filter.is_filtered(line):
                continue
            if '.' not in line and '/' not in line:
                logging.info(f"qrcode extraction: {line} is probably not a url -- skipping")
                continue
            urls.append(line)
        return urls

    def _render_pdf_to_pngs(self, local_file_path: str) -> list[str]:
        """Convert PDF to PNG images, rendering only the needed pages."""
        total_pages = self._get_pdf_page_count(local_file_path)

        if total_pages is not None:
            first_n = self.pdf_first_pages
            last_n = self.pdf_last_pages
            target_file_paths = []

            if total_pages <= first_n + last_n:
                # Render all pages in one call
                target_file_pattern = f"{local_file_path}-%d.png"
                logging.info(f"PDF has {total_pages} pages, rendering all pages")
                if self._render_pdf_pages(local_file_path, 1, total_pages, target_file_pattern):
                    target_file_paths = sorted(glob.glob(f"{local_file_path}-*.png"))
            else:
                logging.info(f"PDF has {total_pages} pages, rendering first {first_n} and last {last_n} pages")
                # Render first N pages
                first_pattern = f"{local_file_path}-first-%d.png"
                if self._render_pdf_pages(local_file_path, 1, first_n, first_pattern):
                    target_file_paths.extend(sorted(glob.glob(f"{local_file_path}-first-*.png")))
                # Render last N pages
                last_start = total_pages - last_n + 1
                last_pattern = f"{local_file_path}-last-%d.png"
                if self._render_pdf_pages(local_file_path, last_start, total_pages, last_pattern):
                    target_file_paths.extend(sorted(glob.glob(f"{local_file_path}-last-*.png")))

            if target_file_paths:
                return target_file_paths
            logging.warning(f"selective rendering failed for {local_file_path}, falling back to full render")

        # Fallback: render all pages then filter
        target_file_pattern = f"{local_file_path}-%d.png"
        logging.info(f"converting {local_file_path} to png @ {target_file_pattern}")
        try:
            process = Popen(["gs", "-sDEVICE=pngalpha", "-o", target_file_pattern, "-r144", local_file_path], stdout=PIPE, stderr=PIPE)
            process.communicate(timeout=self.timeout)
        except TimeoutExpired:
            logging.warning(f"gs timed out on {local_file_path}")
            process.kill()
            process.communicate()
            return []

        target_file_paths = sorted(glob.glob(f"{local_file_path}-*.png"))
        if not target_file_paths:
            logging.warning(f"conversion of {local_file_path} to png failed")
            return []

        # Filter to first N and last N pages
        total_pages = len(target_file_paths)
        first_n = self.pdf_first_pages
        last_n = self.pdf_last_pages

        if total_pages > first_n + last_n:
            pages_to_scan = set(target_file_paths[:first_n] + target_file_paths[-last_n:])
            for p in target_file_paths:
                if p not in pages_to_scan:
                    try:
                        os.unlink(p)
                    except Exception as e:
                        logging.error(f"unable to remove skipped page {p}: {e}")
            target_file_paths = sorted(pages_to_scan)
            logging.info(f"PDF has {total_pages} pages, scanning first {first_n} and last {last_n} pages")
        else:
            logging.info(f"PDF has {total_pages} pages, scanning all pages")

        return target_file_paths

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.hash import FileHashAnalyzer

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        is_pdf_result = is_pdf_file(local_file_path)
        if not is_image(local_file_path) and not is_pdf_result:
            return AnalysisExecutionResult.COMPLETED

        # Determine which files to scan for QR codes
        if is_pdf_result:
            target_file_paths = self._render_pdf_to_pngs(local_file_path)
            if not target_file_paths:
                return AnalysisExecutionResult.COMPLETED
            is_temp_files = True
        else:
            target_file_paths = [local_file_path]
            is_temp_files = False

        # Load QR code filter once before the loop
        qrcode_filter = None
        if self.qrcode_filter_path:
            logging.info(f"loading qrcode filter from {self.qrcode_filter_path}")
            qrcode_filter = QRCodeFilter(self.qrcode_filter_path)
            qrcode_filter.load()

        # Scan each page/image for QR codes, processing results per-page
        normal_urls = []
        inverted_urls = []

        for target_file_path in target_file_paths:
            logging.info(f"looking for a QR code in {target_file_path}")

            # Normal scan
            stdout = self._scan_image(target_file_path)
            page_urls = self._extract_valid_urls(stdout, qrcode_filter) if stdout else []

            if page_urls:
                normal_urls.extend(page_urls)
            else:
                # Only run inverted scan if normal scan found nothing on this page
                inverted_stdout = self._scan_inverted_image(target_file_path)
                inverted_page_urls = self._extract_valid_urls(inverted_stdout, qrcode_filter) if inverted_stdout else []
                if inverted_page_urls:
                    inverted_urls.extend(inverted_page_urls)

            # Clean up temporary PNG file if created from PDF
            if is_temp_files:
                try:
                    os.unlink(target_file_path)
                except Exception as e:
                    logging.error(f"unable to remove {target_file_path}: {e}")

        # Create analysis from results, preferring normal over inverted
        for extracted_urls, is_inverted in [(normal_urls, False), (inverted_urls, True)]:
            if not extracted_urls:
                continue

            analysis = self.create_analysis(_file)
            analysis.inverted = is_inverted
            target_path = f"{local_file_path}.qrcode"
            with open(target_path, "w") as fp:
                for url in extracted_urls:
                    fp.write(f"{url}\n")

            analysis.extracted_text = ", ".join(extracted_urls)

            file_observable = analysis.add_file_observable(target_path)
            if file_observable:
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                file_observable.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
                file_observable.exclude_analysis(FileHashAnalyzer)
                file_observable.add_tag("qr-code")
                if is_inverted:
                    file_observable.add_tag("qr-code-inverted")

                logging.info(f"found QR code in {_file} inverted {is_inverted}")

            break

        return AnalysisExecutionResult.COMPLETED
