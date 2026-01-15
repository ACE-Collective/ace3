import glob
import logging
import os
import re
from subprocess import PIPE, Popen
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
            #logging.debug(f"{url_filter} {url} = {m}")
            if m:
                return True

        return False

class QRCodeAnalyzerConfig(AnalysisModuleConfig):
    filter_path: Optional[str] = Field(default=None, description="Path to a list of strings to exclude from the results relative to ANALYST_DATA_DIR.")
    pdf_first_pages: int = Field(default=3, description="Number of pages to scan from the beginning of a PDF.")
    pdf_last_pages: int = Field(default=3, description="Number of pages to scan from the end of a PDF.")

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
            # Convert PDF to PNG images (one per page) using %d pattern
            target_file_pattern = f"{local_file_path}-%d.png"
            logging.info(f"converting {local_file_path} to png @ {target_file_pattern}")
            process = Popen(["gs", "-sDEVICE=pngalpha", "-o", target_file_pattern, "-r144", local_file_path], stdout=PIPE, stderr=PIPE)
            _stdout, _stderr = process.communicate()

            # Find all generated page PNGs
            target_file_paths = sorted(glob.glob(f"{local_file_path}-*.png"))
            if not target_file_paths:
                logging.warning(f"conversion of {local_file_path} to png failed")
                return AnalysisExecutionResult.COMPLETED

            # Limit to first M and last N pages for QR code scanning
            total_pages = len(target_file_paths)
            first_n = self.pdf_first_pages
            last_n = self.pdf_last_pages

            if total_pages > first_n + last_n:
                pages_to_scan = set(target_file_paths[:first_n] + target_file_paths[-last_n:])
                pages_to_skip = [p for p in target_file_paths if p not in pages_to_scan]
                target_file_paths = sorted(pages_to_scan)
                # Clean up skipped page PNGs immediately
                for skip_path in pages_to_skip:
                    try:
                        os.unlink(skip_path)
                    except Exception as e:
                        logging.error(f"unable to remove skipped page {skip_path}: {e}")
                logging.info(f"PDF has {total_pages} pages, scanning first {first_n} and last {last_n} pages")
            else:
                logging.info(f"PDF has {total_pages} pages, scanning all pages")

            is_temp_files = True
        else:
            target_file_paths = [local_file_path]
            is_temp_files = False

        # Scan each page/image for QR codes
        _stdout = ""
        _stderr = ""
        _stdout_inverted = ""
        _stderr_inverted = ""

        for target_file_path in target_file_paths:
            logging.info(f"looking for a QR code in {target_file_path}")
            process = Popen(["zbarimg", "-q", "--raw", "--nodbus", target_file_path], stdout=PIPE, stderr=PIPE, text=True)
            page_stdout, page_stderr = process.communicate()
            if page_stdout:
                _stdout += page_stdout
            if page_stderr:
                _stderr += page_stderr

            # invert the image and scan that too
            inverted_target_file_path = f"{target_file_path}.inverted.png"
            try:
                image = Image.open(target_file_path).convert("RGB")
                image_inverted = ImageOps.invert(image)
                image_inverted.save(inverted_target_file_path)
            except Exception as e:
                logging.warning(f"unable to invert image {target_file_path}: {e}")

            if os.path.exists(inverted_target_file_path):
                logging.info(f"looking for a QR code in {inverted_target_file_path}")
                process = Popen(["zbarimg", "-q", "--raw", "--nodbus", inverted_target_file_path], stdout=PIPE, stderr=PIPE, text=True)
                page_stdout_inverted, page_stderr_inverted = process.communicate()
                if page_stdout_inverted:
                    _stdout_inverted += page_stdout_inverted
                if page_stderr_inverted:
                    _stderr_inverted += page_stderr_inverted
                try:
                    os.unlink(inverted_target_file_path)
                except Exception as e:
                    logging.error(f"unable to remove {inverted_target_file_path}: {e}")

            # Clean up temporary PNG file if created from PDF
            if is_temp_files:
                try:
                    os.unlink(target_file_path)
                except Exception as e:
                    logging.error(f"unable to remove {target_file_path}: {e}")

        extracted_urls = []
        for _stdout, is_inverted in [ (_stdout, False), (_stdout_inverted, True) ]:
            if not _stdout:
                continue

            qrcode_filter = None
            if self.qrcode_filter_path:
                logging.info(f"loading qrcode filter from {self.qrcode_filter_path}")
                qrcode_filter = QRCodeFilter(self.qrcode_filter_path)
                qrcode_filter.load()

            for line in _stdout.split("\n"):
                if not line:
                    continue

                if qrcode_filter and qrcode_filter.is_filtered(line):
                    continue

                # some of the things the qr code utility extracts is shipping barcodes
                # urls are going to have either a . or a / somewhere in it
                # if you don't see one or the other then don't add it
                if '.' not in line and '/' not in line:
                    logging.info(f"qrcode extraction: {line} is probably not a url -- skipping")
                    continue

                extracted_urls.append(line)

            if not extracted_urls:
                logging.info(f"all urls filtered out for {local_file_path}")
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

        if _stderr:
            logging.info(f"unable to extract qrcode from {local_file_path}: {_stderr}")

        return AnalysisExecutionResult.COMPLETED