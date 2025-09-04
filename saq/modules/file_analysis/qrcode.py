import logging
import os
import re
from subprocess import PIPE, Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, F_FILE, G_ANALYST_DATA_DIR, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.environment import g
from saq.modules import AnalysisModule
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

class QRCodeAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return QRCodeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def qrcode_filter_path(self):
        return os.path.join(g(G_ANALYST_DATA_DIR), self.config.get("filter_path")) if self.config.get("filter_path") else None

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

        target_file_path = local_file_path
        if is_pdf_result:
            # if this is a PDF then we need to convert it into an image first
            target_file_path = f"{local_file_path}.png"
            logging.info(f"converting {local_file_path} to png @ {target_file_path}")
            process = Popen(["gs", "-sDEVICE=pngalpha", "-o", target_file_path, "-r144", local_file_path], stdout=PIPE, stderr=PIPE)
            _stdout, _stderr = process.communicate()
            if not os.path.exists(target_file_path):
                logging.warning(f"conversion of {local_file_path} to png failed")
                return AnalysisExecutionResult.COMPLETED

        logging.info(f"looking for a QR code in {target_file_path}")
        process = Popen(["zbarimg", "-q", "--raw", "--nodbus", target_file_path], stdout=PIPE, stderr=PIPE, text=True)
        _stdout, _stderr = process.communicate()

        # invert the image and scan that too
        inverted_target_file_path = f"{target_file_path}.inverted.png"
        try:
            image = Image.open(target_file_path).convert("RGB")
            image_inverted = ImageOps.invert(image)
            image_inverted.save(inverted_target_file_path)
        except Exception:
            logging.warning(f"unable to invert image {target_file_path}: {e}")

        _stdout_inverted = None
        _stderr_inverted = None
        if os.path.exists(inverted_target_file_path):
            logging.info(f"looking for a QR code in {inverted_target_file_path}")
            process = Popen(["zbarimg", "-q", "--raw", "--nodbus", inverted_target_file_path], stdout=PIPE, stderr=PIPE, text=True)
            _stdout_inverted, _stderr_inverted = process.communicate()
            try:
                os.unlink(inverted_target_file_path)
            except Exception as e:
                logging.error(f"unable to remove {inverted_target_file_path}: {e}")

        if target_file_path != local_file_path:
            # if we created a temporary file, go ahead and delete it as we won't need it anymore
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