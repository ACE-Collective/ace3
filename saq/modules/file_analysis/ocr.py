import logging
import os
from typing import Optional, override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_EXTRACT_URLS, DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL, F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_image
from saq.observables.file import FileObservable
from saq.ocr import get_binary_image, get_image_text, invert_image_color, is_dark, is_small, read_image, remove_line_wrapping, scale_image

KEY_ERROR = "error"
KEY_OCR = "ocr"


class OCRAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,
            KEY_OCR: False,
        }

    @override
    @property
    def display_name(self):
        return "OCR Analysis"

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value: str):
        self.details[KEY_ERROR] = value

    @property
    def ocr(self) -> bool:
        return self.details[KEY_OCR]

    @ocr.setter
    def ocr(self, value: bool):
        self.details[KEY_OCR] = value

    def generate_summary(self) -> Optional[str]:
        if self.error:
            return f"{self.display_name} error: {self.error}"

        if not self.ocr:
            return None

        return self.display_name

class OCRAnalyzer(AnalysisModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def generated_analysis_type(self):
        return OCRAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def valid_analysis_modes(self):
        return [_.strip() for _ in self.config.get('valid_analysis_modes', fallback='').split(',') if _.strip()]

    @property
    def valid_alert_types(self):
        return [_.strip() for _ in self.config.get('valid_alert_types', fallback='').split(',') if _.strip()]

    @property
    def omp_thread_limit(self):
        return self.config.get('omp_thread_limit', fallback=None)

    def custom_requirement(self, observable):
        if self.valid_analysis_modes:
            if self.get_root().analysis_mode not in self.valid_analysis_modes:
                return False

        if self.valid_alert_types:
            if self.get_root().alert_type not in self.valid_alert_types:
                return False

        return True

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        local_file_path = _file.full_path

        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # Currently OCR runs on everything. We could filter on file path, based on Yara, etc. here if needed
        # Check if file is an image
        if not is_image(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        logging.info(f"processing {local_file_path} with OCR")

        if self.omp_thread_limit:
            os.environ["OMP_THREAD_LIMIT"] = str(self.omp_thread_limit)

        # Read the image
        try:
            grayscale_image = read_image(local_file_path)
        except Exception as e:
            logging.warning(f"ocr.read_image({local_file_path}) failed: {e}")
            return AnalysisExecutionResult.COMPLETED

        if grayscale_image is None:
            logging.warning(f"ocr.read_image({local_file_path}) did not return an image")
            return AnalysisExecutionResult.COMPLETED

        # Perform some image pre-processing for better OCR results
        if is_small(grayscale_image):
            grayscale_image = scale_image(grayscale_image, x_factor=2, y_factor=2)

        if is_dark(grayscale_image):
            grayscale_image = invert_image_color(grayscale_image)

        # This dictionary holds the text extracted from the various forms of the image as well as manipulated forms
        # of the text, such as with line breaks removed to help catch multi-line URLs.
        #
        # The dictionary key is the header to use in the output text file, and the value is the extracted text.
        extracted_text = dict()

        # Perform OCR on the grayscale image
        try:
            text = get_image_text(grayscale_image)

            if text:
                extracted_text["GRAYSCALE"] = text
                extracted_text["GRAYSCALE NO LINE BREAKS"] = remove_line_wrapping(text)
        except Exception as e:
            logging.warning(f"Unable to extract text from grayscale image: {local_file_path}: {e}")

        # Perform OCR on the binary form of the image
        binary_image = get_binary_image(grayscale_image)
        try:
            text = get_image_text(binary_image)

            if text:
                extracted_text["BINARY"] = text
                extracted_text["BINARY NO LINE BREAKS"] = remove_line_wrapping(text)
        except Exception as e:
            logging.warning(f"Unable to extract text from binary image: {local_file_path}: {e}")

        # Quit if no text at all was extracted
        if not extracted_text:
            logging.debug(f"nothing was extracted from {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # Create the OCR output directory and write the extracted text to a file
        output_dir = f"{local_file_path}.ocr"
        os.makedirs(output_dir, exist_ok=True)

        output_filename = os.path.join(output_dir, f"{os.path.basename(local_file_path)}.ocr")
        with open(output_filename, "w") as f:
            for ocr_type in sorted(extracted_text.keys()):
                f.write(f"===== {ocr_type} =====\n\n")
                f.write(extracted_text[ocr_type])
                f.write("\n\n")

        # Create the analysis and add the text file as an observable
        analysis = self.create_analysis(_file)
        assert isinstance(analysis, OCRAnalysis)

        analysis.ocr = True
        file_observable = analysis.add_file_observable(output_filename, volatile=True)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL)
            file_observable.redirection = _file

        return AnalysisExecutionResult.COMPLETED