import logging
import os
import pprint
from typing import override

import exiftool
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE, R_EXTRACTED_FROM
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import (
    is_office_file,
    is_ole_file,
    is_pdf_file,
)
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary

example_exif_data = [
    {
        "SourceFile": "ace.out/files/phish.eml.extracted/file_4",
        "ExifTool:ExifToolVersion": 12.57,
        "File:FileName": "file_4",
        "File:Directory": "ace.out/files/phish.eml.extracted",
        "File:FileSize": 69040,
        "File:FileModifyDate": "2025:08:30 23:54:50+00:00",
        "File:FileAccessDate": "2025:08:30 23:54:51+00:00",
        "File:FileInodeChangeDate": "2025:08:30 23:54:50+00:00",
        "File:FilePermissions": 100644,
        "File:FileType": "PDF",
        "File:FileTypeExtension": "PDF",
        "File:MIMEType": "application/pdf",
        "PDF:PDFVersion": 1.4,
        "PDF:Linearized": False,
        "PDF:PageCount": 2,
        "PDF:Creator": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/121.0.0.0 Safari/537.36",
        "PDF:Producer": "Skia/PDF m121",
        "PDF:CreateDate": "2025:07:17 15:02:35+00:00",
        "PDF:ModifyDate": "2025:07:17 15:02:35+00:00",
    }
]

KEY_EXIF_DATA = "exifdata"
KEY_ERROR = "error"

class ExifAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,
            KEY_EXIF_DATA: {},
        }

    @override
    @property
    def display_name(self) -> str:
        return "Exiftool Analysis"

    @property
    def exifdata(self) -> dict:
        return self.details.get(KEY_EXIF_DATA, {})

    @exifdata.setter
    def exifdata(self, value: dict):
        self.details[KEY_EXIF_DATA] = value

    @property
    def error(self) -> str:
        return self.details.get(KEY_ERROR, "")

    @error.setter
    def error(self, value: str):
        self.details[KEY_ERROR] = value

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if self.error:
            return f"{self.display_name}: ⚠ {self.error}"

        parts = []
        for key, value in self.exifdata.items():
            if key.startswith("ExifTool:") or key.startswith("SourceFile") or key.startswith("File:"):
                continue

            # the key shoud start with TYPE: which we want to remove for the summary
            if ":" in key:
                key = key.split(":", 1)[1]

            parts.append(f"{key}={value}")

        return f"{self.display_name}: {format_item_list_for_summary(parts)}"


class ExifAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists("exiftool")

    @property
    def generated_analysis_type(self):
        return ExifAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.hash import FileHashAnalyzer
        from saq.modules.file_analysis.file_type import FileTypeAnalyzer

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # do not analyze pdfparser outupt
        if local_file_path.endswith(".pdfparser"):
            return AnalysisExecutionResult.COMPLETED

        # do not analyze gs output
        if local_file_path.endswith(".gs.pdf"):
            return AnalysisExecutionResult.COMPLETED

        # self.wait_for_analysis(_file, FileTypeAnalysis)
        if (
            not is_office_file(_file)
            and not is_ole_file(local_file_path)
            and not is_pdf_file(local_file_path)
        ):
            logging.debug(f"{local_file_path} is not an office document and not a pdf")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        try:
            with exiftool.ExifToolHelper() as et:
                metadata = et.get_metadata(local_file_path)
                # this should be a list of dictionaries, of which we want the first one
                metadata = metadata[0]
        except Exception as e:
            analysis.details["error"] = str(e)
            logging.info(f"Exif data extraction failed for {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        # return nicely formatted exif data
        # exifdata =  pprint.pformat(metadata)

        analysis.details["exifdata"] = metadata
        if "Error: Exif data extraction failed for" in metadata:
            return AnalysisExecutionResult.COMPLETED

        target_dir = f"{local_file_path}.exif"
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, "exiftool.out")

        # write pretty output to target file
        with open(target_file, "w") as fp:
            exifdata = pprint.pformat(metadata)
            fp.write(exifdata)

        analysis.details["output_dir"] = target_dir
        file_observable = analysis.add_file_observable(target_file)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.exclude_analysis(FileHashAnalyzer)
            file_observable.exclude_analysis(FileTypeAnalyzer)
            # file_observable.add_tag('exif')

        logging.debug("Exif data collection completed.")

        return AnalysisExecutionResult.COMPLETED
