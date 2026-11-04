import json
import logging
import os
import pprint
import signal
from typing import Type, override

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE, R_EXTRACTED_FROM
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.file_type import FileTypeAnalyzer
from saq.modules.file_analysis.hash import FileHashAnalyzer
from saq.modules.file_analysis.is_file_type import (
    is_office_file,
    is_ole_file,
    is_pdf_file,
)
from saq.observables.file import FileObservable
from saq.sandbox.runner import SandboxResult
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


def _read_metadata(stdout: str) -> dict:
    """The metadata exiftool printed for the one file it was given. Raises ValueError for anything else."""
    metadata = json.loads(stdout)
    if not isinstance(metadata, list) or len(metadata) != 1 or not isinstance(metadata[0], dict):
        raise ValueError(f"expected a list holding one object, not {metadata!r:.100}")

    return metadata[0]


def _failure_reason(process: SandboxResult) -> str:
    # a file exiftool cannot read still gets its JSON, with the reason in ExifTool:Error and nothing on stderr
    try:
        reason = _read_metadata(process.stdout).get("ExifTool:Error")
    except ValueError:
        reason = None  # nothing was printed for the file (it vanished, or Perl died), so stderr has the reason

    if reason:
        return str(reason)

    # Perl prints its warnings before the line that ended it, and this ends up in the summary
    lines = process.stderr.strip().splitlines()
    if lines:
        return lines[-1][:500]

    # the sandbox exits 128 + N for a command killed by signal N; Perl exits 255 when it dies
    if 128 < process.returncode <= 128 + signal.SIGRTMAX:
        return f"exiftool was killed by signal {process.returncode - 128}"

    return f"exiftool exited with status {process.returncode}"


class ExifAnalyzerConfig(AnalysisModuleConfig):
    timeout: int = Field(..., gt=0, description="Seconds one exiftool run may take before the file is recorded as timed out. Keep it well below maximum_analysis_time, where the worker itself is killed.")


class ExifAnalyzer(AnalysisModule):

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ExifAnalyzerConfig

    def verify_environment(self):
        self.verify_program_exists("exiftool")

    @property
    def generated_analysis_type(self):
        return ExifAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
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
        log_extra = {"alert_uuid": self.get_root().uuid, "path": local_file_path}

        # exiftool has had code execution bugs in its parsers (CVE-2021-22204), so it runs in the sandbox
        process = self.run_sandboxed_tool(["exiftool", "-j", "-G", "-n", local_file_path], local_file_path,
                                          timeout=self.config.timeout)
        if process is None:
            # stopped (a timeout, too much output) or not run at all; the log says which
            analysis.error = "exiftool did not finish"
            return AnalysisExecutionResult.COMPLETED

        if process.returncode != 0:
            analysis.error = _failure_reason(process)
            logging.info(f"Exif data extraction failed for {local_file_path}: {analysis.error}", extra=log_extra)
            return AnalysisExecutionResult.COMPLETED

        try:
            metadata = _read_metadata(process.stdout)
        except ValueError as e:
            # exiftool escapes whatever a file holds into valid JSON, so output it reports success with that
            # does not parse means exiftool itself changed or broke, not that the file is bad
            analysis.error = f"unreadable exiftool output: {e}"
            logging.exception("unreadable exiftool output for %s", local_file_path, extra=log_extra)
            return AnalysisExecutionResult.COMPLETED

        analysis.exifdata = metadata

        target_dir = f"{local_file_path}.exif"
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, "exiftool.out")

        # pformat recurses in Python once per level of nesting, so a crafted file (a PDF /Title of 500 nested
        # arrays) exceeds the recursion limit. repr recurses in C, much deeper than exiftool can nest within its
        # timeout, and writes the same literals the yara rules match on, only without the line breaks
        try:
            exifdata = pprint.pformat(metadata)
        except RecursionError:
            exifdata = repr(metadata)
            logging.info("exiftool metadata of %s is nested too deeply to pretty print, writing it on one line",
                         local_file_path, extra=log_extra)

        with open(target_file, "w") as fp:
            fp.write(exifdata)

        analysis.details["output_dir"] = target_dir
        file_observable = analysis.add_file_observable(target_file)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.add_yara_meta("type", "metadata.exif")
            file_observable.exclude_analysis(FileHashAnalyzer)
            file_observable.exclude_analysis(FileTypeAnalyzer)
            # file_observable.add_tag('exif')

        logging.debug("Exif data collection completed.")

        return AnalysisExecutionResult.COMPLETED
