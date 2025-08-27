import logging
import os.path
from typing import override

from saq.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE, DIRECTIVE_ORIGINAL_EMAIL, R_EXTRACTED_FROM
from saq.modules import AnalysisModule
from saq.mime_extractor import parse_mime, parse_active_mime
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary

KEY_EXTRACTED_FILES = "extracted_files"

class HiddenMIMEAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_EXTRACTED_FILES: []
        }

    @override
    @property
    def display_name(self) -> str:
        return "Hidden MIME Analysis"

    @property
    def extracted_files(self) -> list[str]:
        return self.details[KEY_EXTRACTED_FILES]

    @extracted_files.setter
    def extracted_files(self, value: list[str]):
        self.details[KEY_EXTRACTED_FILES] = value

    def generate_summary(self) -> str:
        if not self.extracted_files:
            return None

        return f"{self.display_name}: extracted {format_item_list_for_summary(self.extracted_files)}"

class HiddenMIMEAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return HiddenMIMEAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        # do not run this on 
        # - emails
        if _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
            return AnalysisExecutionResult.COMPLETED

        if _file.file_name == "email.rfc822":
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is not None and file_type_analysis.mime_type == "message/rfc822":
            return AnalysisExecutionResult.COMPLETED

        if file_type_analysis is not None and file_type_analysis.is_email_file:
            return AnalysisExecutionResult.COMPLETED

        target_dir = f"{local_file_path}.mime"
        extracted_files = parse_mime(local_file_path, target_dir)
        if not extracted_files:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        analysis.extracted_files = extracted_files
        for file_path in analysis.extracted_files:
            file_observable = analysis.add_file_observable(file_path)
            if file_observable:
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)

        return AnalysisExecutionResult.COMPLETED

KEY_EXTRACTED_FILE = "extracted_file"

class ActiveMimeAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_EXTRACTED_FILE: []
        }

    @override
    @property
    def display_name(self) -> str:
        return "Active MIME Analysis"

    @property
    def extracted_file(self) -> list[str]:
        return self.details[KEY_EXTRACTED_FILE]

    @extracted_file.setter
    def extracted_file(self, value: list[str]):
        self.details[KEY_EXTRACTED_FILE] = value

    def generate_summary(self) -> str:
        if not self.extracted_file:
            return None

        return f"{self.display_name}: extracted {self.extracted_file}"

class ActiveMimeAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return ActiveMimeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        target_path = f"{local_file_path}.activemime"
        if parse_active_mime(local_file_path, target_path):
            analysis = self.create_analysis(_file)
            assert isinstance(analysis, ActiveMimeAnalysis)

            analysis.extracted_file = target_path
            file_observable = analysis.add_file_observable(target_path)
            if file_observable:
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                file_observable.add_tag("activemime")

        return AnalysisExecutionResult.COMPLETED
