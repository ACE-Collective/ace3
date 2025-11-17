import logging
import os
from typing import Optional, List, override

from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import ANALYSIS_MODE_CORRELATION, DIRECTIVE_CRAWL, DIRECTIVE_RENDER, F_URL, F_FILE, AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.phishkit import get_async_scan_result, scan_file, scan_url
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

SCAN_TYPE_URL = "url"
SCAN_TYPE_FILE = "file"


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

    def generate_summary(self):
        if self.error:
            return f"{self.display_name}: failed: {self.error}"
        
        if self.scan_type == SCAN_TYPE_URL or self.scan_type == SCAN_TYPE_FILE:
            return f"{self.display_name}: output files created (" + format_item_list_for_summary(self.output_files) + ")"
        else:
            return f"{self.display_name}: completed"


class PhishkitAnalyzer(AnalysisModule):
    """Analyzes URLs and files using Phishkit for phishing detection."""

    @property
    def generated_analysis_type(self):
        return PhishkitAnalysis

    @property
    def valid_observable_types(self):
        return [F_URL, F_FILE]

    def verify_environment(self):
        """Verify that the required configuration exists."""
        self.verify_config_item_has_value('valid_file_extensions')
        self.verify_config_item_has_value('valid_mime_types')

    def custom_requirement(self, observable: Observable) -> bool:
        """Custom requirement for phishkit analysis."""
        if observable.type == F_URL:
            return True
        elif observable.type == F_FILE:
            # phishkit file rendering only meaningful in correlation mode
            return self.get_root().analysis_mode == ANALYSIS_MODE_CORRELATION
        else:
            return False

    def continue_analysis(self, observable: Observable, analysis: PhishkitAnalysis) -> AnalysisExecutionResult:
        """Completes an existing analysis."""
        if not analysis.job_id:
            logging.error(f"no job ID for analysis {analysis}")
            return AnalysisExecutionResult.COMPLETED
        
        # wait for the job to complete
        logging.info(f"checking for phishkit scan results for {observable} job ID {analysis.job_id}")
        scan_results = get_async_scan_result(analysis.job_id, analysis.output_dir, timeout=1)
        if scan_results is None:
            logging.info(f"scan results not ready yet for {observable} job ID {analysis.job_id}")
            return self.delay_analysis(observable, analysis, seconds=3, timeout_seconds=60)

        # if we get this far then the scan results are ready
        analysis.scan_result = f"successfully scanned {observable}"
        analysis.error = None

        for file_path in scan_results:
            if not os.path.exists(file_path):
                logging.error(f"file {file_path} does not exist for {observable} job ID {analysis.job_id}")
                continue

            if os.path.basename(file_path) == "exit.code":
                with open(file_path, "r") as fp:
                    analysis.exit_code = int(fp.read())
            elif os.path.basename(file_path) == "std.out":
                with open(file_path, "r") as fp:
                    analysis.stdout = fp.read()
            elif os.path.basename(file_path) == "std.err":
                with open(file_path, "r") as fp:
                    analysis.stderr = fp.read()
            else:
                relative_path = os.path.join("phishkit", analysis.job_id, os.path.relpath(file_path, analysis.output_dir))
                file_observable = analysis.add_file_observable(file_path, relative_path)
                if file_observable:
                    from saq.modules.file_analysis.pdf import PDFAnalyzer
                    # do not send phishkit output to phishkit
                    file_observable.exclude_analysis(self)
                    file_observable.exclude_analysis(PDFAnalyzer)
                    #file_observable.add_directive(DIRECTIVE_EXCLUDE_ALL)
                    analysis.output_files.append(file_observable.file_path)


                # TODO follow the logic of the existing crawlphish module here

        return AnalysisExecutionResult.COMPLETED

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        # if the observable is a file, we need to check if the file type is enabled for scanning
        if observable.type == F_FILE:
            if not observable.has_directive(DIRECTIVE_RENDER):
                logging.debug(f"skipping file {observable} - render directive not found")
                return AnalysisExecutionResult.COMPLETED

            # by default we do not accept files for phishkit analysis
            file_accepted = False

            # first check the file extension
            assert isinstance(observable, FileObservable)
            file_extension = os.path.splitext(observable.file_name)[1].lower()
            if file_extension in self.config['valid_file_extensions']:
                logging.debug(f"file {observable} extension {file_extension} enabled for phishkit analysis")
                file_accepted = True

            # then check the mime type
            from saq.modules.file_analysis import FileTypeAnalysis
            file_type_analysis = self.wait_for_analysis(observable, FileTypeAnalysis)

            if file_type_analysis is not None and file_type_analysis.mime_type in self.config['valid_mime_types']:
                file_accepted = True
                logging.debug(f"file {observable} mime type {file_type_analysis.mime_type} enabled for phishkit analysis")

            if not file_accepted:
                logging.debug(f"file {observable} not accepted for phishkit analysis")
                return AnalysisExecutionResult.COMPLETED

        if observable.type == F_URL:
            # urls require crawl directives
            if not observable.has_directive(DIRECTIVE_CRAWL):
                logging.debug(f"skipping URL {observable} - crawl directive not found")
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, PhishkitAnalysis)

        # create a temporary directory to store the output files
        analysis.output_dir = create_temporary_directory()

        if observable.type == F_URL:
            logging.info(f"executing phishkit URL scan for {observable}")
            analysis.scan_type = SCAN_TYPE_URL
            
            try:
                analysis.job_id = scan_url(observable.value, analysis.output_dir, is_async=True)
                self.delay_analysis(observable, analysis, seconds=5, timeout_seconds=60)
                
            except Exception as e:
                error_msg = f"failed to scan URL {observable.value}: {str(e)}"
                logging.error(error_msg)
                analysis.error = error_msg
                return AnalysisExecutionResult.COMPLETED

        elif observable.type == F_FILE:
            logging.info(f"executing phishkit file scan for {observable.value}")
            analysis.scan_type = SCAN_TYPE_FILE
            
            try:
                analysis.job_id = scan_file(observable.full_path, analysis.output_dir, is_async=True)
                return self.delay_analysis(observable, analysis, seconds=5, timeout_seconds=60)
                
            except Exception as e:
                error_msg = f"Failed to scan file {observable.value}: {str(e)}"
                logging.error(error_msg)
                report_exception()
                analysis.error = error_msg
                return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED
