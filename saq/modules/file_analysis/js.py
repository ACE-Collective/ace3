import logging
import os
from subprocess import PIPE, Popen
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_javascript_file
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


class SynchronyFileAnalysis(Analysis):

    KEY_EXTRACTED_FILES = "extracted_files"
    KEY_STDOUT = "stdout"
    KEY_STDERR = "stderr"
    KEY_RETURNCODE = "returncode"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            SynchronyFileAnalysis.KEY_EXTRACTED_FILES: [],
            SynchronyFileAnalysis.KEY_STDOUT: None,
            SynchronyFileAnalysis.KEY_STDERR: None,
            SynchronyFileAnalysis.KEY_RETURNCODE: None,
        }

    @property
    def extracted_files(self):
        if self.details is None:
            return []

        return self.details.get(SynchronyFileAnalysis.KEY_EXTRACTED_FILES, [])

    @property
    def stdout(self):
        if self.details is None:
            return None

        return self.details.get(SynchronyFileAnalysis.KEY_STDOUT)

    @stdout.setter
    def stdout(self, value):
        self.details[SynchronyFileAnalysis.KEY_STDOUT] = value

    @property
    def stderr(self):
        if self.details is None:
            return None

        return self.details.get(SynchronyFileAnalysis.KEY_STDERR)

    @stderr.setter
    def stderr(self, value):
        self.details[SynchronyFileAnalysis.KEY_STDERR] = value

    @property
    def returncode(self):
        if self.details is None:
            return None

        return self.details.get(SynchronyFileAnalysis.KEY_RETURNCODE)

    @returncode.setter
    def returncode(self, value):
        self.details[SynchronyFileAnalysis.KEY_RETURNCODE] = value

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if self.returncode != 0:
            return None

        if not self.extracted_files:
            return None

        return "Synchrony JS Deobfuscator: extracted files " + format_item_list_for_summary(self.extracted_files)

class SynchronyFileAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return SynchronyFileAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path
        # do not analyze the output of this module
        if _file.file_name.startswith("synchrony-"):
            return AnalysisExecutionResult.COMPLETED

        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        # do not analyze JSON files
        if _file.file_name.endswith(".json"):
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is not None and file_type_analysis.mime_type == "application/json":
            return AnalysisExecutionResult.COMPLETED

        # do not analyze exif output
        if _file.file_name == "exiftool.out":
            return AnalysisExecutionResult.COMPLETED

        if not is_javascript_file(local_file_path):
            logging.debug(f"local file {local_file_path} is not a javascript file")
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag("js")

        analysis = self.create_analysis(_file)
        local_file_dir = os.path.dirname(local_file_path)
        local_file_name = os.path.basename(local_file_path)
        target_path = os.path.join(local_file_dir, f"synchrony-{local_file_name}")
        if os.path.exists(target_path):
            logging.warning(f"target file {target_path} already exists")
            return AnalysisExecutionResult.COMPLETED

        logging.info("running synchrony on %s", local_file_path)
        p = Popen(["synchrony", "-o", target_path, local_file_path], stdout=PIPE, stderr=PIPE)
        analysis.stdout, analysis.stderr = p.communicate()
        analysis.returncode = p.returncode

        if os.path.exists(target_path):
            o_file = analysis.add_file_observable(target_path, volatile=True)
            if o_file:
                o_file.add_relationship(R_EXTRACTED_FROM, _file)
                o_file.exclude_analysis(self)
                analysis.extracted_files.append(o_file.file_path)

        return AnalysisExecutionResult.COMPLETED