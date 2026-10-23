import logging
import os
from subprocess import PIPE, Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_autoit
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


KEY_STDOUT = "stdout"
KEY_STDERR = "stderr"
KEY_ERROR = "error"
KEY_SCRIPTS = "scripts"
KEY_OUTPUT_DIR = "output_dir"

class AutoItAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_ERROR: None,
            KEY_SCRIPTS: [],
            KEY_OUTPUT_DIR: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "AutoIt Analysis"

    @property
    def stdout(self):
        return self.details[KEY_STDOUT]

    @stdout.setter
    def stdout(self, value):
        self.details[KEY_STDOUT] = value

    @property
    def stderr(self):
        return self.details[KEY_STDERR]

    @stderr.setter
    def stderr(self, value):
        self.details[KEY_STDERR] = value

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def scripts(self) -> list[str]:
        return self.details[KEY_SCRIPTS]

    @scripts.setter
    def scripts(self, value: list[str]):
        self.details[KEY_SCRIPTS] = value

    @property
    def output_dir(self):
        return self.details[KEY_OUTPUT_DIR]

    @output_dir.setter
    def output_dir(self, value):
        self.details[KEY_OUTPUT_DIR] = value

    def generate_summary(self) -> str:
        if self.error:
            return f"{self.display_name}: {self.error}"

        if not self.scripts:
            return None

        return f"{self.display_name}: decompiled {format_item_list_for_summary(self.scripts)}"

class AutoItAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('unautoit')

    @property
    def generated_analysis_type(self):
        return AutoItAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def custom_requirement(self, observable: Observable) -> bool:
        local_file_path = observable.full_path
        if not os.path.exists(local_file_path) or os.path.getsize(local_file_path) == 0:
            return False

        return is_autoit(local_file_path)

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # custom_requirement already confirmed this is an autoit file
        _file.add_tag('autoit')

        analysis = self.create_analysis(_file)
        output_path = f'{local_file_path}.autoit'
        analysis.output_dir = output_path
        try:
            # Store the "unautoit list" in the analysis details
            analysis.stdout, analysis.stderr = Popen(['unautoit', 'list', local_file_path], stdout=PIPE, stderr=PIPE).communicate()

            # Decompile the executable.
            # unautoit only creates the output dir once it has parsed the file, and the listing below needs it to
            # exist even when parsing fails.
            os.makedirs(output_path)
            _, _ = Popen(['unautoit', 'extract-all', '--output-dir', output_path, local_file_path], stdout=PIPE, stderr=PIPE).communicate()
        except Exception as e:
            analysis.error = str(e)
            logging.info(f'AutoIt decompilation failed for {local_file_path}')

        # Add any decompiled .au3 scripts as file observables
        for f in os.listdir(output_path):
            if f.endswith('.au3'):
                analysis.scripts.append(f)
                full_path = os.path.join(output_path, f)
                file_observable = analysis.add_file_observable(full_path, volatile=True)
                if file_observable:
                    file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                    file_observable.add_tag('autoit')
                    file_observable.add_yara_meta("type", "script.autoit")
                    # avoid recursion -- no idea if this is possible but would rather avoid it
                    file_observable.exclude_analysis(self)

        return AnalysisExecutionResult.COMPLETED