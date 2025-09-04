import logging
import os
from subprocess import PIPE, Popen, TimeoutExpired
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_dotnet
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


KEY_STDOUT = "stdout"
KEY_STDERR = "stderr"
KEY_ERROR = "error"
KEY_DEOBFUSCATED = "deobfuscated"
KEY_EXTRACTED_FILES = "extracted_files"

class De4dotAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_ERROR: None,
            KEY_DEOBFUSCATED: False,
            KEY_EXTRACTED_FILES: [],
        }

    @override
    @property
    def display_name(self) -> str:
        return "De4dot Analysis"

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
    def deobfuscated(self):
        return self.details[KEY_DEOBFUSCATED]

    @deobfuscated.setter
    def deobfuscated(self, value):
        self.details[KEY_DEOBFUSCATED] = value

    @property
    def extracted_files(self) -> list[str]:
        return self.details[KEY_EXTRACTED_FILES]

    @extracted_files.setter
    def extracted_files(self, value: list[str]):
        self.details[KEY_EXTRACTED_FILES] = value

    def generate_summary(self) -> str:
        if self.error:
            return f"{self.display_name} error: {self.error}"
        
        if not self.extracted_files:
            return None

        return f"{self.display_name}: extracted ({format_item_list_for_summary(self.extracted_files)})"

class De4dotAnalyzer(AnalysisModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def generated_analysis_type(self):
        return De4dotAnalysis
    
    def verify_environment(self):
        self.verify_program_exists("de4dot")
    
    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED
       
        # Check if we've already analyzed this file to prevent infinite loop
        if "dotnet_deobfuscated" in local_file_path:
            return AnalysisExecutionResult.COMPLETED

        # Check if file is a .NET exe
        if not is_dotnet(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        # Identify if .NET exe is obfuscated with de4dot
        stdout = b''

        try:
            # Check for obfuscation with -d first
            p = Popen(['de4dot', '-d', local_file_path], stdout=PIPE, stderr=PIPE)

            try:
                stdout, stdint = p.communicate(timeout=10)
            except TimeoutExpired:
                logging.warning("de4dot timed out on {}".format(local_file_path))
                p.kill()
                _, stderr = p.communicate()
        except Exception:
            # analysis.details['error'] = str(e)
            logging.info(f'de4dot analysis failed for {local_file_path}')
            return AnalysisExecutionResult.COMPLETED

        if b'Detected' not in stdout:
            logging.debug(f"No obfuscation detected for file: {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, De4dotAnalysis)

        output_path = f'{local_file_path}.deobfuscated'
        filename = local_file_path.split('/')[-1]
        out_file = f'{output_path}/dotnet_deobfuscated_{filename}'
        # If exe is obfuscated, deobfuscate with de4dot
        try:
            # Deobfuscate (de4dot requires you give the full output path/filename
            p = Popen(['de4dot', local_file_path, '-o', out_file], stdout=PIPE, stderr=PIPE)

            try:
                _, _ = p.communicate(timeout=10)
            except TimeoutExpired:
                logging.warning("de4dot timed out on {}".format(local_file_path))
                p.kill()
                _, stderr = p.communicate()

        except Exception as e:
            analysis.details['error'] = str(e)
            logging.info(f'de4dot analysis failed for {local_file_path}')
        
        # Add any extracted files as file observables
        for f in os.listdir(output_path):
            if f.startswith('dotnet_deobfuscated'):
                analysis.details['deobfuscated'] = True
                full_path = os.path.join(output_path, f)
                file_observable = analysis.add_file_observable(full_path)
                if file_observable:
                    file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                    file_observable.redirection = _file
                    analysis.extracted_files.append(file_observable.file_path)
            

        logging.debug('de4dot Analysis succeeded')

        return AnalysisExecutionResult.COMPLETED