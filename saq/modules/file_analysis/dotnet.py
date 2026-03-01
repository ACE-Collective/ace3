import logging
import os
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Optional, Type, override

from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_dotnet
from saq.observables.file import FileObservable

from saq.modules.file_analysis.hash import FileHashAnalyzer
from saq.modules.file_analysis.file_type import FileTypeAnalyzer


KEY_STDOUT = "stdout"
KEY_STDERR = "stderr"
KEY_ERROR = "error"
KEY_DEOBFUSCATED = "deobfuscated"
KEY_EXIT_CODE = "exit_code"

class De4dotAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_ERROR: None,
            KEY_DEOBFUSCATED: False,
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

    def generate_summary(self) -> str:
        if self.error:
            return f"{self.display_name} error: {self.error}"

        return f"{self.display_name}: deobfuscated"

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
            return AnalysisExecutionResult.COMPLETED
       
        if not is_dotnet(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        stdout = b''

        try:
            # check for obfuscation with -d first
            process = Popen(['de4dot', '-d', local_file_path], stdout=PIPE, stderr=PIPE)

            try:
                stdout, stderr = process.communicate(timeout=10)
            except TimeoutExpired:
                logging.warning("de4dot timed out on {}".format(local_file_path))
                process.kill()
                _, stderr = process.communicate()
        except Exception as e:
            logging.info(f'de4dot analysis failed for {local_file_path}: {e}')
            return AnalysisExecutionResult.COMPLETED

        if b'Detected' not in stdout:
            logging.debug(f"No obfuscation detected for file: {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, De4dotAnalysis)

        output_path = f'{local_file_path}.deobfuscated'

        try:
            process = Popen(['de4dot', local_file_path, '-o', output_path], stdout=PIPE, stderr=PIPE)

            try:
                stdout, stderr = process.communicate(timeout=10)
                analysis.stdout = stdout.decode("utf-8", errors="ignore") if stdout else None
                analysis.stderr = stderr.decode("utf-8", errors="ignore") if stderr else None
            except TimeoutExpired:
                logging.warning("de4dot timed out on {}".format(local_file_path))
                process.kill()
                _, _ = process.communicate()

        except Exception as e:
            analysis.error = str(e)
            logging.info(f'de4dot analysis failed for {local_file_path}')
        
        analysis.details['deobfuscated'] = True
        file_observable = analysis.add_file_observable(output_path, volatile=True)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.add_yara_meta("type", "executable.dotnet")
            file_observable.redirection = _file
            file_observable.exclude_analysis(self)
            file_observable.exclude_analysis(FileHashAnalyzer)
            file_observable.exclude_analysis(FileTypeAnalyzer)

        return AnalysisExecutionResult.COMPLETED

class IlspyConfig(AnalysisModuleConfig):
    binary_path: str = Field(..., description="The path to the ilspy binary.")

class IlspyAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDERR: None,
            KEY_EXIT_CODE: None,
        }

    @property
    def exit_code(self) -> Optional[int]:
        return self.details[KEY_EXIT_CODE]

    @exit_code.setter
    def exit_code(self, value: int):
        self.details[KEY_EXIT_CODE] = value

    @property
    def stderr(self) -> Optional[str]:
        return self.details[KEY_STDERR]

    @stderr.setter
    def stderr(self, value: str):
        self.details[KEY_STDERR] = value

    @override
    def generate_summary(self) -> Optional[str]:
        result = "Ilspy Analysis"

        if self.exit_code is not None:
            result += f": exit code {self.exit_code}"

        if self.stderr:
            result += f": stderr: {self.stderr}"

        return result

class IlspyAnalyzer(AnalysisModule):

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return IlspyConfig

    @property
    def generated_analysis_type(self):
        return IlspyAnalysis
    
    def verify_environment(self):
        self.verify_program_exists(self.binary_path)
    
    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def binary_path(self) -> str:
        return self.config.binary_path

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        if not _file.exists:
            return AnalysisExecutionResult.COMPLETED

        if not is_dotnet(_file.full_path):
            return AnalysisExecutionResult.COMPLETED

        target_path = self.get_root().create_file_path(f"{_file.file_name}_ilspy.il")
        if os.path.exists(target_path):
            for index in range(1024): # put a limit on this just in case something goes wrong
                target_path = self.get_root().create_file_path(f"{_file.file_name}_ilspy_{index}.il")
                if not os.path.exists(target_path):
                    break

        # stil didn't get an empty file path?
        if os.path.exists(target_path):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, IlspyAnalysis)

        with open(target_path, "wb") as fp:
            try:
                process = Popen([self.binary_path, "-il", _file.full_path], stdout=fp, stderr=PIPE)
                _, stderr = process.communicate(timeout=10)
            except TimeoutExpired:
                logging.warning("ilspy timed out on {}".format(_file.full_path))
                process.kill()
                _, stderr = process.communicate()
            except Exception as e:
                analysis.stderr = str(e)
                logging.info(f'ilspy analysis failed for {_file.full_path}')
                return AnalysisExecutionResult.COMPLETED

        analysis.exit_code = process.returncode
        analysis.stderr = stderr.decode("utf-8", errors="ignore") if stderr else None

        file_observable = analysis.add_file_observable(target_path, volatile=True)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.add_yara_meta("type", "script.dotnet.decompiled")
            file_observable.redirection = _file
            file_observable.exclude_analysis(self)
            file_observable.exclude_analysis(FileHashAnalyzer)
            file_observable.exclude_analysis(FileTypeAnalyzer)

        return AnalysisExecutionResult.COMPLETED