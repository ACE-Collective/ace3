import logging
import os
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
KEY_DEOBFUSCATED = "deobfuscated"
KEY_EXIT_CODE = "exit_code"

DE4DOT_TIMEOUT_SECONDS = 10
ILSPY_TIMEOUT_SECONDS = 10

# the .NET runtime reads its own /proc/<pid> (memory maps, cgroup) and will not start without it.
# /proc/self in a Landlock rule is the tool's own directory and no other process's: setpriv opens
# it and then execs the tool in the same process
DOTNET_READ_DIRS = ["/proc/self"]
# the GC reserves 256 GB of address space unless it is given a heap limit and a region range, and
# even then the runtime reserves about 5 GB (ilspycmd 5.4 GB, de4dot 4.7 GB) to use a few hundred MB;
# the heap limit is what bounds the memory a tool actually uses
DOTNET_ENV = {"DOTNET_GCHeapHardLimit": "0x40000000", "DOTNET_GCRegionRange": "0x80000000"}
DOTNET_MEMORY_LIMIT = 12 * 1024 ** 3
# what the .NET host starts its output with when the sandbox keeps CoreCLR from starting: no
# /proc/<pid>, or too little address space for its GC
DOTNET_STARTUP_ERRORS = ["Failed to create CoreCLR", "GC heap initialization failed"]

class De4dotAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
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
    def deobfuscated(self):
        return self.details[KEY_DEOBFUSCATED]

    @deobfuscated.setter
    def deobfuscated(self, value):
        self.details[KEY_DEOBFUSCATED] = value

    def generate_summary(self) -> str:
        if self.error:
            return f"{self.display_name} error: {self.error}"

        return f"{self.display_name}: deobfuscated"

class De4dotConfig(AnalysisModuleConfig):
    binary_path: str = Field(default="/opt/de4dotEx/de4dot", description="The de4dot binary itself, not a wrapper script that runs it: the sandbox makes only the binary's own directory readable.")

class De4dotAnalyzer(AnalysisModule):

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return De4dotConfig

    @property
    def generated_analysis_type(self):
        return De4dotAnalysis
    
    def verify_environment(self):
        self.verify_program_exists(self.config.binary_path)

    def _run_de4dot(self, args: list[str], local_file_path: str, outputs: Optional[dict[str, str]] = None):
        # de4dot's dynamic string decrypters can call the sample's own methods
        return self.run_sandboxed_tool([self.config.binary_path, *args], local_file_path, timeout=DE4DOT_TIMEOUT_SECONDS,
                                       read_dirs=DOTNET_READ_DIRS, env=DOTNET_ENV, memory_limit=DOTNET_MEMORY_LIMIT,
                                       outputs=outputs, startup_errors=DOTNET_STARTUP_ERRORS)
    
    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        
        if not os.path.exists(local_file_path):
            return AnalysisExecutionResult.COMPLETED
       
        if not is_dotnet(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        # check for obfuscation with -d first
        result = self._run_de4dot(["-d", local_file_path], local_file_path)
        if result is None or 'Detected' not in result.stdout:
            logging.debug(f"No obfuscation detected for file: {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, De4dotAnalysis)

        output_path = f'{local_file_path}.deobfuscated'
        result = self._run_de4dot([local_file_path, '-o', 'deobfuscated'], local_file_path,
                                  outputs={'deobfuscated': output_path})
        if result is None:
            analysis.error = "de4dot did not finish"
        else:
            analysis.stdout = result.stdout or None
            analysis.stderr = result.stderr or None
            if not os.path.exists(output_path):
                analysis.error = f"{result.failure_reason('de4dot')}, without writing a deobfuscated file"
                logging.info("%s failed on %s: %s", self, local_file_path, analysis.error,
                             extra={"module_name": self.name, "path": local_file_path, "root_uuid": self.get_root().uuid})

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

        if self.error:
            return f"{result}: failed: {self.error}"

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

        # ilspycmd writes stdout a few bytes per write(), which on a slow filesystem (a macOS bind mount: 38
        # seconds for 2.7 MB of IL) outlasts the timeout; given -o it writes its file through a buffered
        # stream, named after the input. with -o it also checks for a newer release over the network
        # unless told not to
        il_name = f"{os.path.splitext(os.path.basename(_file.full_path))[0]}.il"
        result = self.run_sandboxed_tool([self.binary_path, "-il", "--disable-updatecheck", "-o", ".", _file.full_path],
                                         _file.full_path, timeout=ILSPY_TIMEOUT_SECONDS, read_dirs=DOTNET_READ_DIRS,
                                         env=DOTNET_ENV, memory_limit=DOTNET_MEMORY_LIMIT,
                                         outputs={il_name: target_path}, startup_errors=DOTNET_STARTUP_ERRORS)
        if result is None:
            analysis.error = "ilspy did not finish"
            return AnalysisExecutionResult.COMPLETED

        analysis.exit_code = result.returncode
        analysis.stderr = result.stderr or None

        if not os.path.exists(target_path):
            analysis.error = f"{result.failure_reason('ilspy')}, without writing IL"
            logging.info("%s failed on %s: %s", self, _file.full_path, analysis.error,
                         extra={"module_name": self.name, "path": _file.full_path, "root_uuid": self.get_root().uuid})
            return AnalysisExecutionResult.COMPLETED

        file_observable = analysis.add_file_observable(target_path, volatile=True)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.add_yara_meta("type", "script.dotnet.decompiled")
            file_observable.redirection = _file
            file_observable.exclude_analysis(self)
            file_observable.exclude_analysis(FileHashAnalyzer)
            file_observable.exclude_analysis(FileTypeAnalyzer)

        return AnalysisExecutionResult.COMPLETED