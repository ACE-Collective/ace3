from datetime import datetime
import logging
import os
import shutil
from typing import Optional, Type, override
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_java_class_file
from saq.observables.file import FileObservable

CFR_JAR = "/usr/local/bin/cfr.jar"

# the JVM reserves more address space than the sandbox's memory limit unless it is told how much heap
# and class space to reserve, and then fails to start one time in three
JVM_OPTIONS = ["-Xmx1g", "-XX:CompressedClassSpaceSize=128m", "-XX:ReservedCodeCacheSize=128m", "-XX:-UsePerfData"]

# what the JVM starts its output with when the sandbox keeps it from starting: too little address
# space for its heap, or no readable java.security
JVM_STARTUP_ERRORS = ["Error occurred during initialization of VM",
                      'Exception in thread "main" java.lang.InternalError: Error loading java.security file']


def jvm_conf_dirs() -> list[str]:
    """Where the JVM's configuration really is: Debian links the files in its conf directory into
    /etc/java-<version>-openjdk, which the sandbox does not make readable on its own, and the JVM
    cannot start without java.security."""
    java = shutil.which("java")
    if java is None:
        return []

    java_security = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(java))), "conf", "security",
                                 "java.security")
    conf = os.path.dirname(os.path.dirname(os.path.realpath(java_security)))
    if os.path.isfile(java_security) and os.path.isdir(conf):
        return [conf]

    logging.warning("cannot find the configuration of the JVM %s (no %s): it will not start in the sandbox",
                    java, java_security)
    return []


def strip_banner(source: str) -> str:
    """Removes the comment blocks cfr starts its output with: every block from a line starting with
    "/*" to the next line starting with " */", which a sed script used to cut."""
    lines = []
    in_comment = False
    for line in source.splitlines(keepends=True):
        if in_comment:
            in_comment = not line.startswith(" */")
        elif line.startswith("/*"):
            in_comment = True
        else:
            lines.append(line)

    return "".join(lines)


KEY_DECOMPILED_FILES = 'decompiled_files'

class JavaClassDecompilerAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_DECOMPILED_FILES: [],
        }

    @override
    @property
    def display_name(self):
        return "Java Class Decompiler"

    @property
    def decompiled_files(self):
        return self.details[KEY_DECOMPILED_FILES]

    @decompiled_files.setter
    def decompiled_files(self, value):
        self.details[KEY_DECOMPILED_FILES] = value


class JavaClassDecompilerConfig(AnalysisModuleConfig):
    timeout: int = Field(default=30, description="The maximum amount of time (in seconds) to wait for the decompiler to complete.")

class JavaClassDecompilerAnalysisModule(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return JavaClassDecompilerConfig

    @property
    def timeout(self):
        """The maximum amount of time (in seconds) to wait for the decompiler to complete."""
        return self.config.timeout

    def decompile_class_file(self, class_file: str) -> Optional[str]:
        """Decompiles class_file into class_file-N-decompiled.java next to it, where N makes the name
        unique, and returns its path; None if the decompilation failed."""
        # make sure the class file exists
        if not os.path.exists(class_file):
            logging.error(f"class file {class_file} does not exist")
            return None

        start_time = datetime.now()
        result = self.run_sandboxed_tool(["java", *JVM_OPTIONS, "-jar", CFR_JAR, class_file], class_file,
                                         timeout=self.timeout, read_dirs=jvm_conf_dirs(),
                                         startup_errors=JVM_STARTUP_ERRORS)
        if result is None:
            return None

        # cfr exits 0 for a file it cannot decompile; anything else is a crash, and its output is not source
        if result.returncode != 0:
            logging.info(f"decompilation of {class_file} exited with {result.returncode}: {result.stderr.strip()[-500:]}")
            return None

        source = strip_banner(result.stdout)
        if not source:
            logging.info(f"decompilation of {class_file} returned nothing: {result.stderr.strip()[-500:]}")
            return None

        counter = 0
        output_file = f"{class_file}-{counter}-decompiled.java"
        while os.path.exists(output_file):
            counter += 1
            output_file = f"{class_file}-{counter}-decompiled.java"

        with open(output_file, "w") as fp:
            fp.write(source)

        logging.info(f"decompiled {class_file} in {(datetime.now() - start_time).total_seconds()} seconds")
        return output_file

    @override
    @property
    def generated_analysis_type(self):
        return JavaClassDecompilerAnalysis
    
    @override
    @property
    def valid_observable_types(self):
        return F_FILE

    @override
    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        assert isinstance(observable, FileObservable)

        # make sure the file exists
        if not observable.exists:
            return AnalysisExecutionResult.COMPLETED

        # ignore empty files
        if observable.size == 0:
            return AnalysisExecutionResult.COMPLETED

        # make sure the file is a java class file
        if not is_java_class_file(observable.full_path):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, JavaClassDecompilerAnalysis)

        # attempt to decompile the java class file
        decompiled_file = self.decompile_class_file(observable.full_path)
        if decompiled_file:
            # add the decompiled file as an observable
            decompiled_file_observable = analysis.add_file_observable(decompiled_file)
            if decompiled_file_observable:
                decompiled_file_observable.add_tag("decompiled")
                decompiled_file_observable.add_yara_meta("type", "script.java.decompiled")
                analysis.decompiled_files.append(decompiled_file)

            return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED