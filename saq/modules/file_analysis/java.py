from datetime import datetime
import logging
import os
from subprocess import PIPE, Popen
from typing import Optional, override
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.modules.base_module import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_java_class_file
from saq.observables.file import FileObservable

class DecompileFailedError(Exception):
    pass

def decompile_java_class_file(class_file: str, timeout: float = 30) -> Optional[str]:
    """Decompiles a given java class file into a file in the given output_directory named
    class_file-N-decompiled.java
    where N makes the file name unique.

    Returns the path to the decompiled java file, or, None if the decompliation failed."""

    java = None
    sed = None
    output_file = None

    # make sure the class file exists
    if not os.path.exists(class_file):
        logging.error(f"class file {class_file} does not exist")
        return None

    try:
        # generate a unique output file path
        counter = 0
        output_file = f"{class_file}-{counter}-decompiled.java"
        while os.path.exists(output_file):
            counter += 1
            output_file = f"{class_file}-{counter}-decompiled.java"

    except Exception as e:
        logging.error(f"unable to create output file path: {e}")
        return None
            
    try:
        start_time = datetime.now()
        with open(output_file, 'w') as fp:
            # strip the banner out that this java tool generates
            sed = Popen(['sed', '-e', r'/^\/\*/,/^ \*\// d'], stdin=PIPE, stdout=fp)
            java = Popen(['java', '-jar', '/usr/local/bin/cfr.jar', class_file], stdout=sed.stdin, stderr=PIPE)

            (_, stderr) = sed.communicate(timeout=timeout) # NOTE the high timeout here
            sed.wait(timeout=timeout)
            sed = None
            java.wait(timeout=timeout)
            java = None

        end_time = datetime.now()
        logging.info(f"decompiled {class_file} in {(end_time - start_time).total_seconds()} seconds")

        if os.path.getsize(output_file) == 0:
            logging.warning(f"decompilation of {class_file} returned nothing")
            raise DecompileFailedError(f"decompilation of {class_file} returned nothing")

        return output_file

    except Exception as e:
        logging.info(f"failed to extract java from {class_file}: {e}")

        # this file gets created no matter what
        # delete it if something went wrong
        if output_file:
            try:
                if os.path.exists(output_file):
                    os.remove(output_file)
            except Exception as e:
                logging.error(f"unable to remove {output_file}: {e}")

        return None

    finally:
        # make sure child pids are reaped
        for process in [ java, sed ]:
            try:
                if process:
                    process.kill()
            except Exception:
                pass

            try:
                if process:
                    process.wait()
            except Exception:
                pass


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


class JavaClassDecompilerAnalysisModule(AnalysisModule):
    @property
    def timeout(self):
        """The maximum amount of time (in seconds) to wait for the decompiler to complete."""
        return self.config.getint("timeout", fallback=30)

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
        decompiled_file = decompile_java_class_file(observable.full_path, self.timeout)
        if decompiled_file:
            # add the decompiled file as an observable
            decompiled_file_observable = analysis.add_file_observable(decompiled_file)
            if decompiled_file_observable:
                decompiled_file_observable.add_tag("decompiled")
                analysis.decompiled_files.append(decompiled_file)

            return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED