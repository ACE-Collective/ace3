import logging
import os
from subprocess import Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable

KEY_ANALYSIS_OUTPUT = "analysis_output"

class MicrosoftScriptEncodingAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ANALYSIS_OUTPUT: None
        }

    @override
    @property
    def display_name(self) -> str:
        return "Microsoft Script Encoding Analysis"

    @property
    def analysis_output(self):
        return self.details[KEY_ANALYSIS_OUTPUT]

    @analysis_output.setter
    def analysis_output(self, value):
        self.details[KEY_ANALYSIS_OUTPUT] = value

    def generate_summary(self):
        if self.details:
            return f'{self.display_name}: {self.analysis_output}'

        return None

class MicrosoftScriptEncodingAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('decryption_program')
        self.verify_path_exists(self.config['decryption_program'])

    @property
    def decryption_program(self):
        path = self.config['decryption_program']
        if os.path.isabs(path):
            return path
        return os.path.join(get_base_dir(), path)

    @property
    def generated_analysis_type(self):
        return MicrosoftScriptEncodingAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return AnalysisExecutionResult.COMPLETED

        # these things start with #@~^
        with open(local_file_path, 'rb') as fp:
            header_bytes = fp.read(4)
            if header_bytes != b'#@~^':
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, MicrosoftScriptEncodingAnalysis)

        # weird enough
        _file.add_tag('microsoft_script_encoding')
        _file.add_directive(DIRECTIVE_SANDBOX)

        # attempt to decode it
        output_path = '{}.decrypted'.format(local_file_path)
        stderr_path = '{}.decrypted.stderr'.format(local_file_path)
        if local_file_path.lower().endswith('.vbe'):
            output_path = '{}.vbs'.format(output_path)
        if local_file_path.lower().endswith('.jse'):
            output_path = '{}.js'.format(output_path)

        logging.debug("attempting to decode microsoft script encoded file {} to {}".format(local_file_path, output_path))
        with open(output_path, 'wb') as fp_out:
            with open(stderr_path, 'wb') as fp_err:
                p = Popen([self.decryption_program, local_file_path], stdout=fp_out, stderr=fp_err)
                p.communicate()
                p.wait()

        if os.path.getsize(output_path):
            file_observable = analysis.add_file_observable(output_path, volatile=True)
            if file_observable:
                file_observable.redirection = _file
            analysis.analysis_output = file_observable.file_path

        return AnalysisExecutionResult.COMPLETED