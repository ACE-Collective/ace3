import logging
from mmap import PROT_READ, mmap
import os
from subprocess import Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_office_file
from saq.observables.file import FileObservable


KEY_TOTAL_HEX_STRINGS = "total_hex_strings"
KEY_LARGEST_HEX_STRING = "largest_hex_string"
KEY_PERCENTAGE_OF_HEX_STRINGS = "percentage_of_hex_strings"

class VBScriptAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_TOTAL_HEX_STRINGS: None,
            KEY_LARGEST_HEX_STRING: None,
            KEY_PERCENTAGE_OF_HEX_STRINGS: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "VBScript Analysis"

    @property
    def total_hex_strings(self):
        return self.details[KEY_TOTAL_HEX_STRINGS]

    @total_hex_strings.setter
    def total_hex_strings(self, value):
        self.details[KEY_TOTAL_HEX_STRINGS] = value

    @property
    def largest_hex_string(self):
        return self.details[KEY_LARGEST_HEX_STRING]

    @largest_hex_string.setter
    def largest_hex_string(self, value):
        self.details[KEY_LARGEST_HEX_STRING] = value

    @property
    def percentage_of_hex_strings(self):
        return self.details[KEY_PERCENTAGE_OF_HEX_STRINGS]

    @percentage_of_hex_strings.setter
    def percentage_of_hex_strings(self, value):
        self.details[KEY_PERCENTAGE_OF_HEX_STRINGS] = value

    def generate_summary(self):
        if not self.total_hex_strings:
            return None

        return f"{self.display_name}: {self.total_hex_strings} total hex strings, {self.largest_hex_string} largest hex string, {self.percentage_of_hex_strings}% percentage of file is hex strings"

class VBScriptAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return VBScriptAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def large_hex_string_size(self):
        return self.config.getint('large_hex_string_size')

    @property
    def large_hex_string_quantity(self):
        return self.config.getint('large_hex_string_quantity')

    @property
    def large_hex_string_quantity_count(self):
        return self.config.getint('large_hex_string_quantity_count')

    @property
    def hex_string_percentage_limit(self):
        return self.config.getfloat('hex_string_percentage_limit')

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return AnalysisExecutionResult.COMPLETED

        if not local_file_path.lower().endswith('.vbs'):
            return AnalysisExecutionResult.COMPLETED

        consec_count = 0
        total_count = 0
        hex_string_lengths = []

        with open(local_file_path, 'rb') as fp:
            mm = mmap(fp.fileno(), 0, prot=PROT_READ)
            for line in mm:
                # ignore comments
                if line.lstrip().startswith(b"'") or line.lstrip().startswith(b'REM'):
                    continue

                for c in line:
                    # ignore whitespace
                    if chr(c).isspace():
                        continue

                    if (c > 47 and c < 58) or (c > 64 and c < 71) or (c > 96 and c < 103):
                        consec_count += 1
                        total_count += 1
                    else:
                        # ignore hex strings < 5
                        if consec_count >= 5:
                            hex_string_lengths.append(consec_count)
                        consec_count = 0

        if not hex_string_lengths:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, VBScriptAnalysis)

        analysis.total_hex_strings = len(hex_string_lengths)
        analysis.largest_hex_string = max(hex_string_lengths)
        analysis.percentage_of_hex_strings = (total_count / file_size) * 100.0

        distribution = {}
        for length in hex_string_lengths:
            if str(length) not in distribution:
                distribution[str(length)] = 1
            else:
                distribution[str(length)] += 1

        # do we have a large number of hex strings of the same length that are larger than 50?
        for length in distribution.keys():
            if int(length) > self.large_hex_string_quantity:
                if distribution[length] > self.large_hex_string_quantity_count:
                    _file.add_detection_point("large number of large hex strings of same length")
                    _file.add_directive(DIRECTIVE_SANDBOX)
                    break

        # is a large percentage of the file hex strings?
        if (total_count / file_size) >= self.hex_string_percentage_limit:
            _file.add_detection_point("a large percentage of the file is ascii hex ({0:.2f}%)".format((total_count / file_size) * 100.0))
            _file.add_directive(DIRECTIVE_SANDBOX)

        # if we have a large hex string at all we at least tag it and send it to the sandbox
        if max(hex_string_lengths) > self.large_hex_string_size:
            _file.add_tag("large_hex_string")
            _file.add_directive(DIRECTIVE_SANDBOX)

        return AnalysisExecutionResult.COMPLETED

KEY_LINE_COUNT = "line_count"

class PCodeAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_LINE_COUNT: None
        }

    @override
    @property
    def display_name(self) -> str:
        return "PCode Analysis"

    @property
    def line_count(self):
        return self.details[KEY_LINE_COUNT]

    @line_count.setter
    def line_count(self, value):
        self.details[KEY_LINE_COUNT] = value

    def generate_summary(self):
        if not self.line_count:
            return None

        return f"{self.display_name}: decoded {self.line_count} lines"

class PCodeAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return PCodeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def verify_environment(self):
        self.verify_path_exists(self.pcodedmp_path)

    @property
    def pcodedmp_path(self):
        """Returns the full path to the pcodedmp command line utility."""
        return self.config['pcodedmp_path']

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        self.wait_for_analysis(_file, FileTypeAnalysis)
        if not is_office_file(_file):
            return AnalysisExecutionResult.COMPLETED
        
        stderr_path = '{}.pcode.err'.format(local_file_path)
        stdout_path = '{}.pcode.bas'.format(local_file_path)

        with open(stderr_path, 'wb') as stderr_fp:
            with open(stdout_path, 'wb') as stdout_fp:
                # we use a wrapper program to filter out only the .bas lines
                p = Popen([os.path.join(get_base_dir(), 'bin', 'pcodedmp_wrapper'), 
                           self.pcodedmp_path, local_file_path], stdout=stdout_fp, stderr=stderr_fp)
                p.wait(timeout=30)

        if p.returncode != 0:
            logging.debug("pcodedmp returned error code {} for {}".format(p.returncode, _file))

        if os.path.getsize(stderr_path):
            logging.debug("pcodedmp recorded errors for {}".format(_file))
        else:
            os.remove(stderr_path)

        if os.path.getsize(stdout_path):
            analysis = self.create_analysis(_file)
            assert isinstance(analysis, PCodeAnalysis)
            line_count = 0
            with open(stdout_path, 'rb') as fp:
                for line in fp:
                    line_count += 1
            analysis.line_count = line_count
            output_file = analysis.add_file_observable(stdout_path, volatile=True)
            output_file.redirection = _file
            return AnalysisExecutionResult.COMPLETED

        os.remove(stdout_path)
        return AnalysisExecutionResult.COMPLETED