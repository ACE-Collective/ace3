import logging
import os
from subprocess import PIPE, Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_rtf_file
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary

KEY_STDOUT = 'stdout'
KEY_STDERR = 'stderr'
KEY_RETURN_CODE = 'return_code'
KEY_EXTRACTED_FILES = 'extracted_files'

class RTFOLEObjectAnalysis(Analysis):
    """Does this RTF file have OLE objects inside?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_RETURN_CODE: None,
            KEY_EXTRACTED_FILES: [],
        }

    @override
    @property
    def display_name(self) -> str:
        return "RTF OLE Object Analysis"

    @property
    def stdout(self):
        """Captured standard output of rtfobj.py"""
        return self.details[KEY_STDOUT]

    @stdout.setter
    def stdout(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_STDOUT] = value

    @property
    def stderr(self):
        """Captured standard error of rtfobj.py"""
        return self.details[KEY_STDERR]

    @stderr.setter
    def stderr(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_STDERR] = value

    @property
    def return_code(self):
        """Return code of rtfobj.py"""
        return self.details[KEY_RETURN_CODE]

    @return_code.setter
    def return_code(self, value):
        assert value is None or isinstance(value, int)
        self.details[KEY_RETURN_CODE] = value

    @property
    def extracted_files(self):
        """List of files extracted by rtfobj.py"""
        return self.details[KEY_EXTRACTED_FILES]

    def generate_summary(self):
        if not self.extracted_files:
            return None

        return f"{self.display_name}: extracted {format_item_list_for_summary(self.extracted_files)}"

class RTFOLEObjectAnalyzer(AnalysisModule):

    @property
    def rtfobj_path(self):
        """Path to the rtfobj.py tool from oletools package."""
        return self.config['rtfobj_path']
        

    def verify_environment(self):
        self.verify_config_exists('rtfobj_path')
        self.verify_path_exists(self.config['rtfobj_path'])

    @property
    def generated_analysis_type(self):
        return RTFOLEObjectAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return AnalysisExecutionResult.COMPLETED

        # only analyze rtf files
        if not is_rtf_file(local_file_path):
            logging.debug("{} is not a rtf file".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        output_dir = '{}.rtfobj'.format(local_file_path)
        if os.path.exists(output_dir):
            return AnalysisExecutionResult.COMPLETED

        try:
            os.mkdir(output_dir)
        except Exception as e:
            logging.error("unable to create directory {}: {}".format(output_dir, e))
            report_exception()
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        try:
            p = Popen(['python', self.rtfobj_path, '-d', output_dir, '-s', 'all', local_file_path], 
                      stdout=PIPE, stderr=PIPE, universal_newlines=True)
            analysis.stderr, analysis.stdout = p.communicate()
            analysis.return_code = p.returncode
        except Exception as e:
            logging.error("execution of {} failed: {}".format(self.rtfobj_path, e))
            report_exception()
            return AnalysisExecutionResult.COMPLETED

        # walk the output directory and add all discovered files as observables
        try:
            logging.debug("walking {}".format(output_dir))
            for root, dirs, files in os.walk(output_dir):
                logging.debug("looping {} {} {}".format(root, dirs, files))
                for file_name in files:
                    extracted_file = os.path.join(output_dir, file_name)
                    logging.debug("extracted_file = {}".format(extracted_file))
                    analysis.extracted_files.append(extracted_file)
                    f = analysis.add_file_observable(extracted_file, volatile=True)
                    if f:
                        f.add_tag('extracted_rtf')
                        f.redirection = _file
                        f.add_relationship(R_EXTRACTED_FROM, _file)

        except Exception as e:
            logging.warning("failed to process output directory {}: {}".format(output_dir, e))
            return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED

class ExtractedRTFAnalysis(Analysis):
    pass

class ExtractedRTFAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('suspect_ext')
        self.verify_config_exists('suspect_mime_type')
        self.verify_config_exists('suspect_file_type')

    @property
    def suspect_ext(self):
        """Comma separated list of extensions that are automatically suspect if found inside an RTF OLE object."""
        return map(lambda x: x.strip(), self.config['suspect_ext'].split(','))

    @property
    def suspect_mime_type(self):
        """Comma separated list of mime types that are automatically suspect if found inside an RTF OLE object."""
        return map(lambda x: x.strip(), self.config['suspect_mime_type'].split(','))

    @property
    def suspect_file_type(self):
        """Comma separated list of types types that are automatically suspect if found inside an RTF OLE object."""
        return map(lambda x: x.strip(), self.config['suspect_file_type'].split(','))

    @property
    def generated_analysis_type(self):
        return ExtractedRTFAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        if not _file.has_tag('extracted_rtf'):
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        for ext in self.suspect_ext:
            if _file.file_path.lower().endswith('.{}'.format(ext)):
                _file.add_detection_point('file extracted from RTF has suspect file extension')
                _file.add_directive(DIRECTIVE_SANDBOX)
                #_file.add_tag('suspect')

        for mime_type in self.suspect_mime_type:
            if mime_type.lower() in file_type_analysis.mime_type.lower():
                _file.add_detection_point('file extracted from RTF has suspect mime type')
                _file.add_directive(DIRECTIVE_SANDBOX)
                #_file.add_tag('suspect')

        for file_type in self.suspect_file_type:
            if file_type.lower() in file_type_analysis.file_type.lower():
                _file.add_detection_point('file extracted from RTF has suspect file type')
                _file.add_directive(DIRECTIVE_SANDBOX)
                #_file.add_tag('suspect')

        return AnalysisExecutionResult.COMPLETED

KEY_COUNT = "count"

class NoWhiteSpaceAnalysis(Analysis):
    """Removes all whitespace characters from a file and saves it as file_name.nowhitespace."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_COUNT: 0
        }

    @property
    def count(self):
        return self.details[KEY_COUNT]

    @count.setter
    def count(self, value):
        self.details[KEY_COUNT] = value

    def generate_summary(self):
        if not self.count:
            return None

        return f"{self.display_name}: Ignore Whitespace Characters ({self.count} removed)"

class NoWhiteSpaceAnalyzer(AnalysisModule):
   
    @property
    def generated_analysis_type(self):
        return NoWhiteSpaceAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable):

        from functools import partial

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        if local_file_path.endswith('.nowhitespace'):
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        file_size = _file.size
        if file_size == 0:
            return AnalysisExecutionResult.COMPLETED

        # we only want to do this for RTF files
        if not is_rtf_file(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, NoWhiteSpaceAnalysis)
        output_file = '{}.nowhitespace'.format(local_file_path)
        count = 0

        # this is probably not very efficient...
        with open(local_file_path, 'rb') as fp_in:
            with open(output_file, 'wb') as fp_out:
                for b in iter(partial(fp_in.read, 1), b''):
                    if b not in b' \t\r\n\f\v':
                        fp_out.write(b)
                    else:
                        count += 1

        analysis.count = count
        output_file = analysis.add_file_observable(output_file, volatile=True)
        if output_file:
            output_file.redirection = _file

        return AnalysisExecutionResult.COMPLETED