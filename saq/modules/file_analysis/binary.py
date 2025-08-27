import logging
import os
from typing import override
from saq.analysis.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable


class BinaryFileAnalysis(Analysis):
    @override
    @property
    def display_name(self) -> str:
        return "Binary File Analysis"

class BinaryFileAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BinaryFileAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def is_supported_file(self, path):
        result = self._is_rtf(path)
        # we only care about EPS files in Word documents because we heard it reported once
        result |= ( self._is_eps(path) and '.doc' in path )
        return result

    def _is_rtf(self, local_file_path):
        with open(local_file_path, 'rb') as fp:
            # is this an RTF file?
            header = fp.read(4)
            if header == b'{\\rt':
                return True

        return False

    def _is_eps(self, local_file_path):
        with open(local_file_path, 'rb') as fp:
            # is this an EPS file? (see https://en.wikipedia.org/wiki/Encapsulated_PostScript)
            header = fp.read(4)
            if header == b'\xc5\xd0\xd3\xc6':
                return True
            fp.seek(0)
            header = fp.read(11)
            if header == b'%!PS-Adobe-':
                return True

        return False

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return AnalysisExecutionResult.COMPLETED

        if not self.is_supported_file(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        with open(local_file_path, 'rb') as fp:

            # we're basically looking for any non-binary that has a null byte
            # all of the malicious documents we've found have null bytes
            # and that seems to be somewhat rare with these types of files

            bytes_read = 0

            while True:
                _buffer = fp.read(8192)
                if len(_buffer) == 0:
                    break

                bytes_read += len(_buffer)
                # have we read the last bytes of the file?
                if bytes_read == file_size:
                    # if so, ignore the last byte
                    # RTF files often end with \x00 for some reason
                    _buffer = _buffer[:-1]

                if b'\x00' in _buffer:
                    _file.add_tag('unexpected_binary_data')
                    _file.add_directive(DIRECTIVE_SANDBOX)
                    return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED


class BinaryAnalysisPresenter(AnalysisPresenter):
    """Presenter for BinaryFileAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/default_template.html"


register_analysis_presenter(BinaryFileAnalysis, BinaryAnalysisPresenter)