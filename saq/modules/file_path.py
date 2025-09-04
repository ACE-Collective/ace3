# vim: sw=4:ts=4:et

import logging
import re

from saq.analysis import Analysis
from saq.constants import F_FILE_NAME, F_FILE_PATH, F_USER
from saq.modules import AnalysisModule
from saq.modules.base_module import AnalysisExecutionResult

FILE_NAME_REGEX = re.compile(r'^.*[/\\]([^/\\]+)$')
USER_REGEX = re.compile(r'[a-z]:\\users\\([^\\]+)\\', re.IGNORECASE)

KEY_FILE_NAME = 'file_name'
KEY_USER_NAME = 'user_name'

class FilePathAnalysis(Analysis):
    """Extracts the file name from the file path.  Also extracts user names from Windows file paths."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_FILE_NAME: None,
            KEY_USER_NAME: None,
        }

    def generate_summary(self):
        if not self.file_name and not self.user_name:
            return None

        result = "File Path Analysis:"
        if self.file_name:
            result += f" file name {self.file_name}"
        if self.user_name:
            result += f" user name {self.user_name}"

        return result

    @property
    def file_name(self):
        return self.details[KEY_FILE_NAME]

    @file_name.setter
    def file_name(self, value):
        self.details[KEY_FILE_NAME] = value

    @property
    def user_name(self):
        return self.details[KEY_USER_NAME]

    @user_name.setter
    def user_name(self, value):
        self.details[KEY_USER_NAME] = value

class FilePathAnalyzer(AnalysisModule):
    """Analyzes file paths for F_FILE_NAME and F_USER observables."""

    @property
    def generated_analysis_type(self):
        return FilePathAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE_PATH

    def execute_analysis(self, file_path) -> AnalysisExecutionResult:

        # a file path needs at least one file path separator in it
        # otherwise it's really just a file_name
        if '\\' not in file_path.value and '/' not in file_path.value:
            logging.debug("file_path {} does not have file path separators".format(file_path.value))
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(file_path)

        # figure out the file name
        m = FILE_NAME_REGEX.match(file_path.value)
        if m is not None:
            analysis.file_name = m.group(1)
            logging.debug("extracted file name {} from {}".format(analysis.file_name, file_path.value))
            analysis.add_observable_by_spec(F_FILE_NAME, analysis.file_name)

        # is this a Windows7+ directory with a username?
        m = USER_REGEX.match(file_path.value)
        if m is not None:
            analysis.user_name = m.group(1)
            logging.debug("extracted user name {} from {}".format(analysis.user_name, file_path.value))
            analysis.add_observable_by_spec(F_USER, analysis.user_name)
        
        return AnalysisExecutionResult.COMPLETED
