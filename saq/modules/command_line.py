# vim: sw=4:ts=4:et:cc=120

import shlex

from saq.analysis import Analysis
from saq.constants import F_COMMAND_LINE, F_FILE_LOCATION, F_FILE_PATH, R_EXECUTED_ON, create_file_location, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.filesystem import is_nt_path
from saq.util.strings import format_item_list_for_summary

KEY_FILE_PATHS = 'file_paths'

class CommandLineAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_FILE_PATHS: [],
        }

    @property
    def file_paths(self):
        return self.details[KEY_FILE_PATHS]

    def generate_summary(self):
        if not self.file_paths:
            return None

        return "Command Line Analysis: extracted file paths " + format_item_list_for_summary(self.file_paths)

class CommandLineAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return CommandLineAnalysis

    @property
    def valid_observable_types(self):
        return [ F_COMMAND_LINE ]

    def execute_analysis(self, command_line) -> AnalysisExecutionResult:
        analysis = self.create_analysis(command_line)
        assert isinstance(analysis, CommandLineAnalysis)

        # does this command line have any windows paths?
        for token in shlex.split(command_line.value, posix=False):
            # remove surrounding quotes if they exist
            while token.startswith('"') and token.endswith('"'):
                token = token[1:-1]

            if not is_nt_path(token):
                continue

            analysis.file_paths.append(token)
            file_path = analysis.add_observable_by_spec(F_FILE_PATH, token)

            # if this was executed on a host then we can create a file location too
            if command_line.has_relationship(R_EXECUTED_ON):
                hostname = command_line.get_relationship_by_type(R_EXECUTED_ON).target
                file_location = analysis.add_observable_by_spec(F_FILE_LOCATION,create_file_location(hostname.value, token))

        return AnalysisExecutionResult.COMPLETED
