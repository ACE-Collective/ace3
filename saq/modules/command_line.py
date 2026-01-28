# vim: sw=4:ts=4:et:cc=120

import logging
import os
import shlex
from typing import Type

from pydantic import Field
from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import DIRECTIVE_COLLECT_FILE, F_COMMAND_LINE, F_FILE_LOCATION, F_FILE_PATH, R_EXECUTED_ON, create_file_location, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.util.filesystem import is_nt_path
from saq.util.strings import decode_base64, is_base64

KEY_FILE_PATHS = "file_paths"
KEY_BASE64_PAYLOADS = "base64_payloads"

KEY_BASE64 = "base64"
KEY_FILE_PATH = "file_path"

class CommandLineAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_FILE_PATHS: [],
            KEY_BASE64_PAYLOADS: [],
        }

    @property
    def file_paths(self):
        return self.details[KEY_FILE_PATHS]

    @file_paths.setter
    def file_paths(self, value):
        self.details[KEY_FILE_PATHS] = value

    @property
    def base64_payloads(self):
        return self.details[KEY_BASE64_PAYLOADS]

    @base64_payloads.setter
    def base64_payloads(self, value):
        self.details[KEY_BASE64_PAYLOADS] = value

    def generate_summary(self):
        if not self.file_paths and not self.base64_payloads:
            return None

        result = "Command Line Analysis: extracted "
        parts = []
        if self.file_paths:
            parts.append(f"{len(self.file_paths)} file paths")
        if self.base64_payloads:
            parts.append(f"{len(self.base64_payloads)} base64 payloads")

        return f"{result} {', '.join(parts)}"

class CommandLineAnalyzerConfig(AnalysisModuleConfig):
    base64_minimum_length: int = Field(..., description="The minimum length of a base64 encoded string to be extracted from a command line.")

class CommandLineAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return CommandLineAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return CommandLineAnalysis

    @property
    def valid_observable_types(self):
        return [ F_COMMAND_LINE ]

    @property
    def base64_minimum_length(self):
        return self.config.base64_minimum_length

    def execute_analysis(self, command_line: Observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(command_line)
        assert isinstance(analysis, CommandLineAnalysis)

        # look for interesting things in the command line
        ignore_size_restriction = False
        for token in shlex.split(command_line.value, posix=False):
            # remove surrounding quotes if they exist
            while token.startswith('"') and token.endswith('"'):
                token = token[1:-1]

            # looking specifically for powershell's -EncodedCommand parameter
            # if we see that then we can ignore the size restriction for the next token
            is_encoding_flag = token.lower().startswith("-e") or token.lower().startswith("/e")

            # ignore flags and options when looking for interesting components
            if token.startswith("-") or token.startswith("/"):
                # if this is the encoding flag, set the flag for the next token
                if is_encoding_flag:
                    ignore_size_restriction = True
                continue

            if is_nt_path(token):
                file_path = analysis.add_observable_by_spec(F_FILE_PATH, token)
                analysis.file_paths.append(token)

                # if this was executed on a host then we can create a file location too
                if command_line.has_relationship(R_EXECUTED_ON):
                    hostname = command_line.get_relationship_by_type(R_EXECUTED_ON).target
                    file_location = analysis.add_observable_by_spec(F_FILE_LOCATION,create_file_location(hostname.value, token))
                    if file_location is not None and command_line.has_directive(DIRECTIVE_COLLECT_FILE):
                        file_location.add_directive(DIRECTIVE_COLLECT_FILE)

            if is_base64(token):
                decoded_data = decode_base64(token)
                if ignore_size_restriction or len(decoded_data) >= self.base64_minimum_length:
                    # find a unique file name
                    for file_name_index in range(1024 * 1024): # sanity check
                        file_name = f"command_line_base64_payload_{file_name_index}.bin"
                        target_file = self.get_root().create_file_path(file_name)
                        if not os.path.exists(target_file):
                            break
                        else:
                            target_file = None

                    if not target_file:
                        logging.error("unable to find a unique file name for command line base64 payload")
                        continue

                    with open(target_file, "wb") as fp:
                        fp.write(decoded_data)

                    file_observable = analysis.add_file_observable(target_file)
                    file_observable.add_tag("base64")
                    analysis.base64_payloads.append({
                        KEY_BASE64: token,
                        KEY_FILE_PATH: target_file,
                    })

            # reset the flag after processing each non-flag token
            ignore_size_restriction = False

        return AnalysisExecutionResult.COMPLETED
