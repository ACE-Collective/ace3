# vim: sw=4:ts=4:et:cc=120

import ntpath
import re
import shlex
from typing import Type

from pydantic import Field
from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import DIRECTIVE_COLLECT_FILE, F_COMMAND_LINE, F_FILE_LOCATION, F_FILE_PATH, R_EXECUTED_ON, create_file_location, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.util.filesystem import find_nt_paths_in_text, is_nt_path
from saq.util.strings import decode_base64, is_base64

KEY_FILE_PATHS = "file_paths"
KEY_BASE64_PAYLOADS = "base64_payloads"

KEY_BASE64 = "base64"
KEY_FILE_PATH = "file_path"

# a maximal run of base64 characters (standard or url-safe alphabet) with optional padding
RE_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")

# program names whose -e abbreviates -EncodedCommand
POWERSHELL_PROGRAMS = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}

# powershell reads the en dash, em dash and horizontal bar as a dash, which hides a flag from a match on "-"
DASHES = ("-", "\u2013", "\u2014", "\u2015")

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

    def _add_file_path(self, analysis, command_line, path):
        """Add a file_path observable and optional file_location from a command_line observable."""
        analysis.add_observable_by_spec(F_FILE_PATH, path)
        analysis.file_paths.append(path)

        if command_line.has_relationship(R_EXECUTED_ON):
            hostname = command_line.get_relationship_by_type(R_EXECUTED_ON).target
            file_location = analysis.add_observable_by_spec(F_FILE_LOCATION, create_file_location(hostname.value, path))
            if file_location is not None and command_line.has_directive(DIRECTIVE_COLLECT_FILE):
                file_location.add_directive(DIRECTIVE_COLLECT_FILE)

    def _add_base64_payload(self, analysis, encoded: str, decoded_data: bytes):
        """Write a decoded payload to a file and add it as a file observable."""
        target_file = self.get_root().create_output_file("command_line_base64_payload.bin")
        with open(target_file, "wb") as fp:
            fp.write(decoded_data)

        file_observable = analysis.add_file_observable(target_file)
        if file_observable:
            file_observable.add_tag("base64")
            file_observable.add_yara_meta("type", "payload.base64")
        analysis.base64_payloads.append({
            KEY_BASE64: encoded,
            KEY_FILE_PATH: target_file,
        })

    @staticmethod
    def _remove_prefix_substrings(paths):
        """Remove paths that are a prefix substring of a more specific path.

        For example, if both 'C:\\Program' and 'C:\\Program Files\\foo.exe' are
        present, only the longer path is kept because the shorter one is a
        truncation artifact from shlex splitting on spaces."""
        result = []
        for path in paths:
            if any(other.startswith(path) and other != path for other in paths):
                continue
            result.append(path)
        return result

    def execute_analysis(self, command_line: Observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(command_line)
        assert isinstance(analysis, CommandLineAnalysis)

        # collect file paths from both passes before adding observables
        candidate_paths = []

        # look for interesting things in the command line
        ignore_size_restriction = False
        runs_powershell = False
        try:
            tokens = shlex.split(command_line.value, posix=False)
        except ValueError:
            # an unbalanced quote, common in truncated or deliberately mangled command lines; the
            # regex passes below still read the whole value, so only the token pass is skipped
            tokens = []

        for token in tokens:
            # remove surrounding quotes if they exist
            while token.startswith('"') and token.endswith('"'):
                token = token[1:-1]

            # ntpath splits on both \ and /, so this also finds /usr/bin/pwsh
            if ntpath.basename(token).lower() in POWERSHELL_PROGRAMS:
                runs_powershell = True

            # ignore flags and options when looking for interesting components
            if token.startswith(DASHES + ("/",)):
                # looking specifically for powershell's -EncodedCommand parameter
                # if we see that then we can ignore the size restriction for the next token
                # powershell takes any prefix of the name (-e, -enc) and -ec, but other flags start with e too
                # (-ExecutionPolicy Bypass, -ErrorAction Stop) and the word after them is not base64,
                # and in other programs -e is something else entirely (docker run -e KEY=value, xcopy /e)
                flag_name = token[1:]
                if flag_name.startswith(DASHES):
                    flag_name = flag_name[1:]  # --EncodedCommand
                flag_name = flag_name.lower()
                if runs_powershell and (flag_name == "ec" or (flag_name and "encodedcommand".startswith(flag_name))):
                    ignore_size_restriction = True
                continue

            if is_nt_path(token):
                candidate_paths.append(token)

            if is_base64(token):
                try:
                    decoded_data = decode_base64(token)
                except Exception:
                    continue  # a word made of base64 characters that does not decode is not a payload
                if ignore_size_restriction or len(decoded_data) >= self.base64_minimum_length:
                    self._add_base64_payload(analysis, token, decoded_data)

            # reset the flag after processing each non-flag token
            ignore_size_restriction = False

        # regex-based pass to find base64 that is only part of a token
        # (e.g. -EncodedCommand nested in a quoted -Command script body)
        extracted = {payload[KEY_BASE64] for payload in analysis.base64_payloads}
        for candidate in RE_BASE64_RUN.findall(command_line.value):
            # cheap length check first so the many short words are never decoded
            if candidate in extracted or len(candidate) * 3 // 4 < self.base64_minimum_length:
                continue
            try:
                decoded_data = decode_base64(candidate)
            except Exception:
                continue  # a run of base64 characters that does not decode is not a payload
            if len(decoded_data) >= self.base64_minimum_length:
                self._add_base64_payload(analysis, candidate, decoded_data)
                extracted.add(candidate)

        # regex-based pass to find paths that shlex tokenization missed
        # (e.g. paths embedded in PowerShell -Command script bodies with escaped quotes)
        for path in find_nt_paths_in_text(command_line.value):
            if path not in candidate_paths:
                candidate_paths.append(path)

        # filter out partial paths that are a prefix of a more specific path
        # (e.g. shlex may produce "C:\Program" when the real path is "C:\Program Files\...")
        for path in self._remove_prefix_substrings(candidate_paths):
            self._add_file_path(analysis, command_line, path)

        return AnalysisExecutionResult.COMPLETED
