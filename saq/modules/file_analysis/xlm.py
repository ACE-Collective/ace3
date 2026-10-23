import logging
import os
import re
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Type
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.signatures.builtin import XLM_MACRO_URL
from saq.analysis.observable import Observable
from saq.analysis.search import recurse_tree
from saq.constants import DIRECTIVE_CRAWL, DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, F_FILE, F_URL, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig

import yara

from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class XLMMacroDeobfuscatorAnalysis(Analysis):

    CELL_COUNT = 'cell_count'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            XLMMacroDeobfuscatorAnalysis.CELL_COUNT: 0,
        }

    @property
    def cell_count(self) -> int:
        return self.details[XLMMacroDeobfuscatorAnalysis.CELL_COUNT]

    @cell_count.setter
    def cell_count(self, value: int):
        self.details[XLMMacroDeobfuscatorAnalysis.CELL_COUNT] = value

    def generate_summary(self) -> str:
        return f"XLMMacroDeobfuscator Analysis - analyzed {self.cell_count} cells"

RE_XLM_CELL_PATTERN = re.compile(b'\nCELL:')
RE_XLM_ERROR_PATTERN = re.compile(b'\nError ')
RE_XLM_PARAMS = re.compile(r'^CELL:.*\(([^\)]*)\)$')
RE_XLM_URL = re.compile(r'https?://[^"]+', re.IGNORECASE)

# what _run returns for an encrypted document
ENCRYPTED = object()

# https://blog.reversinglabs.com/blog/excel-4.0-macros

class XLMMacroDeobfuscatorConfig(AnalysisModuleConfig):
    timeout: int = Field(..., description="Timeout in seconds for xlmdeobfuscator execution.")
    maximum_size_mb: int = Field(default=10, description="Maximum file size in MB to process.")
    yara_rule_names: list[str] = Field(..., description="List of yara rule names that can trigger xlm4 analysis.")

class XLMMacroDeobfuscatorAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return XLMMacroDeobfuscatorConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open(os.path.join(get_base_dir(), 'etc', 'xlmdeobfuscator.yar'), 'r') as fp:
            self.xlm_yara_context = yara.compile(source=fp.read())

    @property
    def generated_analysis_type(self):
        return XLMMacroDeobfuscatorAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def verify_environment(self):
        pass

    @property
    def timeout(self) -> int:
        return self.config.timeout

    @property
    def maximum_size_mb(self):
        """Returns the max size in MB of a file this module will process."""
        return self.config.maximum_size_mb

    @property
    def yara_rule_names(self):
        """The list of optional yara rule names that can trigger xlm4 analysis."""
        return self.config.yara_rule_names

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.INCOMPLETE

    # this needs to run last so that all the files that are extracted
    # from office documents have a chance to be scanned by the yara analyzer
    def execute_final_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.yara import YaraScanResults_v3_4

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        if os.path.getsize(local_file_path) > self.maximum_size_mb * 1024 * 1024:
            logging.debug(f"file {local_file_path} too big for {self}")
            return AnalysisExecutionResult.COMPLETED

        # ignore files we're not interested in
        xlm4 = False
        for match in self.xlm_yara_context.match(local_file_path):
            if 'xlm4' in match.tags:
                xlm4 = True
                break

        # does this file or any file extracted from this file have any
        # of the yara rules we're looking for?
        def _callback(target):
            nonlocal xlm4
            if isinstance(target, Observable) and target.type == F_FILE:
                yara_analysis = target.get_and_load_analysis(YaraScanResults_v3_4)
                if yara_analysis and isinstance(yara_analysis.details, dict):
                    for match in yara_analysis.scan_results:
                        if match['rule'] in self.yara_rule_names:
                            xlm4 = True

        recurse_tree(_file, _callback)

        if not xlm4:
            return AnalysisExecutionResult.COMPLETED

        logging.info(f"executing xlmdeobfuscator on {_file} in {self.get_root()}")

        analysis = self.create_analysis(_file)
        target_dir = f'{local_file_path}.xlmdeobfuscator'

        stdout = self._run(['xlmdeobfuscator', '-f', local_file_path], _file, target_dir, 'xlmdeobfuscator', 'xlmdeobfuscator_failed')
        if stdout is ENCRYPTED:
            return AnalysisExecutionResult.COMPLETED

        if stdout:
            self._add_output(analysis, target_dir, 'xlmdeobfuscator.stdout', stdout)

            # this analysis only runs if this document says it has xlm4
            # so if it didn't pull anything out then it's probably noteworthy
            # Jared Anderson commenting this out. This will only tag if the extract option also fails
            """
            analysis.cell_count = len(RE_XLM_CELL_PATTERN.findall(stdout))
            if analysis.cell_count:
                _file.add_tag('xlm4')
            else:
                _file.add_tag('xlm4:no_cells')

            if RE_XLM_ERROR_PATTERN.search(stdout):
                _file.add_tag('xlm4:error')
            """
            self._extract_urls(analysis, _file, stdout)

        # Do similar analysis using the -x option
        stdout = self._run(['xlmdeobfuscator', '-x', '-f', local_file_path], _file, target_dir, 'xlmdeobfuscatorextractcells', 'xlmdeobfuscatorextractcells_failed')
        if stdout is ENCRYPTED:
            return AnalysisExecutionResult.COMPLETED

        if stdout:
            self._add_output(analysis, target_dir, 'xlmdeobfuscatorextractcells.stdout', stdout)

            # this analysis only runs if this document says it has xlm4
            # so if it didn't pull anything out then it's probably noteworthy
            # Jared Anderson update - If we fail xmldeob with emulation enabled, who cares
            # but if extracting cells also fails, let's tag the alert
            analysis.cell_count = len(RE_XLM_CELL_PATTERN.findall(stdout))
            if analysis.cell_count:
                _file.add_tag('xlm4')
            else:
                _file.add_tag('xlm4:no_cells')

            if RE_XLM_ERROR_PATTERN.search(stdout):
                _file.add_tag('xlm4:error')

            self._extract_urls(analysis, _file, stdout)

        return AnalysisExecutionResult.COMPLETED

    def _run(self, args: list[str], _file: FileObservable, target_dir: str, output_name: str, failed_tag: str):
        """Runs xlmdeobfuscator and returns its stdout with the banner cut off, None when it printed
        nothing or timed out, or ENCRYPTED when the document needs a password. Anything it printed
        to stderr is kept in target_dir as <output_name>.stderr."""
        p = Popen(args, stdout=PIPE, stderr=PIPE)
        try:
            stdout, stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired:
            logging.warning(f"xlmdeobfuscator {' '.join(args[1:-1])} timed out analyzing {_file.full_path}")
            _file.add_tag(failed_tag)
            p.kill()
            # reap it: what it printed before it was killed is not used
            p.communicate()
            return None

        # not sure when this happens
        if stderr:
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, f'{output_name}.stderr'), 'wb') as fp:
                fp.write(stderr)

        if not stdout:
            return None

        if b'Failed to decrypt the file\nUse --password switch to provide the correct password' in stdout:
            logging.debug(f"{_file} is encrypted -- cannot xlmdeobfuscator the file")
            return ENCRYPTED

        # cut the banner out
        if b'\nFile:' in stdout:
            stdout = stdout[stdout.index(b'\nFile:'):]

        return stdout

    def _add_output(self, analysis: XLMMacroDeobfuscatorAnalysis, target_dir: str, file_name: str, stdout: bytes):
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, file_name)
        with open(target_file, 'wb') as fp:
            fp.write(stdout)

        file_observable = analysis.add_file_observable(target_file, volatile=True)
        if file_observable:
            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
            file_observable.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
            file_observable.add_yara_meta("type", "script.macro.xlm")

    def _extract_urls(self, analysis: XLMMacroDeobfuscatorAnalysis, _file: FileObservable, stdout: bytes):
        """Adds the URLs passed as parameters in the macro's cells."""
        # the output carries whatever bytes the cells hold
        for line in stdout.decode(errors='replace').split('\n'):
            if not line.startswith('CELL:'):
                continue

            m = RE_XLM_PARAMS.match(line)
            if not m:
                continue

            # a URL ends where its quoted parameter does
            for target_url in RE_XLM_URL.findall(m.group(1)):
                _file.add_detection_point('A url was found in an Excel 4.0 macro.', signature_uuid=XLM_MACRO_URL.uuid)
                url = analysis.add_observable_by_spec(F_URL, target_url)
                if url:
                    url.add_directive(DIRECTIVE_CRAWL)
