import logging
import os
import re
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Type
from pydantic import Field
from saq.analysis.analysis import Analysis
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
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        if os.path.getsize(local_file_path) > self.maximum_size_mb * 1024 * 1024:
            logging.debug(f"file {local_file_path} too big for {self}")
            return AnalysisExecutionResult.COMPLETED

        # wait for yara analysis
        yara_analysis = self.wait_for_analysis(_file, YaraScanResults_v3_4)

        # ignore files we're not interested in
        xlm4 = False
        yara_matches = self.xlm_yara_context.match(local_file_path)
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
                if yara_analysis and isinstance(yara_analysis.details, list):
                    for match in yara_analysis.details:
                        if match['rule'] in self.yara_rule_names:
                            xlm4 = True

        recurse_tree(_file, _callback)

        if not xlm4:
            return AnalysisExecutionResult.COMPLETED

        logging.info(f"executing xlmdeobfuscator on {_file} in {self.get_root()}")

        stdout = None
        stderr = None

        analysis = self.create_analysis(_file)
        p = Popen(['xlmdeobfuscator', '-f', local_file_path], stdout=PIPE, stderr=PIPE)
        try:
            stdout, stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired:
            try:
                logging.warning(f"xlmdeobfuscator timed out analyzing {local_file_path}")
                _file.add_tag('xlmdeobfuscator_failed')
                p.kill()
            except Exception as e:
                logging.error(f"unable to kill xlmdeobfuscator process: {e}")

        if stdout:
            if b'Failed to decrypt the file\nUse --password switch to provide the correct password' in stdout:
                logging.debug(f"{_file} is encrypted -- cannot xlmdeobfuscator the file")
                return AnalysisExecutionResult.COMPLETED

            target_dir = f'{local_file_path}.xlmdeobfuscator'
            os.makedirs(target_dir, exist_ok=True)
            target_file = os.path.join(target_dir, 'xlmdeobfuscator.stdout')
            with open(target_file, 'wb') as fp:
                # cut the banner out
                if b'\nFile:' in stdout:
                    stdout = stdout[stdout.index(b'\nFile:'):]

                fp.write(stdout)

            file_observable = analysis.add_file_observable(target_file, volatile=True)
            if file_observable:
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                file_observable.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
                file_observable.add_yara_meta("type", "script.macro.xlm")

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
            # special URL extraction
            for line in stdout.decode().split('\n'):
                if line.startswith('CELL:'):
                    m = RE_XLM_PARAMS.match(line)
                    if not m:
                        continue

                    params = m.group(1)
                    if not params:
                        continue

                    if 'http' in params.lower():
                        target_url = params[params.lower().index('http'):]
                        _file.add_detection_point('A url was found in an Excel 4.0 macro.')
                        url = analysis.add_observable_by_spec(F_URL, target_url)
                        if url:
                            url.add_directive(DIRECTIVE_CRAWL)

        # not sure when this happens
        if stderr:
            target_dir = f'{local_file_path}.xlmdeobfuscator'
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, 'xlmdeobfuscator.stderr'), 'wb') as fp:
                fp.write(stdout)

        # Do similar analysis using the -x option
        p = Popen(['xlmdeobfuscator', '-x', '-f', local_file_path], stdout=PIPE, stderr=PIPE)
        try:
            stdout, stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired:
            try:
                logging.warning(f"xlmdeobfuscator timed out extracting cells from {local_file_path}")
                _file.add_tag('xlmdeobfuscatorextractcells_failed')
                p.kill()
            except Exception as e:
                logging.error(f"unable to kill xlmdeobfuscator process: {e}")

        if stdout:
            if b'Failed to decrypt the file\nUse --password switch to provide the correct password' in stdout:
                logging.debug(f"{_file.value} is encrypted -- cannot xlmdeobfuscator the file")
                return AnalysisExecutionResult.COMPLETED

            target_dir = f'{local_file_path}.xlmdeobfuscator'
            os.makedirs(target_dir, exist_ok=True)
            target_file = os.path.join(target_dir, 'xlmdeobfuscatorextractcells.stdout')
            with open(target_file, 'wb') as fp:
                # cut the banner out
                if b'\nFile:' in stdout:
                    stdout = stdout[stdout.index(b'\nFile:'):]

                fp.write(stdout)

            file_observable = analysis.add_file_observable(target_file, volatile=True)
            if file_observable:
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                file_observable.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
                file_observable.add_yara_meta("type", "script.macro.xlm")

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

            # special URL extraction
            for line in stdout.decode().split('\n'):
                if line.startswith('CELL:'):
                    m = RE_XLM_PARAMS.match(line)
                    if not m:
                        continue

                    params = m.group(1)
                    if not params:
                        continue

                    if 'http' in params.lower():
                        target_url = params[params.lower().index('http'):]
                        _file.add_detection_point('A url was found in an Excel 4.0 macro.')
                        url = analysis.add_observable_by_spec(F_URL, target_url)
                        if url:
                            url.add_directive(DIRECTIVE_CRAWL)

        # not sure when this happens
        if stderr:
            target_dir = f'{local_file_path}.xlmdeobfuscator'
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, 'xlmdeobfuscatorextractcells.stderr'), 'wb') as fp:
                fp.write(stdout)


        return AnalysisExecutionResult.COMPLETED