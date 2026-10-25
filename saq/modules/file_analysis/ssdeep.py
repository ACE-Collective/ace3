import logging
import os
import re
from typing import Type
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path
from saq.environment import get_base_dir


class SsdeepAnalysis(Analysis):
    """Does this file match any other files by fuzzy hash?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'matches': [], # [] of { 'file': blah, 'score': int }
        }

    def generate_summary(self):
        if len(self.details['matches']) > 0:
            return "Ssdeep Analysis ({0} matches {1}% highest match)".format(
                len(self.details['matches']), max([x['score'] for x in self.details['matches']]))
        return None

class SsdeepAnalyzerConfig(AnalysisModuleConfig):
    ssdeep_hashes: str = Field(..., description="The location of the ssdeep hashes to match against.")
    maximum_size: int = Field(..., description="Maximum file size (in bytes).")
    ssdeep_match_threshold: int = Field(..., description="Minimum matching threshold (in percent) before the file is tagged as ssdeep.")

class SsdeepAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return SsdeepAnalyzerConfig

    def verify_environment(self):
        ssdeep_path = self.ssdeep_hashes
        if not os.path.isabs(ssdeep_path):
            ssdeep_path = os.path.join(get_base_dir(), ssdeep_path)
        self.verify_path_exists(ssdeep_path)
        self.verify_program_exists('ssdeep')

    @property
    def ssdeep_hashes(self):
        path = self.config.ssdeep_hashes
        if os.path.isabs(path):
            return path
        return os.path.join(get_base_dir(), path)

    @property
    def maximum_size(self):
        return self.config.maximum_size

    @property
    def ssdeep_match_threshold(self):
        return self.config.ssdeep_match_threshold

    @property
    def generated_analysis_type(self):
        return SsdeepAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # don't bother for files that are really small
        file_size = os.path.getsize(local_file_path)
        if file_size < 1024:
            logging.debug("{} too small for ssdeep analysis".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        # and bail if the file is too big
        if file_size > self.maximum_size:
            logging.debug("{} too large ({}) for ssdeep analysis".format(local_file_path, file_size))
            return AnalysisExecutionResult.COMPLETED

        logging.debug("analyzing file {}".format(local_file_path))
        p = self.run_tool(['ssdeep', '-m', self.ssdeep_hashes, local_file_path], local_file_path,
                          capture_output=True, universal_newlines=True)
        if p is None:
            return AnalysisExecutionResult.COMPLETED

        stdout, stderr = p.stdout, p.stderr

        if p.returncode != 0:
            # a missing or unreadable hashes file fails every file, so an operator has to hear about it
            logging.error(f"ssdeep failed on {local_file_path} with exit code {p.returncode}: {stderr.strip()}",
                          extra={"path": local_file_path, "ssdeep_hashes": self.ssdeep_hashes})
            return AnalysisExecutionResult.COMPLETED

        if stderr:
            # a bad line in the hashes file is only a warning: ssdeep still matched against the rest
            logging.warning(f"ssdeep warned on {local_file_path}: {stderr.strip()}")

        analysis = None

        for line in stdout.split('\n'):
            # example output:
            # /opt/mwzoo/data/pos/frameworkpos/1/a5dc57aea5f397c2313e127a6e01aa00 matches all_the_hashes.ssdeep:/opt/mwzoo/data/pos/frameworkpos/1/a5dc57aea5f397c2313e127a6e01aa00.sample (100)
            if line == '':
                continue

            m = re.match(r'^.+? matches [^:]+:(.+) \(([0-9]{1,3})\)$', line)
            if not m:
                logging.error("unexpected ssdeep output: {}".format(line))
                continue

            matched_file = m.group(1)
            ssdeep_score = int(m.group(2))

            if ssdeep_score >= self.ssdeep_match_threshold:
                _file.add_tag('ssdeep')
                _file.add_directive(DIRECTIVE_SANDBOX)
                if not analysis:
                    analysis = self.create_analysis(_file)

                analysis.details['matches'].append({'file': matched_file, 'score': ssdeep_score})

        return AnalysisExecutionResult.COMPLETED