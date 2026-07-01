import logging
import os
from subprocess import Popen
from typing import Type

from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.configuration.config import get_config
from saq.constants import AnalysisExecutionResult, F_FILE
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable

class BroAnalyzerConfig(AnalysisModuleConfig):
    bro_bin_path: str = Field(..., description="The path to the bro binary.")

class BroAnalysis(Analysis):
    pass

class BroAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return BroAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return BroAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, pcap: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis import FileTypeAnalysis

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(pcap, FileTypeAnalysis)
        if not file_type_analysis:
            return AnalysisExecutionResult.COMPLETED

        # make sure the file exists
        if not pcap.exists:
            logging.error("pcap path {0} does not exist".format(pcap.value))
            return AnalysisExecutionResult.COMPLETED

        # make sure this is a pcap file
        if file_type_analysis.mime_type != 'application/vnd.tcpdump.pcap':
            return AnalysisExecutionResult.COMPLETED
        
        # we need a directory to put all these things into
        output_dir = '{0}.bro_analysis'.format(os.path.join(self.get_root().file_dir, pcap.value))
        if not os.path.isdir(output_dir):
            try:
                os.mkdir(output_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(output_dir, str(e)))
                return AnalysisExecutionResult.COMPLETED

        # and a place to put all the extracted files into
        extraction_dir = os.path.join(output_dir, 'extraction')
        if not os.path.isdir(extraction_dir):
            try:
                os.mkdir(extraction_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(extraction_dir, str(e)))
                return AnalysisExecutionResult.COMPLETED

        bro_stdout_path = os.path.join(output_dir, 'bro.stdout')
        bro_stderr_path = os.path.join(output_dir, 'bro.stdout')

        with open(bro_stdout_path, 'wb') as stdout_fp:
            with open(bro_stderr_path, 'wb') as stderr_fp:
                logging.debug("executing bro against {0}".format(pcap.value))
                p = Popen([
                    self.config.bro_bin_path,
                    '-r', os.path.join(get_base_dir(), pcap.value),
                    '-e', 'redef FileExtract::prefix = "{0}/";'.format(extraction_dir),
                    os.path.join(get_base_dir(), 'etc', 'bro', 'ace.bro')],
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    cwd=output_dir)
                p.wait()

        # parse bro log files
        # TODO
        
        return AnalysisExecutionResult.COMPLETED