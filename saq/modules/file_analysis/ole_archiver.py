import logging
import os
import shutil
from typing import Type
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class OLEArchiverAnalysis_v1_0(Analysis):
    """What is the path to the archived copy of this file?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'archive_path': None,
        }

    @property
    def archive_path(self):
        return self.details['archive_path']

    @archive_path.setter
    def archive_path(self, value):
        self.details['archive_path'] = value

class OLEArchiverConfig(AnalysisModuleConfig):
    ole_archive_dir: str = Field(..., description="The directory (relative to SAQ_DATA) to store the archived OLE documents.")

class OLEArchiver_v1_0(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return OLEArchiverConfig

    def verify_environment(self):
        self.verify_path_exists(self.config.ole_archive_dir)

    @property
    def ole_archive_dir(self):
        result = self.config.ole_archive_dir
        if os.path.isabs(result):
            return result

        return os.path.join(get_base_dir(), result)

    @property
    def generated_analysis_type(self):
        return OLEArchiverAnalysis_v1_0

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.file_type import FileTypeAnalysis
        from saq.modules.file_analysis.hash import FileHashAnalysis

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis:
            return AnalysisExecutionResult.COMPLETED

        # and the file hash analysis
        hash_analysis = self.wait_for_analysis(_file, FileHashAnalysis)
        if not hash_analysis:
            return AnalysisExecutionResult.COMPLETED

        if hash_analysis.md5 is None:
            logging.debug("no hash available for {} - no archiving possible".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        if not file_type_analysis.is_ole_file and not file_type_analysis.is_office_ext:
            logging.debug("not archiving {} as ole file".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        logging.debug("archiving {} as OLE file".format(local_file_path))
        analysis = self.create_analysis(_file)

        # archive the file by md5
        dest_dir = os.path.join(self.ole_archive_dir, hash_analysis.md5[0:2])
        if not os.path.exists(dest_dir):
            logging.debug("creating directory {}".format(dest_dir))
            try:
                os.mkdir(dest_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(dest_dir, e))
                report_exception()
                return AnalysisExecutionResult.COMPLETED

        dest_path = os.path.join(dest_dir, hash_analysis.md5)
        try:
            shutil.copy(local_file_path, dest_path)
        except Exception as e:
            logging.error("unable to copy {} to {}: {}".format(local_file_path, dest_path, e))
            report_exception()
            return AnalysisExecutionResult.COMPLETED

        # and then save some meta data about it
        with open('{}.meta'.format(dest_path), 'w') as fp:
            fp.write('{}\n'.format(local_file_path))

        analysis.archive_path = dest_path
        return AnalysisExecutionResult.COMPLETED