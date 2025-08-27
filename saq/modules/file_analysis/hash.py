from fnmatch import fnmatch
import logging
import os
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE, F_MD5, F_SHA256, R_IS_HASH_OF
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class FileHashAnalysis(Analysis):
    """What are the hash values of this file?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'md5': None,
            'sha1': None,
            'sha256': None, }

    @override
    @property
    def display_name(self) -> str:
        return "File Hash Analysis"

    @property
    def md5(self):
        if self.details is None:
            return None

        return self.details['md5']

    @md5.setter
    def md5(self, value):
        self.details['md5'] = value

    @property
    def sha1(self):
        if self.details is None:
            return None

        return self.details['sha1']

    @sha1.setter
    def sha1(self, value):
        self.details['sha1'] = value

    @property
    def sha256(self):
        if self.details is None:
            return None

        return self.details['sha256']

    @sha256.setter
    def sha256(self, value):
        self.details['sha256'] = value

    def generate_summary(self):
        return None

class FileHashAnalyzer(AnalysisModule):
    """Perform hash analysis on F_FILE indicator types for files attached to the alert."""

    @property
    def generated_analysis_type(self):
        return FileHashAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
    
    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.get_root(), _file)
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip empty files
        if os.path.getsize(local_file_path) == 0:
            return AnalysisExecutionResult.COMPLETED

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        # some files we skip hashing, specifically the files that we generate
        for section in self.config.keys():
            if section.startswith('ignore_pattern_'):
                ignore_pattern = self.config[section]
                if fnmatch(local_file_path, ignore_pattern):
                    logging.debug("skipping file hash analysis on {} for ignore pattern {}".format(
                        local_file_path, ignore_pattern))
                    return AnalysisExecutionResult.COMPLETED

            if section.startswith('ignore_mime_type_'):
                ignore_pattern = self.config[section]
                if fnmatch(file_type_analysis.mime_type, ignore_pattern):
                    logging.debug("skipping file hash analysis on {} for ignore mime type {}".format(
                                  local_file_path, ignore_pattern))
                    return AnalysisExecutionResult.COMPLETED

        # the FileObservable actually defines it's own compute_hashes function that does all the work
        if not _file.compute_hashes():
            logging.error("file hash analysis failed for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        logging.debug("analyzing file {}".format(local_file_path))

        result = self.create_analysis(_file)

        o_md5 = result.add_observable_by_spec(F_MD5, _file.md5_hash)
        o_sha256 = result.add_observable_by_spec(F_SHA256, _file.sha256_hash)

        result.md5 = _file.md5_hash
        result.sha1 = _file.sha1_hash
        result.sha256 = _file.sha256_hash

        if o_md5: 
            o_md5.add_link(_file)
            o_md5.add_relationship(R_IS_HASH_OF, _file)

        if o_sha256: 
            o_sha256.add_link(_file)
            o_sha256.add_relationship(R_IS_HASH_OF, _file)

        return AnalysisExecutionResult.COMPLETED