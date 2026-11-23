import logging
import os
from typing import Type, override
import zipfile

from pydantic import Field
from saq.signatures.builtin import EMAIL_ENCRYPTED_DECRYPTED
from saq.constants import DIRECTIVE_EXTRACT_URLS, AnalysisExecutionResult
from saq.cracking import wordlist_from_email
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.encryption.email_password import (
    EmailPasswordAnalysis,
    EmailPasswordAnalyzer,
    EmailPasswordAnalyzerConfig,
)
from saq.observables.file import FileObservable


KEY_ENCRYPTION_INFO = 'encryption_info'


class ZipEncryptionAnalysis(EmailPasswordAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details[KEY_ENCRYPTION_INFO] = None

    @override
    @property
    def display_name(self) -> str:
        return "Zip Encryption Analysis"

    @property
    def encryption_info(self):
        return self.details[KEY_ENCRYPTION_INFO]

    @encryption_info.setter
    def encryption_info(self, value):
        self.details[KEY_ENCRYPTION_INFO] = value


class ZipEncryptionAnalyzerConfig(EmailPasswordAnalyzerConfig):
    extract_timeout: int = Field(default=5, description="The maximum amount of time (in seconds) to wait for 7z to complete.")


class ZipEncryptionAnalyzer(EmailPasswordAnalyzer):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ZipEncryptionAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return ZipEncryptionAnalysis

    @property
    def extract_timeout(self):
        return self.config.extract_timeout

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)

        # does this file exist as an attachment?
        if not _file.exists:
            return AnalysisExecutionResult.COMPLETED

        # is this an encrypted zip file? one encrypted entry is enough
        try:
            with zipfile.ZipFile(_file.full_path) as zip_fp:
                if not any(zip_info.flag_bits & 0x1 for zip_info in zip_fp.infolist()):
                    return AnalysisExecutionResult.COMPLETED

        # expected condition if it's not an zip archive
        except Exception as e:
            logging.debug(f"Loading {_file} as zip failed: {e}")
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag('encrypted_zip')
        analysis = self.create_analysis(_file)

        # extract the hash for cracking
        p = self.run_sandboxed_tool([os.path.join(self.john_bin_path, 'zip2john'), _file.full_path], _file.full_path)
        if p is None:
            analysis.error = "zip2john did not finish"
            return AnalysisExecutionResult.COMPLETED

        # did we get the hash?
        if not p.stdout:
            analysis.error = f"zip2john failed: {p.stderr}"
            return AnalysisExecutionResult.COMPLETED

        # build wordlist for cracking password from the email's body text, if available
        try:
            analysis.email, analysis.email_body, analysis.word_list = wordlist_from_email(
                _file, range_low=self.range_low, range_high=self.range_high,
                byte_limit=self.byte_limit, list_limit=self.list_limit)
        except Exception as e:
            logging.exception(f"unable to build the password wordlist for {_file}",
                              extra={"path": _file.full_path, "root_uuid": self.get_root().uuid})
            analysis.error = f"unable to build the password wordlist: {str(e) or type(e).__name__}"
            return AnalysisExecutionResult.COMPLETED

        if analysis.word_list:
            try:
                analysis.password = self.crack(p.stdout, analysis.word_list, _file.full_path)
            except Exception as e:
                logging.exception(f"unable to crack the password for {_file}",
                                  extra={"path": _file.full_path, "root_uuid": self.get_root().uuid})
                analysis.error = f"unable to crack the password: {str(e) or type(e).__name__}"
                return AnalysisExecutionResult.COMPLETED

        # none of the candidates was the password: the summary says so, and it is not an error
        if not analysis.password:
            return AnalysisExecutionResult.COMPLETED

        # got the password!
        # make output directory for files in zip
        output_dir = f'{_file.full_path}.decrypted'
        try:
            os.makedirs(output_dir)
        except Exception as e:
            if not os.path.isdir(output_dir):
                raise Exception(f"unable to create archive directory {output_dir}: {e}")

        # extract data from zip to output directory w/ 7zip
        # 'x' = extract, '-y' = assume yes to all queries
        result = self.run_sandboxed_tool(['7z', 'x', '-y', f'-p{analysis.password}', f"-o{output_dir}",
                                          _file.full_path], _file.full_path, timeout=self.extract_timeout,
                                         write_dirs=[output_dir])
        if result is None:
            # run_sandboxed_tool() logged why (a timeout, a member over the file size limit). What it
            # extracted before it was stopped is still decrypted content and is still added: the last
            # file may be cut short
            analysis.error = "7z did not finish"
        elif result.returncode > 1:
            # 7z exits 1 for a warning; what it extracted before an error is still added
            logging.warning(f"7z could not extract every file of encrypted zip {_file}: {result.stderr.strip()[-500:]}")
            analysis.error = result.failure_reason("7z")

        # add files in the zip as observables
        for dirpath, dirnames, filenames in os.walk(output_dir):
            for file_name in filenames:
                full_path = os.path.join(dirpath, file_name)
                _file = analysis.add_file_observable(full_path)
                if _file:
                    _file.add_detection_point("Was able to decrypt based on contents of email.", signature_uuid=EMAIL_ENCRYPTED_DECRYPTED.uuid)
                    _file.add_directive(DIRECTIVE_EXTRACT_URLS)

        return AnalysisExecutionResult.COMPLETED
