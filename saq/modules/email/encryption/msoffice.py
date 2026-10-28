import logging
import os
from subprocess import PIPE, Popen
from typing import Type, override

import msoffcrypto
from saq.signatures.builtin import EMAIL_ENCRYPTED_DECRYPTED
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.cracking import crack_password, wordlist_from_email
from saq.environment import get_base_dir
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.encryption.email_password import (
    EmailPasswordAnalysis,
    EmailPasswordAnalyzer,
    EmailPasswordAnalyzerConfig,
)

from saq.observables.file import FileObservable

KEY_ENCRYPTION_INFO = 'encryption_info'


class MSOfficeEncryptionAnalysis(EmailPasswordAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details[KEY_ENCRYPTION_INFO] = None

    @override
    @property
    def display_name(self) -> str:
        return "MSOffice Encryption Analysis"

    @property
    def encryption_info(self):
        return self.details[KEY_ENCRYPTION_INFO]

    @encryption_info.setter
    def encryption_info(self, value):
        self.details[KEY_ENCRYPTION_INFO] = value


class MSOfficeEncryptionAnalyzer(EmailPasswordAnalyzer):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailPasswordAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return MSOfficeEncryptionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)

        # does this file exist as an attachment?
        if not _file.exists:
            return AnalysisExecutionResult.COMPLETED

        # is this an encrypted OLE document?
        try:
            with open(_file.full_path, 'rb') as office_fp:
                try:
                    office_file = msoffcrypto.OfficeFile(office_fp)
                except Exception:
                    logging.debug(f"msoffcrypto unable to parse file: {_file.full_path}")
                    return AnalysisExecutionResult.COMPLETED

                try:
                    if not office_file.is_encrypted():
                        return AnalysisExecutionResult.COMPLETED
                except Exception as e:
                    # msoffcrypto cannot/does not support certain types of encryption
                    if str(e) == 'Unsupported encryption method':
                        analysis = self.create_analysis(_file)
                        analysis.error = str(e)
                        _file.add_tag('encrypted_msoffice')
                        return AnalysisExecutionResult.COMPLETED

                    # Some office documents cause these errors in msoffcrypto that we want to ignore
                    common_errors = ['unpack requires a buffer of 4 bytes']
                    if str(e) not in common_errors:
                        logging.exception(f"Unable to check encryption status of {_file.full_path}: {str(e)}")

                    return AnalysisExecutionResult.COMPLETED

            analysis = self.create_analysis(_file)
            _file.add_tag('encrypted_msoffice')

            # extract the hash for cracking
            p = Popen(['python3', os.path.join(get_base_dir(), "bin", "office2john.py"), _file.full_path], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate()

            # did we get the hash?
            if not stdout:
                analysis.error = f"office2john.py failed: {stderr.decode()}"
                return AnalysisExecutionResult.COMPLETED

            hash_file = f'{_file.full_path}.hash'
            with open(hash_file, 'wb') as fp:
                fp.write(stdout)

            # OK then we've found an office document that is encrypted

            # no matter what these are the first passwords we try
            # see https://isc.sans.edu/diary/rss/23774
            # see https://twitter.com/BouncyHat/status/1308897932389896192
            analysis.word_list = ['VelvetSweatshop', '/01Hannes Ruescher/01']

            # we'll try to find additional passwords by looking at the plain text and html of the email, if they exist
            analysis.email, analysis.email_body, email_words = wordlist_from_email(
                _file, range_low=self.range_low, range_high=self.range_high,
                byte_limit=self.byte_limit, list_limit=self.list_limit)
            analysis.word_list.extend(email_words)

            wordlist_path = f'{_file.full_path}.wordlist'
            with open(wordlist_path, 'w') as fp:
                for word in analysis.word_list:
                    fp.write(f'{word}\n')

            # crack it with john the ripper using wordlist
            analysis.password = crack_password(self.john_bin_path, hash_file, _file.full_path, f'--wordlist={wordlist_path}')

            if not analysis.password:
                analysis.error = "could not crack password"
                return AnalysisExecutionResult.COMPLETED

            # got the password!
            output_file = f'{_file.full_path}.decrypted'
            with open(_file.full_path, 'rb') as office_fp:
                office_file = msoffcrypto.OfficeFile(office_fp)
                office_file.load_key(password=analysis.password)
                with open(output_file, 'wb') as decrypted_fp:
                    office_file.decrypt(decrypted_fp)

            # add the decrypted file for analysis
            decrypted_file = analysis.add_file_observable(output_file)
            if decrypted_file:
                decrypted_file.add_tag('decrypted_msoffice')
                decrypted_file.add_detection_point("Was able to decrypt based on contents of email.", signature_uuid=EMAIL_ENCRYPTED_DECRYPTED.uuid)
                decrypted_file.add_yara_meta("type", "document.office")

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            # expected condition if it's not an office document
            if str(e) not in ['Unsupported file format', 'Unrecognized file format']:
                logging.exception(f"decryption for {_file} failed: {e}")

            logging.debug(f"decryption failed for unsupported file format on file {_file}")

            return AnalysisExecutionResult.COMPLETED