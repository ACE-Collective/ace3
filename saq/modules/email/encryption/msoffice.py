import logging
import os
from subprocess import PIPE, Popen
from typing import override

import msoffcrypto
from saq.analysis.analysis import Analysis
from saq.analysis.search import search_down
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.cracking import crack_password, generate_wordlist
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule

from html2text import html2text

from saq.observables.file import FileObservable

KEY_ENCRYPTION_INFO = 'encryption_info'
KEY_EMAIL = 'email'
KEY_EMAIL_BODY = 'email_body'
KEY_WORD_LIST = 'word_list'
KEY_PASSWORD = 'password'
KEY_ERROR = 'error'


class MSOfficeEncryptionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ENCRYPTION_INFO: None,
            KEY_EMAIL: False,
            KEY_EMAIL_BODY: None,
            KEY_WORD_LIST: [],
            KEY_PASSWORD: None,
            KEY_ERROR: None
        }

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

    @property
    def email(self):
        return self.details[KEY_EMAIL]

    @email.setter
    def email(self, value):
        self.details[KEY_EMAIL] = value

    @property
    def email_body(self):
        return self.details[KEY_EMAIL_BODY]

    @email_body.setter
    def email_body(self, value):
        self.details[KEY_EMAIL_BODY] = value

    @property
    def word_list(self):
        return self.details[KEY_WORD_LIST]

    @word_list.setter
    def word_list(self, value):
        self.details[KEY_WORD_LIST] = value

    @property
    def password(self):
        return self.details[KEY_PASSWORD]

    @password.setter
    def password(self, value):
        self.details[KEY_PASSWORD] = value

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    def generate_summary(self):
        if self.details is None:
            return None

        result = self.display_name
        if self.error:
            return f"{result}: {self.error}"
        elif self.password:
            return f"{result}: password {self.password}"
        elif not self.email:
            return f"{result}: no associated email detected"
        elif not self.email_body:
            return f"{result}: email body cannot be determined"
        elif not self.word_list:
            return f"{result}: word list could not be created from email"
        elif not self.password:
            return f"{result}: password not available"
        else:
            return f"{result}: could not decrypt"


class MSOfficeEncryptionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MSOfficeEncryptionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def range_low(self):
        return self.config.getint('range_low')

    @property
    def range_high(self):
        return self.config.getint('range_high')

    @property
    def byte_limit(self):
        return self.config.getint('byte_limit')

    @property
    def list_limit(self):
        return self.config.getint('list_limit')

    @property
    def john_bin_path(self):
        return self.config.get('john_bin_path')

    @property
    def attempt_brute_force(self):
        return self.config.getboolean('attempt_brute_force')

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        from saq.modules.email.rfc822 import EmailAnalysis

        # does this file exist as an attachment?
        if not _file.exists:
            return AnalysisExecutionResult.COMPLETED

        # is this an encrypted OLE document?
        try:
            with open(_file.full_path, 'rb') as office_fp:
                try:
                    office_file = msoffcrypto.OfficeFile(office_fp)
                except:
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
                        logging.error(f"Unable to check encryption status of {_file.full_path}: {str(e)}")
                        report_exception()

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
            email = search_down(_file, lambda obj: isinstance(obj, EmailAnalysis) and obj.email is not None)
            if email:
                analysis.email = True

                # email needs to have a body
                if email.body:

                    # convert html to text
                    with open(email.body.full_path, 'r', errors='ignore') as fp:
                        logging.debug("parsing {} for html".format(email.body.value))
                        analysis.email_body = html2text(fp.read())[:self.byte_limit]

                    analysis.word_list.extend(generate_wordlist(text_content=analysis.email_body,
                                                                range_low=self.range_low,
                                                                range_high=self.range_high,
                                                                byte_limit=self.byte_limit,
                                                                list_limit=self.list_limit))

            wordlist_path = f'{_file.full_path}.wordlist'
            with open(wordlist_path, 'w') as fp:
                for word in analysis.word_list:
                    fp.write(f'{word}\n')

            # crack it with john the ripper using wordlist
            analysis.password = crack_password(self.john_bin_path, hash_file, _file.full_path, f'--wordlist={wordlist_path}')

            # let's try brute forcing it if we didn't crack it with the email
            if not analysis.password and self.attempt_brute_force:
                analysis.password = crack_password(self.john_bin_path, hash_file, _file.full_path, '--incremental=DigitsCustom')

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
                decrypted_file.add_detection_point("Was able to decrypt based on contents of email.")

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            # expected condition if it's not an office document
            if str(e) not in ['Unsupported file format', 'Unrecognized file format']:
                logging.error(f"decryption for {_file} failed: {e}")
                report_exception()

            logging.debug(f"decryption failed for unsupported file format on file {_file}")

            return AnalysisExecutionResult.COMPLETED