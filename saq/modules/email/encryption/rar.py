import logging
import os
from subprocess import PIPE, Popen
from typing import override

from html2text import html2text
from saq.analysis.analysis import Analysis
from saq.analysis.search import search_down
from saq.constants import DIRECTIVE_EXTRACT_URLS, F_FILE, AnalysisExecutionResult
from saq.cracking import crack_password, generate_wordlist
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable

KEY_ENCRYPTION_INFO = 'encryption_info'
KEY_EMAIL = 'email'
KEY_EMAIL_BODY = 'email_body'
KEY_WORD_LIST = 'word_list'
KEY_PASSWORD = 'password'
KEY_ERROR = 'error'


class RarEncryptionAnalysis(Analysis):
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
        return "Rar Encryption Analysis"

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


class RarEncryptionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return RarEncryptionAnalysis

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

        import rarfile

        # is this an encrypted rar file?
        try:
            with rarfile.RarFile(_file.full_path) as rar_fp:
                if not rar_fp.needs_password():
                    return AnalysisExecutionResult.COMPLETED

        # expected condition if it's not an rar archive
        except Exception as e:
            logging.debug(f"Loading {_file} as rar failed: {e}")
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag('encrypted_rar')
        analysis = self.create_analysis(_file)

        # extract the hash for cracking
        p = Popen([os.path.join(self.john_bin_path, 'rar2john'), _file.full_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

        # did we get the hash?
        if not stdout:
            analysis.error = f"rar2john failed: {stderr.decode()}"
            return AnalysisExecutionResult.COMPLETED

        hash_file = f'{_file.full_path}.hash'
        with open(hash_file, 'wb') as fp:
            fp.write(stdout)

        # build wordlist for cracking password from email body text, if available
        analysis.word_list = []
        source_email = search_down(_file, lambda obj: isinstance(obj, EmailAnalysis) and obj.email is not None)
        if source_email and source_email.body:
            analysis.email = True

            # convert html to text
            try:
                with open(os.path.join(self.get_root().storage_dir, source_email.body.value), 'r', errors='ignore') as fp:
                    logging.debug(f"parsing {source_email.body.value} for html")
                    analysis.email_body = html2text(fp.read())[:self.byte_limit]

                analysis.word_list.extend(generate_wordlist(text_content=analysis.email_body,
                                                            range_low=self.range_low,
                                                            range_high=self.range_high,
                                                            byte_limit=self.byte_limit,
                                                            list_limit=self.list_limit))

                if analysis.word_list:
                    wordlist_path = f'{_file.full_path}.wordlist'
                    with open(wordlist_path, 'w') as fp:
                        for word in analysis.word_list:
                            fp.write(f'{word}\n')

                    try:
                        analysis.password = crack_password(self.john_bin_path, hash_file, _file.full_path, f'--wordlist={wordlist_path}')
                    except Exception as e:
                        logging.error(f"Error encountered when trying to crack password for {_file}: {e}")
                        return AnalysisExecutionResult.COMPLETED

            except Exception as e:
                logging.error(f"Error encountered when building password wordlist for {_file}: {e}")
                return AnalysisExecutionResult.COMPLETED

        # let's try brute forcing it if we didn't crack it with the email
        if not analysis.password and self.attempt_brute_force:
            analysis.password = crack_password(self.john_bin_path, hash_file, _file.full_path, f'--incremental=DigitsCustom')

        if not analysis.password:
            analysis.error = f"RarEncryptionAnalyzer could not crack password!"
            return AnalysisExecutionResult.COMPLETED

        # got the password!
        # make output directory for files in rar
        output_dir = f'{_file.full_path}.decrypted'
        try:
            os.makedirs(output_dir)
        except Exception as e:
            if not os.path.isdir(output_dir):
                raise Exception(f"unable to create archive directory {output_dir}: {e}")

        try:
            with rarfile.RarFile(_file.full_path) as rar_fp:
                rar_fp.extractall(output_dir, pwd=analysis.password)
        except Exception as e:
            logging.error(f"Unable to extract data from encrypted rar {_file}: {e}")
            return AnalysisExecutionResult.COMPLETED

        # add files in the Rar as observables
        for dirpath, dirnames, filenames in os.walk(output_dir):
            for file_name in filenames:
                full_path = os.path.join(dirpath, file_name)
                _file = analysis.add_file_observable(full_path)
                if _file:
                    _file.add_detection_point("Was able to decrypt based on contents of email.")
                    _file.add_directive(DIRECTIVE_EXTRACT_URLS)

        return AnalysisExecutionResult.COMPLETED
