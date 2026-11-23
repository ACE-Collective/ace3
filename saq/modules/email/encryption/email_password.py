import os
import tempfile
from typing import Type

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import F_FILE
from saq.cracking import crack_password
from saq.environment import get_temp_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig

KEY_EMAIL = 'email'
KEY_EMAIL_BODY = 'email_body'
KEY_WORD_LIST = 'word_list'
KEY_PASSWORD = 'password'


class EmailPasswordAnalysis(Analysis):
    """An encrypted attachment cracked with candidate passwords from the body of the email that carried it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_EMAIL: False,
            KEY_EMAIL_BODY: None,
            KEY_WORD_LIST: [],
            KEY_PASSWORD: None,
        }

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
        else:
            return f"{result}: password not available"


class EmailPasswordAnalyzerConfig(AnalysisModuleConfig):
    range_low: int = Field(..., description="The minimum size of the passwords to try.")
    range_high: int = Field(..., description="The maximum size of the passwords to try.")
    byte_limit: int = Field(..., description="How many characters of each email body part (html converted to text) to read for candidate passwords.")
    list_limit: int = Field(..., description="The maximum size of the word list created.")
    john_bin_path: str = Field(..., description="Full path to john the ripper binary.")


class EmailPasswordAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailPasswordAnalyzerConfig

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def range_low(self):
        return self.config.range_low

    @property
    def range_high(self):
        return self.config.range_high

    @property
    def byte_limit(self):
        return self.config.byte_limit

    @property
    def list_limit(self):
        return self.config.list_limit

    @property
    def john_bin_path(self):
        return self.config.john_bin_path

    def crack(self, john_hash: str, word_list: list[str], filename: str, login: str | None = None) -> str | None:
        """Cracks john_hash, the output of a *2john tool, with the candidates in word_list and returns
        the password, or None. filename is the path of the encrypted file and login the login the hash
        line starts with, either of which crack_password finds the cracked line by."""
        # the hash, the wordlist and john's session and pot files are not analysis output, and named
        # after the attachment in its directory they could collide with another attachment's file
        with tempfile.TemporaryDirectory(dir=get_temp_dir()) as work_dir:
            hash_file = os.path.join(work_dir, 'hash')
            with open(hash_file, 'w') as fp:
                fp.write(john_hash)

            wordlist_path = os.path.join(work_dir, 'wordlist')
            with open(wordlist_path, 'w') as fp:
                fp.writelines(f'{word}\n' for word in word_list)

            return crack_password(self, self.john_bin_path, hash_file, filename, f'--wordlist={wordlist_path}',
                                  login=login, read_files=[wordlist_path])
