from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig

KEY_EMAIL = 'email'
KEY_EMAIL_BODY = 'email_body'
KEY_WORD_LIST = 'word_list'
KEY_PASSWORD = 'password'
KEY_ERROR = 'error'


class EmailPasswordAnalysis(Analysis):
    """An encrypted attachment cracked with candidate passwords from the body of the email that carried it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_EMAIL: False,
            KEY_EMAIL_BODY: None,
            KEY_WORD_LIST: [],
            KEY_PASSWORD: None,
            KEY_ERROR: None,
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
        else:
            return f"{result}: password not available"


class EmailPasswordAnalyzerConfig(AnalysisModuleConfig):
    range_low: int = Field(..., description="The minimum size of the passwords to try.")
    range_high: int = Field(..., description="The maximum size of the passwords to try.")
    byte_limit: int = Field(..., description="How many bytes into the email do you want to look?")
    list_limit: int = Field(..., description="The maximum size of the word list created.")
    john_bin_path: str = Field(..., description="Full path to john the ripper binary.")


class EmailPasswordAnalyzer(AnalysisModule):
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
