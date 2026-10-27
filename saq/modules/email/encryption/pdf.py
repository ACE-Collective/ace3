import logging
from typing import Type, override

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.cracking import crack_password, wordlist_from_email
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_pdf_file
from saq.observables.file import FileObservable
from saq.signatures.builtin import EMAIL_ENCRYPTED_DECRYPTED

KEY_EMAIL = 'email'
KEY_EMAIL_BODY = 'email_body'
KEY_WORD_LIST = 'word_list'
KEY_PASSWORD = 'password'
KEY_ERROR = 'error'


class PDFEncryptionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_EMAIL: False,
            KEY_EMAIL_BODY: None,
            KEY_WORD_LIST: [],
            KEY_PASSWORD: None,
            KEY_ERROR: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "PDF Encryption Analysis"

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
            return f"{result}: could not decrypt"


class PDFEncryptionAnalyzerConfig(AnalysisModuleConfig):
    range_low: int = Field(..., description="The minimum size of the passwords to try.")
    range_high: int = Field(..., description="The maximum size of the passwords to try.")
    byte_limit: int = Field(..., description="How many bytes into the email do you want to look?")
    list_limit: int = Field(..., description="The maximum size of the word list created.")
    john_bin_path: str = Field(..., description="Full path to john the ripper binary.")
    pdf2john_path: str = Field(..., description="Full path to the pdf2john.pl hash extractor.")


class PDFEncryptionAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return PDFEncryptionAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return PDFEncryptionAnalysis

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

    @property
    def pdf2john_path(self):
        return self.config.pdf2john_path

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        # imported here: the search indexer and the GUI import this module only to read PDFEncryptionAnalysis
        import pikepdf

        # does this file exist as an attachment?
        if not _file.exists:
            return AnalysisExecutionResult.COMPLETED

        if not is_pdf_file(_file.full_path):
            return AnalysisExecutionResult.COMPLETED

        # is this an encrypted PDF whose user password we need to crack?
        try:
            try:
                pdf = pikepdf.open(_file.full_path)
                # opened with no password: either not encrypted, or encrypted with an owner
                # (permissions) password only, which leaves the content readable - nothing for us
                pdf.close()
                return AnalysisExecutionResult.COMPLETED
            except pikepdf.PasswordError:
                # a user password is required, which is what this module cracks
                pass
            except pikepdf.PdfError as e:
                # damaged or not really a PDF; nothing this module can decrypt
                logging.debug(f"pikepdf cannot open {_file.full_path}: {e}")
                return AnalysisExecutionResult.COMPLETED

            analysis = self.create_analysis(_file)
            _file.add_tag('encrypted_pdf')

            # extract the hash for cracking
            p = self.run_tool(['perl', self.pdf2john_path, _file.full_path], _file.full_path, capture_output=True)
            if p is None:
                analysis.error = "pdf2john.pl timed out"
                return AnalysisExecutionResult.COMPLETED

            if not p.stdout:
                stderr = p.stderr.decode(errors='ignore')
                analysis.error = f"pdf2john.pl failed: {stderr}"
                logging.error(f"pdf2john.pl failed on {_file.full_path} with exit code {p.returncode}: {stderr.strip()}",
                              extra={"path": _file.full_path, "root_uuid": self.get_root().uuid})
                return AnalysisExecutionResult.COMPLETED

            hash_file = f'{_file.full_path}.hash'
            with open(hash_file, 'wb') as fp:
                fp.write(p.stdout)

            # find candidate passwords in the body of the email that carried this PDF
            analysis.email, analysis.email_body, analysis.word_list = wordlist_from_email(
                _file, range_low=self.range_low, range_high=self.range_high,
                byte_limit=self.byte_limit, list_limit=self.list_limit)

            if not analysis.word_list:
                analysis.error = "could not crack password"
                return AnalysisExecutionResult.COMPLETED

            wordlist_path = f'{_file.full_path}.wordlist'
            with open(wordlist_path, 'w') as fp:
                for word in analysis.word_list:
                    fp.write(f'{word}\n')

            # crack it with john the ripper using the wordlist
            analysis.password = crack_password(self.john_bin_path, hash_file, _file.full_path, f'--wordlist={wordlist_path}')

            if not analysis.password:
                analysis.error = "could not crack password"
                return AnalysisExecutionResult.COMPLETED

            # got the password! write out the decrypted copy
            output_file = f'{_file.full_path}.decrypted'
            with pikepdf.open(_file.full_path, password=analysis.password) as pdf:
                pdf.save(output_file)

            decrypted_file = analysis.add_file_observable(output_file)
            if decrypted_file:
                decrypted_file.add_tag('decrypted_pdf')
                decrypted_file.add_detection_point("Was able to decrypt based on contents of email.", signature_uuid=EMAIL_ENCRYPTED_DECRYPTED.uuid)
                decrypted_file.add_yara_meta("type", "document.pdf")

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            logging.exception(f"decryption for {_file} failed: {e}")
            return AnalysisExecutionResult.COMPLETED
