import logging
import os
import tempfile
from typing import Type, override

from saq.constants import F_FILE, AnalysisExecutionResult
from saq.cracking import crack_password, wordlist_from_email
from saq.environment import get_temp_dir
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.encryption.email_password import (
    EmailPasswordAnalysis,
    EmailPasswordAnalyzer,
    EmailPasswordAnalyzerConfig,
)
from saq.modules.file_analysis.is_file_type import is_pdf_file
from saq.observables.file import FileObservable
from saq.signatures.builtin import EMAIL_ENCRYPTED_DECRYPTED


class PDFEncryptionAnalysis(EmailPasswordAnalysis):
    @override
    @property
    def display_name(self) -> str:
        return "PDF Encryption Analysis"


class PDFEncryptionAnalyzer(EmailPasswordAnalyzer):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailPasswordAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return PDFEncryptionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def crack(self, pdf_hash: bytes, word_list: list[str]) -> str | None:
        # the hash, the wordlist and john's session and pot files are not analysis output, and named
        # after the attachment in its directory they could collide with another attachment's file
        with tempfile.TemporaryDirectory(dir=get_temp_dir()) as work_dir:
            hash_file = os.path.join(work_dir, 'pdf.hash')
            with open(hash_file, 'wb') as fp:
                fp.write(pdf_hash)

            wordlist_path = os.path.join(work_dir, 'wordlist')
            with open(wordlist_path, 'w') as fp:
                fp.writelines(f'{word}\n' for word in word_list)

            return crack_password(self.john_bin_path, hash_file, hash_file, f'--wordlist={wordlist_path}', login='pdf')

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

        try:
            # find candidate passwords in the body of the email that carried this PDF
            analysis.email, analysis.email_body, analysis.word_list = wordlist_from_email(
                _file, range_low=self.range_low, range_high=self.range_high,
                byte_limit=self.byte_limit, list_limit=self.list_limit)

            # the summary says whether the email, its body or a candidate password was missing
            if not analysis.word_list:
                return AnalysisExecutionResult.COMPLETED

            # extract the hash for cracking; pdf2john.pl ships in john's run directory (the .py variant needs pyhanko)
            p = self.run_tool(['perl', os.path.join(self.john_bin_path, 'pdf2john.pl'), _file.full_path], _file.full_path, capture_output=True)
            if p is None:
                analysis.error = "pdf2john.pl timed out"
                return AnalysisExecutionResult.COMPLETED

            # pdf2john prints "<path>:" before it parses anything, so output with no hash is its failure too
            if b'$pdf$' not in p.stdout:
                stderr = p.stderr.decode(errors='ignore')
                analysis.error = f"pdf2john.pl failed: {stderr}"
                logging.error(f"pdf2john.pl failed on {_file.full_path} with exit code {p.returncode}: {stderr.strip()}",
                              extra={"path": _file.full_path, "root_uuid": self.get_root().uuid})
                return AnalysisExecutionResult.COMPLETED

            # pdf2john puts the file's path in front of the hash, and john splits the line at the
            # first ':', so a ':' in the attachment's name would keep it from loading the hash
            analysis.password = self.crack(b'pdf:' + p.stdout[p.stdout.index(b'$pdf$'):], analysis.word_list)

            if not analysis.password:
                analysis.error = "could not crack password"
                return AnalysisExecutionResult.COMPLETED

            # got the password! write out the decrypted copy
            output_file = self.get_root().create_output_file(f'{_file.file_name}.decrypted')
            # saved through the file create_output_file made: given a path, pikepdf writes a temporary
            # file beside it with a longer name, which a long attachment name pushes past NAME_MAX
            with pikepdf.open(_file.full_path, password=analysis.password) as pdf, open(output_file, 'wb') as fp:
                pdf.save(fp)

            decrypted_file = analysis.add_file_observable(output_file)
            if decrypted_file:
                decrypted_file.add_tag('decrypted_pdf')
                decrypted_file.add_detection_point("Was able to decrypt based on contents of email.", signature_uuid=EMAIL_ENCRYPTED_DECRYPTED.uuid)
                decrypted_file.add_yara_meta("type", "document.pdf")

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            # the engine logs the failure and writes the crash report, which keeps this PDF; the
            # analysis says why it stopped
            analysis.error = f"decryption failed: {e}"
            raise
