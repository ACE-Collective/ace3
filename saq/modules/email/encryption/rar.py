import logging
import os
from typing import override

from saq.signatures.builtin import EMAIL_ENCRYPTED_DECRYPTED
from saq.constants import DIRECTIVE_EXTRACT_URLS, AnalysisExecutionResult
from saq.cracking import wordlist_from_email
from saq.modules.email.encryption.email_password import EmailPasswordAnalysis, EmailPasswordAnalyzer
from saq.modules.file_analysis.archive import UNRAR_WRITE_ERROR, archive_volumes
from saq.observables.file import FileObservable

KEY_ENCRYPTION_INFO = 'encryption_info'


class RarEncryptionAnalysis(EmailPasswordAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details[KEY_ENCRYPTION_INFO] = None

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


class RarEncryptionAnalyzer(EmailPasswordAnalyzer):
    @property
    def generated_analysis_type(self):
        return RarEncryptionAnalysis

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)

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
        p = self.run_sandboxed_tool([os.path.join(self.john_bin_path, 'rar2john'), _file.full_path], _file.full_path)
        if p is None:
            analysis.error = "rar2john did not finish"
            return AnalysisExecutionResult.COMPLETED

        # did we get the hash?
        if not p.stdout:
            analysis.error = f"rar2john failed: {p.stderr}"
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
        # make output directory for files in rar
        output_dir = f'{_file.full_path}.decrypted'
        try:
            os.makedirs(output_dir)
        except Exception as e:
            if not os.path.isdir(output_dir):
                raise Exception(f"unable to create archive directory {output_dir}: {e}")

        # rarfile would run unrar outside the sandbox. the trailing separator makes unrar take
        # output_dir as the directory to extract into
        # -kb keeps a member cut off at the file size limit (UNRAR_WRITE_ERROR)
        result = self.run_sandboxed_tool(['unrar', 'x', '-y', '-kb', f'-p{analysis.password}', _file.full_path,
                                          os.path.join(output_dir, '')], _file.full_path,
                                         read_files=archive_volumes(_file.full_path), write_dirs=[output_dir])
        if result is None:
            # run_sandboxed_tool() logged why (a timeout). What it extracted before it was stopped is
            # still decrypted content and is still added: the last file may be cut short
            analysis.error = "unrar did not finish"
        elif result.returncode == UNRAR_WRITE_ERROR:
            # what it wrote before the member it could not is still decrypted content and is still added
            logging.warning(f"unrar could not write every file of encrypted rar {_file}: {result.stderr.strip()[-500:]}")
            analysis.error = "unrar could not write every file"
        elif result.returncode != 0:
            logging.warning(f"Unable to extract data from encrypted rar {_file}: {result.stderr.strip()[-500:]}")
            analysis.error = result.failure_reason("unrar")
            return AnalysisExecutionResult.COMPLETED

        # add files in the Rar as observables
        for dirpath, dirnames, filenames in os.walk(output_dir):
            for file_name in filenames:
                full_path = os.path.join(dirpath, file_name)
                _file = analysis.add_file_observable(full_path)
                if _file:
                    _file.add_detection_point("Was able to decrypt based on contents of email.", signature_uuid=EMAIL_ENCRYPTED_DECRYPTED.uuid)
                    _file.add_directive(DIRECTIVE_EXTRACT_URLS)

        return AnalysisExecutionResult.COMPLETED
