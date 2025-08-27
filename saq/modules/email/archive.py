import gzip
import logging
import os
import shutil
from typing import Optional
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.search import recurse_tree
from saq.constants import DB_EMAIL_ARCHIVE, DIRECTIVE_ARCHIVE, F_FILE, F_URL, G_ENCRYPTION_INITIALIZED, TAG_DECRYPTED_EMAIL, AnalysisExecutionResult
from saq.crypto import decrypt
from saq.database.pool import get_db_connection
from saq.email_archive import FIELD_URL, archive_email, index_email_archive
from saq.environment import g_boolean
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.time import local_time


KEY_DECRYPTED_FILE = "decrypted_file"

class EncryptedArchiveAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_DECRYPTED_FILE: None,
        }

    @property
    def decrypted_file(self) -> Optional[str]:
        return self.details.get(KEY_DECRYPTED_FILE)

    @decrypted_file.setter
    def decrypted_file(self, value: str):
        self.details[KEY_DECRYPTED_FILE] = value

    def generate_summary(self):
        if not self.decrypted_file:
            return None

        return "Encrypted Archive Analysis - retrieved {}".format(self.decrypted_file)

class EncryptedArchiveAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_program_exists('zcat')

    @property
    def generated_analysis_type(self):
        return EncryptedArchiveAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        # do we have the decryption password available?
        if not g_boolean(G_ENCRYPTION_INITIALIZED):
            return AnalysisExecutionResult.COMPLETED

        # encrypted archives end with .gz.e
        if not _file.file_name.endswith('.gz.e'):
            return AnalysisExecutionResult.COMPLETED

        gzip_path = '{}.rfc822.gz'.format(_file.full_path[:-len('.gz.e')])
        dest_path = '{}.rfc822'.format(_file.full_path[:-len('.gz.e')])

        # decrypt and decompress the archive file
        try:
            decrypt(_file.full_path, gzip_path)
            with gzip.open(gzip_path, 'rb') as fp_in:
                with open(dest_path, 'wb') as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

        except Exception as e:
            logging.error("unable to decrypt {}: {}".format(_file.full_path, e))
            report_exception()
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        # add the resulting file as an observable
        file_observable = analysis.add_file_observable(dest_path)
        if file_observable:
            #file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
            file_observable.add_tag(TAG_DECRYPTED_EMAIL)
        analysis.decrypted_file = os.path.relpath(dest_path, start=self.get_root().storage_dir)
        return AnalysisExecutionResult.COMPLETED

KEY_MESSAGE_ID = "message_id"
KEY_ARCHIVE_ID = "archive_id"
KEY_ARCHIVE_PATH = "archive_path"
KEY_HASH = "hash"

class EmailArchiveResults(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_MESSAGE_ID: None,
            KEY_ARCHIVE_ID: None,
            KEY_ARCHIVE_PATH: None,
            KEY_HASH: None
        }

    @property
    def message_id(self) -> Optional[str]:
        return self.details[KEY_MESSAGE_ID]

    @message_id.setter
    def message_id(self, value: str):
        self.details[KEY_MESSAGE_ID] = value

    @property
    def archive_id(self) -> Optional[int]:
        return self.details[KEY_ARCHIVE_ID]

    @archive_id.setter
    def archive_id(self, value: int):
        self.details[KEY_ARCHIVE_ID] = value

    @property
    def archive_path(self) -> Optional[str]:
        return self.details[KEY_ARCHIVE_PATH]

    @archive_path.setter
    def archive_path(self, value: str):
        self.details[KEY_ARCHIVE_PATH] = value

    @property
    def hash(self) -> Optional[str]:
        return self.details[KEY_HASH]

    @hash.setter
    def hash(self, value: str):
        self.details[KEY_HASH] = value

    def generate_summary(self):
        if not self.archive_path:
            return None

        return f"Archive Path: {self.archive_path}"

class EmailArchiveAction(AnalysisModule):
    @property
    def valid_observable_types(self):
        return [ F_FILE ]

    @property
    def required_directives(self):
        return [ DIRECTIVE_ARCHIVE ]

    @property
    def generated_analysis_type(self):
        return EmailArchiveResults

    def execute_analysis(self, _file: Observable) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        from saq.modules.email.rfc822 import EmailAnalysis

        # has this been whitelisted?
        if _file.whitelisted:
            logging.debug(f"{_file} has been whitelisted - not archiving")
            return AnalysisExecutionResult.COMPLETED

        # if this file has been decrypted from the archives then we obviously don't need to process any further
        if _file.has_tag(TAG_DECRYPTED_EMAIL):
            # this should not happen now
            logging.warning(f"detected decrypted email {_file} as original email")
            return AnalysisExecutionResult.COMPLETED

        email_analysis = self.wait_for_analysis(_file, EmailAnalysis)
        if not email_analysis:
            logging.warning("unable to obtain EmailAnalysis for %s", _file)
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, EmailArchiveResults)

        insert_date = local_time()
        archive_result = archive_email(_file.full_path, email_analysis.message_id, email_analysis.env_rcpt_to, insert_date)
        analysis.hash = archive_result.hash
        analysis.archive_id = archive_result.archive_id
        analysis.archive_path = archive_result.archive_path

        return AnalysisExecutionResult.COMPLETED

    def index_email(self, _file: Observable):
        analysis = _file.get_and_load_analysis(EmailArchiveResults)
        assert isinstance(analysis, EmailArchiveResults)

        # find all the urls rooted at this email
        transactions = []

        def _callback(target):
            if isinstance(target, Observable) and target.type == F_URL:
                transactions.append((FIELD_URL, target.value))
                    
        recurse_tree(_file, _callback)

        with get_db_connection(DB_EMAIL_ARCHIVE) as db:
            cursor = db.cursor()

            # update the fast search indexes
            insert_date = local_time()
            for field, email_property in transactions:
                index_email_archive(db, cursor, analysis.archive_id, field, email_property, insert_date)

            db.commit()

    # url and content data found in attachments can (will) be added after we
    # initially record the archive analysis

    def execute_post_analysis(self):
        from saq.modules.email.rfc822 import EmailAnalysis

        for _file in self.get_root().find_observables(lambda o: o.type == F_FILE):
            email_analysis = _file.get_and_load_analysis(EmailAnalysis)
            if not email_analysis:
                continue

            archive_analysis = _file.get_and_load_analysis(EmailArchiveResults)
            if not archive_analysis:
                continue

            self.index_email(_file)
