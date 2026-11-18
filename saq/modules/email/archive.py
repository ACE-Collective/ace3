import logging
import os
import shutil
import uuid
from typing import Optional, Type

from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import DIRECTIVE_ARCHIVE, F_FILE, TAG_DECRYPTED_EMAIL, AnalysisExecutionResult
from saq.email_archive import archive_email
from saq.environment import get_data_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.rfc822 import TAG_OUTBOUND_EMAIL, EmailAnalysis
from saq.observables.file import FileObservable
from saq.util.time import local_time


KEY_MESSAGE_ID = "message_id"
KEY_HASH = "hash"

class EmailArchiveActionConfig(AnalysisModuleConfig):
    expiration_days: int = Field(..., description="The number of days to keep archived emails.")

class EmailArchiveResults(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_MESSAGE_ID: None,
            KEY_HASH: None
        }

    @property
    def message_id(self) -> Optional[str]:
        return self.details[KEY_MESSAGE_ID]

    @message_id.setter
    def message_id(self, value: str):
        self.details[KEY_MESSAGE_ID] = value

    @property
    def hash(self) -> Optional[str]:
        return self.details[KEY_HASH]

    @hash.setter
    def hash(self, value: str):
        self.details[KEY_HASH] = value

    def generate_summary(self):
        if not self.hash:
            return None

        return f"Archived Email: {self.hash}"

class EmailArchiveAction(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailArchiveActionConfig

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

        # if this file has been decrypted from the archives then we obviously don't need to process any further
        if _file.has_tag(TAG_DECRYPTED_EMAIL):
            # this should not happen now
            logging.warning(f"detected decrypted email {_file} as original email")
            return AnalysisExecutionResult.COMPLETED

        email_analysis = _file.get_and_load_analysis(EmailAnalysis)
        if not email_analysis:
            # scan_inbound_only skips the email analysis of outbound mail on purpose
            if _file.has_tag(TAG_OUTBOUND_EMAIL):
                logging.debug(f"outbound email {_file} was not analyzed - not archiving")
            else:
                logging.warning(f"unable to obtain EmailAnalysis for {_file}")
            return AnalysisExecutionResult.COMPLETED

        # the archive is found by Message-ID, so an email without one could never be found again
        if not email_analysis.message_id:
            review_dir = os.path.join(get_data_dir(), "review", "rfc822")
            os.makedirs(review_dir, exist_ok=True)
            review_path = os.path.join(review_dir, f"{uuid.uuid4()}.rfc822")
            shutil.copy2(_file.full_path, review_path)
            logging.error(f"unable to archive {_file} - missing message-id header - saved to {review_path} for review")
            return AnalysisExecutionResult.COMPLETED

        digest = archive_email(_file.full_path, email_analysis.message_id, local_time())

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, EmailArchiveResults)
        analysis.hash = digest

        return AnalysisExecutionResult.COMPLETED
