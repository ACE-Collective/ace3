import hashlib
import logging
import os
from typing import Optional, override
from saq.email_archive import iter_archived_email, email_is_archived
from saq.analysis.analysis import Analysis
from saq.analysis.search import search_down
from saq.constants import F_MESSAGE_ID, AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule

KEY_ERROR = "error"
KEY_EXTRACTED_EMAIL = "extracted_email"

class MessageIDAnalysisV2(Analysis):
    """Is there an email with this Message-ID available anywhere?"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_ERROR: None,
            KEY_EXTRACTED_EMAIL: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "Message ID Analysis"

    @property
    def error(self) -> Optional[str]:
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value: str):
        self.details[KEY_ERROR] = value

    @property
    def extracted_email(self) -> Optional[str]:
        return self.details[KEY_EXTRACTED_EMAIL]

    @extracted_email.setter
    def extracted_email(self, value: str):
        self.details[KEY_EXTRACTED_EMAIL] = value

    def generate_summary(self):
        if self.error:
            return f"{self.display_name}: ERROR: {self.error}"

        if not self.extracted_email:
            return None

        return f"{self.display_name}: archived email extracted {self.extracted_email}"

class MessageIDAnalyzerV2(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return MessageIDAnalysisV2

    @property
    def valid_observable_types(self):
        return F_MESSAGE_ID

    def execute_analysis(self, message_id) -> AnalysisExecutionResult:

        # if we've already analyzed this email then we don't need to extract it
        from saq.modules.email import EmailAnalysis
        email_analysis = search_down(message_id, 
                lambda x: isinstance(x, EmailAnalysis) and x.message_id == message_id.value)

        if email_analysis:
            logging.debug(f"already have email analysis for {message_id.value}")
            return AnalysisExecutionResult.COMPLETED

        if not email_is_archived(message_id.value):
            logging.info(f"email {message_id.value} is not archived")
            return AnalysisExecutionResult.COMPLETED

        file_name = f"{message_id.value}.rfc822"
        
        # Some message IDs can be extremely long, so instead we hash them
        # so that the resulting file name/path is not too long for the filesystem.
        if len(file_name) > 200:
            hash_prefix = hashlib.sha256(message_id.value.encode()).hexdigest()[:32]
            file_name = f"{hash_prefix}.rfc822"
        target_path = self.get_root().create_file_path(file_name)
        analysis = None

        try:
            if os.path.exists(target_path):
                logging.info(f"archived email {target_path} already exists")
            else:
                with open(target_path, "wb") as fp:
                    for chunk in iter_archived_email(message_id.value):
                        fp.write(chunk)

            if os.path.getsize(target_path) == 0:
                logging.info(f"got 0 bytes for {message_id.value}")
                os.unlink(target_path)
                return AnalysisExecutionResult.COMPLETED
            else:
                analysis = self.create_analysis(message_id)
                assert isinstance(analysis, MessageIDAnalysisV2)
                file_observable = analysis.add_file_observable(target_path)
                if file_observable:
                    file_observable.add_tag('decrypted_email')

                return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            logging.info(f"unable to get archived email {message_id.value}: {e}")
            report_exception()
            if analysis:
                analysis.error = str(e)

            return AnalysisExecutionResult.COMPLETED

