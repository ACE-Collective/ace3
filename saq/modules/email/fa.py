import logging
import re
from typing import Type
from pydantic import Field, ConfigDict
from saq.analysis.analysis import Analysis
from saq.signatures.builtin import EMAIL_MACRO_NEW_SENDER, EMAIL_SUSPECT_URL_NEW_SENDER
from saq.analysis.observable import Observable
from saq.analysis.search import search_down
from saq.brocess import query_brocess_by_email_conversation, query_brocess_by_source_email
from saq.constants import DIRECTIVE_SANDBOX, F_EMAIL_CONVERSATION, F_FILE, F_URL, parse_email_conversation, AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig


class EmailConversationFrequencyAnalysis(Analysis):
    """How often does this external person email this internal person?"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "source_count": None,
            "dest_count": None,
        }

    @property
    def source_count(self):
        return self.details["source_count"]

    @source_count.setter
    def source_count(self, value):
        self.details["source_count"] = value

    @property
    def dest_count(self):
        return self.details["dest_count"]

    @dest_count.setter
    def dest_count(self, value):
        self.details["dest_count"] = value

    def generate_summary(self):
        if not self.source_count:
            return None

        result = 'Email Conversation Frequency Analysis -'
        if not self.source_count:
            return f"{result} first time received"

        return f"{result} {self.source_count} emails received before, {self.dest_count} to this user"

class EmailConversationFrequencyAnalyzerConfig(AnalysisModuleConfig):
    conversation_count_threshold: int = Field(..., description="When two people email each other frequently we want to know that. This is the minimum number of times we've seen this email address email this other email address that we consider to be 'frequent'.")

class EmailConversationFrequencyAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailConversationFrequencyAnalyzerConfig

    def verify_environment(self):
        pass

    @property
    def conversation_count_threshold(self):
        # when two people email each other frequently we want to know that
        # this is the minimum number of times we've seen this email address email this other email address
        # that we consider to be "frequent"
        return self.config.conversation_count_threshold

    @property
    def generated_analysis_type(self):
        return EmailConversationFrequencyAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_CONVERSATION

    def execute_analysis(self, email_conversation) -> AnalysisExecutionResult:
        # are we on cooldown?
        # XXX this should be done from the engine!
        if self._context.cooldown_timeout:
            logging.debug("{} on cooldown - not checking".format(self))
            return AnalysisExecutionResult.COMPLETED

        mail_from, rcpt_to = parse_email_conversation(email_conversation.value)

        # how often do we see this email address sending us emails?
        source_count = 0
        try:
            source_count = query_brocess_by_source_email(mail_from)
        except Exception as e:
            logging.error("unable to query brocess: {}".format(e))
            report_exception()
            self.enter_cooldown()
            return AnalysisExecutionResult.COMPLETED

        if not source_count:
            email_conversation.add_tag('new_sender')

        analysis = self.create_analysis(email_conversation)
        assert isinstance(analysis, EmailConversationFrequencyAnalysis)
        analysis.source_count = source_count

        # if this is the first time we've ever seen this email address then we don't need to do any
        # more frequency analysis
        if source_count:
            # how often do these guys talk?
            conversation_count = 0
            try:
                conversation_count = query_brocess_by_email_conversation(mail_from, rcpt_to)

                # do these guys talk a lot?
                if conversation_count >= self.conversation_count_threshold:
                    email_conversation.add_tag('frequent_conversation')

                analysis.dest_count = conversation_count
                return AnalysisExecutionResult.COMPLETED

            except Exception as e:
                logging.error("unable to query brocess: {}".format(e))
                report_exception()
                self.enter_cooldown()
                return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED

class EmailConversationAttachmentAnalysis(Analysis):
    """Has someone who has never sent us an email before sent us an attachment used in attacks?"""
    pass

class EmailConversationAttachmentAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailConversationAttachmentAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        from saq.modules.file_analysis import FileTypeAnalysis
        from saq.modules.email.rfc822 import EmailAnalysis

        # the file that we are looking at is word documents and the like
        file_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not isinstance(file_analysis, FileTypeAnalysis):
            return AnalysisExecutionResult.COMPLETED

        # this is really only valid for email scanning
        # look for a file with EmailAnalysis
        if len(self.get_root().get_analysis_by_type(EmailAnalysis)) == 0:
            return AnalysisExecutionResult.COMPLETED

        if not file_analysis.is_office_document:
            return AnalysisExecutionResult.COMPLETED

        # is there a macro anywhere?
        if not _file.search_tree(tags='macro'):
            return AnalysisExecutionResult.COMPLETED

        # wait for email conversation analysis to complete
        is_new_sender = False
        for ec_observable in self.get_root().get_observables_by_type(F_EMAIL_CONVERSATION):
            if ec_observable.get_and_load_analysis(EmailConversationFrequencyAnalysis) is None:
                continue

            # is this tagged as new_sender?
            if not ec_observable.has_tag('new_sender'):
                continue

            is_new_sender = True
            break

        if not is_new_sender:
            return AnalysisExecutionResult.COMPLETED

        #_file.add_tag('suspect')
        _file.add_directive(DIRECTIVE_SANDBOX)
        _file.add_detection_point("An email from a new sender contained a macro.", signature_uuid=EMAIL_MACRO_NEW_SENDER.uuid)

        analysis = self.create_analysis(_file)
        return AnalysisExecutionResult.COMPLETED

class EmailConversationLinkAnalysis(Analysis):
    """Has someone who has never sent us an email before sent us a potentially malicious link?"""
    pass

class EmailConversationLinkAnalyzerConfig(AnalysisModuleConfig):
    # Dynamic keys like url_pattern_* are allowed via extra fields
    model_config = ConfigDict(extra='allow')

class EmailConversationLinkAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailConversationLinkAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # load the list of url patterns we want to alert on
        self.url_patterns = []
        config_dict = self.config.model_dump()
        for key in config_dict.keys():
            if key.startswith('url_pattern_'):
                try:
                    pattern = config_dict[key]
                    self.url_patterns.append(re.compile(pattern))
                except Exception as e:
                    logging.error(f"unable to add pattern {pattern}: {e}")

    @property
    def generated_analysis_type(self):
        return EmailConversationLinkAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, url) -> AnalysisExecutionResult:

        from saq.modules.email.rfc822 import EmailAnalysis

        # does this URL match one of our patterns?
        matches = False
        for pattern in self.url_patterns:
            if pattern.search(url.value):
                matches = True
                break

        if not matches:
            return AnalysisExecutionResult.COMPLETED

        # get the email this url came from
        def _is_email(_file):
            if isinstance(_file, Observable):
                if _file.type == F_FILE:
                    if self.wait_for_analysis(_file, EmailAnalysis):
                        return True

        email = search_down(url, _is_email)
        if not email:
            return AnalysisExecutionResult.COMPLETED

        email_analysis = email.get_and_load_analysis(EmailAnalysis)
        assert isinstance(email_analysis, EmailAnalysis)

        # are any of the email conversations tagged as new sender?
        for ec in email_analysis.get_observables_by_type(F_EMAIL_CONVERSATION):
            if self.wait_for_analysis(ec, EmailConversationFrequencyAnalysis):
                if ec.has_tag('new_sender'):
                    # this is a url we would crawl AND it's from a new sender
                    url.add_detection_point("Suspect URL sent from new sender.", signature_uuid=EMAIL_SUSPECT_URL_NEW_SENDER.uuid)

        analysis = self.create_analysis(url)
        return AnalysisExecutionResult.COMPLETED