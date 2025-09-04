from saq.analysis.analysis import Analysis
from saq.constants import ANALYSIS_TYPE_MAILBOX, DIRECTIVE_ORIGINAL_EMAIL, DIRECTIVE_TRACKED, F_FILE, F_MESSAGE_ID, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable

MAILBOX_ALERT_PREFIX = 'ACE Mailbox Scanner Detection -'

KEY_ERROR = "error"
KEY_RESULTS = "results"

class MailboxEmailAnalysis(Analysis):
    pass

class MailboxEmailAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return MailboxEmailAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_ORIGINAL_EMAIL ]

    # TODO I think this maybe should be a post analysis thing?
    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        from saq.modules.email.rfc822 import EmailAnalysis

        # this is ONLY for analysis of type "mailbox"
        if self.get_root().alert_type != ANALYSIS_TYPE_MAILBOX:
            return AnalysisExecutionResult.COMPLETED

        # did we end up whitelisting the email?
        # this actually shouldn't even fire because if the email is whitelisted then the work queue is ignored
        # for this analysis
        if self.get_root().whitelisted:
            return AnalysisExecutionResult.COMPLETED

        email_analysis = self.wait_for_analysis(_file, EmailAnalysis)

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, MailboxEmailAnalysis)

        if email_analysis is None or isinstance(email_analysis, bool):
            self.get_root().description = '{} unparsable email'.format(MAILBOX_ALERT_PREFIX)
        else:
            assert isinstance(email_analysis, EmailAnalysis)
            email_analysis.load_details()
            if email_analysis.decoded_subject:
                self.get_root().description = '{} {}'.format(MAILBOX_ALERT_PREFIX, email_analysis.decoded_subject)
            elif email_analysis.subject:
                self.get_root().description = '{} {}'.format(MAILBOX_ALERT_PREFIX, email_analysis.subject)
            else:
                self.get_root().description = '{} (no subject)'.format(MAILBOX_ALERT_PREFIX)

            # merge the email analysis into the details of the root analysis
            if self.get_root().details is None:
                self.get_root().details = {}

            # XXX HACK
            self.get_root().details.update(email_analysis.details)
            self.get_root().set_details_modified()

            # make sure we track message IDs across analysis
            # this is basically so that cloudphish requests receive the message_id
            for observable in email_analysis.observables:
                if observable.type == F_MESSAGE_ID:
                    observable.add_directive(DIRECTIVE_TRACKED)

        return AnalysisExecutionResult.COMPLETED