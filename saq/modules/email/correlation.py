import logging
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import F_URL, AnalysisExecutionResult
from saq.database.pool import get_db_connection
from saq.email import get_email_archive_sections
from saq.modules import AnalysisModule
from saq.modules.email.constants import KEY_COUNT, KEY_EMAILS


class URLEmailPivotAnalysis_v2(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_COUNT: None,
            KEY_EMAILS: None,
        }

    @override
    @property
    def display_name(self):
        return "URL Email Pivot Analyzer"

    @property
    def count(self):
        return self.details[KEY_COUNT]

    @count.setter
    def count(self, value):
        self.details[KEY_COUNT] = value

    @property
    def emails(self):
        return self.details[KEY_EMAILS]

    @emails.setter
    def emails(self, value):
        self.details[KEY_EMAILS] = value

    def generate_summary(self):
        if not self.count:
            return None

        return f"{self.display_name} ({self.count} emails matched)"

class URLEmailPivotAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return URLEmailPivotAnalysis_v2

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def result_limit(self):
        return self.config.getint('result_limit')

    def execute_analysis(self, url) -> AnalysisExecutionResult:

        # at the minimum we look up all the emails that have this url in them
        db_sections = get_email_archive_sections()
        emails = {}
        count = 0

        for section in db_sections:
            with get_db_connection(section) as db:
                c = db.cursor()
                c.execute("""
SELECT 
    COUNT(DISTINCT(archive_id))
FROM 
    archive_index 
WHERE 
    field = 'url' AND hash = UNHEX(SHA2(%s, 256))""", ( url.value, ))

                # first we check to see how many of these we've got
                row = c.fetchone()
                if row:
                    count += row[0]

        # didn't find anything?
        if not count:
            logging.debug("did not find anything matching {}".format(url.value))
            return AnalysisExecutionResult.COMPLETED

        # if there are too many then we just report the number of them
        if count >= self.result_limit:
            analysis = self.create_analysis(url)
            analysis.count = count
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(url)
        analysis.count = count
        #for source in emails.keys():
            #for archive_id in emails[source].keys():
                #emails[source][archive_id] = emails[source][archive_id].json

        #analysis.emails = emails
        return AnalysisExecutionResult.COMPLETED