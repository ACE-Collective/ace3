import logging
from typing import override
from urllib.parse import parse_qs, urlparse
from saq.analysis.analysis import Analysis
from saq.constants import F_URL, AnalysisExecutionResult
from saq.modules import AnalysisModule


KEY_PROTECTION_TYPE = 'protection_type'
KEY_EXTRACTED_URL = 'extracted_url'

class ProtectedURLAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_PROTECTION_TYPE: None,
            KEY_EXTRACTED_URL: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "Protected URL Analysis"

    @property
    def protection_type(self):
        return self.details[KEY_PROTECTION_TYPE]

    @protection_type.setter
    def protection_type(self, value):
        self.details[KEY_PROTECTION_TYPE] = value

    @property
    def extracted_url(self):
        return self.details[KEY_EXTRACTED_URL]

    @extracted_url.setter
    def extracted_url(self, value):
        self.details[KEY_EXTRACTED_URL] = value

    def generate_summary(self):
        if not self.protection_type:
            return None

        if not self.extracted_url:
            return None

        return f"{self.display_name}: detected type {self.protection_type} extracted url {self.extracted_url}"


PROTECTION_TYPE_ONE_DRIVE = 'one drive'


class ProtectedURLAnalyzer(AnalysisModule):
    """Is this URL protected by another company by wrapping it inside another URL they check first?"""
    """Most of this AnalysisModule has been moved to URLObservable.sanitize_protected_urls, OneDrive analysis remains
        as it relies on CrawlPhish analysis"""
    
    @property
    def generated_analysis_type(self):
        return ProtectedURLAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, url) -> AnalysisExecutionResult:

        from saq.modules.url.crawlphish import CrawlphishAnalysisV2

        protection_type = None
        extracted_url = None

        try:
            parsed_url = urlparse(url.value)
        except Exception as e:
            logging.error("unable to parse url {}: {}".format(url.value, e))
            return AnalysisExecutionResult.COMPLETED

        # one drive links
        if parsed_url.netloc.lower().endswith('1drv.ms'):
            # need to wait for the redirection information
            crawlphish_analysis = self.wait_for_analysis(url, CrawlphishAnalysisV2)
            if not crawlphish_analysis:
                logging.debug("one drive url {} requires unavailable crawlphish analysis".format(url.value))
                return AnalysisExecutionResult.COMPLETED

            # https://1drv.ms/b/s!AvqIO0JVRziVa0IWW7c6GG3YkdU
            # redirects to https://onedrive.live.com/redir?resid=95384755423B88FA!107&authkey=!AEIWW7c6GG3YkdU&ithint=file%2cpdf
            # transform to https://onedrive.live.com/download?authkey=!AEIWW7c6GG3YkdU&cid=95384755423B88FA&resid=95384755423B88FA!107&parId=root&o=OneUp

            # the final url should be the redirection target
            if not crawlphish_analysis.final_url:
                logging.debug("one drive url {} missing final url".format(url.value))
                return AnalysisExecutionResult.COMPLETED

            try:
                parsed_final_url = urlparse(crawlphish_analysis.final_url)
                _qs = parse_qs(parsed_final_url.query)
            except Exception as e:
                logging.error("unable to parse final url {}: {}".format(crawlphish_analysis.final_url, e))
                return AnalysisExecutionResult.COMPLETED

            protection_type = PROTECTION_TYPE_ONE_DRIVE
            extracted_url = 'https://onedrive.live.com/download?authkey={}&resid={}&parId=root&o=OneUp'.format(
                            _qs['authkey'][0], _qs['resid'][0])

            logging.info("translated one drive url {} to {}".format(url.value, extracted_url))

        if not extracted_url or not protection_type:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(url)
        analysis.protection_type = protection_type
        analysis.extracted_url = extracted_url
        extracted_url = analysis.add_observable_by_spec(F_URL, extracted_url)

        # don't analyze the extracted url with this module again
        extracted_url.exclude_analysis(self)
        
        # copy any directives so they apply to the extracted one
        url.copy_directives_to(extracted_url)
        return AnalysisExecutionResult.COMPLETED