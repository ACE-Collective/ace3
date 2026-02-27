import logging
from typing import Optional
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import F_URL, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.url import ProtectionType, extract_protected_url


KEY_PROTECTION_TYPE = 'protection_type'
KEY_EXTRACTED_URL = 'extracted_url'

class ProtectedURLAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_PROTECTION_TYPE: None,
            KEY_EXTRACTED_URL: None,
        }

    @property
    def protection_type(self) -> Optional[str]:
        return self.details.get(KEY_PROTECTION_TYPE)

    @protection_type.setter
    def protection_type(self, value: str):
        self.details[KEY_PROTECTION_TYPE] = value

    @property
    def extracted_url(self) -> Optional[str]:
        return self.details[KEY_EXTRACTED_URL]

    @extracted_url.setter
    def extracted_url(self, value: str):
        self.details[KEY_EXTRACTED_URL] = value

    def generate_summary(self):
        if not self.protection_type:
            return None

        if not self.extracted_url:
            return None

        if self.protection_type == ProtectionType.UNPROTECTED.value:
            return None

        return f"Protected URL Analysis: detected type {self.protection_type} extracted url {self.extracted_url}"


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

    def execute_analysis(self, url: Observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(url)
        try:
            protection_type, extracted_url_value = extract_protected_url(url.value)
        except ValueError as e:
            logging.debug("error extracting protected url from %s: %s", url.value, e)
            return AnalysisExecutionResult.COMPLETED

        analysis.protection_type = protection_type.value
        analysis.extracted_url = extracted_url_value

        if protection_type == ProtectionType.UNPROTECTED:
            return AnalysisExecutionResult.COMPLETED

        extracted_url_observable = analysis.add_observable_by_spec(F_URL, extracted_url_value)
        if extracted_url_observable:
            url.add_tag('protected_url')
            extracted_url_observable.add_relationship(R_EXTRACTED_FROM, url)
            # copy any directives so they apply to the extracted one
            url.copy_directives_to(extracted_url_observable)

        return AnalysisExecutionResult.COMPLETED