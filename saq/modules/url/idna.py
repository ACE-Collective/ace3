from typing import Optional
from saq.analysis.analysis import Analysis
from saq.constants import F_FQDN, AnalysisExecutionResult
from saq.modules import AnalysisModule

from urlfinderlib.url import URL

KEY_ORIGINAL = "original"
KEY_IDNA = "idna"
KEY_UNICODE = "unicode"


class IDNAAnalysis(Analysis):
    """Analyzes internationalized domains to convert them to IDNA and vice-versa"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ORIGINAL: None,
            KEY_IDNA: None,
            KEY_UNICODE: None,
        }

    @property
    def original(self) -> Optional[str]:
        return self.details[KEY_ORIGINAL]

    @original.setter
    def original(self, value: str):
        self.details[KEY_ORIGINAL] = value

    @property
    def idna(self) -> Optional[str]:
        return self.details[KEY_IDNA]

    @idna.setter
    def idna(self, value: str):
        self.details[KEY_IDNA] = value

    @property
    def unicode(self) -> Optional[str]:
        return self.details[KEY_UNICODE]

    @unicode.setter
    def unicode(self, value: str):
        self.details[KEY_UNICODE] = value

    def generate_summary(self):
        parts = []

        if self.idna:
            parts.append(f"idna={self.idna}")

        if self.unicode:
            parts.append(f"unicode={self.unicode}")

        if not parts:
            return None

        return "IDNA: " + ", ".join(parts)


class IDNAAnalyzer(AnalysisModule):
    """Analyzes internationalized domains to convert them to IDNA and vice-versa"""

    @property
    def generated_analysis_type(self):
        return IDNAAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, observable, **kwargs) -> AnalysisExecutionResult:
        url = URL(f"https://{observable.value}")

        # If the IDNA and Unicode form of the domains are the same, then stop analyzing
        if url.netloc_idna == url.netloc_unicode:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, IDNAAnalysis)
        analysis.original = url.netloc_original
        analysis.idna = url.netloc_idna
        analysis.unicode = url.netloc_unicode

        # Add either the IDNA or Unicode domain as an observable, depending on which one is not
        # the same as the original form of the domain.
        if url.netloc_idna != url.netloc_original:
            idna_observable = analysis.add_observable_by_spec(F_FQDN, url.netloc_idna)
            idna_observable.exclude_analysis(self)
            idna_observable.add_tag('idna_domain')

        if url.netloc_unicode != url.netloc_original:
            unicode_observable = analysis.add_observable_by_spec(F_FQDN, url.netloc_unicode)
            unicode_observable.exclude_analysis(self)
            unicode_observable.add_tag('unicode_domain')

        return AnalysisExecutionResult.COMPLETED