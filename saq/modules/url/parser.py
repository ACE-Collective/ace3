import logging
from typing import Optional
from urllib.parse import parse_qsl, unquote_plus
from saq.analysis.analysis import Analysis
from saq.constants import F_FQDN, F_IPV4, F_URI_PATH, F_URL, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary

from urlfinderlib.url import URL

KEY_NETLOC = "netloc"
KEY_SCHEME = "scheme"
KEY_PATH = "path"
KEY_QUERY = "query"
KEY_PARAMS = "params"
KEY_FRAGMENT = "fragment"

class ParseURLAnalysis(Analysis):
    """Add the hostname and path of the URL as observables."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_NETLOC: None,
            KEY_SCHEME: None,
            KEY_PATH: None,
            KEY_QUERY: None,
            KEY_PARAMS: None,
            KEY_FRAGMENT: None,
        }

    @property
    def netloc(self) -> Optional[str]:
        return self.details[KEY_NETLOC]

    @netloc.setter
    def netloc(self, value: str):
        self.details[KEY_NETLOC] = value

    @property
    def scheme(self) -> Optional[str]:
        return self.details[KEY_SCHEME]

    @scheme.setter
    def scheme(self, value: str):
        self.details[KEY_SCHEME] = value

    @property
    def path(self) -> Optional[str]:
        return self.details[KEY_PATH]

    @path.setter
    def path(self, value: str): 
        self.details[KEY_PATH] = value

    @property
    def query(self) -> Optional[str]:
        return self.details[KEY_QUERY]

    @query.setter
    def query(self, value: str):
        self.details[KEY_QUERY] = value

    @property
    def fragment(self) -> Optional[str]:
        return self.details[KEY_FRAGMENT]

    @fragment.setter
    def fragment(self, value: str):
        self.details[KEY_FRAGMENT] = value

    def generate_summary(self):
        parts = []
        if self.scheme:
            parts.append(f"scheme={self.scheme}")

        if self.netloc:
            parts.append(f"netloc={self.netloc}")

        if self.path:
            parts.append(f"path={self.path}")

        if self.query:
            parts.append(f"query={self.query}")

        if self.params:
            decoded_params = [f"{k}={v}" for k, v in self.params.items()]
            parts.append("params=(" + format_item_list_for_summary(decoded_params) + ")")

        if self.fragment:
            parts.append(f"fragment={self.fragment}")

        if not parts:
            return None

        return "URL Parser: " + ", ".join(parts)

class ParseURLAnalyzer(AnalysisModule):
    """Parse the URL and add the hostname and path as observables."""

    @property
    def generated_analysis_type(self):
        return ParseURLAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        try:
            url = URL(observable.value)

            analysis = self.create_analysis(observable)
            assert isinstance(analysis, ParseURLAnalysis)
            analysis.netloc = url.split_value.netloc
            analysis.scheme = url.split_value.scheme
            analysis.path = url.split_value.path
            analysis.query = url.split_value.query
            analysis.fragment = url.split_value.fragment

            # set analysis.params to a dict of key=value query parameters, urldecoded
            analysis.params = {k: unquote_plus(v) for k, v in parse_qsl(url.split_value.query, keep_blank_values=True)}

            if url.is_netloc_ipv4:
                ip_observable = analysis.add_observable_by_spec(F_IPV4, url.split_value.hostname)
                if ip_observable:
                    ip_observable.add_tag('ip_in_url')
            elif url.is_netloc_valid_tld:
                domain_observable = analysis.add_observable_by_spec(F_FQDN, url.split_value.hostname)
                if domain_observable:
                    domain_observable.add_tag('domain_in_url')

            if url.path_original:
                analysis.add_observable_by_spec(F_URI_PATH, url.path_original)

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            logging.warning(f"problem parsing URL: {e}")
            raise e