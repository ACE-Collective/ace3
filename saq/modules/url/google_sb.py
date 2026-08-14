import logging
from typing import Any, Type, override
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.signatures.builtin import URL_GOOGLE_SAFE_BROWSING
from saq.constants import F_URL, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig

from gglsbl_rest_client import GGLSBL_Rest_Service_Client as GRS_Client

KEY_MATCH_TAGS = "match_tags"
KEY_RESULT = "result"

class GoogleSafeBrowsingAnalysis(Analysis):
    """URL matches against Google's SafeBrowsing List using the [gglsbl-rest](https://github.com/mlsecproject/gglsbl-rest) service.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_MATCH_TAGS: None,
            KEY_RESULT: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "Google SafeBrowsing Analysis"

    @property
    def match_tags(self) -> list[str]:
        return self.details[KEY_MATCH_TAGS]

    @match_tags.setter
    def match_tags(self, value: list[str]):
        self.details[KEY_MATCH_TAGS] = value

    @property
    def result(self) -> Any:
        return self.details[KEY_RESULT]

    @result.setter
    def result(self, value: Any):
        self.details[KEY_RESULT] = value

    def generate_summary(self):
        return "Google SafeBrowsing Results: {}".format(' '.join(self.details['match_tags']))

class GoogleSafeBrowsingAnalyzerConfig(AnalysisModuleConfig):
    server: str = Field(..., description="The server address for the gglsbl-rest service.")
    port: int = Field(..., description="The port number for the gglsbl-rest service.")
    verify_ssl: bool = Field(default=False, description="If we're verifying ssl and the cert is signed by an authority the OS trusts, then True. Else, it should be the path to the CA chain.")

class GoogleSafeBrowsingAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return GoogleSafeBrowsingAnalyzerConfig

    """Lookup a URL against a gglsbl-rest service.
    """

    @property
    def generated_analysis_type(self):
        return GoogleSafeBrowsingAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def remote_server(self) -> str:
        return self.config.server

    @property
    def remote_port(self) -> int:
        return self.config.port

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        logging.info("looking up '{}' in gglsbl-rest service at '{}'".format(observable.value, self.remote_server))       
        try:
            breakpoint()
            sbc = GRS_Client(self.remote_server, self.remote_port)
            result = sbc.lookup(observable.value)
            matches = result['matches']
            if matches:
                logging.info("Matches found for '{}' in gglsbl. Adding analysis.".format(observable.value))
                observable.add_detection_point("URL has matches on Google Safe Browsing List", signature_uuid=URL_GOOGLE_SAFE_BROWSING.uuid)

                analysis = self.create_analysis(observable)
                assert isinstance(analysis, GoogleSafeBrowsingAnalysis)
                analysis.result = result
                analysis.match_tags = list(set([ m['threat'] for m in matches if m['threat_entry'] == 'URL' ]))
                observable.add_tag('gglsbl match')
                for tag in analysis.details['match_tags']:
                    observable.add_tag(tag.replace('_',' ').lower())
                observable.add_detection_point("URL has matches on Google Safe Browsing List", signature_uuid=URL_GOOGLE_SAFE_BROWSING.uuid)
                return AnalysisExecutionResult.COMPLETED
            else:
                return AnalysisExecutionResult.COMPLETED
        except Exception as e:
            logging.error("Error using the gglsbl-rest service at {} : {}".format(self.remote_server, e))
            return AnalysisExecutionResult.COMPLETED 