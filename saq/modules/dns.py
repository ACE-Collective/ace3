import logging
import socket
from typing import Optional

from saq.analysis import Analysis
from saq.constants import F_FQDN, F_IPV4, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary 

KEY_IP_ADDRESS = "ip_address"
KEY_RESOLUTION_COUNT = "resolution_count"
KEY_ALIASLIST = "aliaslist"
KEY_ALL_RESOLUTIONS = "all_resolutions"


class FQDNAnalysis(Analysis):
    """What IP adderss does this FQDN resolve to?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_IP_ADDRESS: None,
            KEY_RESOLUTION_COUNT: None,
            KEY_ALIASLIST: [],
            KEY_ALL_RESOLUTIONS: [],
        }

    @property
    def ip_address(self) -> Optional[str]:
        return self.details[KEY_IP_ADDRESS]

    @ip_address.setter
    def ip_address(self, value: str):
        self.details[KEY_IP_ADDRESS] = value

    @property
    def resolution_count(self) -> Optional[int]:
        return self.details[KEY_RESOLUTION_COUNT]

    @resolution_count.setter
    def resolution_count(self, value: int):
        self.details[KEY_RESOLUTION_COUNT] = value

    @property
    def aliaslist(self) -> list[str]:
        return self.details[KEY_ALIASLIST]

    @aliaslist.setter
    def aliaslist(self, value: list[str]):
        self.details[KEY_ALIASLIST] = value

    @property
    def all_resolutions(self) -> list[str]:
        return self.details[KEY_ALL_RESOLUTIONS]

    @all_resolutions.setter
    def all_resolutions(self, value: list[str]):
        self.details[KEY_ALL_RESOLUTIONS] = value

    def generate_summary(self):
        if not self.ip_address:
            return None

        message = "DNS Analysis:"

        if self.aliaslist:
            message += f" aliaslist ({format_item_list_for_summary(self.aliaslist)})"

        if self.all_resolutions:
            message += f" ip addresses ({format_item_list_for_summary(self.all_resolutions)})"

        return message


class FQDNAnalyzer(AnalysisModule):
    """What IP address does this FQDN resolve to?"""
    # Add anything else you want to this FQDN Analyzer.

    @property
    def generated_analysis_type(self):
        return FQDNAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        try:
            logging.info("executing dns lookup of %s", observable.value)
            _hostname, _aliaslist, ipaddrlist = socket.gethostbyname_ex(observable.value)
            if ipaddrlist:
                # ipaddrlist should always be a list of strings
                analysis = self.create_analysis(observable)
                assert isinstance(analysis, FQDNAnalysis)
                analysis.resolution_count = len(ipaddrlist)
                analysis.all_resolutions = ipaddrlist
                analysis.aliaslist = _aliaslist
                # for now, just add the first ip address
                analysis.ip_address = ipaddrlist[0]
                analysis.add_observable_by_spec(F_IPV4, ipaddrlist[0])

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            logging.warning("Problem resolving FQDN %s: %s", observable.value, e)
            return AnalysisExecutionResult.COMPLETED
