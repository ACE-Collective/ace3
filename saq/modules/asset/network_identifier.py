import csv
import logging
import os

import iptools
from saq.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.configuration.config import get_config_value
from saq.constants import F_ASSET, F_IPV4, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary

KEY_IDENTIFIED_NETWORKS = "identified_networks"

class _NetworkDefinition(object):
    def __init__(self, cidr, name):
        self.cidr = cidr
        self.name = name

class NetworkIdentifierAnalysis(Analysis):
    """Is this a managed IP address?  What is the general network location?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_IDENTIFIED_NETWORKS: [],
        }

    @property
    def identified_networks(self) -> list[str]:
        return self.details[KEY_IDENTIFIED_NETWORKS]

    @identified_networks.setter
    def identified_networks(self, value: list[str]):
        self.details[KEY_IDENTIFIED_NETWORKS] = value

    @property
    def is_asset(self):
        return len(self.identified_networks) > 0

    def generate_summary(self):
        if not self.identified_networks:
            return None

        return "Network Identification Analysis: " + format_item_list_for_summary(self.identified_networks)

class NetworkIdentifier(AnalysisModule):
    """Looks up what network(s) a given IP address belong to."""

    def verify_environment(self):
        self.verify_config_exists('csv_file')
        self.verify_path_exists(self.config['csv_file'])

    @property
    def generated_analysis_type(self):
        return NetworkIdentifierAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4
    
    def __init__(self, *args, **kwargs):
        super(NetworkIdentifier, self).__init__(*args, **kwargs)
        self._networks = [] # list of _NetworkDefinition
        
        # load the network definitions from the CSV file
        with open(os.path.join(get_base_dir(), get_config_value(self.config_section_name, "csv_file")), 'r') as fp:
            reader = csv.reader(fp)
            # these are pulled from splunk and these are the header names
            header = next(reader)
            assert header[0] == 'Indicator'
            assert header[1] == 'Indicator_Type'
            for row in reader:
                #logging.debug("loading {0} = {1}".format(row[0], row[1]))
                self._networks.append(_NetworkDefinition(iptools.IpRange(row[0]), row[1]))

        logging.debug("loaded {0} network definitions".format(len(self._networks)))

    def execute_analysis(self, observable) -> AnalysisExecutionResult:

        # results contain a list of the names of the networks this IP address is in
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, NetworkIdentifierAnalysis)

        for network in self._networks:
            try:
                if observable.value in network.cidr:
                    analysis.identified_networks.append(network.name)
            except Exception as e:
                logging.error("invalid ipv4 {}: {}".format(observable.value, str(e)))
                continue

        # if this ipv4 has at least one identified network then we can assume it's an asset
        if len(analysis.identified_networks) > 0:
            analysis.add_observable_by_spec(F_ASSET, observable.value)

        return AnalysisExecutionResult.COMPLETED


class NetworkIdentifierAnalysisPresenter(AnalysisPresenter):
    """Presenter for NetworkIdentifierAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/network_identifier.html"


register_analysis_presenter(NetworkIdentifierAnalysis, NetworkIdentifierAnalysisPresenter)