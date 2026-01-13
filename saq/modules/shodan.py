# vim: sw=4:ts=4:et

import json
import logging
import os.path

import shodan

from saq import x509
from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.constants import F_IP, F_IPV4, F_SHA1, SUMMARY_DETAIL_FORMAT_PRE, AnalysisExecutionResult, register_directive
from saq.modules import AnalysisModule

KEY_SHODAN_RESULTS = 'shodan_results'
KEY_ERROR = 'error'

DIRECTIVE_QUERY_SHODAN = 'query_shodan'
register_directive(DIRECTIVE_QUERY_SHODAN, 'query shodan API for details', gui=True)

CONFIG_SHODAN = "shodan"
CONFIG_SHODAN_DELAY = "delay"
CONFIG_SHODAN_API_KEY = "api_key"
TAG_SHODAN = "shodan"
TAG_X509 = "x509"

class ShodanAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.details = {
            KEY_SHODAN_RESULTS: None,
            KEY_ERROR: None,
        }

    @property
    def shodan_results(self):
        return self.details[KEY_SHODAN_RESULTS]

    @shodan_results.setter
    def shodan_results(self, value):
        self.details[KEY_SHODAN_RESULTS] = value

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def dns(self):
        return self.shodan_results.get('domains', []) if self.shodan_results else []

    @property
    def open_ports(self):
        return self.shodan_results.get('ports', []) if self.shodan_results else []

    @property
    def vulns(self):
        return self.shodan_results.get('vulns', []) if self.shodan_results else []

    def generate_summary(self):
        if self.shodan_results:
            if self.observable.type in [ F_IP, F_IPV4 ]:
                result = f"Shodan Results: dns ({','.join(self.dns)}) open ports ({','.join(map(str, self.open_ports))})"
                if self.vulns:
                    result += f" vulns ({', '.join(self.vulns)})"
            elif self.observable.type == F_SHA1:
                result = "Shodan Results: certificate"

            return result

        elif self.error:
            return f"Shodan Query Error: {self.error}"
        else:
            return None

class ShodanAnalyzer(AnalysisModule):
    _test_data = None

    @property
    def generated_analysis_type(self):
        return ShodanAnalysis

    @property
    def valid_observable_types(self):
        return [F_IP, F_IPV4, F_SHA1]

    @property
    def required_directives(self):
        return [ DIRECTIVE_QUERY_SHODAN ]

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis import FileHashAnalyzer

        # XXX use delay analysis instead of just sleeping here >:(
        #time.sleep(get_config_value_as_int(CONFIG_SHODAN, CONFIG_SHODAN_DELAY, default=1))

        analysis = self.create_analysis(observable)

        # Query Shodan depending on the type of observable
        try:
            if observable.type in [ F_IP, F_IPV4 ]:
                analysis.shodan_results = self.search_host(observable.value)
            elif observable.type == F_SHA1:
                analysis.shodan_results = self.search_cert(observable.value)
        except Exception as e:
            analysis.error = str(e)
            logging.warning(f"unable to query shodan: {e}")
            return AnalysisExecutionResult.COMPLETED

        file_path = os.path.join(self._context.root.storage_dir, f'{observable.value}.shodan')
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as fp:
            json.dump(analysis.shodan_results, fp)

        if file_observable := analysis.add_file_observable(file_path):
            file_observable.add_tag(TAG_SHODAN)
            file_observable.exclude_analysis(FileHashAnalyzer)

        try:
            if observable.type == F_IPV4:
                summary_detail = f'{observable.value}\n\n'
                if 'domains' in analysis.shodan_results:
                    summary_detail += 'domains'
                    for domain in analysis.shodan_results['domains']:
                        summary_detail += f'\n\t- {domain}'

                    summary_detail += '\n\n'

                if 'ports' in analysis.shodan_results:
                    summary_detail += 'ports'
                    for port in analysis.shodan_results['ports']:
                        summary_detail += f'\n\t- {port}'

                    summary_detail += '\n\n'

                if 'vulns' in analysis.shodan_results:
                    summary_detail += 'vulns'
                    for vuln_name in analysis.shodan_results.get('vulns', []):
                        observable.add_tag(vuln_name)
                        summary_detail += f'\n\t- {vuln_name}'

                    summary_detail += '\n\n'

                self._context.root.add_summary_detail(header='Shodan Analysis', content=summary_detail, format=SUMMARY_DETAIL_FORMAT_PRE)

                for data in analysis.shodan_results['data']:
                    if 'ssl' in data and 'chain' in data['ssl']:
                        for idx, cert in enumerate(data['ssl']['chain']):
                            self._add_cert_observable(analysis, f"{observable.value}.{idx}", cert)

            elif observable.type == F_SHA1:
                for match in analysis.shodan_results['matches']:
                    if 'ssl' in match and 'chain' in match['ssl']:
                        for cert in match['ssl']['chain']:
                            # Load the cert and get its fingerprint. Only add the cert as an observable
                            # if the fingerprint matches the initial sha1 observable that initiated the analysis.
                            c = x509.load_cert(bytes(cert, 'utf-8'))
                            if x509.sha1(c) == observable.value:
                                self._add_cert_observable(analysis, observable.value, cert)

        except Exception as e:
            analysis.error = str(e)
            logging.warning(f"unable to parse shodan results: {e}")

        return AnalysisExecutionResult.COMPLETED
        
    def _add_cert_observable(self, analysis: ShodanAnalysis, filename: str, cert: str):
        file_path = os.path.join(self._context.root.storage_dir, f'{filename}.x509')
        if os.path.exists(file_path):
            logging.info(f"skipping overwrite of {file_path}")
        else:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as fp:
                fp.write(cert)

            if file_observable := analysis.add_file_observable(file_path):
                file_observable.add_tag(TAG_X509)

    def _get_shodan_client(self):
        if not get_config().shodan.api_key:
            raise ValueError("missing api key for shodan")

        return shodan.Shodan(get_config().shodan.api_key)

    def search_cert(self, sha1):
        if self._test_data:
            return self._test_data

        client = self._get_shodan_client()
        logging.info(f"searching shodan cert {sha1}")
        return client.search(f"ssl.cert.fingerprint:{sha1}")

    def search_host(self, value):
        if self._test_data:
            return self._test_data

        client = self._get_shodan_client()
        logging.info(f"searching shodan host {value}")
        return client.host(value)
