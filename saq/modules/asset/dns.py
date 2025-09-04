import logging
import re
from subprocess import DEVNULL, PIPE, Popen
from saq.analysis.analysis import Analysis
from saq.configuration.config import get_config_value_as_list
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS, F_ASSET, F_FQDN, F_HOSTNAME, F_IPV4, G_DEFAULT_ENCODING, G_LOCAL_DOMAINS, AnalysisExecutionResult
from saq.environment import g, g_list
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary

#(env)jdavison@NAKYLEXSEC101:~/saq$ dig -x 162.128.155.20

#; <<>> DiG 9.9.5-3-Ubuntu <<>> -x 162.128.155.20
#;; global options: +cmd
#;; Got answer:
#;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15793
#;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

#;; OPT PSEUDOSECTION:
#; EDNS: version: 0, flags:; udp: 4000
#;; QUESTION SECTION:
#;20.155.128.162.in-addr.arpa.   IN      PTR

#;; ANSWER SECTION:
#20.155.128.162.in-addr.arpa. 1200 IN    PTR     nakylexadc106.ashland.ad.ai.

#;; Query time: 0 msec
#;; SERVER: 162.128.155.16#53(162.128.155.16)
#;; WHEN: Mon Oct 06 13:59:43 EDT 2014
#;; MSG SIZE  rcvd: 97

ANALYSIS_DNS_RESOLVED = 'resolved'
ANALYSIS_DNS_FQDN = 'fqdn'
ANALYSIS_DNS_HOSTNAME = 'hostname'
ANALYSIS_DNS_IPV4 = 'ipv4'

class DNSAnalysis(Analysis):
    """What is the DNS resolution of this asset?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            ANALYSIS_DNS_RESOLVED: False,
            ANALYSIS_DNS_HOSTNAME: None,
            ANALYSIS_DNS_FQDN: None,
            ANALYSIS_DNS_IPV4: []
        }

    @property
    def dns_resolved(self):
        return self.details[ANALYSIS_DNS_RESOLVED]

    @dns_resolved.setter
    def dns_resolved(self, value):
        assert isinstance(value, bool)
        self.details[ANALYSIS_DNS_RESOLVED] = value

    @property
    def dns_hostname(self):
        return self.details[ANALYSIS_DNS_HOSTNAME]

    @dns_hostname.setter
    def dns_hostname(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_DNS_HOSTNAME] = value

    @property
    def dns_fqdn(self):
        return self.details[ANALYSIS_DNS_FQDN]

    @dns_fqdn.setter
    def dns_fqdn(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_DNS_FQDN] = value

    @property
    def dns_ipv4(self):
        return self.details[ANALYSIS_DNS_IPV4]

    def generate_summary(self):
        if not self.dns_resolved:
            return None

        return "DNS Analysis: hostname: {0} fqdn {1} ipv4 {2}".format(
            self.dns_hostname,
            self.dns_fqdn,
            format_item_list_for_summary(self.dns_ipv4))

class DNSAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('dig')
    
    @property
    def generated_analysis_type(self):
        return DNSAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET, F_FQDN, F_HOSTNAME

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        from saq.modules.asset.util import is_hostname

        if observable.type == F_FQDN:
            is_local_domain = False
            if '.' in observable.value:
                domain = '.'.join(observable.value.split('.')[1:])
                if domain.startswith('.'):
                    domain = domain[1:]
                    if domain in g_list(G_LOCAL_DOMAINS):
                        logging.debug("{} identified as local domain".format(observable))
                        is_local_domain = True
            else:
                is_local_domain = True

            if not is_local_domain:
                logging.debug("not doing DNS resolution on non-local domain {}".format(observable))
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, DNSAnalysis)

        logging.debug("performing DNS query for {}".format(observable))

        dig_process = ['dig']
        if observable.type == F_ASSET:
            dig_process.append('-x')
        else:
            dig_process.append('+search')

        target_queries = [ observable.value ]

        # if we have a hostname then we try all the local domains we know about as well
        if observable.type == F_HOSTNAME:
            for local_domain in g_list(G_LOCAL_DOMAINS):
                for local_domain in get_config_value_as_list(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS):
                    target_queries.append(f'{observable.value}.{local_domain}')

        for target_query in target_queries:

            dig_process.append(target_query)

            # are we executing this from a host in a target network?
            if self.config['ssh_host']:
                dig_process.insert(0, self.config['ssh_host'])
                dig_process.insert(0, 'ssh')

            p = Popen(dig_process, stdout=PIPE, stderr=DEVNULL)
            try:
                answer_section = False # state flag
                for line in p.stdout:
                    #logging.debug(line)
                    if ';; ANSWER SECTION' in line.decode():
                        answer_section = True
                        continue

                    if not answer_section:
                        continue

                    m = re.match(r'^\S+\s+[0-9]+\s+IN\s+PTR\s+(\S+)$', line.decode(g(G_DEFAULT_ENCODING)))
                    if m:
                        (fqdn,) = m.groups()
                        analysis.dns_resolved = True
                        if observable.value not in analysis.dns_ipv4:
                            analysis.dns_ipv4.append(observable.value)
                        if '.' in fqdn:
                            analysis.dns_hostname = fqdn.split('.')[0]
                        analysis.dns_fqdn = fqdn
                        continue

                    # PCN0117337.ashland.ad.ai. 1200  IN      A       149.55.130.115
                    m = re.match(r'^\S+\s+[0-9]+\s+IN\s+A\s+(\S+)$', line.decode())
                    if m:
                        (ipv4,) = m.groups()
                        if ipv4 is not None:
                            logging.debug("hostname {} resolved to {}".format(observable.value, ipv4))
                            analysis.add_observable_by_spec(F_IPV4, ipv4)
                            analysis.dns_resolved = True
                            if is_hostname(observable.value):
                                analysis.dns_hostname = observable.value
                            else:
                                analysis.dns_fqdn = observable.value

                            if ipv4 not in analysis.dns_ipv4:
                                analysis.dns_ipv4.append(ipv4)
                        continue
            finally:
                p.wait()

        if not analysis.dns_resolved:
            logging.debug("reverse dns lookup failed for asset {}".format(observable))
        else:
            logging.debug("found fqdn {} hostname {} for asset {}".format(
                analysis.dns_fqdn, analysis.dns_hostname, observable))

        return AnalysisExecutionResult.COMPLETED