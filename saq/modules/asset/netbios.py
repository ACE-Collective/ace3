# jdavison@NAKYLEXSEC101:~/saq$ sudo nmap -sU --script /usr/share/nmap/scripts/nbstat.nse -p137 149.55.130.115

# Starting Nmap 6.40 ( http://nmap.org ) at 2014-10-03 16:00 EDT
# Nmap scan report for 149.55.130.115
# Host is up (0.011s latency).
# PORT    STATE SERVICE
# 137/udp open  netbios-ns

# Host script results:
# | nbstat:
# |   NetBIOS name: PCN0117337, NetBIOS user: <unknown>, NetBIOS MAC: 28:d2:44:51:01:7b (Lcfc(hefei) Electronics Technology Co.)
# |   Names
# |     PCN0117337<00>       Flags: <unique><active>
# |     ASHLAND<00>          Flags: <group><active>
# |     PCN0117337<20>       Flags: <unique><active>
# |_    ASHLAND<1e>          Flags: <group><active>

# Nmap done: 1 IP address (1 host up) scanned in 1.54 seconds

import logging
import re
from subprocess import Popen
import tempfile
from saq.analysis.analysis import Analysis
from saq.constants import F_ASSET, F_HOSTNAME, F_USER, G_DEFAULT_ENCODING, G_TEMP_DIR, AnalysisExecutionResult
from saq.environment import g
from saq.modules import AnalysisModule

ANALYSIS_NETBIOS_OPEN = 'netbios_open'
ANALYSIS_NETBIOS_NAME = 'netbios_name'
ANALYSIS_NETBIOS_USER = 'netbios_user'
ANALYSIS_NETBIOS_MAC = 'netbios_mac'
ANALYSIS_NETBIOS_DOMAIN = 'netbios_domain'


class NetBIOSAnalysis(Analysis):
    """What are the NetBIOS query results for this asset?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            ANALYSIS_NETBIOS_OPEN: False,
            ANALYSIS_NETBIOS_NAME: None,
            ANALYSIS_NETBIOS_USER: None,
            ANALYSIS_NETBIOS_MAC: None,
            ANALYSIS_NETBIOS_DOMAIN: None
        }

    @property
    def netbios_open(self):
        return self.details[ANALYSIS_NETBIOS_OPEN]

    @netbios_open.setter
    def netbios_open(self, value):
        assert isinstance(value, bool)
        self.details[ANALYSIS_NETBIOS_OPEN] = value

    @property
    def netbios_name(self):
        return self.details[ANALYSIS_NETBIOS_NAME]

    @netbios_name.setter
    def netbios_name(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_NAME] = value

    @property
    def netbios_mac(self):
        return self.details[ANALYSIS_NETBIOS_MAC]

    @netbios_mac.setter
    def netbios_mac(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_MAC] = value

    @property
    def netbios_user(self):
        return self.details[ANALYSIS_NETBIOS_USER]

    @netbios_user.setter
    def netbios_user(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_USER] = value

    @property
    def netbios_domain(self):
        return self.details[ANALYSIS_NETBIOS_DOMAIN]

    @netbios_domain.setter
    def netbios_domain(self, value):
        assert isinstance(value, str)
        self.details[ANALYSIS_NETBIOS_DOMAIN] = value

    def generate_summary(self):
        if self.netbios_open:
            return 'NetBIOS Analysis: name {0} domain {1} user {2} MAC {3}'.format(
                self.netbios_name if self.netbios_name is not None else '?', 
                self.netbios_domain if self.netbios_domain is not None else '?', 
                self.netbios_user if self.netbios_user is not None else '?', 
                self.netbios_mac if self.netbios_mac is not None else '?')

        return None

class NetBIOSAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_program_exists('nmap')
        self.verify_path_exists('/usr/share/nmap/scripts/nbstat.nse')

    @property
    def generated_analysis_type(self):
        return NetBIOSAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET

    def execute_analysis(self, asset) -> AnalysisExecutionResult:

        logging.debug("performing netbios query against {}".format(asset))
        
        analysis = self.create_analysis(asset)

        args = [
            'sudo', '/usr/bin/nmap', 
            '-sU', 
            '--script', '/usr/share/nmap/scripts/nbstat.nse', 
            '-p137', asset.value]

        # are we executing this from a host in a target network?
        if self.config['ssh_host']:
            args.insert(0, self.config['ssh_host'])
            args.insert(0, 'ssh')

        with tempfile.TemporaryFile(dir=g(G_TEMP_DIR)) as fp:
            with tempfile.TemporaryFile(dir=g(G_TEMP_DIR)) as stderr_fp:
                p = Popen(args, stdout=fp, stderr=stderr_fp)
                try:
                    p.wait(timeout=10)
                except Exception as e:
                    logging.error(f"netbios query timeout against {asset}: {e}")

                    p.kill()

                    fp.seek(0)
                    for line in fp:
                        logging.info(f"NETBIOS STDOUT OUTPUT: {line}")

                    stderr_fp.seek(0)
                    for line in stderr_fp:
                        logging.info(f"NETBIOS STDERR OUTPUT: {line}")
                    
                    return AnalysisExecutionResult.COMPLETED

                fp.seek(0)

                for line in fp:
                    if re.match(r'^137/udp\s+open\s+netbios-ns$', line.decode(g(G_DEFAULT_ENCODING))):
                        logging.debug("{} responded to a netbios query".format(asset))
                        analysis.netbios_open = True
                        continue

                    if not analysis.netbios_open:
                        continue

                    m = re.search(r'NetBIOS name: ([^,]+), NetBIOS user: ([^,]+), NetBIOS MAC: (..:..:..:..:..:..)', line.decode(g(G_DEFAULT_ENCODING)))
                    if m:
                        (name, user, mac) = m.groups()
                        analysis.netbios_name = name
                        analysis.netbios_user = user
                        analysis.netbios_mac = mac
                        
                        logging.debug("found netbios_name {0} netbios_user {1} netbios_mac {2} for asset {3}".format(
                            name, user, mac, asset))
                        continue

                    m = re.search(r'\s([^<\s]+)<00>\s+Flags:\s+<group><active>', line.decode(g(G_DEFAULT_ENCODING)))
                    if m:
                        (domain,) = m.groups()
                        analysis.netbios_domain = domain
                        logging.debug("found netbios_domain {0} for asset {1}".format(domain, asset))
                        continue

        asset.add_analysis(analysis)

        if analysis.netbios_open:
            if analysis.netbios_name is not None and analysis.netbios_name != '<unknown>':
                analysis.add_observable_by_spec(F_HOSTNAME, analysis.netbios_name)

            if analysis.netbios_user is not None and analysis.netbios_user != '<unknown>':
                analysis.add_observable_by_spec(F_USER, analysis.netbios_user)

        return AnalysisExecutionResult.COMPLETED
