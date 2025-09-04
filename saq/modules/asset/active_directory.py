import logging
import re
from saq.analysis.analysis import Analysis
from saq.constants import F_FQDN, F_HOSTNAME, F_USER, AnalysisExecutionResult
from saq.ldap import lookup_hostname
from saq.modules import AnalysisModule

KEY_RESULT = "result"

class ActiveDirectoryAnalysis(Analysis):
    """What does Active Directory know about this asset?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_RESULT: {},
        }

    @property
    def result(self):
        return self.details[KEY_RESULT]
    
    @result.setter
    def result(self, value):
        self.details[KEY_RESULT] = value

    @property
    def is_asset(self):
        return bool(self.result)

    @property
    def fqdn(self):
        if 'dNSHostName' in self.result and len(self.result['dNSHostName']) > 0:
            return self.result['dNSHostName']

        return None

    # XXX pretty sure this is specific to Ashland
    @property
    def owner(self):
        if 'description' in self.result and len(self.result['description']) > 0:
            m = re.match(r'^(\S+) - (.+)$', self.result['description'][0])
            if m:
                (account, name) = m.groups()
                return (account, name)

        return None

    @property
    def operating_system(self):
        result = []
        if ('operatingSystem' in self.result
            and len(self.result['operatingSystem']) > 0):
            result.append(self.result['operatingSystem'])
        if ('operatingSystemServicePack' in self.details
            and len(self.details['operatingSystemServicePack']) > 0):
            result.append(self.details['operatingSystemServicePack'])
        if ('operatingSystemVersion' in self.result
            and len(self.result['operatingSystemVersion']) > 0):
            result.append(self.result['operatingSystemVersion'])
        
        if len(result) > 0:
            return ' '.join(result)
    
        return None

    def generate_summary(self):
        if not self.result:
            return None

        result = 'Active Directory Analysis: '

        if self.fqdn is not None:
            result += ' ({0})'.format(self.fqdn)

        # example: 'description': ['A346348 - Timothy Anderson'],
        if self.owner is not None:
            user, _ = self.owner
            user = user.strip()
            if user is not None and user != '-' and user != '':
                result += ' ({0})'.format(user)

        return result

class ActiveDirectoryAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return ActiveDirectoryAnalysis

    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    def execute_analysis(self, hostname) -> AnalysisExecutionResult:
        lookup_result = lookup_hostname(hostname.value)
        if lookup_result is None:
            logging.debug("no result received from ldap query for {}".format(hostname.value))
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(hostname)
        assert isinstance(analysis, ActiveDirectoryAnalysis)
        analysis.result = lookup_result

        if analysis.fqdn is not None:
            analysis.add_observable_by_spec(F_FQDN, analysis.fqdn)

        # example: 'description': ['A346348 - Timothy Anderson'],
        if analysis.owner is not None:
            user, _ = analysis.owner
            user = user.strip()
            if user is not None and user != '-' and user != '':
                analysis.add_observable_by_spec(F_USER, user)

        return AnalysisExecutionResult.COMPLETED