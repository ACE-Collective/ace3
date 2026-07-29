"""DNS facts about an FQDN: what it resolves to, whether it resolves at all, and — for a
registrable apex — whether it can receive mail and whether its DNS is a wildcard.

Negative answers are first-class here. Creating an analysis object only when the name had an A
record made "this domain does not exist" indistinguishable in the GUI from "not analysed yet",
which throws away the most useful fact there is about a typo'd or parked hostname. Every outcome
produces an analysis carrying a `status`, using the taxonomy the hunt-side dns_lookup script also
reports (`ok` / `nxdomain` / `no_answer` / `dns_error`). Only `nxdomain` and `no_answer` prove
anything about the name; `dns_error` means we could not look, which is not an answer and must not
be read as one.
"""

import logging
from typing import Optional

import dns.rdatatype
import dns.resolver
import tldextract

from saq.analysis import Analysis
from saq.constants import F_FQDN, F_IP, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary

KEY_IP_ADDRESS = "ip_address"
KEY_RESOLUTION_COUNT = "resolution_count"
KEY_ALIASLIST = "aliaslist"
KEY_ALL_RESOLUTIONS = "all_resolutions"
KEY_STATUS = "status"
KEY_MX = "mx"
KEY_WILDCARD_DNS = "wildcard_dns"

STATUS_OK = "ok"
STATUS_NXDOMAIN = "nxdomain"
STATUS_NO_ANSWER = "no_answer"
STATUS_DNS_ERROR = "dns_error"

# MX and the wildcard probe are properties of the REGISTRABLE DOMAIN, not of an arbitrary hostname:
# MX on a CDN subdomain is meaningless and probing under one answers a question nobody asked. They
# are collected only when the observable already IS its own registrable apex, which also keeps the
# two extra lookups off the many subdomain observables a typical alert carries.
#
# The probe label is one no real deployment configures. Constant rather than random so repeated
# analysis of the same name is reproducible and cacheable; an operator special-casing this exact
# string is a threat worth strictly less than the caching.
WILDCARD_PROBE_LABEL = "ace-wildcard-probe-nonexistent"

RESOLVER_TIMEOUT = 5.0


class FQDNAnalysis(Analysis):
    """What does this FQDN resolve to, and does it resolve at all?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_IP_ADDRESS: None,
            KEY_RESOLUTION_COUNT: None,
            KEY_ALIASLIST: [],
            KEY_ALL_RESOLUTIONS: [],
            KEY_STATUS: None,
            KEY_MX: None,
            KEY_WILDCARD_DNS: None,
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

    @property
    def status(self) -> Optional[str]:
        """STATUS_OK / STATUS_NXDOMAIN / STATUS_NO_ANSWER / STATUS_DNS_ERROR."""
        return self.details[KEY_STATUS]

    @status.setter
    def status(self, value: str):
        self.details[KEY_STATUS] = value

    @property
    def mx(self) -> Optional[list[str]]:
        """MX exchanges, or None when not looked up (the name is not a registrable apex)."""
        return self.details[KEY_MX]

    @mx.setter
    def mx(self, value: list[str]):
        self.details[KEY_MX] = value

    @property
    def wildcard_dns(self) -> Optional[bool]:
        """True when a name that cannot exist still resolves. None when not looked up."""
        return self.details[KEY_WILDCARD_DNS]

    @wildcard_dns.setter
    def wildcard_dns(self, value: bool):
        self.details[KEY_WILDCARD_DNS] = value

    def generate_summary(self):
        if self.status is None:
            return None

        if self.status == STATUS_NXDOMAIN:
            return "DNS Analysis: does not exist (nxdomain)"

        if self.status == STATUS_DNS_ERROR:
            return "DNS Analysis: lookup failed (no answer from any nameserver)"

        if self.status == STATUS_NO_ANSWER:
            message = "DNS Analysis: exists but has no A record"
            if self.mx:
                message += f", mx ({format_item_list_for_summary(self.mx)})"
            return message

        message = "DNS Analysis:"

        if self.aliaslist:
            message += f" aliaslist ({format_item_list_for_summary(self.aliaslist)})"

        if self.all_resolutions:
            message += f" ip addresses ({format_item_list_for_summary(self.all_resolutions)})"

        if self.mx:
            message += f" mx ({format_item_list_for_summary(self.mx)})"
        elif self.mx is not None:
            message += " no mx"

        if self.wildcard_dns:
            message += " WILDCARD DNS"

        return message


class FQDNAnalyzer(AnalysisModule):
    """What IP address does this FQDN resolve to?"""

    @property
    def generated_analysis_type(self):
        return FQDNAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = RESOLVER_TIMEOUT
        resolver.lifetime = RESOLVER_TIMEOUT
        return resolver

    def _is_registrable_apex(self, fqdn: str) -> bool:
        apex = tldextract.extract(fqdn).top_domain_under_public_suffix
        return bool(apex) and fqdn.lower().rstrip(".") == apex.lower()

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        fqdn = observable.value
        logging.info(f"executing dns lookup of {fqdn}")

        resolver = self._resolver()
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, FQDNAnalysis)

        try:
            answer = resolver.resolve(fqdn, "A")
        except dns.resolver.NXDOMAIN:
            analysis.status = STATUS_NXDOMAIN
            return AnalysisExecutionResult.COMPLETED
        except dns.resolver.NoAnswer:
            # The name exists but carries no A record. The apex lookups still matter: a domain with
            # MX and no A is an ordinary mail-only domain, one with neither is a shell.
            analysis.status = STATUS_NO_ANSWER
            self._analyze_apex(analysis, resolver, fqdn)
            return AnalysisExecutionResult.COMPLETED
        except Exception as e:
            logging.warning(f"Problem resolving FQDN {fqdn}: {e}")
            analysis.status = STATUS_DNS_ERROR
            return AnalysisExecutionResult.COMPLETED

        analysis.status = STATUS_OK
        addresses = sorted(rdata.address for rdata in answer)
        analysis.all_resolutions = addresses
        analysis.resolution_count = len(addresses)
        analysis.aliaslist = [
            str(rrset[0].target).rstrip(".")
            for rrset in answer.response.answer
            if rrset.rdtype == dns.rdatatype.CNAME
        ]
        if addresses:
            # for now, just add the first ip address
            analysis.ip_address = addresses[0]
            analysis.add_observable_by_spec(F_IP, addresses[0])

        self._analyze_apex(analysis, resolver, fqdn)
        return AnalysisExecutionResult.COMPLETED

    def _analyze_apex(self, analysis: FQDNAnalysis, resolver: dns.resolver.Resolver, fqdn: str):
        """MX and wildcard detection, only for a name that is its own registrable apex."""
        if not self._is_registrable_apex(fqdn):
            return

        try:
            answer = resolver.resolve(fqdn, "MX")
            analysis.mx = sorted(str(rdata.exchange).rstrip(".") for rdata in answer)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            analysis.mx = []
        except Exception as e:
            logging.warning(f"Problem resolving MX for {fqdn}: {e}")

        try:
            resolver.resolve(f"{WILDCARD_PROBE_LABEL}.{fqdn}", "A")
            # A name that cannot exist resolving at all means a wildcard record, whatever it points
            # at. Legitimate wildcards are common (CDN and SaaS tenancy), so this is an indicator to
            # show an analyst, never grounds to judge the domain on its own.
            analysis.wildcard_dns = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            analysis.wildcard_dns = False
        except Exception as e:
            logging.warning(f"Problem probing {fqdn} for wildcard DNS: {e}")
