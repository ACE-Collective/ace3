import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import Field

from saq.analysis import Analysis
from saq.constants import (
    ANALYSIS_MODULE_NRD_ANALYZER,
    DIRECTIVE_CHECK_DOMAIN_AGE,
    F_EMAIL_ADDRESS,
    F_EMAIL_REPLY_TO,
    F_FQDN,
    AnalysisExecutionResult,
)
from saq.email import get_email_domain, normalize_email_address
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.constants import KEY_FROM
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.rdap import RdapAnalysis
from saq.signatures.builtin import EMAIL_REPLY_TO_NEW_DOMAIN

KEY_DOMAIN = "domain"


class EmailAddressFQDNAnalysis(Analysis):
    """Extracts the domain portion of an email address as an FQDN observable."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {KEY_DOMAIN: None}

    @property
    def domain(self) -> Optional[str]:
        return self.details[KEY_DOMAIN]

    @domain.setter
    def domain(self, value: str):
        self.details[KEY_DOMAIN] = value

    def generate_summary(self):
        if not self.domain:
            return None
        return f"Email Address FQDN: {self.domain}"


class EmailAddressFQDNAnalyzer(AnalysisModule):
    """Adds the domain of an email_address observable as a volatile fqdn observable."""

    @property
    def generated_analysis_type(self):
        return EmailAddressFQDNAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        domain = get_email_domain(observable.value)
        if not domain:
            logging.debug(f"no domain extractable from email address {observable.value}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, EmailAddressFQDNAnalysis)
        analysis.domain = domain
        analysis.add_observable_by_spec(F_FQDN, domain, volatile=True)
        return AnalysisExecutionResult.COMPLETED


# the instance of rdap_analyzer that only looks up domains carrying DIRECTIVE_CHECK_DOMAIN_AGE
# (analysis_module_rdap_domain_age_analyzer in etc/saq.default.yaml)
RDAP_DOMAIN_AGE_INSTANCE = "domain_age"

# how the Reply-To domain's age was learned when RDAP and WHOIS had no registration date
AGE_SOURCE_NRD = "nrd"

KEY_REPLY_TO_DOMAIN = "reply_to_domain"
KEY_FROM_DOMAIN = "from_domain"
KEY_REGISTERED = "registered"
KEY_AGE_IN_DAYS = "age_in_days"
KEY_AGE_SOURCE = "age_source"
KEY_LOOKUP_ERROR = "lookup_error"
KEY_LOOKALIKE = "lookalike"
KEY_IS_NEW = "is_new"


class EmailReplyToDomainAgeAnalyzerConfig(AnalysisModuleConfig):
    max_domain_age_days: int = Field(..., description="A Reply-To domain registered at most this many days before the email is analyzed is a detection.")


class EmailReplyToDomainAgeAnalysis(Analysis):
    """Was the Reply-To domain, which is not the From domain, registered recently?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_REPLY_TO_DOMAIN: None,
            KEY_FROM_DOMAIN: None,
            KEY_REGISTERED: None,
            KEY_AGE_IN_DAYS: None,
            KEY_AGE_SOURCE: None,
            KEY_LOOKUP_ERROR: None,
            KEY_LOOKALIKE: False,
            KEY_IS_NEW: False,
        }

    @property
    def reply_to_domain(self) -> Optional[str]:
        return self.details[KEY_REPLY_TO_DOMAIN]

    @property
    def from_domain(self) -> Optional[str]:
        return self.details[KEY_FROM_DOMAIN]

    @property
    def registered(self) -> Optional[str]:
        return self.details[KEY_REGISTERED]

    @property
    def age_in_days(self) -> Optional[int]:
        return self.details[KEY_AGE_IN_DAYS]

    @property
    def age_source(self) -> Optional[str]:
        return self.details[KEY_AGE_SOURCE]

    @property
    def lookup_error(self) -> Optional[str]:
        return self.details[KEY_LOOKUP_ERROR]

    @property
    def lookalike(self) -> bool:
        return self.details[KEY_LOOKALIKE]

    @property
    def is_new(self) -> bool:
        return self.details[KEY_IS_NEW]

    def describe(self) -> str:
        if self.age_in_days is not None:
            age = f"registered {self.age_in_days} days ago"
        elif self.age_source == AGE_SOURCE_NRD:
            age = "on the newly registered domain list"
        else:
            age = "registration date unknown"

        result = f"Reply-To domain {self.reply_to_domain} ({age}) is not the From domain {self.from_domain}"
        if self.lookalike:
            result += " and looks like it"
        return result

    def generate_summary(self):
        if not self.reply_to_domain:
            return None
        return f"Reply-To Domain Age: {self.describe()}"


class EmailReplyToDomainAgeAnalyzer(AnalysisModule):
    """Flags a Reply-To on a recently registered domain that is not the From domain.

    The From of such an email is often an established sender that passes SPF, DKIM and DMARC,
    sometimes through a compromised account or a misused mail relay, while replies go to a
    look-alike the attacker registered days before. Comparing the domains needs nothing but the
    parsed headers, so the registration lookup runs only for the few emails whose domains differ.
    """

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return EmailReplyToDomainAgeAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return EmailReplyToDomainAgeAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_REPLY_TO

    def execute_analysis(self, reply_to) -> AnalysisExecutionResult:
        # tldextract, jellyfish and the confusables tables are imported only where they run: the GUI and the
        # search indexer import this module to read EmailAddressFQDNAnalysis (docs/IMPORTS.md)
        from saq.domain_similarity import compare_domains, registrable_domain

        reply_to_domain = registrable_domain(get_email_domain(reply_to.value) or "")
        from_domain = self._other_from_domain(reply_to, reply_to_domain, registrable_domain)
        if not from_domain:
            return AnalysisExecutionResult.COMPLETED

        # the lookup runs on the Reply-To's fqdn, where the result depends on the domain alone and so
        # rdap_analyzer's cache holds it; this module's result also depends on the From domain.
        # a Reply-To excluded from FQDN extraction (the site's own addresses) never gets an answer to this
        # wait, so this module does not run again; no analysis means the Reply-To has no domain
        fqdn_analysis = self.wait_for_analysis(reply_to, EmailAddressFQDNAnalysis)
        fqdn = fqdn_analysis.get_observable_by_type(F_FQDN) if fqdn_analysis else None
        if fqdn is None:
            return AnalysisExecutionResult.COMPLETED

        fqdn.add_directive(DIRECTIVE_CHECK_DOMAIN_AGE)
        rdap = self.wait_for_analysis(fqdn, RdapAnalysis, instance=RDAP_DOMAIN_AGE_INSTANCE)
        registered = self._registration_date(rdap)
        # every wait comes before create_analysis: a wait re-runs this method from the top
        on_nrd_list = registered is None and self._on_nrd_list(fqdn)

        analysis = self.create_analysis(reply_to)
        assert isinstance(analysis, EmailReplyToDomainAgeAnalysis)
        analysis.details[KEY_REPLY_TO_DOMAIN] = reply_to_domain
        analysis.details[KEY_FROM_DOMAIN] = from_domain
        similarity = compare_domains(reply_to_domain, from_domain)
        # compare_domains misses a swapped suffix on a short name (acme.com, acme.net)
        analysis.details[KEY_LOOKALIKE] = similarity.is_similar or reply_to_domain.split(".", 1)[0] == from_domain.split(".", 1)[0]

        if registered is not None:
            analysis.details[KEY_REGISTERED] = registered.isoformat(" ")
            analysis.details[KEY_AGE_IN_DAYS] = max((datetime.now(timezone.utc) - registered).days, 0)
            analysis.details[KEY_AGE_SOURCE] = rdap.lookup_protocol
            analysis.details[KEY_IS_NEW] = analysis.age_in_days <= self.config.max_domain_age_days
        else:
            analysis.details[KEY_LOOKUP_ERROR] = rdap.error if rdap else None
            if on_nrd_list:
                analysis.details[KEY_AGE_SOURCE] = AGE_SOURCE_NRD
                analysis.details[KEY_IS_NEW] = True

        if analysis.is_new:
            reply_to.add_detection_point(analysis.describe(), signature_uuid=EMAIL_REPLY_TO_NEW_DOMAIN.uuid)
            logging.info(f"reply-to {reply_to.value} is on a new domain: {analysis.describe()}",
                         extra={"root_uuid": self.get_root().uuid, "observable_uuid": reply_to.uuid,
                                "reply_to_domain": reply_to_domain, "from_domain": from_domain})

        return AnalysisExecutionResult.COMPLETED

    @staticmethod
    def _other_from_domain(reply_to, reply_to_domain: str, registrable_domain) -> Optional[str]:
        """Returns the From domain of an email this Reply-To is on, when it is not the Reply-To domain."""
        for parent in reply_to.parents:
            if not isinstance(parent, EmailAnalysis):
                continue

            parent.load_details()
            from_address = normalize_email_address(parent.email.get(KEY_FROM))
            from_domain = registrable_domain(get_email_domain(from_address) or "") if from_address else ""
            if from_domain and from_domain != reply_to_domain:
                return from_domain

        return None

    def _on_nrd_list(self, fqdn) -> bool:
        """Returns True if nrd_analyzer found the domain on the newly registered domain list.

        The list is the only age a domain has when neither RDAP nor WHOIS gives a registration date,
        as for most of .de. It is not the first answer because it lags registration by a day or more,
        and because its feeds usually reach back weeks, past max_domain_age_days.
        """
        # saq.nrd.util loads tldextract and idna at import (docs/IMPORTS.md)
        from saq.modules.nrd import NRDAnalysis

        if not self._context.configuration_manager.is_module_enabled(ANALYSIS_MODULE_NRD_ANALYZER):
            return False

        nrd = self.wait_for_analysis(fqdn, NRDAnalysis)
        return bool(nrd) and nrd.is_nrd

    @staticmethod
    def _registration_date(rdap) -> Optional[datetime]:
        if not rdap or not rdap.datetime_created:
            return None

        registered = datetime.fromisoformat(rdap.datetime_created)
        return registered if registered.tzinfo else registered.replace(tzinfo=timezone.utc)
