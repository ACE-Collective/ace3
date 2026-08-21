"""Analysis module that flags FQDN observables found in the local NRD database.

Runs on every FQDN observable in every analysis mode. The database lookup is a
microsecond-cheap SQLite query through ``saq.nrd.util.is_newly_registered``.
The NRD feeds include recently *updated* domains as well as recently
registered ones, so on a hit (rare) the analyzer verifies the domain's actual
registration date via RDAP (WHOIS fallback) and treats the hit as a miss when
the domain is older than the configured ``max_registration_age_days`` —
otherwise a decades-old domain can fire NRD detections after a routine
update. Lookup failures fail open: the hit is kept and the analysis records
why it could not be verified.

Adding a *detection point* is intentionally not done here — promoting an
email to an alert is the job of a separate observable modifier rule (see
``docs/design/newly_registered_domains.md``).
"""

import logging
import os
from datetime import datetime, timezone

from pydantic import Field

from saq.analysis import Analysis
from saq.constants import F_FQDN, F_URL, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.rdap import _age_in_days_as_string, lookup_domain_creation_date
from saq.nrd import util as nrd_util
from saq.nrd.util import is_newly_registered

KEY_IS_NRD = "is_nrd"
KEY_MATCHED_AT = "matched_at"
KEY_DATETIME_CREATED = "datetime_created"
KEY_AGE_CREATED_IN_DAYS = "age_created_in_days"
KEY_LOOKUP_PROTOCOL = "lookup_protocol"
KEY_LOOKUP_ERROR = "lookup_error"

TAG_NRD = "suspect:nrd"


class NRDAnalysis(Analysis):
    """Marker analysis for FQDNs found in the local newly-registered-domains database."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_IS_NRD: None,
            KEY_MATCHED_AT: None,
            KEY_DATETIME_CREATED: None,
            KEY_AGE_CREATED_IN_DAYS: None,
            KEY_LOOKUP_PROTOCOL: None,
            KEY_LOOKUP_ERROR: None,
        }

    @property
    def is_nrd(self) -> bool:
        return bool(self.details.get(KEY_IS_NRD))

    @is_nrd.setter
    def is_nrd(self, value: bool) -> None:
        self.details[KEY_IS_NRD] = bool(value)

    @property
    def matched_at(self):
        return self.details.get(KEY_MATCHED_AT)

    @matched_at.setter
    def matched_at(self, value) -> None:
        self.details[KEY_MATCHED_AT] = value

    @property
    def datetime_created(self):
        return self.details.get(KEY_DATETIME_CREATED)

    @datetime_created.setter
    def datetime_created(self, value) -> None:
        self.details[KEY_DATETIME_CREATED] = value

    @property
    def age_created_in_days(self):
        return self.details.get(KEY_AGE_CREATED_IN_DAYS)

    @age_created_in_days.setter
    def age_created_in_days(self, value) -> None:
        self.details[KEY_AGE_CREATED_IN_DAYS] = value

    @property
    def lookup_protocol(self):
        """``"rdap"`` | ``"whois"`` | ``None`` (not verified)."""
        return self.details.get(KEY_LOOKUP_PROTOCOL)

    @lookup_protocol.setter
    def lookup_protocol(self, value) -> None:
        self.details[KEY_LOOKUP_PROTOCOL] = value

    @property
    def lookup_error(self):
        return self.details.get(KEY_LOOKUP_ERROR)

    @lookup_error.setter
    def lookup_error(self, value) -> None:
        self.details[KEY_LOOKUP_ERROR] = value

    def generate_summary(self):
        if not self.is_nrd:
            return None
        if self.age_created_in_days is not None:
            return (
                "Newly Registered Domain: present in local NRD list "
                f"(registered {self.age_created_in_days} day(s) ago)"
            )
        if self.lookup_error:
            return (
                "Newly Registered Domain: present in local NRD list "
                f"(registration age unverified: {self.lookup_error})"
            )
        return "Newly Registered Domain: present in local NRD list"


class NRDAnalyzerConfig(AnalysisModuleConfig):
    max_registration_age_days: int | None = Field(
        default=90,
        description=(
            "On an NRD database hit, verify the domain's actual registration "
            "date via RDAP (WHOIS fallback) and treat the hit as a miss when "
            "the domain was registered more than this many days ago. Lookup "
            "failures fail open (the hit is kept). Set to 0 or null to "
            "disable verification."
        ),
    )


class NRDAnalyzer(AnalysisModule):
    """Tag FQDN or URL observables whose host appears in the local NRD database.

    Runs on both FQDN and URL observables. ``is_newly_registered`` auto-detects
    URL inputs and extracts the host, so the analyzer body is the same for
    either type. URL coverage is what makes this work in email mode, where
    ``parse_url`` is not enabled and URL-host FQDN observables therefore don't
    get created as a separate observable for the analyzer to run against.
    """

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return NRDAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return NRDAnalysis

    @property
    def valid_observable_types(self):
        return [F_FQDN, F_URL]

    @property
    def extended_version(self) -> dict[str, str]:
        """Mix the NRD database's file identity into the cache key.

        The NRD analyzer's output depends entirely on what's in the SQLite
        database, which the daily refresh script *atomically swaps* (a new
        file replaces the old — never an in-place edit). That makes
        ``(st_mtime_ns, st_size)`` a sufficient version fingerprint: any
        content change goes through a file replacement that moves mtime
        forward. A content hash would be more defensive but costs hundreds
        of ms on a multi-hundred-MB database and gains us nothing given
        the refresh script's invariants.

        Returns ``{}`` when the database file is missing — fresh-deploy /
        pre-first-refresh state, where the analyzer also produces no
        analysis, so the empty delta wouldn't be cached anyway.
        """
        try:
            st = os.stat(nrd_util.get_database_path())
        except FileNotFoundError:
            return {}
        return {"nrd_db_version": f"{st.st_mtime_ns}-{st.st_size}"}

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        if not is_newly_registered(observable.value):
            return AnalysisExecutionResult.COMPLETED

        now = datetime.now(timezone.utc)

        max_age_days = self.config.max_registration_age_days
        if max_age_days:
            domain = nrd_util.registrable_domain(observable.value)
            lookup = lookup_domain_creation_date(domain)
            if lookup.created is not None:
                created = (
                    lookup.created.astimezone(timezone.utc)
                    if lookup.created.tzinfo is not None
                    else lookup.created.replace(tzinfo=timezone.utc)
                )
                age_days = max((now - created).days, 0)
                if age_days > max_age_days:
                    logging.info(
                        "suppressing NRD hit for %s: registered %d days ago "
                        "(> %d day threshold) — feed inclusion was likely a "
                        "domain update, not a registration",
                        domain, age_days, max_age_days,
                    )
                    return AnalysisExecutionResult.COMPLETED
        else:
            lookup = None

        analysis = self.create_analysis(observable)
        analysis.is_nrd = True
        analysis.matched_at = now.isoformat()

        if lookup is not None:
            if lookup.created is not None:
                analysis.datetime_created = lookup.created.isoformat(" ")
                analysis.age_created_in_days = _age_in_days_as_string(lookup.created, now)
                analysis.lookup_protocol = lookup.protocol
            else:
                # Fail open: keep the hit, record why it could not be verified.
                analysis.lookup_error = lookup.error

        observable.add_tag(TAG_NRD)

        return AnalysisExecutionResult.COMPLETED
