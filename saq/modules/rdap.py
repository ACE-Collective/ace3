"""Module for RDAP analysis of domain names and IP addresses.

RDAP (RFC 7480-7484, RFC 9083) is ICANN's replacement for WHOIS. We
prefer RDAP, falling back to legacy WHOIS only when RDAP cannot
answer — primarily for country-code TLDs (.de, .br, etc.) that have
not yet stood up an RDAP service.

The module runs on both FQDN and IP observables:

    - For domains, ``whoisit.domain()`` returns registrar / nameserver /
      registration data.
    - For IPs, ``whoisit.ip()`` returns the owning network (CIDR), the
      responsible RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC), country,
      allocation dates, and abuse/registrant contacts. All five RIRs
      serve RDAP for IP queries, so this path is reliable. IPs that are
      not globally routable (RFC1918, loopback, link-local, CGNAT,
      multicast, reserved) are skipped entirely — they have no public
      registration data.

RDAP and WHOIS are *registry* protocols: for domains they only answer
for registered domains, never for subdomains. The FQDN observable is
therefore first reduced to its registrable domain (eTLD+1) — e.g.
``www.example.com`` is queried as ``example.com`` — otherwise the
registry returns a spurious 404 for the host. IP observables are
queried verbatim (no such reduction).

Outcomes to handle:

    - RDAP succeeds: parsed registration data + raw JSON response.
    - RDAP says "domain not found": authoritative negative, no
      fallback to WHOIS (the registry told us the truth).
    - RDAP can't serve this TLD / bootstrap failed / RDAP server
      errored: fall back to ``python-whois``.
    - Both fail: surface a combined error so the analyst sees both
      failure modes.
    - Query succeeds but the registry omits creation / last-changed
      events: record the metadata we did get; ages stay None.

The cacheability contract still applies (no removals, no file
observables), so this module is opted into the 7-day analysis cache
the same way the legacy WhoisAnalyzer was.
"""

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import NamedTuple

import tldextract
import whois
import whoisit
from whois.exceptions import PywhoisError
from whoisit.errors import (
    BootstrapError,
    QueryError,
    ResourceDoesNotExist,
    UnsupportedError,
)

from saq.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import (
    AnalysisPresenter,
    register_analysis_presenter,
)
from saq.constants import F_FQDN, F_IP, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary

KEY_ERROR = "error"
KEY_LOOKUP_PROTOCOL = "lookup_protocol"
KEY_RDAP_ATTEMPT_ERROR = "rdap_attempt_error"

KEY_AGE_CREATED_IN_DAYS = "age_created_in_days"
KEY_AGE_LAST_UPDATED_IN_DAYS = "age_last_updated_in_days"
KEY_DATETIME_CREATED = "datetime_created"
KEY_DATETIME_EXPIRATION = "datetime_expiration"
KEY_DATETIME_OF_ANALYSIS = "datetime_of_analysis"
KEY_DATETIME_OF_LAST_UPDATE = "datetime_of_last_update"

KEY_DOMAIN_NAME = "domain_name"
KEY_REGISTRAR = "registrar"
KEY_RDAP_SERVICE_URL = "rdap_service_url"
KEY_NAME_SERVERS = "name_servers"
KEY_EMAILS = "emails"

# IP-only fields (populated when the observable is an IP address).
KEY_NETWORK_CIDR = "network_cidr"
KEY_NETWORK_NAME = "network_name"
KEY_COUNTRY = "country"
KEY_IP_VERSION = "ip_version"
KEY_ASSIGNMENT_TYPE = "assignment_type"

KEY_RDAP_DATA = "rdap_data"
KEY_RDAP_RAW_JSON = "rdap_raw_json"
KEY_WHOIS_DATA = "whois_data"
KEY_WHOIS_RAW_TEXT = "whois_raw_text"

# Cap stored email count so a pathological registry response can't
# inflate the cached payload past the blob-spill threshold.
_MAX_EMAILS_STORED = 20


def _age_in_days_as_string(past: datetime, present: datetime) -> str:
    past = (
        past.astimezone(timezone.utc)
        if past.tzinfo is not None
        else past.replace(tzinfo=timezone.utc)
    )
    present = (
        present.astimezone(timezone.utc)
        if present.tzinfo is not None
        else present.replace(tzinfo=timezone.utc)
    )
    delta = present - past
    # Negative deltas usually mean tz weirdness; clamp to zero.
    if delta.days < 0:
        return "0"
    return str(delta.days)


def _extract_rdap_registrar(rdap_dict: dict) -> str | None:
    entities = rdap_dict.get("entities") or {}
    for entity in entities.get("registrar") or []:
        if isinstance(entity, dict):
            name = entity.get("name")
            if name:
                return name
    return None


def _extract_rdap_emails(rdap_dict: dict) -> list[str]:
    emails: set[str] = set()
    entities = rdap_dict.get("entities") or {}
    for entity_list in entities.values():
        for entity in entity_list or []:
            if not isinstance(entity, dict):
                continue
            email = entity.get("email")
            if email:
                emails.add(email)
    return sorted(emails)[:_MAX_EMAILS_STORED]


def _registrable_domain(value: str) -> str:
    """Reduce an FQDN to its registrable domain (eTLD+1).

    RDAP and WHOIS are registry protocols — they only answer for
    registered domains, never for subdomains, so ``www.example.com``
    must be queried as ``example.com``. Falls back to the input
    unchanged when no public suffix is identifiable (bare hostnames,
    internal names), matching ``saq/nrd/util.py``'s handling.
    """
    normalized = (value or "").strip().lower().rstrip(".")
    if not normalized:
        return value
    registrable = tldextract.extract(normalized).top_domain_under_public_suffix
    return registrable or normalized


def _ensure_rdap_bootstrap() -> str | None:
    """Best-effort lazy bootstrap of the IANA RDAP registry. Returns
    ``None`` on success, or an error string on failure (callers treat
    that as a reason to skip RDAP and go straight to WHOIS). Repeated
    bootstrap attempts are cheap because ``whoisit`` caches state in
    module-level globals.
    """
    try:
        if not whoisit.is_bootstrapped():
            whoisit.bootstrap()
        return None
    except BootstrapError as e:
        return f"bootstrap failed: {e}".split("\n", 1)[0].strip()


class DomainCreationLookup(NamedTuple):
    """Result of a standalone creation-date lookup for a registrable domain."""

    created: datetime | None  # tz-aware creation date, or None
    protocol: str | None      # "rdap" | "whois" | None
    error: str | None         # set when created is None


# Per-process memo of *successful* creation-date lookups, keyed on the
# registrable domain. The analysis result cache does not store empty deltas,
# so a module that looks up a domain and then produces no analysis (e.g.
# NRDAnalyzer suppressing a stale feed hit) would otherwise re-query the
# registry for every tree the domain appears in. Failures are not memoized
# so transient registry errors get retried.
_creation_date_memo: dict[str, DomainCreationLookup] = {}
_CREATION_DATE_MEMO_MAX = 4096


def lookup_domain_creation_date(domain: str) -> DomainCreationLookup:
    """Return the creation (registration) date for a registrable domain.

    Standalone counterpart to ``RdapAnalyzer`` for callers that only need
    the creation date: tries RDAP first, falls back to legacy WHOIS when
    RDAP cannot answer. ``domain`` must already be a normalized registrable
    domain (eTLD+1, A-label form) — no reduction is performed here.

    An authoritative RDAP "domain not found" is terminal (no WHOIS attempt),
    matching ``RdapAnalyzer``'s handling.
    """
    memoized = _creation_date_memo.get(domain)
    if memoized is not None:
        return memoized

    rdap_error = _ensure_rdap_bootstrap()
    if rdap_error is None:
        try:
            result = whoisit.domain(domain)
        except ResourceDoesNotExist as e:
            error = f"rdap: domain not found: {e}".split("\n", 1)[0].strip()[:200]
            return DomainCreationLookup(None, None, error)
        except UnsupportedError as e:
            rdap_error = f"no RDAP service for TLD: {e}".split("\n", 1)[0].strip()
        except QueryError as e:
            rdap_error = str(e).split("\n", 1)[0].strip() or "query failed"
        except Exception as e:  # noqa: BLE001 — defensive against lib changes
            rdap_error = f"rdap client error: {type(e).__name__}: {e}".split(
                "\n", 1
            )[0].strip()
        else:
            created = result.get("registration_date")
            if isinstance(created, datetime):
                lookup = DomainCreationLookup(created, "rdap", None)
                _memoize_creation_date(domain, lookup)
                return lookup
            # Query succeeded but the registry omitted the registration
            # event — WHOIS may still know the creation date.
            rdap_error = "rdap result has no registration date"

    # ---- WHOIS fallback ----------------------------------------------------
    try:
        whois_result = whois.whois(domain)
    except PywhoisError as e:
        whois_error = str(e).split("\n", 1)[0].strip()[:200] or "query failed"
        return DomainCreationLookup(None, None, f"rdap: {rdap_error}; whois: {whois_error}")
    except Exception as e:  # noqa: BLE001
        whois_error = f"whois client error: {type(e).__name__}: {e}".split(
            "\n", 1
        )[0].strip()
        return DomainCreationLookup(None, None, f"rdap: {rdap_error}; whois: {whois_error}")

    created = whois_result.get("creation_date")
    if isinstance(created, list) and created:
        created = created[0]
    if isinstance(created, datetime):
        lookup = DomainCreationLookup(created, "whois", None)
        _memoize_creation_date(domain, lookup)
        return lookup

    return DomainCreationLookup(
        None, None, f"rdap: {rdap_error}; whois: no creation date in result"
    )


def _memoize_creation_date(domain: str, lookup: DomainCreationLookup) -> None:
    # Crude size cap: drop the oldest entry once full. Insertion order is
    # good enough — the memo only exists to collapse repeated lookups of the
    # same handful of popular domains within one worker process.
    if len(_creation_date_memo) >= _CREATION_DATE_MEMO_MAX:
        _creation_date_memo.pop(next(iter(_creation_date_memo)))
    _creation_date_memo[domain] = lookup


def _reset_creation_date_memo_for_tests() -> None:
    """Clear the per-process creation-date memo between test cases."""
    _creation_date_memo.clear()


class RdapAnalysis(Analysis):
    """Registration data for a domain, sourced from RDAP (preferred)
    or WHOIS (fallback)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,
            KEY_LOOKUP_PROTOCOL: None,
            KEY_RDAP_ATTEMPT_ERROR: None,

            KEY_AGE_CREATED_IN_DAYS: None,
            KEY_AGE_LAST_UPDATED_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
            KEY_DATETIME_EXPIRATION: None,
            KEY_DATETIME_OF_ANALYSIS: None,
            KEY_DATETIME_OF_LAST_UPDATE: None,

            KEY_DOMAIN_NAME: None,
            KEY_REGISTRAR: None,
            KEY_RDAP_SERVICE_URL: None,
            KEY_NAME_SERVERS: None,
            KEY_EMAILS: None,

            KEY_NETWORK_CIDR: None,
            KEY_NETWORK_NAME: None,
            KEY_COUNTRY: None,
            KEY_IP_VERSION: None,
            KEY_ASSIGNMENT_TYPE: None,

            KEY_RDAP_DATA: None,
            KEY_RDAP_RAW_JSON: None,
            KEY_WHOIS_DATA: None,
            KEY_WHOIS_RAW_TEXT: None,
        }

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def lookup_protocol(self):
        """``"rdap"`` | ``"whois"`` | ``None`` (both failed)."""
        return self.details[KEY_LOOKUP_PROTOCOL]

    @lookup_protocol.setter
    def lookup_protocol(self, value):
        self.details[KEY_LOOKUP_PROTOCOL] = value

    @property
    def rdap_attempt_error(self):
        """RDAP-side error message when we fell back to WHOIS."""
        return self.details[KEY_RDAP_ATTEMPT_ERROR]

    @rdap_attempt_error.setter
    def rdap_attempt_error(self, value):
        self.details[KEY_RDAP_ATTEMPT_ERROR] = value

    @property
    def rdap_data(self):
        """Parsed RDAP response dict from ``whoisit``."""
        return self.details[KEY_RDAP_DATA]

    @rdap_data.setter
    def rdap_data(self, value):
        self.details[KEY_RDAP_DATA] = value

    @property
    def rdap_raw_json(self):
        """Raw RDAP response (RFC 9083 JSON), serialized as a string."""
        return self.details[KEY_RDAP_RAW_JSON]

    @rdap_raw_json.setter
    def rdap_raw_json(self, value):
        self.details[KEY_RDAP_RAW_JSON] = value

    @property
    def whois_data(self):
        """Parsed WHOIS response (only set on fallback)."""
        return self.details[KEY_WHOIS_DATA]

    @whois_data.setter
    def whois_data(self, value):
        self.details[KEY_WHOIS_DATA] = value

    @property
    def whois_raw_text(self):
        """Raw WHOIS response text (only set on fallback)."""
        return self.details[KEY_WHOIS_RAW_TEXT]

    @whois_raw_text.setter
    def whois_raw_text(self, value):
        self.details[KEY_WHOIS_RAW_TEXT] = value

    @property
    def age_created_in_days(self):
        return self.details[KEY_AGE_CREATED_IN_DAYS]

    @age_created_in_days.setter
    def age_created_in_days(self, value):
        self.details[KEY_AGE_CREATED_IN_DAYS] = value

    @property
    def age_last_updated_in_days(self):
        return self.details[KEY_AGE_LAST_UPDATED_IN_DAYS]

    @age_last_updated_in_days.setter
    def age_last_updated_in_days(self, value):
        self.details[KEY_AGE_LAST_UPDATED_IN_DAYS] = value

    @property
    def datetime_created(self):
        return self.details[KEY_DATETIME_CREATED]

    @datetime_created.setter
    def datetime_created(self, value):
        self.details[KEY_DATETIME_CREATED] = value

    @property
    def datetime_expiration(self):
        return self.details[KEY_DATETIME_EXPIRATION]

    @datetime_expiration.setter
    def datetime_expiration(self, value):
        self.details[KEY_DATETIME_EXPIRATION] = value

    @property
    def datetime_of_analysis(self):
        return self.details[KEY_DATETIME_OF_ANALYSIS]

    @datetime_of_analysis.setter
    def datetime_of_analysis(self, value):
        self.details[KEY_DATETIME_OF_ANALYSIS] = value

    @property
    def datetime_of_last_update(self):
        return self.details[KEY_DATETIME_OF_LAST_UPDATE]

    @datetime_of_last_update.setter
    def datetime_of_last_update(self, value):
        self.details[KEY_DATETIME_OF_LAST_UPDATE] = value

    @property
    def domain_name(self):
        return self.details[KEY_DOMAIN_NAME]

    @domain_name.setter
    def domain_name(self, value):
        self.details[KEY_DOMAIN_NAME] = value

    @property
    def registrar(self):
        return self.details[KEY_REGISTRAR]

    @registrar.setter
    def registrar(self, value):
        self.details[KEY_REGISTRAR] = value

    @property
    def rdap_service_url(self):
        """URL of the upstream RDAP service that answered the query."""
        return self.details[KEY_RDAP_SERVICE_URL]

    @rdap_service_url.setter
    def rdap_service_url(self, value):
        self.details[KEY_RDAP_SERVICE_URL] = value

    @property
    def name_servers(self):
        return self.details[KEY_NAME_SERVERS]

    @name_servers.setter
    def name_servers(self, value):
        self.details[KEY_NAME_SERVERS] = value

    @property
    def emails(self):
        return self.details[KEY_EMAILS]

    @emails.setter
    def emails(self, value):
        self.details[KEY_EMAILS] = value

    @property
    def network_cidr(self):
        """CIDR of the network the IP belongs to (IP lookups only)."""
        return self.details[KEY_NETWORK_CIDR]

    @network_cidr.setter
    def network_cidr(self, value):
        self.details[KEY_NETWORK_CIDR] = value

    @property
    def network_name(self):
        """Network/allocation name (IP lookups only)."""
        return self.details[KEY_NETWORK_NAME]

    @network_name.setter
    def network_name(self, value):
        self.details[KEY_NETWORK_NAME] = value

    @property
    def country(self):
        """Registered country code for the network (IP lookups only)."""
        return self.details[KEY_COUNTRY]

    @country.setter
    def country(self, value):
        self.details[KEY_COUNTRY] = value

    @property
    def ip_version(self):
        """IP version (4 or 6) reported by the RDAP service (IP lookups only)."""
        return self.details[KEY_IP_VERSION]

    @ip_version.setter
    def ip_version(self, value):
        self.details[KEY_IP_VERSION] = value

    @property
    def assignment_type(self):
        """Allocation/assignment type, e.g. ``"allocated"`` (IP lookups only)."""
        return self.details[KEY_ASSIGNMENT_TYPE]

    @assignment_type.setter
    def assignment_type(self, value):
        self.details[KEY_ASSIGNMENT_TYPE] = value

    def generate_summary(self):
        parts = []
        suffix = ""
        if self.lookup_protocol == "whois":
            suffix = " (whois fallback)"

        if self.error:
            parts.append(f"error: {self.error}")
        else:
            if self.network_cidr:
                network = self.network_cidr
                if self.network_name:
                    network += f" ({self.network_name})"
                parts.append(f"network: {network}")
            if self.country:
                parts.append(f"country: {self.country}")
            if self.age_created_in_days:
                parts.append(f"created: {self.age_created_in_days} day(s) ago")
            if self.age_last_updated_in_days:
                parts.append(f"last updated: {self.age_last_updated_in_days} day(s) ago")
            if self.name_servers:
                parts.append(
                    f"nameservers: ({format_item_list_for_summary(self.name_servers)})"
                )
            if self.registrar:
                parts.append(f"registrar: {self.registrar}")
            if self.rdap_service_url:
                parts.append(f"rdap service: {self.rdap_service_url}")
            if self.emails:
                parts.append(f"emails: ({format_item_list_for_summary(self.emails)})")

        if not parts:
            return None

        return f"RDAP Analysis{suffix}: " + ", ".join(parts)


class RdapAnalyzer(AnalysisModule):
    """Analysis module performing RDAP (with WHOIS fallback) on FQDN
    observables.
    """

    @property
    def generated_analysis_type(self):
        return RdapAnalysis

    @property
    def valid_observable_types(self):
        return [F_FQDN, F_IP]

    def custom_requirement(self, observable) -> bool:
        """Skip IP observables that are not globally routable (RFC1918,
        loopback, link-local, CGNAT, multicast, reserved) — they have no
        public RDAP registration data."""
        if observable.type != F_IP:
            return True
        try:
            return ipaddress.ip_address(observable.value).is_global
        except ValueError:
            # not parseable as an IP — let the module run and surface
            # the lookup error as before
            return True

    def _ensure_rdap_bootstrap(self) -> str | None:
        return _ensure_rdap_bootstrap()

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        now = datetime.now(timezone.utc)
        analysis.datetime_of_analysis = now.isoformat(" ")

        is_ip = observable.type == F_IP
        if is_ip:
            # IPs are queried verbatim; RDAP answers for the network the
            # address falls in, so no eTLD+1-style reduction applies.
            query_target = observable.value
        else:
            # RDAP/WHOIS only answer for registered domains — query the
            # registrable domain, not the (possibly subdomain) observable.
            query_target = _registrable_domain(observable.value)

        # ---- RDAP attempt --------------------------------------------------
        bootstrap_error = self._ensure_rdap_bootstrap()
        if bootstrap_error is not None:
            rdap_error: str | None = bootstrap_error
        else:
            rdap_error = self._try_rdap(observable, query_target, analysis, now, is_ip)
            if rdap_error is None:
                analysis.lookup_protocol = "rdap"
                return AnalysisExecutionResult.COMPLETED
            if rdap_error == _RDAP_NXDOMAIN_SENTINEL:
                # Authoritative "not found" — don't waste a WHOIS query.
                return AnalysisExecutionResult.COMPLETED

        # ---- WHOIS fallback ------------------------------------------------
        analysis.rdap_attempt_error = rdap_error
        whois_error = self._try_whois(observable, query_target, analysis, now)
        if whois_error is None:
            analysis.lookup_protocol = "whois"
            return AnalysisExecutionResult.COMPLETED

        analysis.error = f"rdap: {rdap_error}; whois: {whois_error}"
        return AnalysisExecutionResult.COMPLETED

    def _try_rdap(
        self,
        observable,
        query_target: str,
        analysis: RdapAnalysis,
        now: datetime,
        is_ip: bool,
    ) -> str | None:
        """Populate ``analysis`` from an RDAP query for ``query_target``
        (the registrable domain reduced from ``observable``, or the raw
        IP when ``is_ip``).

        Returns:
            ``None`` on success;
            ``_RDAP_NXDOMAIN_SENTINEL`` for an authoritative "does not
                exist" answer (no fallback needed; the error is also
                stored on the analysis);
            a free-form error string for any other failure (caller
                will fall back to WHOIS).
        """
        try:
            if is_ip:
                result = whoisit.ip(query_target, include_raw=True)
            else:
                result = whoisit.domain(query_target, include_raw=True)
        except ResourceDoesNotExist as e:
            analysis.error = f"rdap: domain not found: {e}".split(
                "\n", 1
            )[0].strip()[:200]
            return _RDAP_NXDOMAIN_SENTINEL
        except UnsupportedError as e:
            return f"no RDAP service for TLD: {e}".split("\n", 1)[0].strip()
        except QueryError as e:
            return str(e).split("\n", 1)[0].strip() or "query failed"
        except Exception as e:  # noqa: BLE001 — defensive against lib changes
            return f"rdap client error: {type(e).__name__}: {e}".split(
                "\n", 1
            )[0].strip()

        raw = result.pop("raw", None)
        # Plain-dict copy of the parsed result. datetime values and the
        # ``network`` ipaddress object (IP results) are both handled by ACE's
        # analysis JSON encoder (saq/json_encoding.py).
        analysis.rdap_data = dict(result)
        analysis.rdap_raw_json = json.dumps(raw, default=str) if raw is not None else None

        analysis.domain_name = result.get("name") or query_target
        analysis.registrar = _extract_rdap_registrar(result)
        nameservers = result.get("nameservers") or []
        analysis.name_servers = list(nameservers)
        analysis.emails = _extract_rdap_emails(result)
        # whoisit surfaces the upstream RDAP service URL under ``url``
        # (the link analysts can click) and the auth registry under
        # ``rir``. ``url`` is the more useful of the two for an analyst.
        analysis.rdap_service_url = result.get("url") or result.get("rir")

        if is_ip:
            # ``network`` is an ipaddress.IPv4Network/IPv6Network — stringify
            # so the stored details stay JSON-clean.
            network = result.get("network")
            analysis.network_cidr = str(network) if network is not None else None
            analysis.network_name = result.get("name") or None
            analysis.country = result.get("country") or None
            analysis.ip_version = result.get("ip_version")
            analysis.assignment_type = result.get("assignment_type") or None

        created = result.get("registration_date")
        if isinstance(created, datetime):
            analysis.datetime_created = created.isoformat(" ")
            analysis.age_created_in_days = _age_in_days_as_string(created, now)
        elif created is not None:
            logging.warning(
                f"RDAP result for {observable} has unexpected "
                f"registration_date format: {type(created).__name__}"
            )

        updated = result.get("last_changed_date")
        if isinstance(updated, datetime):
            analysis.datetime_of_last_update = updated.isoformat(" ")
            analysis.age_last_updated_in_days = _age_in_days_as_string(updated, now)
        elif updated is not None:
            logging.warning(
                f"RDAP result for {observable} has unexpected "
                f"last_changed_date format: {type(updated).__name__}"
            )

        expires = result.get("expiration_date")
        if isinstance(expires, datetime):
            analysis.datetime_expiration = expires.isoformat(" ")

        return None

    def _try_whois(
        self,
        observable,
        query_domain: str,
        analysis: RdapAnalysis,
        now: datetime,
    ) -> str | None:
        """Populate ``analysis`` from a legacy WHOIS query for
        ``query_domain`` (the registrable domain reduced from
        ``observable``). Returns ``None`` on success or an error string
        on failure.
        """
        try:
            whois_result = whois.whois(query_domain)
        except PywhoisError as e:
            return str(e).split("\n", 1)[0].strip()[:200] or "query failed"
        except Exception as e:  # noqa: BLE001
            return f"whois client error: {type(e).__name__}: {e}".split(
                "\n", 1
            )[0].strip()

        # ``python-whois`` returns a ``WhoisEntry`` (dict subclass).
        # Flatten to a plain dict so the cached payload doesn't depend
        # on the library's class survival across versions.
        analysis.whois_data = dict(whois_result) if whois_result else {}
        analysis.whois_raw_text = getattr(whois_result, "text", None)

        # WHOIS responses can pack multi-value fields as either scalar
        # or list — mirror the legacy module's "take the first if list"
        # behaviour.
        def _first(value):
            return value[0] if isinstance(value, list) and value else value

        domain_name = _first(whois_result.get("domain_name"))
        analysis.domain_name = domain_name
        analysis.registrar = whois_result.get("registrar")
        analysis.name_servers = whois_result.get("name_servers") or []
        emails = whois_result.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        analysis.emails = sorted(set(emails))[:_MAX_EMAILS_STORED]

        created = _first(whois_result.get("creation_date"))
        if isinstance(created, datetime):
            analysis.datetime_created = created.isoformat(" ")
            analysis.age_created_in_days = _age_in_days_as_string(created, now)
        elif created is not None:
            logging.warning(
                f"whois fallback for {observable} has unexpected "
                f"creation_date format: {type(created).__name__}"
            )

        updated = _first(whois_result.get("updated_date"))
        if isinstance(updated, datetime):
            analysis.datetime_of_last_update = updated.isoformat(" ")
            analysis.age_last_updated_in_days = _age_in_days_as_string(updated, now)
        elif updated is not None:
            logging.warning(
                f"whois fallback for {observable} has unexpected "
                f"updated_date format: {type(updated).__name__}"
            )

        expires = _first(whois_result.get("expiration_date"))
        if isinstance(expires, datetime):
            analysis.datetime_expiration = expires.isoformat(" ")

        return None


# Sentinel returned by ``_try_rdap`` to distinguish "RDAP says no" from
# "RDAP can't answer". Internal; never stored on the analysis.
_RDAP_NXDOMAIN_SENTINEL = "__rdap_nxdomain__"


class RdapAnalysisPresenter(AnalysisPresenter):
    """Presenter for RdapAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/rdap.html"


register_analysis_presenter(RdapAnalysis, RdapAnalysisPresenter)
