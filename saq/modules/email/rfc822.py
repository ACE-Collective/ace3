import email
import hashlib
import logging
import mimetypes
import os
import re
import shutil
import uuid
from datetime import datetime
from functools import cached_property
from ipaddress import ip_address
from subprocess import PIPE, Popen
from typing import Optional, Type, override

import dateutil
import pytz
from pydantic import BaseModel, Field

from saq.analysis.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import (
    AnalysisPresenter,
    register_analysis_presenter,
)
from saq.constants import (
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_ORIGINAL_EMAIL,
    DIRECTIVE_PREVIEW,
    DIRECTIVE_REMEDIATE,
    DIRECTIVE_RENAME_ANALYSIS,
    DIRECTIVE_RENDER,
    F_EMAIL_ADDRESS,
    F_EMAIL_CC,
    F_EMAIL_CONVERSATION,
    F_EMAIL_DELIVERY,
    F_EMAIL_DKIM_SIGNING_DOMAIN,
    F_EMAIL_ENVELOPE_MAIL_FROM,
    F_EMAIL_ENVELOPE_RCPT_TO,
    F_EMAIL_FIRST_HOP_FROM,
    F_EMAIL_FIRST_HOP_HELO,
    F_EMAIL_FIRST_HOP_IP,
    F_EMAIL_FROM,
    F_EMAIL_REPLY_TO,
    F_EMAIL_RETURN_PATH,
    F_EMAIL_SENDER_TENANT_ID,
    F_EMAIL_SUBJECT,
    F_EMAIL_TO,
    F_EMAIL_X_AUTH_ID,
    F_EMAIL_X_MAILER,
    F_EMAIL_X_ORIGINAL_SENDER,
    F_EMAIL_X_SENDER,
    F_EMAIL_X_SENDER_ID,
    F_FILE,
    F_IP,
    F_MESSAGE_ID,
    F_USER_AGENT,
    AnalysisExecutionResult,
    create_email_conversation,
    create_email_delivery,
)
from saq.configuration.config import get_config
from saq.observables.type_hierarchy import get_type_hierarchy
from saq.email import (
    decode_rfc2822,
    is_local_email_domain,
    normalize_email_address,
    normalize_message_id,
)
from saq.environment import get_base_dir, get_data_dir, get_local_timezone
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.constants import (
    KEY_CC,
    KEY_COMPAUTH_REASON,
    KEY_COMPAUTH_RESULT,
    KEY_DECODED_SUBJECT,
    KEY_DKIM_RESULT,
    KEY_DKIM_SIGNING_DOMAINS,
    KEY_DMARC_RESULT,
    KEY_EMAIL,
    KEY_ENV_MAIL_FROM,
    KEY_ENV_RCPT_TO,
    KEY_EXTRACTION_ERRORS,
    KEY_FIRST_HOP_FROM,
    KEY_FIRST_HOP_HELO,
    KEY_FIRST_HOP_IP,
    KEY_FROM,
    KEY_FROM_ADDRESS,
    KEY_HEADERS,
    KEY_INTERNAL_ORG_SENDER,
    KEY_IS_ANONYMOUS_DIRECT_SEND,
    KEY_MESSAGE_DIRECTIONALITY,
    KEY_SPF_RESULT,
    KEY_LOG_ENTRY,
    KEY_MESSAGE_ID,
    KEY_ORIGINATING_IP,
    KEY_PARSING_ERROR,
    KEY_REPLY_TO,
    KEY_REPLY_TO_ADDRESS,
    KEY_RETURN_PATH,
    KEY_SENDER_TENANT_ID,
    KEY_SUBJECT,
    KEY_TO,
    KEY_TO_ADDRESSES,
    KEY_USER_AGENT,
    KEY_X_AUTH_ID,
    KEY_X_MAILER,
    KEY_X_ORIGINAL_SENDER,
    KEY_X_SENDER,
    KEY_X_SENDER_ID,
    KEY_X_SENDER_IP,
)
from saq.observables.file import FileObservable
from saq.util.filesystem import shorten_basename_for_suffix
from saq.util.networking import is_subdomain
from saq.whitelist import (
    WHITELIST_TYPE_SMTP_FROM,
    WHITELIST_TYPE_SMTP_TO,
    BrotexWhitelist,
)

TAG_OUTBOUND_EMAIL = 'outbound_email'
TAG_OUTBOUND_EXCEPTION_EMAIL = 'outbound_email_exception'
TAG_EMAIL_PARSE_INCOMPLETE = 'email_parse_incomplete'
TAG_AUTHENTICATION_FAILED = 'authentication_failed'
TAG_ANONYMOUS_DIRECT_SEND = 'anonymous_direct_send'
TAG_SPOOFED_INTERNAL = 'spoofed_internal'

# regex to match Received date
RE_EMAIL_RECEIVED_DATE = re.compile(r';\s?(.+)$')

def get_received_time(received_header):
    m = RE_EMAIL_RECEIVED_DATE.search(received_header, re.M)
    if m:
        try:
            return dateutil.parser.parse(m.group(1)).astimezone(pytz.UTC)
        except Exception as e:
            logging.debug(f"unable to parse {m.group(1)} as date time: {e}")

    return None

# the clauses of a Received: header we care about, e.g.
# Received: from mail-lf1-f52.google.com ([209.85.167.52]) by mailserver.company.com with ESMTP
RE_RECEIVED_FROM = re.compile(r'\bfrom\s+(\S+)', re.I)
RE_RECEIVED_BY = re.compile(r'\bby\s+(\S+)', re.I)
# both `(helo=foo.com)` and `(HELO foo.com)` are seen in the wild
RE_RECEIVED_HELO = re.compile(r'\bhelo\s*[=\s]\s*([^\s()\[\],;]+)', re.I)
# any bracketed or parenthesized group, which is where hop IPs live
RE_RECEIVED_GROUP = re.compile(r'[(\[]([^)\]]*)[)\]]')
# the parenthesized group of a Received `from` clause, e.g. `(rdns.host [1.2.3.4])`
RE_RECEIVED_PARENS = re.compile(r'\(([^)]*)\)')
# a dotted host name (at least one label separator, must contain a letter so it is not an IPv4)
RE_HOSTNAME = re.compile(r'\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b')

# the d= tag of a DKIM-Signature header (values are folded across lines, hence \s*)
RE_DKIM_SIGNING_DOMAIN = re.compile(r'(?:^|;)\s*d\s*=\s*([^;\s]+)', re.I)

# Default header names for each provider-specific fact we extract. These are the
# shipped defaults (Microsoft 365 header names); a deployment on a different mail
# provider overrides them via the analysis module's provider_headers config. All
# lookups are case-insensitive (email.message membership is case-insensitive).

# headers the provider stamps with the sending IP of the first external hop, most
# authoritative first. OriginalAttributedTenantConnectingIp is only present on
# tenant-to-tenant relayed mail and carries the true external ingress IP, whereas
# OriginalClientIPAddress on that same mail is a Microsoft-internal hop -- so it
# is listed first and OriginalClientIPAddress is the fallback for ordinary inbound.
DEFAULT_FIRST_HOP_IP_HEADERS = [
    'x-ms-exchange-organization-originalattributedtenantconnectingip',
    'x-ms-exchange-organization-originalclientipaddress',
    'x-sender-ip',
]

# headers identifying the tenant/organization the message was sent from
DEFAULT_SENDER_TENANT_ID_HEADERS = [
    'x-ms-exchange-crosstenant-id',
    'x-ms-exchange-organization-originaltenant-id',
    'x-ms-exchange-organization-outboundhop-sender-tenantid',
]

# headers carrying the provider's composite authentication verdict / reason code
DEFAULT_COMPOSITE_AUTH_RESULT_HEADERS = ['x-ms-exchange-organization-compauthres']
DEFAULT_COMPOSITE_AUTH_REASON_HEADERS = ['x-ms-exchange-organization-compauthreason']

# provenance flag headers (a value of 'true' means the flag is set)
DEFAULT_ANONYMOUS_DIRECT_SEND_HEADERS = ['x-ms-exchange-organization-isanonymousdirectsend']
DEFAULT_INTERNAL_ORG_SENDER_HEADERS = ['x-ms-exchange-organization-internalorgsender']

# headers stating the message direction (inbound vs our own outbound)
DEFAULT_MESSAGE_DIRECTIONALITY_HEADERS = ['x-ms-exchange-organization-messagedirectionality']


class EmailProviderHeaders(BaseModel):
    """Per-provider header names for each provider-specific fact EmailAnalyzer extracts.

    Defaults are the Microsoft 365 header names. A deployment on another mail
    provider overrides only the lists that differ; any list left empty simply
    disables that extraction (a provider without the concept never errors).
    """
    first_hop_ip: list[str] = Field(
        default_factory=lambda: list(DEFAULT_FIRST_HOP_IP_HEADERS),
        description="Headers carrying the sending IP of the first external hop.")
    sender_tenant_id: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SENDER_TENANT_ID_HEADERS),
        description="Headers carrying the sending organization's tenant GUID.")
    composite_auth_result: list[str] = Field(
        default_factory=lambda: list(DEFAULT_COMPOSITE_AUTH_RESULT_HEADERS),
        description="Headers carrying the provider's composite authentication verdict.")
    composite_auth_reason: list[str] = Field(
        default_factory=lambda: list(DEFAULT_COMPOSITE_AUTH_REASON_HEADERS),
        description="Headers carrying the provider's composite authentication reason code.")
    anonymous_direct_send: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ANONYMOUS_DIRECT_SEND_HEADERS),
        description="Boolean headers set when the message arrived via unauthenticated direct send.")
    internal_org_sender: list[str] = Field(
        default_factory=lambda: list(DEFAULT_INTERNAL_ORG_SENDER_HEADERS),
        description="Boolean headers set when the provider treated the sender as internal to the org.")
    message_directionality: list[str] = Field(
        default_factory=lambda: list(DEFAULT_MESSAGE_DIRECTIONALITY_HEADERS),
        description="Headers stating the message direction (e.g. 'Incoming' vs outbound).")


def normalize_ip_header_value(value: str) -> Optional[str]:
    """Return the IP address carried by a header value, or None if there isn't one.

    Headers like X-Originating-IP and X-Sender-IP wrap the address in brackets
    (`[10.0.0.1]`), so the decoration has to come off. Note that stripping every
    character outside [0-9.] would destroy IPv6 addresses, hence the parse.
    """
    if value is None:
        return None

    candidate = value.strip().strip('[]').strip()
    try:
        return str(ip_address(candidate))
    except ValueError:
        logging.debug(f"header value {value} is not a valid ip address")
        return None


# candidate IP tokens inside a structured header value (bare, or bracketed like `[10.0.0.1]`)
RE_IP_TOKEN = re.compile(r'\[?([0-9a-fA-F:.]+)\]?')


def extract_first_hop_ip(value: str) -> Optional[str]:
    """Return the sending IP carried by a first-hop header value, or None.

    Most first-hop headers are a bare (optionally bracketed) IP -- that fast path
    is unchanged. Some, however, are structured; e.g. a tenant-relayed message
    records `TenantId=<guid>;Ip=[<ip>];Helo=[<host>]`. When the whole value is not
    itself an IP we scan for the first token that parses as one, which yields the
    connecting IP ahead of any trailing helo/loopback token.
    """
    if value is None:
        return None

    direct = normalize_ip_header_value(value)
    if direct is not None:
        return direct

    for m in RE_IP_TOKEN.finditer(value):
        try:
            return str(ip_address(m.group(1)))
        except ValueError:
            continue

    return None


def _received_from_clause(received: str) -> str:
    """Return the part of a Received: header between its `from` and `by` clauses."""
    m = RE_RECEIVED_FROM.search(received)
    if not m:
        return ''

    tail = received[m.end():]
    by = RE_RECEIVED_BY.search(tail)
    return tail[:by.start()] if by else tail


def _looks_like_ip(value: Optional[str]) -> bool:
    """True if the value parses as an IP address (after stripping any brackets)."""
    if not value:
        return False
    try:
        ip_address(value.strip('[]'))
        return True
    except ValueError:
        return False


def _received_rdns_host(from_clause: str) -> Optional[str]:
    """Return the reverse-DNS host name inside a Received `from` clause's parentheses.

    e.g. `(mail.example.com [1.2.3.4])` -> `mail.example.com`. Returns None when the
    parentheses hold only an IP, the `unknown` placeholder, or nothing host-like.
    """
    parens = RE_RECEIVED_PARENS.search(from_clause)
    if not parens:
        return None

    for m in RE_HOSTNAME.finditer(parens.group(1)):
        host = m.group(1)
        if host.lower() == 'unknown':
            continue
        if _looks_like_ip(host):  # a dotted-decimal IPv4 also matches RE_HOSTNAME
            continue
        return host.lower()

    return None


def _extract_hop_ip(received: str) -> Optional[str]:
    """Return the sending IP recorded in the `from` clause of a Received: header."""
    for group in RE_RECEIVED_GROUP.findall(_received_from_clause(received)):
        for token in group.replace('[', ' ').replace(']', ' ').split():
            try:
                return str(ip_address(token.strip('.,;')))
            except ValueError:
                continue

    return None


def resolve_first_hop(
        target_email,
        ip_headers: list[str] = DEFAULT_FIRST_HOP_IP_HEADERS,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve (ip, helo, from_host) for the first external hop of a message.

    Prefers the ``ip_headers`` the provider stamps with the authoritative sending
    IP. When none are present we fall back to the earliest Received: hop that was
    accepted *by* one of our own hosts -- that is the perimeter MTA, so the host it
    received *from* is the external sender.

    We deliberately do not use "the bottom-most non-private Received: hop", because
    the bottom hop is frequently the sender's own webmail client rather than the
    sending MTA (e.g. `from 10.13.46.65 ([UNAVAILABLE]. [82.117.219.130])`).

    Any component that does not resolve comes back as None rather than a guess.
    """
    received_headers = [decode_rfc2822(_) for _ in target_email.get_all('received', [])]

    hop_ip = None
    for header in ip_headers:
        if header not in target_email:
            continue

        hop_ip = extract_first_hop_ip(decode_rfc2822(target_email[header]))
        if hop_ip:
            break

    hop_header = None
    if hop_ip:
        # find the hop that carries the authoritative IP so we can read its helo/from
        for received in received_headers:
            if _extract_hop_ip(received) == hop_ip:
                hop_header = received
                break
    else:
        local_domains = set(get_config().global_settings.local_domains)
        local_domains |= set(get_config().global_settings.local_email_domains)

        # reversed() walks the hops earliest-first, so the first local receipt is the perimeter
        for received in reversed(received_headers):
            m = RE_RECEIVED_BY.search(received)
            if not m:
                continue

            by_host = m.group(1).strip('.,;')
            if not any(is_subdomain(by_host, _) for _ in local_domains):
                continue

            candidate_ip = _extract_hop_ip(received)
            if candidate_ip and ip_address(candidate_ip).is_private:
                # an internal relay handing off to another internal host (journaling,
                # smart hosts) is not the external hop we're looking for -- keep walking
                continue

            hop_header = received
            hop_ip = candidate_ip
            break

    if hop_header is None:
        return hop_ip, None, None

    # In `Received: from <token> (<rdns> [<ip>])`, <token> is the string the client
    # presented in HELO/EHLO and <rdns> is the sender's reverse-DNS host name. Some MTAs
    # (Exim style) instead write `from <rdns> ([<ip>] helo=<token>)` with an explicit
    # helo= tag -- when that tag is present it is authoritative, and the token after `from`
    # is then the verified host rather than the helo.
    from_clause = _received_from_clause(hop_header)

    inline_helo = None
    m = RE_RECEIVED_HELO.search(from_clause)
    if m:
        inline_helo = m.group(1).strip('[]').lower()

    from_token = None
    m = RE_RECEIVED_FROM.search(hop_header)
    if m:
        from_token = m.group(1).strip('.,;').strip('[]').lower()

    if inline_helo is not None:
        hop_helo = inline_helo
        # the token after `from` is the verified host in this form; keep it only if it is a
        # host name, not an address literal
        hop_from = from_token if not _looks_like_ip(from_token) else None
    else:
        # the token after `from` IS the helo (may be an address literal like `[127.0.0.1]`);
        # the sending host, if named at all, is the reverse-DNS host inside the parentheses
        hop_helo = from_token
        hop_from = _received_rdns_host(from_clause)

    return hop_ip, hop_helo, hop_from


def get_dkim_signing_domains(target_email) -> list[str]:
    """Return the d= signing domain of every DKIM-Signature header on the message."""
    results = []
    for header in target_email.get_all('dkim-signature', []):
        m = RE_DKIM_SIGNING_DOMAIN.search(decode_rfc2822(header))
        if not m:
            continue

        domain = m.group(1).strip('.').lower()
        if domain and domain not in results:
            results.append(domain)

    return results


def get_sender_tenant_id(
        target_email,
        tenant_headers: list[str] = DEFAULT_SENDER_TENANT_ID_HEADERS,
) -> Optional[str]:
    """Return the sending organization's tenant GUID, if any.

    ``tenant_headers`` defaults to the Microsoft 365 cross-tenant headers and is
    overridable per provider via config.
    """
    for header in tenant_headers:
        if header not in target_email:
            continue

        value = decode_rfc2822(target_email[header]).strip()
        try:
            return str(uuid.UUID(value))
        except ValueError:
            logging.debug(f"{header} value {value} is not a valid guid")

    return None


# per-verdict extraction from the free-form Authentication-Results header, e.g.
# Authentication-Results: spf=fail (...) smtp.mailfrom=x; dkim=none (...); dmarc=fail action=oreject ...
RE_AUTH_SPF = re.compile(r'\bspf=(\w+)', re.I)
RE_AUTH_DKIM = re.compile(r'\bdkim=(\w+)', re.I)
RE_AUTH_DMARC = re.compile(r'\bdmarc=(\w+)', re.I)
RE_AUTH_COMPAUTH = re.compile(r'\bcompauth=(\w+)', re.I)
RE_AUTH_COMPAUTH_REASON = re.compile(r'\breason=(\w+)', re.I)


def _first_present_header(target_email, headers: list[str]) -> Optional[str]:
    """Return the decoded value of the first header in ``headers`` that is present."""
    for header in headers:
        if header in target_email:
            return decode_rfc2822(target_email[header]).strip()

    return None


def _any_header_is_true(target_email, headers: list[str]) -> bool:
    """True if any header in ``headers`` is present with a value of 'true'."""
    value = _first_present_header(target_email, headers)
    return value is not None and value.lower() == 'true'


def parse_email_authentication(
        target_email,
        provider_headers: Optional[EmailProviderHeaders] = None,
) -> dict:
    """Parse the message authentication verdicts and provider provenance flags.

    These are message-level verdicts (fail/pass/True/Incoming), not pivotable
    IOCs, so callers store them in the analysis details and drive tags/detections
    from them rather than emitting observables.

    SPF/DKIM/DMARC come from the standard Authentication-Results header (RFC 8601);
    composite auth and the provenance flags come from provider-specific headers
    named in ``provider_headers``. Any header list left empty simply yields None --
    a provider without a given concept never errors.
    """
    if provider_headers is None:
        provider_headers = EmailProviderHeaders()

    # composite auth prefers the provider's dedicated header; fall back to the
    # compauth token inside Authentication-Results when no dedicated header is set.
    compauth_result = _first_present_header(target_email, provider_headers.composite_auth_result)
    compauth_reason = _first_present_header(target_email, provider_headers.composite_auth_reason)

    result = {
        KEY_SPF_RESULT: None,
        KEY_DKIM_RESULT: None,
        KEY_DMARC_RESULT: None,
        KEY_COMPAUTH_RESULT: compauth_result.lower() if compauth_result else None,
        KEY_COMPAUTH_REASON: compauth_reason,
        KEY_IS_ANONYMOUS_DIRECT_SEND: _any_header_is_true(
            target_email, provider_headers.anonymous_direct_send),
        KEY_INTERNAL_ORG_SENDER: _any_header_is_true(
            target_email, provider_headers.internal_org_sender),
        KEY_MESSAGE_DIRECTIONALITY: _first_present_header(
            target_email, provider_headers.message_directionality),
    }

    # prefer the Authentication-Results header that actually carries a dmarc verdict
    # (a message can accrue several as it transits relays)
    auth_results_headers = [decode_rfc2822(_) for _ in target_email.get_all('authentication-results', [])]
    auth_results = next((_ for _ in auth_results_headers if RE_AUTH_DMARC.search(_)),
                        auth_results_headers[0] if auth_results_headers else '')

    for key, pattern in (
        (KEY_SPF_RESULT, RE_AUTH_SPF),
        (KEY_DKIM_RESULT, RE_AUTH_DKIM),
        (KEY_DMARC_RESULT, RE_AUTH_DMARC),
    ):
        m = pattern.search(auth_results)
        if m:
            result[key] = m.group(1).lower()

    if result[KEY_COMPAUTH_RESULT] is None:
        m = RE_AUTH_COMPAUTH.search(auth_results)
        if m:
            result[KEY_COMPAUTH_RESULT] = m.group(1).lower()

    if result[KEY_COMPAUTH_REASON] is None:
        m = RE_AUTH_COMPAUTH_REASON.search(auth_results)
        if m:
            result[KEY_COMPAUTH_REASON] = m.group(1)

    return result


def add_email_address_observable(analysis, otype, address, *, conversation_source=None):
    """Add an email-address subtype observable, plus an optional supporting observable.

    The display_type for the email address observable comes from the
    observable_types.yaml registry (default_display_type per subtype) — no
    explicit setter is needed.

    Args:
        analysis: the Analysis to add the observable to.
        otype: one of the F_EMAIL_* subtypes (e.g., F_EMAIL_FROM, F_EMAIL_TO).
        address: the (already-normalized) email address.
        conversation_source: if set, also add an F_EMAIL_CONVERSATION observable
            for `conversation_source` -> `address`.

    Returns the email address observable (or None if creation failed).
    """
    obs = analysis.add_observable_by_spec(otype, address)
    if obs is None:
        return None
    if conversation_source:
        analysis.add_observable_by_spec(
            F_EMAIL_CONVERSATION,
            create_email_conversation(conversation_source, address),
        )
    return obs


def get_address_list(email_obj, header_name):
    # decode each header to str so email.utils.getaddresses doesn't see the
    # encoded form when the value comes back as an email.header.Header
    headers = [decode_rfc2822(h) for h in email_obj.get_all(header_name, [])]
    addresses = email.utils.getaddresses(headers)
    return [x[1] for x in addresses]


class EmailAnalysis(Analysis):
    """What are all the contents of this email?"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_PARSING_ERROR: None,
            KEY_EXTRACTION_ERRORS: [],
            KEY_EMAIL: None
        }

    @override
    @property
    def display_name(self) -> str:
        return "Email Analysis"
        
    @property
    def parsing_error(self):
        return self.details[KEY_PARSING_ERROR]

    @parsing_error.setter
    def parsing_error(self, value):
        self.details[KEY_PARSING_ERROR] = value

    @property
    def extraction_errors(self):
        if not self.details:
            return []
        return self.details.get(KEY_EXTRACTION_ERRORS, []) or []

    @property
    def email(self):
        if not self.details:
            return {}

        if KEY_EMAIL not in self.details:
            return {}

        return self.details[KEY_EMAIL]

    @email.setter
    def email(self, value):
        self.details[KEY_EMAIL] = value

    @property
    def env_mail_from(self):
        if self.email and KEY_ENV_MAIL_FROM in self.email:
            return self.email[KEY_ENV_MAIL_FROM]

        return None

    @env_mail_from.setter
    def env_mail_from(self, value):
        self.email[KEY_ENV_MAIL_FROM] = value

    @property
    def env_rcpt_to(self):
        if self.email and KEY_ENV_RCPT_TO in self.email:
            return self.email[KEY_ENV_RCPT_TO]

        return None

    @env_rcpt_to.setter
    def env_rcpt_to(self, value):
        self.email[KEY_ENV_RCPT_TO] = value

    @property
    def mail_from(self):
        if self.email and KEY_FROM in self.email:
            return self.email[KEY_FROM]

        return None

    @property
    def mail_from_address(self):
        if self.email and KEY_FROM_ADDRESS in self.email:
            return self.email[KEY_FROM_ADDRESS]

        return None

    @property
    def mail_to(self):
        if self.email and KEY_TO in self.email:
            return self.email[KEY_TO]

        return []

    @property
    def mail_to_addresses(self):
        if self.email and KEY_TO_ADDRESSES in self.email:
            return self.email[KEY_TO_ADDRESSES]

        return []

    @property
    def cc(self):
        if self.email and KEY_CC in self.email:
            return self.email[KEY_CC]

        return []

    @property
    def reply_to(self):
        if self.email and KEY_REPLY_TO in self.email:
            return self.email[KEY_REPLY_TO]

        return None

    @property
    def reply_to_address(self):
        if self.email and KEY_REPLY_TO_ADDRESS in self.email:
            return self.email[KEY_REPLY_TO_ADDRESS]

        return None

    @property
    def subject(self):
        if self.email and KEY_SUBJECT in self.email:
            return self.email[KEY_SUBJECT]

        return None

    @property
    def decoded_subject(self):
        if self.email and KEY_DECODED_SUBJECT in self.email:
            return self.email[KEY_DECODED_SUBJECT]

        return None

    @property
    def message_id(self):
        if self.email and KEY_MESSAGE_ID in self.email:
            if self.email[KEY_MESSAGE_ID]:
                return self.email[KEY_MESSAGE_ID].strip()
            else:
                return self.email[KEY_MESSAGE_ID] 

        return None

    @property
    def originating_ip(self):
        if self.email and KEY_ORIGINATING_IP in self.email:
            return self.email[KEY_ORIGINATING_IP]

        return None

    @property
    def return_path(self):
        if self.email and KEY_RETURN_PATH in self.email:
            return self.email[KEY_RETURN_PATH]

        return None

    @property
    def user_agent(self):
        if self.email and KEY_USER_AGENT in self.email:
            return self.email[KEY_USER_AGENT]

        return None

    @property
    def x_mailer(self):
        if self.email and KEY_X_MAILER in self.email:
            return self.email[KEY_X_MAILER]

        return None

    @property
    def x_sender_ip(self):
        if self.email and KEY_X_SENDER_IP in self.email:
            return self.email[KEY_X_SENDER_IP]

        return None

    @property
    def x_sender(self):
        if self.email and KEY_X_SENDER in self.email:
            return self.email[KEY_X_SENDER]

        return None

    @property
    def x_sender_id(self):
        if self.email and KEY_X_SENDER_ID in self.email:
            return self.email[KEY_X_SENDER_ID]

        return None

    @property
    def x_auth_id(self):
        if self.email and KEY_X_AUTH_ID in self.email:
            return self.email[KEY_X_AUTH_ID]

        return None

    @property
    def x_original_sender(self):
        if self.email and KEY_X_ORIGINAL_SENDER in self.email:
            return self.email[KEY_X_ORIGINAL_SENDER]

        return None

    @property
    def received(self):
        """Returns the list of Received: headers of the email, or None if the headers are not available."""
        if not self.headers:
            return None

        result = []

        for key, value in self.headers:
            if key == 'Received':
                result.append(value)

        return result

    @property
    def received_time(self):
        if self.received:
            return get_received_time(self.received[0])

        return None

    @property
    def headers(self):
        if self.email and KEY_HEADERS in self.email:
            return self.email[KEY_HEADERS]

        return None

    @property
    def headers_formatted(self) -> str:
        headers = ''
        if self.headers:
            for header in self.headers:
                headers = f'{headers}{header[0]}: {header[1]}\n'
        return headers

    @property
    def log_entry(self):
        if not self.email:
            return None

        if KEY_LOG_ENTRY in self.email:
            return self.email[KEY_LOG_ENTRY]

        return None

    @property
    def body_html(self) -> str:
        body_observable = next(
            (o for o in self.observables if o.type == F_FILE and 'unknown_text_html_000' in o.file_name), None)

        if body_observable:
            path = body_observable.full_path
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return f.read().decode('utf-8', errors='ignore')

        return ''

    @property
    def body_text(self) -> str:
        body_observable = next(
            (o for o in self.observables if o.type == F_FILE and 'unknown_text_plain_000' in o.file_name), None)

        if body_observable:
            path = body_observable.full_path
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return f.read().decode('utf-8', errors='ignore')

        return ''
    
    @property
    def body(self):
        """Returns the file observable that should be considered the body of the email, or None if one cannot be found."""

        if hasattr(self, '_body'):
            return self._body

        # keep track of the first plain text and html files we find
        first_html = None
        first_plain_text = None

        for _file in self.observables:
            if _file.type != F_FILE:
                continue

            if '.unknown_' not in _file.file_name:
                continue

            # if all we have is a single text_plain file then that is the body of the email
            plain_text_files = list(filter(lambda o: o.type == F_FILE and 'unknown_text_plain' in o.file_name, self.observables))
            html_files = list(filter(lambda o: o.type == F_FILE and 'unknown_text_html' in o.file_name, self.observables))

            if len(plain_text_files) == 1 and len(html_files) == 0:
                self._body = plain_text_files[0]
                return self._body

            # otherwise we always skip this one first
            if '.unknown_text_plain_000' in _file.file_name:
                continue

            if first_html is None and 'unknown_text_html' in _file.file_name:
                first_html = _file
                continue

            if first_plain_text is None and 'unknown_text_plain' in _file.file_name:
                first_plain_text = _file
                continue

        # if we found html then we return that as the body
        if first_html:
            self._body = first_html
        else:
            # otherwise we return the plain text
            self._body = first_plain_text # if there isn't one then it returns None anyways

        return self._body

    @property
    def attachments(self):
        """Returns the list of F_FILE observables that were attachments to the email (not considered the body.)"""
        result = []

        for _file in self.observables:
            if _file.type != F_FILE:
                continue

            # skip any file with an auto-generated name (these are typically part of the body)
            # XXX hack
            if "email.rfc822" in _file.file_name:
                continue

            result.append(_file)

        return result

    @property
    def attachment_names(self):
        """Returns the list of the attachment filenames."""
        return [
            attachment.file_path for attachment in self.attachments
            if 'unknown_text_plain_000' not in attachment.file_path
            and 'unknown_text_html_000' not in attachment.file_path
            and not attachment.file_path.endswith('rfc822.headers')
        ]

    @property
    def jinja_template_path(self):
        return "analysis/email_analysis.html"
        
    def generate_summary(self):
        if self.parsing_error:
            return self.parsing_error

        if self.observable.has_tag('whitelisted'):
            return "Email Analysis: (whitelisted email)"

        if self.email:
            result = "Email Analysis:"
            if self.extraction_errors:
                result = "Email Analysis [partial extraction: {} error(s)]:".format(len(self.extraction_errors))
            if KEY_FROM in self.email:
                result = "{} From {}".format(result, self.email[KEY_FROM])
            if KEY_ENV_RCPT_TO in self.email and self.email[KEY_ENV_RCPT_TO]:
                result = "{} To {}".format(result, self.email[KEY_ENV_RCPT_TO][0])
            elif KEY_TO in self.email and self.email[KEY_TO]:
                result = "{} To {}".format(result, self.email[KEY_TO][0])
            if KEY_DECODED_SUBJECT in self.email:
                result = "{} Subject {}".format(result, self.email[KEY_DECODED_SUBJECT])
            elif KEY_SUBJECT in self.email:
                result = "{} Subject {}".format(result, self.email[KEY_SUBJECT])

            return result

        return None

# example
#Received: from BN6PR1601CA0006.namprd16.prod.outlook.com (10.172.104.144) by
 #BN6PR1601MB1156.namprd16.prod.outlook.com (10.172.107.18) with Microsoft SMTP
 #Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384) id
 #15.1.707.6; Thu, 10 Nov 2016 15:47:33 +0000

_PATTERN_RECEIVED_IPADDR = re.compile(r'from\s\S+\s\(([^)]+)\)\s', re.M)

class EmailAnalyzerConfig(AnalysisModuleConfig):
    whitelist_path: str = Field(..., description="Relative path to the brotex custom whitelist file.")
    scan_inbound_only: bool = Field(..., description="Office365 journaling will cause outbound emails to also get journaled. Set this to no to scan outbound office365 emails.")
    outbound_exceptions: str = Field(..., description="When only scanning inbound emails from office365, scan the following outbound emails found in outbound_exceptions. Comma separated list!")
    provider_headers: EmailProviderHeaders = Field(
        default_factory=EmailProviderHeaders,
        description="Per-provider header names for provider-specific facts (first-hop IP, sender tenant, "
                    "composite auth, provenance flags). Defaults are the Microsoft 365 names; override for "
                    "other providers. Any list left empty disables that extraction.")

class EmailAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailAnalyzerConfig

    @override
    def get_presenter_class(self) -> Type[AnalysisPresenter]:
        return EmailAnalysisPresenter

    def verify_environment(self):
        self.verify_path_exists(self.config.whitelist_path)

    @cached_property
    def whitelist(self) -> BrotexWhitelist:
        result = BrotexWhitelist(os.path.join(get_base_dir(), self.config.whitelist_path))
        result.check_whitelist()
        return result

    #def load_config(self):
        #self.whitelist = BrotexWhitelist(os.path.join(get_base_dir(), self.config.whitelist_path))
        #self.auto_reload()

    def auto_reload(self):
        # make sure the whitelist if up-to-date
        self.whitelist.check_whitelist()
        
    @property
    def generated_analysis_type(self):
        return EmailAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def outbound_exception_list(self):
        return self.config.outbound_exceptions.split(',')

    def analyze_rfc822(self, _file):
        assert isinstance(_file, FileObservable)
        from saq.modules.email.message_id import MessageIDAnalyzerV2

        # if this is a headers file then we skip it
        # this will look like a legit email file
        # XXX take this out an add an exclusion when we add it
        if _file.full_path.endswith('.headers'):
            return False

        # parse the email
        parsed_email = None

        # sometimes the actual email we want will be an attachment
        # this will point to a MIME part
        target_email = None

        #
        # something changed at some point with office365 journaled emails
        # we used to be able to use the header X-MS-Exchange-Organization-OriginalEnvelopeRecipients
        # to determine who the email was *actually* delivered to
        # this appears to not be the case anymore
        #

        #
        # so in the case of office365 journal emails we will see something like the following:
        #
        # --_f72c3c83-af4f-4c48-af8e-4aaa9b7206c6_
        # Content-Type: text/plain; charset="us-ascii"
        # Content-Transfer-Encoding: 7bit
        #
        # Sender: H.Abdelrahim@rbht.nhs.uk
        # Subject: Completed: Order No.2739382. 
        # Message-Id: <B2810E1E-329D-494C-B84F-1B10F18FD41C@rbht.nhs.uk>
        # Recipient: Timothy.Spence@53.mail.onmicrosoft.com
        #
        # This is the only part that contains who the *actual* recipient was.
        # I'm calling this the "meta block" of journaled email messages.
        # There's an assumption that the information follows the following regex format.
        # If Microsoft ever decides to change that then this will break.
        #
        # this suff points to that part if it exists
        #

        o365_meta_part = None
        o365_meta_re = re.compile(r'^Sender: (.+?)^Subject: (.+?)^Message-Id: (.+?)^Recipient: ', re.M | re.DOTALL)
        o365_meta_recipient_re = re.compile(r'^Recipient: ([^,\n]+)', re.M)
        o365_meta_sender = None
        o365_meta_subject = None
        o365_meta_message_id = None
        o365_meta_recipients = []

        try:
            logging.debug("parsing email file {}".format(_file))
            # parse as bytes so non-ASCII payloads (e.g. UTF-8 BOMs in nested HTML parts)
            # can later be re-serialized via Message.as_bytes() during recursive extraction
            with open(_file.full_path, 'rb') as fp:
                target_email = parsed_email = email.parser.BytesParser().parse(fp)

        except Exception as e:
            logging.error("unable to parse email {}: {}".format(_file, e))

            try:
                # if Python's email parsing library can't parse it then we copy it off to the side
                # for analysis later
                src_path = _file.full_path
                dst_path = os.path.join(get_data_dir(), 'review', 'rfc822', str(uuid.uuid4()))
                shutil.copy(src_path, dst_path)

            except Exception as e:
                logging.error("unable to save file for review: {}".format(e))

            return False

        email_details = {}
        target_message_id = None # the message-id we've identified as the main one
        is_office365 = False # is this an office365 journaled message?

        # NOTE A
        # find the email we actually want to target
        # by default we target the entire email itself
        for part in parsed_email.walk():
            # look for what looks like the office365 meta part
            if o365_meta_part is None:
                if part.get_content_type() == 'text/plain':
                    cte = str(part.get('content-transfer-encoding', '')).strip().lower()

                    if cte in ('quoted-printable', 'base64'):
                        # For encoded content, decode=True properly decodes the CTE to raw bytes
                        target_payload_bytes = part.get_payload(decode=True)
                        if target_payload_bytes is None:
                            continue

                        charset = part.get_content_charset() or "utf-8"

                        try:
                            target_payload = target_payload_bytes.decode(charset)
                        except (UnicodeDecodeError, LookupError):
                            # (do the best you can)
                            target_payload = target_payload_bytes.decode("utf-8", errors="ignore")
                    else:
                        # For 7bit/8bit, get_payload(decode=True) uses raw-unicode-escape
                        # which mangles non-ASCII characters like the UTF-8 BOM.
                        # get_payload() returns the string directly, preserving Unicode chars.
                        target_payload = part.get_payload()
                        if not isinstance(target_payload, str):
                            continue

                    # some of these have this BOM at the start
                    target_payload = target_payload.lstrip("\ufeff")

                    m = o365_meta_re.search(target_payload)
                    if m:
                        o365_meta_sender = m.group(1).strip()
                        o365_meta_subject = m.group(2).strip()
                        o365_meta_message_id = m.group(3).strip()
                        o365_meta_recipients = [r.strip() for r in o365_meta_recipient_re.findall(target_payload)]
                        o365_meta_part = part
                        logging.info(f"parsed o365 meta block sender [{o365_meta_sender}] "
                                     f"subject [{o365_meta_subject}] "
                                     f"message id [{o365_meta_message_id}] "
                                     f"recipients {o365_meta_recipients}")

            # look for office365 header indicating a parent message-id
            if 'X-MS-Exchange-Parent-Message-Id' in part:
                is_office365 = True # we use this to identify this is an office365 journaled message
                target_message_id = decode_rfc2822(part['X-MS-Exchange-Parent-Message-Id']).strip()
                logging.debug("found office365 parent message-id {}".format(target_message_id))
                continue

            if 'message-id' in part:
                # if we are looking for a specific message-id...
                if target_message_id:
                    if decode_rfc2822(part['message-id']).strip() == target_message_id:
                        # found the part we're looking for
                        target_email = part
                        logging.debug("found target email using message-id{}".format(target_message_id))
                        break

        # at this point target_email either points at the original parse email
        # or it points to a MIME part (an attachment inside the email)

        # START WHITELISTING

        # check to see if the sender or receiver has been whitelisted
        # this is useful to filter out internally sourced garbage
        if 'from' in target_email:
            file_path, address = email.utils.parseaddr(decode_rfc2822(target_email['from']))
            if address != '':
                if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, address):
                    _file.whitelist()
                    return False

        header_tos = [] # list of header-to addresses
        env_rcpt_to = [] # list of env-to addresses 
        env_mail_from = None # the smtp envelope MAIL FROM

        # if this is an office365 email then we know who the email was actually delivered to
        if is_office365 and 'X-MS-Exchange-Organization-OriginalEnvelopeRecipients' in target_email:
            file_path, address = email.utils.parseaddr(decode_rfc2822(target_email['X-MS-Exchange-Organization-OriginalEnvelopeRecipients']))
            if address:
                env_rcpt_to = [ address ]

        # same as above but we pull this information out of what I'm calling the "meta block"
        # for lack of a better term
        if o365_meta_part:
            if o365_meta_recipients:
                env_rcpt_to = []
                for recipient in o365_meta_recipients:
                    _, address = email.utils.parseaddr(recipient)
                    if address:
                        env_rcpt_to.append(address)

            if o365_meta_sender:
                file_path, address = email.utils.parseaddr(o365_meta_sender)
                env_mail_from = address

        # if we know this is an office365 journaled email AND we did not find the "meta block"
        # then at least log that something is wrong
        if is_office365 and not o365_meta_part:
            try:
                message_id = parsed_email['message-id']
            except:
                message_id = "unknown"

            logging.info(f"unable to find meta block for message-id {message_id} in {self.get_root().storage_dir}")

        # emails that come from the SMTP collector should already have observables added with tags smtp_mail_from and
        # smtp_rctp_to
        hierarchy = get_type_hierarchy()
        for smtp_rcpt_to in [o.value for o in self.get_root().find_observables(
                lambda o: hierarchy.is_subtype(o.type, F_EMAIL_ADDRESS) and o.has_tag('smtp_rcpt_to'))]:
            if smtp_rcpt_to not in env_rcpt_to:
                env_rcpt_to.append(smtp_rcpt_to)

        mail_from = self.get_root().find_observable(
                lambda o: hierarchy.is_subtype(o.type, F_EMAIL_ADDRESS) and o.has_tag('smtp_mail_from'))
        if mail_from:
            env_mail_from = mail_from.value

        # we also have what To: addrsses are in the headers
        # use get_address_list (which calls email.utils.getaddresses) so a single
        # To: header listing multiple comma-separated addresses is split correctly
        for mail_to in get_address_list(target_email, 'to'):
            address = normalize_email_address(mail_to)
            if address:
                header_tos.append(address)

        for address in header_tos + env_rcpt_to:
            if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address):
                _file.whitelist()
                return False

        # for journaled provider mail we check to see if this email is inbound
        # this only applies to the original email, not email attachments
        if is_office365 and _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
            directionality = _first_present_header(
                target_email, self.config.provider_headers.message_directionality)
            if directionality is not None:
                if directionality != 'Incoming':
                    _file.add_tag(TAG_OUTBOUND_EMAIL)
                    if self.config.scan_inbound_only:
                        # do we have a configured exception?
                        for email_exception in self.outbound_exception_list:
                            logging.debug("searching header To addresses ({}) for '{}'".format(header_tos,
                                                                                               email_exception))
                            if email_exception in header_tos:
                                _file.add_tag(TAG_OUTBOUND_EXCEPTION_EMAIL)
                                logging.info("Outbound office365 email exception found: {}".format(email_exception))
                                break
                        else:
                            logging.info("skipping outbound office365 email {}".format(_file))
                            _file.whitelist()
                            return False

        # END WHITELISTING

        analysis = self.create_analysis(_file)

        # if it's not whitelisted we'll want to archive it
        #_file.add_directive(DIRECTIVE_ARCHIVE)

        # parse out important email header information and add observables

        # capture all email headers
        # decode values to str so downstream consumers (re.sub, str ops, JSON) don't
        # trip on email.header.Header instances returned under compat32 policy.
        email_details[KEY_HEADERS] = []
        for header, value in target_email.items():
            email_details[KEY_HEADERS].append([header, decode_rfc2822(value)])

        # who did the email come from and who did it go to?
        # with office365 journaling all you have is the header from
        mail_from = None # str

        received_time = None

        # figure out when the email was received
        if 'received' in target_email:
            # use the last received email header as the date
            received_time = get_received_time(decode_rfc2822(target_email.get_all('received')[0]))

        if 'from' in target_email:
            email_details[KEY_FROM] = decode_rfc2822(target_email['from'])
            from_address = get_address_list(target_email, 'from')
            if len(from_address):
                email_details[KEY_FROM_ADDRESS] = from_address[0]

            address = normalize_email_address(email_details[KEY_FROM])
            if address:
                mail_from = address
                add_email_address_observable(analysis, F_EMAIL_FROM, address)

        email_details[KEY_ENV_RCPT_TO] = env_rcpt_to
        email_details[KEY_ENV_MAIL_FROM] = env_mail_from

        for rcpt_to in email_details[KEY_ENV_RCPT_TO]:
            address = normalize_email_address(rcpt_to)
            if address:
                add_email_address_observable(analysis, F_EMAIL_ENVELOPE_RCPT_TO, address, conversation_source=mail_from)

        email_details[KEY_TO] = [decode_rfc2822(h) for h in target_email.get_all('to', [])]
        email_details[KEY_TO_ADDRESSES] = get_address_list(target_email, 'to')
        # iterate KEY_TO_ADDRESSES (parsed via email.utils.getaddresses) so multi-address
        # To: headers like "a@x, Name <b@x>" produce one observable per recipient
        for addr in email_details[KEY_TO_ADDRESSES]:
            address = normalize_email_address(addr)
            if address:
                add_email_address_observable(analysis, F_EMAIL_TO, address, conversation_source=mail_from)

        if 'subject' in target_email:
            # KEY_SUBJECT keeps the raw (possibly RFC 2822-encoded) value as a str;
            # KEY_DECODED_SUBJECT is populated below from this value.
            raw_subject = target_email['subject']
            if raw_subject is not None:
                raw_subject = str(raw_subject)
            email_details[KEY_SUBJECT] = raw_subject
            if raw_subject:
                analysis.add_observable_by_spec(F_EMAIL_SUBJECT, raw_subject)

        if 'message-id' in target_email:
            message_id = decode_rfc2822(target_email['message-id'])
            email_details[KEY_MESSAGE_ID] = message_id
            message_id_observable = analysis.add_observable_by_spec(
                    F_MESSAGE_ID,
                    normalize_message_id(message_id),
                    o_time=received_time)

            if message_id_observable:
                # this module will extract an email from the archives based on the message-id
                # we don't want to do that here so we exclude that analysis
                message_id_observable.exclude_analysis(MessageIDAnalyzerV2)

            # note that we're adding delivery observables for *every* local recipient
            # even though we're not directly observing it, we assume so that
            # remediation can pick it up and run with it
            delivery_recipients = []
            for raw_recipient in set(
                    env_rcpt_to
                    + email_details[KEY_TO_ADDRESSES]
                    + get_address_list(target_email, 'cc')
                    + get_address_list(target_email, 'bcc')
                ):
                recipient = normalize_email_address(raw_recipient)
                if is_local_email_domain(recipient):
                    delivery_recipients.append(recipient)

            # if a message_id observable has the DIRECTIVE_REMEDIATE directive
            # then that directive gets copied to every delivery observable so
            # the remediation system knows where to find the email
            should_remediate = message_id_observable is not None and any(
                _.value == message_id_observable.value and _.has_directive(DIRECTIVE_REMEDIATE)
                for _ in self.get_root().get_observables_by_type(F_MESSAGE_ID))

            for recipient in delivery_recipients:
                email_delivery_observable = analysis.add_observable_by_spec(F_EMAIL_DELIVERY,
                                            create_email_delivery(email_details[KEY_MESSAGE_ID], recipient))
                if email_delivery_observable and should_remediate:
                    logging.info(f"copying directive {DIRECTIVE_REMEDIATE} from message-id "
                                 f"{message_id_observable.value} to {email_delivery_observable.value}")
                    email_delivery_observable.add_directive(DIRECTIVE_REMEDIATE)

        if 'x-sender' in target_email:
            address = normalize_email_address(decode_rfc2822(target_email['x-sender']))
            if address:
                email_details[KEY_X_SENDER] = address
                add_email_address_observable(analysis, F_EMAIL_X_SENDER, address)

        if 'x-sender-id' in target_email:
            address = normalize_email_address(decode_rfc2822(target_email['x-sender-id']))
            if address:
                email_details[KEY_X_SENDER_ID] = address
                add_email_address_observable(analysis, F_EMAIL_X_SENDER_ID, address)

        if 'x-auth-id' in target_email:
            address = normalize_email_address(decode_rfc2822(target_email['x-auth-id']))
            if address:
                email_details[KEY_X_AUTH_ID] = address
                add_email_address_observable(analysis, F_EMAIL_X_AUTH_ID, address)

        if 'x-original-sender' in target_email:
            address = normalize_email_address(decode_rfc2822(target_email['x-original-sender']))
            if address:
                email_details[KEY_X_ORIGINAL_SENDER] = address
                add_email_address_observable(analysis, F_EMAIL_X_ORIGINAL_SENDER, address)

        if 'reply-to' in target_email:
            address = normalize_email_address(decode_rfc2822(target_email['reply-to']))
            if address:
                email_details[KEY_REPLY_TO] = address
                email_details[KEY_REPLY_TO_ADDRESS] = address
                add_email_address_observable(analysis, F_EMAIL_REPLY_TO, address)

        if 'return-path' in target_email:
            address = normalize_email_address(decode_rfc2822(target_email['return-path']))
            if address:
                email_details[KEY_RETURN_PATH] = address
                add_email_address_observable(analysis, F_EMAIL_RETURN_PATH, address)

        # we add these last since there could be a lot of them

        if 'cc' in target_email:
            email_details[KEY_CC] = get_address_list(target_email, 'cc')
            for address in email_details[KEY_CC]:
                add_email_address_observable(analysis, F_EMAIL_CC, address, conversation_source=mail_from)

        # the rest of these details are for the generate logging output
        # (there may be a limit configured for the maximum number of observables)

        # extract CC and BCC recipients (use get_address_list so display names
        # containing commas, e.g. `"Doe, John" <a@x>`, don't get mis-split)
        cc = get_address_list(target_email, 'cc') if 'cc' in target_email else []
        bcc = get_address_list(target_email, 'bcc') if 'bcc' in target_email else []

        path = []
        for header in target_email.get_all('received', []):
            m = _PATTERN_RECEIVED_IPADDR.match(decode_rfc2822(header))
            if not m:
                continue

            path_item = m.group(1)
            path.append(path_item)

        user_agent = None
        if 'user-agent' in target_email:
            user_agent = decode_rfc2822(target_email['user-agent'])
            email_details[KEY_USER_AGENT] = user_agent
            analysis.add_observable_by_spec(F_USER_AGENT, user_agent)

        x_mailer = None
        if 'x-mailer' in target_email:
            x_mailer = decode_rfc2822(target_email['x-mailer'])
            email_details[KEY_X_MAILER] = x_mailer
            analysis.add_observable_by_spec(F_EMAIL_X_MAILER, x_mailer)

        # sender IP address (office365)
        if 'x-originating-ip' in target_email:
            value = normalize_ip_header_value(decode_rfc2822(target_email['x-originating-ip']))
            if value:
                email_details[KEY_ORIGINATING_IP] = value
                ip = analysis.add_observable_by_spec(F_IP, value, o_time=received_time)
                if ip:
                    ip.display_type = "Originating IP"

        if 'x-sender-ip' in target_email:
            value = normalize_ip_header_value(decode_rfc2822(target_email['x-sender-ip']))
            if value:
                email_details[KEY_X_SENDER_IP] = value
                ip = analysis.add_observable_by_spec(F_IP, value, o_time=received_time)
                if ip:
                    ip.display_type = "Sender IP"

        # who handed this message to us from outside the perimeter?
        first_hop_ip, first_hop_helo, first_hop_from = resolve_first_hop(
            target_email, self.config.provider_headers.first_hop_ip)

        if first_hop_ip:
            email_details[KEY_FIRST_HOP_IP] = first_hop_ip
            analysis.add_observable_by_spec(F_EMAIL_FIRST_HOP_IP, first_hop_ip, o_time=received_time)

        if first_hop_helo:
            email_details[KEY_FIRST_HOP_HELO] = first_hop_helo
            analysis.add_observable_by_spec(F_EMAIL_FIRST_HOP_HELO, first_hop_helo, o_time=received_time)

        if first_hop_from:
            email_details[KEY_FIRST_HOP_FROM] = first_hop_from
            analysis.add_observable_by_spec(F_EMAIL_FIRST_HOP_FROM, first_hop_from, o_time=received_time)

        dkim_signing_domains = get_dkim_signing_domains(target_email)
        if dkim_signing_domains:
            email_details[KEY_DKIM_SIGNING_DOMAINS] = dkim_signing_domains
            for domain in dkim_signing_domains:
                analysis.add_observable_by_spec(F_EMAIL_DKIM_SIGNING_DOMAIN, domain, o_time=received_time)

        sender_tenant_id = get_sender_tenant_id(
            target_email, self.config.provider_headers.sender_tenant_id)
        if sender_tenant_id:
            email_details[KEY_SENDER_TENANT_ID] = sender_tenant_id
            analysis.add_observable_by_spec(F_EMAIL_SENDER_TENANT_ID, sender_tenant_id, o_time=received_time)

        # message authentication verdicts + provider provenance flags. These are message-level
        # verdicts, not observables — we store them in the details and drive tags/detections.
        auth = parse_email_authentication(target_email, self.config.provider_headers)
        email_details.update(auth)

        authentication_failed = (
            auth[KEY_COMPAUTH_RESULT] == 'fail' or auth[KEY_DMARC_RESULT] == 'fail')
        if authentication_failed:
            _file.add_tag(TAG_AUTHENTICATION_FAILED)
        if auth[KEY_IS_ANONYMOUS_DIRECT_SEND]:
            _file.add_tag(TAG_ANONYMOUS_DIRECT_SEND)

        # a message that forges one of our own domains in From, that the provider's
        # authentication rejected, arriving inbound (not our own outbound) is a confirmed
        # internal spoof. Anonymous direct send is one common vector but is not required.
        if (mail_from and is_local_email_domain(mail_from)
                and authentication_failed
                and not _file.has_tag(TAG_OUTBOUND_EMAIL)):
            _file.add_tag(TAG_SPOOFED_INTERNAL)
            _file.add_detection_point(
                f"Inbound email forges managed From domain ({mail_from}) and failed "
                f"authentication (compauth={auth[KEY_COMPAUTH_RESULT]}, dmarc={auth[KEY_DMARC_RESULT]})")

        # is the subject rfc2822 encoded?
        if KEY_SUBJECT in email_details:
            email_details[KEY_DECODED_SUBJECT] = decode_rfc2822(email_details[KEY_SUBJECT])
            if email_details[KEY_DECODED_SUBJECT]:
                decoded_subject_observable = analysis.add_observable_by_spec(F_EMAIL_SUBJECT, email_details[KEY_DECODED_SUBJECT])
                if decoded_subject_observable:
                    decoded_subject_observable.display_type = "Decoded Subject"

        # get the first and last received header values
        # NOTE: do NOT reassign `path` here — the IP path list built earlier
        # from received-from headers is what feeds log_entry['path'].
        last_received = None
        first_received = None
        for header, value in email_details[KEY_HEADERS]:
            if header.lower().startswith('received'):
                if not last_received:
                    last_received = value
                first_received = value

        # START ATTACHMENT PARSING

        # we use this later when we write the log message
        attachments = [] # of ( size, type, name, sha256 )

        def __recursive_parser(target):
            nonlocal target_message_id

            # if this attachment is an email and it's not the target email
            # OR this attachment is not a multipart attachment (is a single file)
            # THEN we want to extract it as a another file for analysis

            # is this another email or a single file attachment?
            if target.get_content_type() == 'message/rfc822' or not target.is_multipart():

                file_name = None

                # for unnamed inline parts derive a real extension from the
                # part's *declared* content type
                unknown_ext = mimetypes.guess_extension(target.get_content_type()) or ''

                # do not extract the target email
                if target.get_content_type() == 'message/rfc822':
                    # the actual message-id will be in one of the payloads of the email
                    for payload in target.get_payload():
                        if 'message-id' in payload and decode_rfc2822(payload['message-id']).strip() == target_message_id:
                            # Even though we skip extracting the target email as a file,
                            # we still need to recursively process its payload to extract
                            # any embedded files (e.g., PDF in the body)
                            _recursive_parser(payload)
                            return

                    # if we are going to extract it then we name it here
                    file_name = '{}.email.rfc822'.format(_file.file_path)

                # extract it
                if not file_name:
                    file_name = target.get_filename()

                if file_name:
                    # decode_header returns a list of (bytes_or_str, charset) chunks for
                    # RFC2047 encoded-word headers; make_header concatenates and decodes
                    # them all so multi-chunk filenames aren't truncated to the first piece.
                    try:
                        file_name = str(email.header.make_header(email.header.decode_header(file_name)))
                    except (LookupError, UnicodeDecodeError) as e:
                        logging.warning(f"unable to fully decode attachment filename {file_name!r}: {e}")

                    file_name = re.sub(r'[\r\n]', '', file_name)

                else:
                    file_name = '{}.unknown_{}_{}_000{}'.format(_file.file_path, target.get_content_maintype(),
                                                                           target.get_content_subtype(), unknown_ext)

                # sanitize the file name
                sanitized_file_name = re.sub(r'_+', '_', re.sub(r'\.\.', '_', re.sub(r'/', '_', file_name)))
                if file_name != sanitized_file_name:
                    logging.debug("changed file name from {} to {}".format(file_name, sanitized_file_name))
                    file_name = sanitized_file_name

                if not file_name:
                    file_name = '{}.unknown_{}_{}_000{}'.format(_file.file_path, target.get_content_maintype(),
                                                                           target.get_content_subtype(), unknown_ext)

                # make sure the file name isn't too long
                if len(file_name) > 120:
                    logging.debug("file name {} is too long".format(file_name))
                    _file_name, _file_ext = os.path.splitext(file_name)
                    # this can be wrong too
                    if len(_file_ext) > 40:
                        _file_ext = '.unknown'
                    file_name = '{}{}'.format(file_name[:120], _file_ext)

                # make sure it's unique
                file_path = self.get_root().create_file_path(file_name)
                while True:
                    if not os.path.exists(file_path):
                        break

                    _file_name, _file_ext = os.path.splitext(os.path.basename(file_path))
                    m = re.match('(.+)_([0-9]{3})$', _file_name)
                    if m:
                        _file_name = m.group(1)
                        index = int(m.group(2)) + 1
                    else:
                        index = 0

                    _file_name = '{}_{:03}'.format(_file_name, index)
                    file_path = '{}{}'.format(_file_name, _file_ext)
                    file_path = self.get_root().create_file_path(file_path)

                # figure out what the payload should be
                if target.get_content_type() == 'message/rfc822':
                    inner = target.get_payload()
                    if isinstance(inner, list) and inner:
                        payload = inner[0].as_bytes()
                    elif isinstance(inner, email.message.Message):
                        payload = inner.as_bytes()
                    else:
                        # nothing usable inside the rfc822 part; skip extraction
                        logging.debug(f"message/rfc822 part in {_file} has no extractable payload")
                        return
                elif target.is_multipart():
                    # in the case of email attachments we need the whole things (including headers)
                    payload = target.as_bytes()
                else:
                    # otherwise we just need the decoded contents as bytes
                    payload = target.get_payload(decode=True)

                with open(file_path, 'wb') as fp:
                    fp.write(payload)

                logging.debug("extracted {} from {}".format(file_path, _file))

                extracted_file = analysis.add_file_observable(file_path)

                if extracted_file:
                    extracted_file.add_directive(DIRECTIVE_EXTRACT_URLS)
                    extracted_file.add_yara_meta("type", "email.attachment")

                    # get_content_type() returns the text/plain default when the
                    # header is missing OR unparseable, and those two cases are not
                    # equivalent. Missing is legitimate: RFC 2045 says a part with
                    # no Content-Type IS text/plain. Malformed is not -- a sender
                    # writing "Content-Type: text" (no subtype) gets it silently
                    # normalized to text/plain and takes the preview branch, which
                    # suppresses the render. That is attacker-controlled input
                    # deciding whether we analyze the part, and it fails toward not
                    # analyzing, so only trust the default when the header is
                    # genuinely absent or the raw type really is text/plain.
                    declared_content_type = target.get('Content-Type')
                    if declared_content_type is None:
                        declared_plain_text = True
                    else:
                        raw_type = str(declared_content_type).split(';', 1)[0].strip().lower()
                        declared_plain_text = (
                            target.get_content_type() == 'text/plain'
                            and raw_type == 'text/plain'
                        )

                    if declared_plain_text:
                        extracted_file.add_directive(DIRECTIVE_PREVIEW)
                    else:
                        extracted_file.add_directive(DIRECTIVE_RENDER)

                # tracking attachments for logging purposes
                # always store a path relative to the files dir; when the file observable could not be
                # added (per-type limit reached) file_path is a full path, so make it relative here
                attachment_rel_path = (extracted_file.file_path if extracted_file
                                       else os.path.relpath(file_path, self.get_root().file_dir))
                attachments.append((len(payload), target.get_content_type(),
                                    attachment_rel_path,
                                    hashlib.sha256(payload).hexdigest()))

                # If this was a message/rfc822, recursively process its payload
                # to extract any embedded files (e.g., PDF attachments in the inner email body)
                if target.get_content_type() == 'message/rfc822':
                    inner_payload = target.get_payload()
                    if inner_payload:
                        for inner_part in inner_payload:
                            _recursive_parser(inner_part)

            # otherwise, if it's a multi-part then we want to recurse into it
            elif target.is_multipart():
                for part in target.get_payload():
                    _recursive_parser(part)

            else:
                raise RuntimeError("parsing logic error: {}".format(_file))

        def _recursive_parser(target, *args, **kwargs):
            try:
                return __recursive_parser(target, *args, **kwargs)
            except Exception as e:
                logging.error("recursive parsing failed on %s (part content-type=%s): %s",
                              _file, target.get_content_type() if target is not None else None, e,
                              exc_info=True)
                report_exception()

                # record the failure on the analysis so the analyst can see that
                # part of the email was not fully extracted
                analysis.details[KEY_EXTRACTION_ERRORS].append({
                    'content_type': target.get_content_type() if target is not None else None,
                    'filename': target.get_filename() if target is not None else None,
                    'exception': '{}: {}'.format(type(e).__name__, e),
                })
                _file.add_tag(TAG_EMAIL_PARSE_INCOMPLETE)

                target_path = os.path.join(get_data_dir(), 'review', 'rfc822', '{}.{}'.format(
                                           _file.file_path, datetime.now().strftime('%Y%m%d%H%M%S')))
                shutil.copy(_file.full_path, target_path)

        _recursive_parser(target_email)

        # END ATTACHMENT PARSING

        # generate data suitable for logging
        log_entry = {
            'date': get_local_timezone().localize(datetime.now()).strftime('%Y-%m-%d %H:%M:%S.%f %z'),
            'first_received': first_received,
            'last_received': last_received,
            'env_mail_from': email_details[KEY_ENV_MAIL_FROM] if KEY_ENV_MAIL_FROM in email_details else None,
            'env_rcpt_to': email_details[KEY_ENV_RCPT_TO] if KEY_ENV_RCPT_TO in email_details else [],
            'mail_from': email_details[KEY_FROM] if KEY_FROM in email_details else None,
            'mail_to': email_details[KEY_TO] if KEY_TO in email_details else [],
            'reply_to': email_details[KEY_REPLY_TO] if KEY_REPLY_TO in email_details else None,
            'cc': cc,
            'bcc': bcc,
            'message_id': email_details[KEY_MESSAGE_ID] if KEY_MESSAGE_ID in email_details else None,
            'in_reply_to': decode_rfc2822(target_email['in-reply-to']) if 'in-reply-to' in target_email else None,
            'subject': email_details.get(KEY_DECODED_SUBJECT) or email_details.get(KEY_SUBJECT),
            'subject_raw': email_details[KEY_SUBJECT] if KEY_SUBJECT in email_details else None,
            'path': path,
            'size': _file.size,
            'user_agent': user_agent,
            'x_mailer': x_mailer,
            'originating_ip': email_details[KEY_ORIGINATING_IP] if KEY_ORIGINATING_IP in email_details else None,
            'headers': ['{}: {}'.format(h[0], re.sub('[\t\n]', '', h[1])) for h in email_details[KEY_HEADERS] if not h[0].lower().startswith('x-ms-exchange-')] if KEY_HEADERS in email_details else None,
            'attachment_count': len(attachments),
            'attachment_sizes': [a[0] for a in attachments],
            'attachment_types': [a[1] for a in attachments],
            'attachment_names': [a[2] for a in attachments],
            'attachment_hashes': [a[3] for a in attachments],
            'thread_topic': decode_rfc2822(target_email['thread-topic']) if 'thread-topic' in target_email else None,
            'thread_index': decode_rfc2822(target_email['thread-index']) if 'thread-index' in target_email else None,
            'refereneces': decode_rfc2822(target_email['references']) if 'references' in target_email else None,
            'x_sender': decode_rfc2822(target_email['x-sender']) if 'x-sender' in target_email else None,
        }

        email_details[KEY_LOG_ENTRY] = log_entry
        analysis.email = email_details

        # create a file with just the header information and scan that separately
        headers_path = None
        if KEY_HEADERS in email_details:
            rel_path = _file.file_path
            shortened_basename = shorten_basename_for_suffix(os.path.basename(rel_path), '.headers')
            headers_path = self.get_root().create_file_path(os.path.join(os.path.dirname(rel_path), shortened_basename))
            if os.path.exists(headers_path):
                logging.debug("headers file {} already exists".format(headers_path))
            else:
                with open(headers_path, 'w') as fp:
                    fp.write('\n'.join(['{}: {}'.format(h[0], h[1]) for h in email_details[KEY_HEADERS]]))

                headers_file = analysis.add_file_observable(headers_path)

                # we don't want to analyze this with the email analyzer
                if headers_file:
                    headers_file.exclude_analysis(self)
                    headers_file.add_yara_meta("type", "email.headers")

        # combine the header and the decoded parts of the email into a single buffer for scanning with yara
        # we only combine the un-named html and text parts, not additional attachements
        if headers_path:
            rel_path = _file.file_path
            shortened_basename = shorten_basename_for_suffix(os.path.basename(rel_path), '.combined')
            combined_path = self.get_root().create_file_path(os.path.join(os.path.dirname(rel_path), shortened_basename))
            if os.path.exists(combined_path):
                logging.debug(f"combined path {combined_path} already exists")
            else:
                # copy the headers over first
                shutil.copy(headers_path, combined_path)
                with open(combined_path, 'ab') as fp:
                    fp.write(b'\n\n')

                    # copy each attachment in the order it was seen in the email if it has 'unknown_' in the name
                    for _size, _content_type, attachment_file_path, _sha256 in attachments:
                        if 'unknown_' in attachment_file_path:
                            attachment_path = self.get_root().create_file_path(attachment_file_path)
                            try:
                                with open(attachment_path, 'rb') as fp_in:
                                    shutil.copyfileobj(fp_in, fp)

                                fp.write(b'\n\n')

                            except Exception as e:
                                logging.error(f"unable to copy {attachment_path} to {combined_path}: {e}")
                                report_exception()

                    combined_file = analysis.add_file_observable(combined_path)

                    # we don't want to analyze this with the email analyzer
                    if combined_file:
                        combined_file.exclude_analysis(self)
                        combined_file.add_yara_meta("type", "email.combined")

        # are we renaming the root analysis?
        if _file.has_directive(DIRECTIVE_RENAME_ANALYSIS):
            if KEY_SUBJECT in email_details and email_details[KEY_SUBJECT]:
                self.get_root().description += ' - ' + email_details[KEY_SUBJECT]

        mail_rcpt_to = log_entry['env_rcpt_to'] if log_entry['env_rcpt_to'] else log_entry['mail_to']
        logging.info("scanning email [{}] {} from {} to {} subject {}".format(
                     self.get_root().uuid,
                     log_entry['message_id'], log_entry['mail_from'], mail_rcpt_to,
                     log_entry['subject']))

        return True

    def analyze_missing_stream(self, _file):
        """Analyzes the output of bro failing to capture the stream data but still extracted protocol meta and files."""
        assert isinstance(_file, FileObservable)

        from saq.modules.email.stream import pattern_brotex_connection

        file_path = _file.full_path
        extracted_dir = '{}.extracted'.format(file_path)
        if not os.path.isdir(extracted_dir):
            try:
                os.mkdir(extracted_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(extracted_dir, e))
                return False

        analysis = self.create_analysis(_file)

        # extract all the things into the brotex_dir
        p = Popen(['tar', 'xf', file_path, '-C', extracted_dir], 
                  stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()
        p.wait()

        if p.returncode:
                logging.warning("unable to extract files from {} (tar returned error code {}".format(
                                _file, p.returncode))
                return False

        if stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, stderr))

        # iterate over all the extracted files
        # map message numbers to the connection file
        connection_files = {} # key = message_number, value = path to connection file
        for dirpath, dirnames, filenames in os.walk(extracted_dir):
            for file_name in filenames:
                m = pattern_brotex_connection.match(file_name)
                if m:
                    # keep track of the largest trans_depth
                    trans_depth = m.group(1)
                    connection_files[trans_depth] = os.path.join(dirpath, file_name)

                full_path = os.path.join(dirpath, file_name)
                # go ahead and add every file to be scanned
                _file = analysis.add_file_observable(full_path)
                if _file:
                    _file.add_directive(DIRECTIVE_EXTRACT_URLS)

        def _parse_bro_mv(value):
            """Parse bro multivalue field."""
            # interpreting what I see here...
            if not value.startswith('{^J^I') and value.endswith('^J}'):
                return [ value ]

            return value[len('{^J^I]')-1:-len('^J}')].split(',^J^I')

        # parse each message
        for message_number in connection_files.keys():
            details = { }

            # parse the connection file
            logging.debug("parsing bro connection file {}".format(connection_files[message_number]))
            with open(connection_files[message_number], 'r') as fp:
                # these files are generated by the brotex.bro script in the brotex git repo
                # they are stored in the following order
                uid = fp.readline().split(' = ', 1)[1].strip()
                mailfrom = fp.readline().split(' = ', 1)[1].strip()
                rcptto = fp.readline().split(' = ', 1)[1].strip()
                from_ = fp.readline().split(' = ', 1)[1].strip()
                to_ = fp.readline().split(' = ', 1)[1].strip()
                reply_to = fp.readline().split(' = ', 1)[1].strip()
                in_reply_to = fp.readline().split(' = ', 1)[1].strip()
                msg_id = fp.readline().split(' = ', 1)[1].strip()
                subject= fp.readline().split(' = ', 1)[1].strip()
                x_originating_ip = fp.readline().split(' = ', 1)[1].strip()

            # some of these fields are multi value fields
            rcptto = _parse_bro_mv(rcptto)
            to_ = _parse_bro_mv(to_)

            details[KEY_ENV_MAIL_FROM] = mailfrom
            details[KEY_ENV_RCPT_TO] = rcptto
            details[KEY_FROM] = from_
            details[KEY_TO] = to_
            details[KEY_SUBJECT] = subject
            details[KEY_REPLY_TO] = reply_to
            #details[KEY_IN_REPLY_TO] = in_reply_to
            details[KEY_MESSAGE_ID] = msg_id
            details[KEY_ORIGINATING_IP] = x_originating_ip

            analysis.email = details

            # add the appropriate observables
            mailfrom_n = None
            if mailfrom:
                mailfrom_n = normalize_email_address(mailfrom)
                if mailfrom_n:
                    add_email_address_observable(analysis, F_EMAIL_ENVELOPE_MAIL_FROM, mailfrom_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, mailfrom_n):
                        _file.whitelist()

            for address in rcptto:
                if address:
                    address_n = normalize_email_address(address)
                    if address_n:
                        add_email_address_observable(analysis, F_EMAIL_ENVELOPE_RCPT_TO, address_n)
                        # whitelist-by-recipient must run regardless of whether MAIL FROM is known
                        if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address_n):
                            _file.whitelist()
                        if mailfrom_n:
                            analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(mailfrom,
                                                    address_n))

            from_n = None
            if from_:
                from_n = normalize_email_address(from_)
                if from_n:
                    add_email_address_observable(analysis, F_EMAIL_FROM, from_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, from_n):
                        _file.whitelist()

            for address in to_:
                address_n = normalize_email_address(address)
                if address_n:
                    add_email_address_observable(analysis, F_EMAIL_TO, address_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address_n):
                        _file.whitelist()

                    if from_n:
                        analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(
                                                from_n,
                                                address_n))

            if x_originating_ip:
                analysis.add_observable_by_spec(F_IP, x_originating_ip)

        return True


    def execute_analysis(self, _file) -> AnalysisExecutionResult:

        from saq.modules.email.stream import pattern_brotex_missing_stream_package
        from saq.modules.file_analysis import FileTypeAnalysis

        # is this a "missing stream archive" that gets generated by the BrotexSMTPPackageAnalyzer module?
        if pattern_brotex_missing_stream_package.match(os.path.basename(_file.file_name)):
            self.analyze_missing_stream(_file)
            return AnalysisExecutionResult.COMPLETED

        # is this an RFC 822 email?
        file_type_analysis = _file.get_and_load_analysis(FileTypeAnalysis)
        if not file_type_analysis or not file_type_analysis.file_type:
            logging.debug("missing file type analysis for {}:".format(_file))
            return AnalysisExecutionResult.COMPLETED

        is_email = 'RFC 822 mail' in file_type_analysis.file_type
        is_email |= 'message/rfc822' in file_type_analysis.file_type
        is_email |= 'message/rfc822' in file_type_analysis.mime_type
        is_email |= _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL)
        if file_type_analysis is not None:
            is_email |= file_type_analysis.is_email_file

        if not is_email:
            logging.debug("unsupported file type for email analysis: {} {}".format(
                          file_type_analysis.file_type,
                          file_type_analysis.mime_type))
            return AnalysisExecutionResult.COMPLETED

        self.analyze_rfc822(_file)
        return AnalysisExecutionResult.COMPLETED

class EmailAnalysisPresenter(AnalysisPresenter):
    """Presenter for EmailAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/email_analysis.html"

register_analysis_presenter(EmailAnalysis, EmailAnalysisPresenter)