"""The SVS test hosts: the hosts test runs may target (docs/SVS_RUNS.md, *Test hosts*).

A launcher registers a run against targets, each a (hostname, username) pair. A target matches a
test host when its host name is the host's short name or fully qualified name, and its user is one
the host lists (or the host lists none). Matching ignores case, and treats `DOMAIN\\user`,
`user@domain` and `user` as the same user [FR-15].

The table is written here only, by an svs:admin through the API. Every write is logged as an AUDIT
line with the host's fields in extra.
"""

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from sqlalchemy.exc import IntegrityError

from saq.database.model import SVSTestHost
from saq.database.pool import get_db
from saq.svs.preconditions import NONE, Precondition, StaleWrite

# the Atomic Red Team names of the platforms a test host can be (a test's supported_platforms
# also names cloud platforms, which are not hosts)
PLATFORMS = ("windows", "linux", "macos")

MAX_USERNAMES = 100
MAX_IPS = 100


class InvalidTestHost(ValueError):
    """A field of a test host can't be used; the message says which and why."""


class DuplicateTestHost(ValueError):
    """Another test host already has this short name."""


class UnknownTestHost(LookupError):
    pass


def split_hostname(value: str) -> tuple[str, Optional[str]]:
    """(short name, fully qualified name or None) of a host name, lower case. Raises
    InvalidTestHost for an empty name or one with whitespace or path characters."""
    name = (value or "").strip().rstrip(".").lower()
    if not name or any(c.isspace() for c in name) or any(c in name for c in "\\/@"):
        raise InvalidTestHost(f"{value!r} is not a host name")

    short, _, domain = name.partition(".")
    if not short or (domain and not all(domain.split("."))):
        raise InvalidTestHost(f"{value!r} is not a host name")

    return short, name if domain else None


def normalize_username(value: str) -> str:
    """The bare user name, lower case: `CORP\\Alice`, `alice@corp.example` and `alice` are all
    `alice`. Raises InvalidTestHost for an empty one."""
    name = (value or "").strip().lower()
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    if not name or any(c.isspace() for c in name):
        raise InvalidTestHost(f"{value!r} is not a user name")
    return name


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise InvalidTestHost(f"{value!r} is not an IP address") from None


@dataclass(frozen=True)
class HostSpec:
    """A test host's fields, normalized and validated (build_spec)."""

    hostname: str
    fqdn: Optional[str] = None
    usernames: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    platform: Optional[str] = None
    notes: Optional[str] = None


def build_spec(hostname: str, *, fqdn: Optional[str] = None, usernames=(), ips=(), platform: Optional[str] = None,
               notes: Optional[str] = None) -> HostSpec:
    """Normalizes and validates a test host. A fully qualified hostname also sets fqdn. Raises
    InvalidTestHost."""
    short, qualified = split_hostname(hostname)
    if fqdn:
        fqdn_short, fqdn_qualified = split_hostname(fqdn)
        if fqdn_qualified is None or fqdn_short != short:
            raise InvalidTestHost(f"fqdn {fqdn!r} is not a fully qualified name of {short!r}")
        if qualified is not None and qualified != fqdn_qualified:
            raise InvalidTestHost(f"hostname {hostname!r} and fqdn {fqdn!r} name different hosts")
        qualified = fqdn_qualified

    usernames = list(usernames or ())
    ips = list(ips or ())
    if len(usernames) > MAX_USERNAMES:
        raise InvalidTestHost(f"at most {MAX_USERNAMES} usernames")
    if len(ips) > MAX_IPS:
        raise InvalidTestHost(f"at most {MAX_IPS} ips")

    if platform is not None:
        platform = platform.strip().lower() or None
    if platform is not None and platform not in PLATFORMS:
        raise InvalidTestHost(f"platform {platform!r} is not one of {', '.join(PLATFORMS)}")

    return HostSpec(
        hostname=short,
        fqdn=qualified,
        usernames=tuple(sorted({normalize_username(name) for name in usernames})),
        ips=tuple(sorted({normalize_ip(ip) for ip in ips}, key=lambda ip: (":" in ip, ip))),
        platform=platform,
        notes=(notes or "").strip() or None,
    )


#
# reading
#

def host_usernames(host: SVSTestHost) -> list[str]:
    return json.loads(host.usernames)


def host_ips(host: SVSTestHost) -> list[str]:
    return json.loads(host.ips)


def get_host(host_id: int, *, lock: bool = False) -> SVSTestHost:
    """The host; with lock, read again and locked until the transaction ends."""
    host = get_db().get(SVSTestHost, host_id, with_for_update=lock, populate_existing=lock)
    if host is None:
        raise UnknownTestHost(f"test host {host_id} not found")
    return host


@dataclass(frozen=True)
class TargetMatch:
    """How a (hostname, username) target matched the test hosts."""

    host: Optional[SVSTestHost] = None
    # the host lists the target's user, or lists none
    user_allowed: bool = False
    # why it didn't match, for the refusal
    reason: Optional[str] = None
    usernames: list[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return self.host is not None and self.user_allowed


def match_target(hostname: str, username: Optional[str] = None) -> TargetMatch:
    """Finds the test host a run target names. Its hostname may be the short or the fully qualified
    name; a fully qualified one must agree with the host's fqdn when the host has one, so a
    production host that shares a short name in another domain never matches. Without a username
    the target matches only a host that lists no users."""
    try:
        short, qualified = split_hostname(hostname)
    except InvalidTestHost:
        return TargetMatch(reason=f"{hostname!r} is not a host name")

    host = get_db().query(SVSTestHost).filter(SVSTestHost.hostname == short).one_or_none()
    if host is None:
        return TargetMatch(reason=f"{short} is not a test host")

    if qualified is not None and host.fqdn is not None and qualified != host.fqdn:
        return TargetMatch(reason=f"{qualified} is not test host {host.fqdn}")

    usernames = host_usernames(host)
    if not usernames:
        return TargetMatch(host=host, user_allowed=True, usernames=usernames)

    if username is None:
        return TargetMatch(host=host, reason=f"test host {host.hostname} lists its users and no user was given",
                           usernames=usernames)

    try:
        user = normalize_username(username)
    except InvalidTestHost:
        return TargetMatch(host=host, reason=f"{username!r} is not a user name", usernames=usernames)

    if user not in usernames:
        return TargetMatch(host=host, reason=f"{user} is not a user of test host {host.hostname}", usernames=usernames)

    return TargetMatch(host=host, user_allowed=True, usernames=usernames)


#
# writing (svs:admin)
#

def _audit_extra(host: SVSTestHost, actor: Optional[str]) -> dict:
    return {"svs_test_host": host.hostname, "fqdn": host.fqdn, "usernames": host_usernames(host),
            "ips": host_ips(host), "platform": host.platform, "actor": actor}


def _apply(host: SVSTestHost, spec: HostSpec) -> None:
    host.hostname = spec.hostname
    host.fqdn = spec.fqdn
    host.usernames = json.dumps(list(spec.usernames))
    host.ips = json.dumps(list(spec.ips))
    host.platform = spec.platform
    host.notes = spec.notes


def _commit(host: SVSTestHost) -> None:
    db = get_db()
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise DuplicateTestHost(f"{host.hostname} is already a test host") from None
    db.refresh(host)


def create_host(spec: HostSpec, user_id: Optional[int], actor: Optional[str] = None) -> SVSTestHost:
    """Adds a test host. Raises DuplicateTestHost when its short name is taken."""
    # created_at is stored to the second and MySQL rounds a fraction up: floored, it is never after
    # the updated_at the server stamps on the same insert
    host = SVSTestHost(created_by=user_id, created_at=datetime.now().replace(microsecond=0))
    _apply(host, spec)
    get_db().add(host)
    _commit(host)
    logging.info("AUDIT: svs test host added", extra=_audit_extra(host, actor))
    return host


def update_host(host_id: int, spec: HostSpec, actor: Optional[str] = None,
                precondition: Precondition = NONE) -> SVSTestHost:
    """Replaces a test host's fields. Raises UnknownTestHost, DuplicateTestHost, StaleWrite."""
    # a write from a form loaded before someone else changed the host is refused, not applied over it
    host = get_host(host_id, lock=precondition.given)
    try:
        precondition.check(host, f"test host {host.hostname}")
    except StaleWrite:
        get_db().rollback()
        raise
    before = _audit_extra(host, actor)
    _apply(host, spec)
    _commit(host)
    logging.info("AUDIT: svs test host changed",
                 extra={**_audit_extra(host, actor), "before": {k: v for k, v in before.items() if k != "actor"}})
    return host


def delete_host(host_id: int, actor: Optional[str] = None) -> None:
    """Removes a test host. Runs keep the targets they were registered with. Raises UnknownTestHost."""
    host = get_host(host_id)
    extra = _audit_extra(host, actor)
    db = get_db()
    db.delete(host)
    db.commit()
    logging.info("AUDIT: svs test host removed", extra=extra)
