"""The search query language: `tag:phish`, `ip:1.2.3.4`, `observable:url:https://evil.com`.

A query is a mix of *field terms* and free text. A literal is only looked up when it is named
by a field term; everything else is free text for the semantic lanes.

    tag:phish                        the tag
    ipv4:10.20.30.40                 an observable, by type shorthand
    signature_id:6f3a…               ditto -- any registered observable type works
    observable:url:https://evil.com  the explicit form, for values containing colons
    uuid:1f2e3d4c-…                  an alert uuid (a prefix of one also works)
    queue:default                    a narrowing filter
    detection_point:<sig uuid>[:<v>] alerts with a detection point from that signature (version)
    disposition:DELIVERY,IGNORE      one term, values ORed
    alert_date:-7d                   a relative window
    -tag:whitelisted                 inverted (! works too)
    tag:"vendor mailer"              quoted, for a value with a space or comma
    docusign invoice                 free text -- the semantic lanes, and nothing else

The field names are the permanent URL slugs from `saq/gui/filter_names.py` plus every
registered observable type, so the search box, a share link and the API all name a filter the
same way. A prefix that resolves to neither is NOT a field term and the token stays free text
verbatim -- which is what keeps `https://evil.com` and `C:\\windows\\system32` out of the
parser.

Two deliberate differences from `saq/gui/filter_url.py`, which encodes the same filters into a
URL:

  * values here are LITERAL. A share link is machine-generated and percent-encodes `:`, `,`
    and `%`; a search box is typed by hand and must not demand that. Spaces and commas inside a
    value are expressed by quoting instead.
  * `uuid:` means the ALERT uuid. `uuid` is also a registered observable type, so that
    observable has to be written `observable:uuid:<value>`.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import pytz

from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    resolve_observable_identity,
)
from saq.gui.detection_point_value import normalize_detection_point_value
from saq.gui.filter_names import DATE_RANGE_FILTER_NAMES, FILTER_NAMES_BY_SLUG
from saq.observables.type_hierarchy import get_all_valid_types
from saq.util.relative_time import RelativeTimeError, parse_date_range

# canonical field names that produce exact lookups rather than narrowing filters
FIELD_OBSERVABLE = "observable"
FIELD_TAG = "tag"
FIELD_ALERT_UUID = "uuid"

EXACT_FIELDS = frozenset([FIELD_OBSERVABLE, FIELD_TAG, FIELD_ALERT_UUID])

# a term is `[-!]name:value`; the name is deliberately narrow so a url scheme or a drive letter
# followed by a path never looks like one
TERM_RE = re.compile(r"^(?P<invert>[-!])?(?P<name>[A-Za-z0-9_]+):(?P<value>.+)$", re.DOTALL)

UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.IGNORECASE)
UUID_PREFIX_RE = re.compile(r"^[a-f0-9]{8}(-[a-f0-9]{0,4}){0,4}$", re.IGNORECASE)

# Shapes that look like an identifier when pasted bare. Used only to offer
# "did you mean ipv4:...?" -- never to match anything.
IDENTIFIER_HINT_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}"
    r"|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}"
    r"|[^@\s]+@[^@\s]+\.[a-z]{2,}"
    r"|[a-z][a-z0-9+.-]*://\S+)$",
    re.IGNORECASE,
)

# Bounds on how much SQL one query may generate. A term is an analyst's explicit instruction,
# so hitting these means a pasted list.
MAX_TERMS = 32
MAX_VALUES_PER_TERM = 64

_QUOTE_PLACEHOLDER_RE = re.compile("\x00(\\d+)\x00")


@dataclass(frozen=True)
class FieldTerm:
    """One resolved `field:value` term."""

    field: str                      # a canonical slug, or observable/tag/uuid
    values: tuple                   # str values, or (type, value) pairs when field is observable
    inverted: bool = False


@dataclass(frozen=True)
class ParsedQuery:
    """What a query string means, split by where each part has to be applied."""

    # the free-text remainder, for the dense and sparse lanes. Empty means DO NOT run them:
    # an embedding of "" still has a nearest neighbour and would pull in unrelated alerts.
    text: str = ""
    # non-inverted observable/tag/uuid terms -- the exact lane
    exact: tuple[FieldTerm, ...] = ()
    # everything else, in the canonical [{"name", "inverted", "values"}] filter-list shape
    filters: tuple = ()
    # human-readable problems. A term that cannot be honored is reported, never dropped: a
    # dropped filter silently WIDENS the result set.
    errors: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (self.text or self.exact or self.filters)

    def hint(self) -> Optional[str]:
        """A "did you mean" line when the query is a bare indicator with no field term.

        A bare ip or hash is free text, so it never runs an exact lookup. The hint names the
        field-term form that would.
        """
        if self.exact or not self.text:
            return None

        for token in self.text.split():
            if IDENTIFIER_HINT_RE.match(token):
                return (f"No exact match was searched for. To find every alert containing "
                        f"{token!r}, use an observable type, e.g. ipv4:{token} or "
                        f"observable:<type>:{token}.")

        return None


def mask_quoted(query: str) -> tuple[str, list[str]]:
    """Replaces every "..." span with a \\x00<n>\\x00 placeholder.

    The placeholder contains no whitespace, colon or comma, so it survives tokenizing, the
    field/value split and the comma split intact -- which is what makes `tag:"a, b"` one value
    rather than two. Raises ValueError on an unterminated quote rather than guessing where the
    value was meant to end.
    """
    parts: list[str] = []
    values: list[str] = []
    index = 0
    while True:
        start = query.find('"', index)
        if start == -1:
            parts.append(query[index:])
            break

        end = query.find('"', start + 1)
        if end == -1:
            raise ValueError("unterminated quote in query")

        parts.append(query[index:start])
        parts.append(f"\x00{len(values)}\x00")
        values.append(query[start + 1:end])
        index = end + 1

    return "".join(parts), values


def unmask(text: str, quoted: list[str]) -> str:
    """Puts the quoted spans back, without their quotes."""
    return _QUOTE_PLACEHOLDER_RE.sub(lambda m: quoted[int(m.group(1))], text)


def resolve_field(name: str) -> Optional[str]:
    """The canonical field a prefix names, or None when it names none.

    Resolution order matters. `uuid` wins over the observable type of the same name (see the
    module docstring); a filter slug wins over an observable type so that the slugs stay the
    one permanent vocabulary; anything else is an observable type shorthand.
    """
    lowered = name.casefold()
    if lowered == FIELD_ALERT_UUID:
        return FIELD_ALERT_UUID

    if lowered in FILTER_NAMES_BY_SLUG:
        return lowered

    if lowered in {observable_type.casefold() for observable_type in get_all_valid_types()}:
        return lowered

    return None


def _is_observable_type(name: str) -> bool:
    lowered = name.casefold()
    return lowered not in FILTER_NAMES_BY_SLUG and lowered != FIELD_ALERT_UUID


def _split_values(raw: str, quoted: list[str]) -> list[str]:
    return [unmask(value, quoted) for value in raw.split(",")]


def _parse_term(token: str, quoted: list[str], errors: list[str]) -> tuple[bool, Optional[FieldTerm]]:
    """Parses one token.

    Returns (is_field_term, term). `(False, None)` means the token is ordinary free text.
    `(True, None)` means it WAS a field term but every value in it was rejected -- the caller
    must not fall back to treating it as free text, because an error has already been recorded
    and searching for the literal text `ipv4:not-an-ip` would be nonsense.
    """
    match = TERM_RE.match(token)
    if not match:
        return False, None

    field = resolve_field(match.group("name"))
    if field is None:
        return False, None

    inverted = match.group("invert") is not None
    raw_value = match.group("value")

    if field == FIELD_ALERT_UUID:
        if inverted:
            errors.append("uuid: cannot be inverted (there is no 'not this alert' filter)")
            return True, None
        return True, _uuid_term(_split_values(raw_value, quoted), errors)

    if field == FIELD_OBSERVABLE:
        # the explicit form carries the type in the value: observable:<type>:<value>. Split at
        # the FIRST colon only -- url and email_address values contain colons constantly.
        pairs = []
        for value in _split_values(raw_value, quoted):
            observable_type, separator, observable_value = value.partition(":")
            if not separator or not observable_value:
                errors.append(f"observable:{value!r} must be written observable:<type>:<value>")
                continue
            pairs.append((observable_type, observable_value))

        return True, _observable_term(pairs, inverted, errors)

    if _is_observable_type(field):
        return True, _observable_term(
            [(field, value) for value in _split_values(raw_value, quoted)], inverted, errors)

    return True, _filter_term(field, _split_values(raw_value, quoted), inverted, errors)


def _uuid_term(values: list[str], errors: list[str]) -> Optional[FieldTerm]:
    resolved = []
    for value in values:
        lowered = value.strip().casefold()
        if UUID_RE.match(lowered) or (UUID_PREFIX_RE.match(lowered) and len(lowered) >= 8):
            resolved.append(lowered)
        else:
            errors.append(f"uuid:{value!r} is not an alert uuid or a uuid prefix")

    return FieldTerm(FIELD_ALERT_UUID, tuple(resolved)) if resolved else None


def _observable_term(pairs: list, inverted: bool, errors: list[str]) -> Optional[FieldTerm]:
    resolved = []
    for observable_type, observable_value in pairs:
        try:
            # normalize through the real observable class, exactly as the engine did when it
            # indexed the observable -- an un-normalized value silently matches nothing
            identity = resolve_observable_identity(observable_type, observable_value)
        except InvalidDetectionValue as e:
            errors.append(f"{observable_type}:{observable_value!r} is not a valid {observable_type}: {e}")
            continue

        resolved.append((identity.type, identity.value))

    return FieldTerm(FIELD_OBSERVABLE, tuple(resolved), inverted) if resolved else None


def _filter_term(field: str, values: list[str], inverted: bool, errors: list[str]) -> Optional[FieldTerm]:
    name = FILTER_NAMES_BY_SLUG[field]
    if name == "Detection Point":
        kept = []
        for value in values:
            try:
                kept.append(normalize_detection_point_value(value))
            except ValueError as e:
                errors.append(f"{field}:{value!r} is not a detection point: {e}")

        values = kept

    elif name in DATE_RANGE_FILTER_NAMES:
        now = datetime.now(pytz.utc)
        kept = []
        for value in values:
            try:
                parse_date_range(value, now=now, tz=pytz.utc)
            except RelativeTimeError as e:
                errors.append(f"{field}:{value!r} is not a time window: {e}")
                continue
            kept.append(value)

        values = kept

    return FieldTerm(field, tuple(values), inverted) if values else None


def _add_filter_entry(filters: list, entry: dict) -> None:
    """Appends a filter entry, merging it into one that already names the same filter.

    Entries are ANDed by the query builder, so `queue:a queue:b` as two entries would ask a
    single alert to be in two queues and match nothing at all. Repeating a field means "either"
    -- the same rule resolve_saved_filter() applies to a stored filter list.
    """
    for existing in filters:
        if existing["name"] == entry["name"] and existing["inverted"] == entry["inverted"]:
            existing["values"].extend(v for v in entry["values"] if v not in existing["values"])
            return

    filters.append(entry)


def _to_filter_entry(term: FieldTerm) -> dict:
    """A FieldTerm in the canonical filter-list shape the filter query builder consumes.

    `uuid` deliberately has no entry in FILTER_SLUGS -- there is no "not this alert" filter --
    so it must never reach here. _parse_term rejects an inverted `uuid:` outright, which is the
    only way one could.
    """
    values = [list(value) for value in term.values] if term.field == FIELD_OBSERVABLE else list(term.values)
    return {
        "name": FILTER_NAMES_BY_SLUG[term.field],
        "inverted": term.inverted,
        "values": values,
    }


def parse_search_query(query: str) -> ParsedQuery:
    """Splits a query into its field terms and its free text."""
    query = (query or "").strip()
    if not query:
        return ParsedQuery()

    errors: list[str] = []
    try:
        masked, quoted = mask_quoted(query)
    except ValueError as e:
        return ParsedQuery(errors=(str(e),))

    exact: list[FieldTerm] = []
    filters: list[dict] = []
    free_text: list[str] = []

    for token in masked.split():
        is_field, term = _parse_term(token, quoted, errors)
        if not is_field:
            free_text.append(unmask(token, quoted))
            continue

        if term is None:
            continue

        if len(term.values) > MAX_VALUES_PER_TERM:
            errors.append(f"{term.field}: has more than {MAX_VALUES_PER_TERM} values")
            term = FieldTerm(term.field, term.values[:MAX_VALUES_PER_TERM], term.inverted)

        # Inversion means "alerts WITHOUT this", which is a narrowing filter, not a lookup --
        # there is nothing for the exact lane to return a hit for. A wildcard tag is the same:
        # the lexical lane matches tag names exactly, so `tag:phish*` has to go through SQL.
        wildcard_tag = term.field == FIELD_TAG and any("*" in value for value in term.values)
        if term.field in EXACT_FIELDS and not term.inverted and not wildcard_tag:
            exact.append(term)
        else:
            _add_filter_entry(filters, _to_filter_entry(term))

        if len(exact) + len(filters) > MAX_TERMS:
            errors.append(f"too many field terms (at most {MAX_TERMS}); the rest were ignored")
            break

    return ParsedQuery(
        text=" ".join(free_text).strip(),
        exact=tuple(exact),
        filters=tuple(filters),
        errors=tuple(errors),
    )
