"""Encode and decode alert management filters as durable URL query parameters.

A share link carries the filter itself, so it depends on nothing that can be deleted:

    /ace/manage?f=queue:default
               &f=disposition:OPEN,FALSE_POSITIVE
               &f=!tag:whitelisted
               &f=alert_date:-7d
               &f=observable:url:https%3A%2F%2Fevil.com%2Fa%2Cb

One repeated `f` parameter per filter. Separate params are ANDed; commas within one are
ORed. A leading `!` inverts. The slug is split off at the first literal colon.

ESCAPING -- the part that is easy to get wrong. Three characters are structural inside a
value and must be percent-encoded there: ':' -> %3A, ',' -> %2C, '%' -> %25.

Observable values are [type, value] pairs and their type/value colon stays LITERAL, giving
`observable:<type>:<encoded value>`. Encoding that colon instead would be ambiguous the
moment a value contains one, which url and email_address observables do constantly:
`url:https://evil.com` must not parse as a type of "https".
"""

import json
from urllib.parse import quote, unquote

from saq.gui.filter_names import (
    FILTER_NAMES_BY_SLUG,
    FILTER_SLUGS,
    LEGACY_FILTER_NAME_ALIASES,
)

# Everything except the three structural characters survives unescaped. quote() already
# leaves unreserved characters alone; safe="" makes it escape ':' and ',' too, and it
# always escapes '%'.
_VALUE_SAFE = ""

# filters whose values are [type, value] pairs rather than plain strings
_PAIR_FILTER_NAMES = frozenset(["Observable"])


def _is_empty(value) -> bool:
    if isinstance(value, (list, tuple)):
        return not value or all(v is None or str(v) == "" for v in value)

    return value is None or str(value) == ""


class FilterQueryError(ValueError):
    """A filter query parameter is malformed -- a broken link, not merely an outdated one."""


def _encode_value(name: str, value) -> str:
    if name in _PAIR_FILTER_NAMES:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise FilterQueryError(f"{name} value must be a [type, value] pair, got {value!r}")
        # the type/value colon stays literal so nested colons in the value are unambiguous
        return f"{quote(str(value[0]), safe=_VALUE_SAFE)}:{quote(str(value[1]), safe=_VALUE_SAFE)}"

    if isinstance(value, (list, tuple)):
        raise FilterQueryError(f"{name} value must be a string, got {value!r}")

    return quote("" if value is None else str(value), safe=_VALUE_SAFE)


def _decode_value(name: str, token: str):
    if name in _PAIR_FILTER_NAMES:
        observable_type, separator, observable_value = token.partition(":")
        if not separator:
            raise FilterQueryError(
                f"{name} value {token!r} must be '<type>:<value>'")
        return [unquote(observable_type), unquote(observable_value)]

    return unquote(token)


def encode_filter_query(filters: list) -> list[str]:
    """Render a filter list as the `f` query parameter values for a share link."""
    params = []
    for entry in filters or []:
        try:
            name = entry["name"]
            values = entry["values"]
        except (TypeError, KeyError) as e:
            raise FilterQueryError(f"malformed filter entry {entry!r}") from e

        slug = FILTER_SLUGS.get(name)
        if slug is None:
            raise FilterQueryError(f"unknown filter name {name!r}")

        # An empty value is dropped rather than encoded. It is meaningless at best, and for
        # a TextFilter it is actively dangerous: `ilike '%%'` matches EVERYTHING, so a link
        # carrying one would show far more alerts than its author intended.
        encoded = [_encode_value(name, value) for value in values if not _is_empty(value)]
        if not encoded:
            continue

        prefix = "!" if entry.get("inverted") else ""
        params.append(f"{prefix}{slug}:{','.join(encoded)}")

    return params


def decode_filter_query(params) -> tuple[list, list[str]]:
    """Parse `f` query parameter values into a filter list."""

    # Returns (filters, warnings). An unknown slug is SKIPPED and reported in warnings rather
    # than raising: a link written years ago may name a filter type that no longer exists,
    # and hard-failing would make every old link worthless. Dropping it silently would be
    # worse still -- a missing filter shows MORE alerts than the author intended -- so the
    # caller is expected to surface the warnings.

    # A malformed parameter raises FilterQueryError: that is a broken link, not an outdated
    # one, and silently ignoring it would show the analyst the wrong alerts.

    filters = []
    warnings = []

    for param in params or []:
        if not isinstance(param, str) or not param.strip():
            raise FilterQueryError("empty filter parameter")

        raw = param.strip()
        inverted = raw.startswith("!")
        if inverted:
            raw = raw[1:]

        slug, separator, value_part = raw.partition(":")
        if not separator:
            raise FilterQueryError(
                f"malformed filter parameter {param!r}: expected '<slug>:<value>'")
        if not slug:
            raise FilterQueryError(f"malformed filter parameter {param!r}: empty filter name")

        name = FILTER_NAMES_BY_SLUG.get(slug.lower())
        if name is None:
            warnings.append(
                f"This link uses a filter that no longer exists ({slug!r}); "
                f"it was skipped and the remaining filters were applied.")
            continue

        tokens = value_part.split(",")
        if any(token == "" for token in tokens):
            # see the note in encode_filter_query: an empty value can silently widen the
            # result set, so refuse it rather than guess what the link meant
            raise FilterQueryError(f"filter {slug!r} has an empty value")

        filters.append({
            "name": name,
            "inverted": inverted,
            "values": [_decode_value(name, token) for token in tokens],
        })

    return filters, warnings


def decode_legacy_filter_json(raw: str) -> list:
    """Parse a legacy ?filters=<json> payload into a filter list."""

    # Permanently supported: these URLs are already pasted in wikis and tickets. The display
    # names they embed are mapped through LEGACY_FILTER_NAME_ALIASES, which is what lets the
    # GUI rename a filter without breaking links written before the rename.

    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as e:
        raise FilterQueryError(f"malformed legacy filter payload: {e}") from e

    if not isinstance(parsed, list):
        # the very old shape was a dict of {name: values}; it predates inverted filters
        if isinstance(parsed, dict):
            parsed = [{"name": k, "inverted": False, "values": v} for k, v in parsed.items()]
        else:
            raise FilterQueryError("legacy filter payload must be a list of filter entries")

    filters = []
    for entry in parsed:
        if not isinstance(entry, dict) or "name" not in entry:
            raise FilterQueryError(f"malformed legacy filter entry {entry!r}")

        slug = LEGACY_FILTER_NAME_ALIASES.get(entry["name"])
        if slug is None:
            raise FilterQueryError(f"unknown legacy filter name {entry['name']!r}")

        values = entry.get("values") or []
        if not values:
            continue

        filters.append({
            "name": FILTER_NAMES_BY_SLUG[slug],
            "inverted": bool(entry.get("inverted", False)),
            "values": [list(v) if isinstance(v, (list, tuple)) else v for v in values],
        })

    return filters
