"""Values of the alert screen's Observable Pattern filter: an observable value with `*` wildcards.

An index can serve a LIKE only from the end of the pattern that is literal text: `i_obs_value`
when the pattern starts with text (`https://evil.com/*`), `i_obs_value_rev`, the value
reversed, when it ends with text (`*.evil.com`). A pattern with a wildcard at both ends
(`*evil*`) has neither, so it would read the whole observables table (over a second at 1.25M
rows) on every page load, every 30 second refresh and every badge count. It is refused, at
write time here and again when a stored filter is run (saq/gui/filter_query.py).

Kept apart from filter_query so the filter entry validator and the search syntax can check a
pattern without importing the ORM.
"""

WILDCARD = "*"

# the type option meaning "any observable type", for this filter and the exact Observable filter
ANY_OBSERVABLE_TYPE = "Any"


class ObservablePatternError(ValueError):
    """An Observable Pattern value no index can serve, or one that matches too many observables.
    The message is written for the analyst who typed the pattern."""


def check_observable_pattern(pattern) -> str:
    """The pattern without surrounding whitespace. Raises ObservablePatternError if it is empty,
    only wildcards, or has a wildcard at both ends."""
    if not isinstance(pattern, str):
        raise ObservablePatternError(f"observable pattern must be a string, got {pattern!r}")

    stripped = pattern.strip()
    if not stripped.replace(WILDCARD, ""):
        raise ObservablePatternError(f"observable pattern {pattern!r} has no text to match")

    if stripped.startswith(WILDCARD) and stripped.endswith(WILDCARD):
        raise ObservablePatternError(
            f"observable pattern {pattern!r} has a wildcard at both ends; it must start or end with "
            f"text (e.g. evil.com/* or *.evil.com)")

    return stripped
