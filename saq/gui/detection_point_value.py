"""The value format of the Detection Point filter: `<signature uuid>[:<signature version>]`.

Every entry point -- the filter editor, a saved filter or share link (FilterEntry), a
`detection_point:` search term and the search API's `detection_points` field -- validates through
parse_detection_point_value(), so a value that one of them accepts means the same thing to all.
"""

import re

SIGNATURE_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def parse_detection_point_value(value: str) -> tuple[str, str | None]:
    """Splits a filter value into (signature uuid, signature version or None).

    The split is at the FIRST colon: the uuid never contains one, and the version is an opaque
    string (often a git commit hash) matched exactly. No version means "any version". The uuid
    is returned lowercased. Raises ValueError for anything else.
    """
    if not isinstance(value, str):
        raise ValueError(f"detection point value must be a string, got {value!r}")

    signature_uuid, separator, signature_version = value.strip().partition(":")
    if not SIGNATURE_UUID_RE.match(signature_uuid):
        raise ValueError(f"{value!r} must be written <signature uuid>[:<version>]")

    if separator and not signature_version:
        raise ValueError(f"{value!r} has an empty signature version (omit the colon to match any version)")

    return signature_uuid.lower(), signature_version if separator else None


def normalize_detection_point_value(value: str) -> str:
    """The canonical spelling of a valid value (lowercased uuid). Raises ValueError."""
    signature_uuid, signature_version = parse_detection_point_value(value)
    return signature_uuid if signature_version is None else f"{signature_uuid}:{signature_version}"
