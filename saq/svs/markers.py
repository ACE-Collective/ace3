"""Run markers (docs/SVS.md, Part 3, *Markers*): `svs-` followed by 26 base32 characters, 128
random bits. A launcher puts its run's marker where the test's process telemetry shows it, and
attribution finds it with MARKER_REGEX. A marker is not secret: it attributes an alert only when the
alert agrees with its run."""

import base64
import re
import secrets

MARKER_PREFIX = "svs-"
MARKER_LENGTH = len(MARKER_PREFIX) + 26

# case-insensitive: telemetry may change the case of a command line. Bounded by anything that is
# not a base32 character, so a marker inside a longer token is not found
MARKER_REGEX = re.compile(r"(?<![a-z0-9])svs-[a-z2-7]{26}(?![a-z0-9])", re.IGNORECASE)


def new_marker() -> str:
    """A new random marker, lower case."""
    return MARKER_PREFIX + base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=").lower()


def normalize_marker(value: str) -> str:
    """A marker as runs store it (lower case)."""
    return value.strip().lower()


def find_markers(text: str) -> list[str]:
    """The distinct markers in text, normalized, in the order they first appear."""
    return list(dict.fromkeys(normalize_marker(match) for match in MARKER_REGEX.findall(text or "")))
