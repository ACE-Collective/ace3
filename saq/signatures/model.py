"""Data model for the signature inventory.

These objects describe detection signatures so they can be *studied* (counted,
tagged, diffed across commits). They are deliberately not used by any of the
mechanisms that actually perform detection - see saq/signatures/loader.py."""

from dataclasses import dataclass
from enum import StrEnum


class SignatureType(StrEnum):
    YARA = "yara"
    HUNT = "hunt"
    OBSERVABLE_MODIFIER = "observable_modifier"
    # declared for completeness (built-in signatures live in saq.signatures.builtin
    # and are not loaded from a repo) - there is no parser for this type
    BUILTIN = "builtin"


@dataclass(frozen=True)
class Signature:
    """A single detection signature as it exists in a rule repository."""

    name: str
    uuid: str
    type: SignatureType

    # the git commit hash of the repo the signature was loaded from, or
    # SIGNATURE_VERSION_UNKNOWN when it did not come from a git repo. same
    # value the detection path stamps on a DetectionPoint as signature_version.
    version: str

    # the URL of the repo's remote, or None for a repo with no remotes
    git_remote: str | None

    # path of the file the signature was loaded from, relative to the root of
    # the repo (posix separators) so it is stable across checkouts
    source_path: str

    # sha256 of the signature's own content, not of the file it came from: a
    # single .yar file holds many rules and a single rules yaml holds many
    # observable modifier rules
    content_hash: str

    # sorted, deduplicated
    tags: tuple[str, ...]
