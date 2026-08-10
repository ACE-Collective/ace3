"""Data model for the signature inventory.

These objects describe detection signatures so they can be *studied* (counted,
tagged, diffed across commits), and the places they are loaded from. They are
deliberately not used by any of the mechanisms that actually perform detection -
see saq/signatures/loaders/.
"""

import os
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


@dataclass(frozen=True)
class SignatureLocation:
    """One place ACE loads signatures of a given type from, as the runtime
    configuration declares it.

    git_dirs is plural because that is what the three types have in common: yara
    declares a list (service_yara.git_repo_dirs) while hunt and observable
    modifier declare at most one. The shared meaning is that a signature is
    versioned by the declared checkout covering it, and is
    SIGNATURE_VERSION_UNKNOWN when none does - which is what all three detection
    paths already do. An empty tuple therefore means "declared, none", not
    "undeclared": everything at this location is unversioned.

    How a checkout is matched against the signatures under path is left to each
    loader, because each one mirrors a different mechanism: yara matches rule
    directories by exact realpath the way YaraScanner does, while hunt and
    observable modifier match by containment (saq.git.git_dir_contains)."""

    signature_type: SignatureType

    # absolute. a directory for YARA (the signature_dir holding one subdirectory
    # per rule set) and HUNT, the rules file itself for OBSERVABLE_MODIFIER
    path: str

    # absolute. the git checkouts declared as versioning what is under path
    git_dirs: tuple[str, ...]

    # the configuration block this came from: "service_yara", "hunt_type_splunk",
    # "analysis_module_observable_modifier"
    source: str

    def exists(self) -> bool:
        return os.path.exists(self.path)
