"""Data model for the signature inventory.

These objects describe detection signatures so they can be *studied* (counted,
tagged, diffed across commits), and the places they are loaded from. They are
deliberately not used by any of the mechanisms that actually perform detection -
see saq/signatures/loaders/.
"""

import os
import re
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Optional


# the width of every signature uuid column (detection_points.signature_uuid, yara_qa_matches,
# svs_yara_captures, ...): a uuid meta longer than this cannot be recorded against its rule
SIGNATURE_UUID_MAX_LENGTH = 36

# what an API accepts as a signature uuid in a path or a filter. Rule uuids are uuids in practice,
# but the meta is free text; this is what the stores accept, and nothing that can reach a path or a
# query outside a bound parameter
SIGNATURE_UUID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0," + str(SIGNATURE_UUID_MAX_LENGTH - 1) + r"}$")


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

    # yara only: the rule's `modifiers` meta, in order (saq.signatures.yara_meta). empty for
    # every other type
    modifiers: tuple[str, ...] = ()

    # yara only: False when the rule's `enabled` meta turns it off in place. True for every other
    # type
    enabled: bool = True


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


@dataclass(frozen=True)
class YaraInventory:
    """The YARA rules this deployment loads, as saq/signatures/yara_inventory.py read them. Kept
    here, apart from the loader, so that the API can import it: the signature loaders import the
    hunter and, through it, the engine, which the API must not pull in at import time."""

    # every yara rule with a uuid, by uuid
    by_uuid: dict[str, Signature] = field(default_factory=dict)
    # monotonic time it was built
    built_at: float = field(default_factory=time.monotonic)
    # why the inventory is empty or partial, for callers to pass on; None when it loaded cleanly
    error: Optional[str] = None
