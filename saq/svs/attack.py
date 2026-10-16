"""The ATT&CK release SVS coverage is computed against (docs/SVS_COVERAGE.md, *The ATT&CK release*).

ACE never fetches ATT&CK. Each supported release is a compact extract vendored at
etc/attack/<release>.json, built by bin/update-attack-catalog, and svs.attack_release names the one
in use. It gives the names of techniques and tactics, each sub-technique's parent, each technique's
tactics and platforms, and where a revoked technique went.

Technique ids from anywhere else (an atomic's attack_technique, a signature's mitre: tag) go
through resolve(): a revoked id becomes its successor, and an id the release doesn't have is kept
as it is, as unknown.
"""

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from pathlib import Path
from typing import Iterable, Optional

from saq.configuration.config import get_config
from saq.svs.attack_files import release_path

# the layout of the extract this module reads (bin/update-attack-catalog FORMAT)
FORMAT = 1

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Atomic Red Team's platform names that ATT&CK calls something else; any iaas:<provider> is iaas
ART_PLATFORM_ALIASES = {
    "azure-ad": "identity-provider",
    "office-365": "office-suite",
    "google-workspace": "office-suite",
}


class TechniqueStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    # not in the release: a custom atomic's technique, a typo, or a release newer than the one pinned
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    parent: Optional[str]
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    deprecated: bool

    @property
    def status(self) -> TechniqueStatus:
        return TechniqueStatus.DEPRECATED if self.deprecated else TechniqueStatus.ACTIVE


@dataclass(frozen=True)
class Resolution:
    """What a technique id means in the release: the technique it counts as, and whether it was
    revoked to get there."""
    technique: str
    status: TechniqueStatus
    revoked_from: Optional[str] = None


def normalize_technique_id(value: str) -> Optional[str]:
    """T1059.001 from t1059.001 or ' T1059.001 '; None for anything that isn't a technique id (a
    tactic, a template, free text)."""
    value = value.strip().upper()
    return value if TECHNIQUE_RE.match(value) else None


def syntactic_parent(technique_id: str) -> Optional[str]:
    """The parent a sub-technique id names (T1059 for T1059.001), whatever the release says."""
    return technique_id.split(".")[0] if "." in technique_id else None


def normalize_platform(name: str) -> str:
    """The platform slug for one of a test's supported_platforms (Atomic Red Team's names)."""
    name = name.strip().lower()
    if name.startswith("iaas:"):
        return "iaas"
    return ART_PLATFORM_ALIASES.get(name, name)


class AttackCatalog:
    def __init__(self, release: str, platforms: dict[str, str], tactics: Iterable[Tactic],
                 techniques: Iterable[Technique], revoked: dict[str, str], renamed: dict[str, dict]):
        self.release = release
        # slug -> ATT&CK's name, in display order
        self.platforms = dict(platforms)
        self.tactics = tuple(tactics)
        self.techniques = {technique.id: technique for technique in techniques}
        self.revoked = dict(revoked)
        self.renamed = dict(renamed)
        self._tactics = {tactic.id: tactic for tactic in self.tactics}
        self._tactics.update({tactic.shortname: tactic for tactic in self.tactics})
        children: dict[str, list[str]] = {}
        for technique in self.techniques.values():
            if technique.parent is not None:
                children.setdefault(technique.parent, []).append(technique.id)
        self._children = {parent: tuple(sorted(ids)) for parent, ids in children.items()}

    def technique(self, technique_id: str) -> Optional[Technique]:
        return self.techniques.get(technique_id)

    def resolve(self, technique_id: str) -> Resolution:
        """Raises ValueError for something that isn't a technique id."""
        normalized = normalize_technique_id(technique_id)
        if normalized is None:
            raise ValueError(f"{technique_id!r} is not an ATT&CK technique id")
        successor = self.revoked.get(normalized)
        effective = successor or normalized
        technique = self.techniques.get(effective)
        status = technique.status if technique is not None else TechniqueStatus.UNKNOWN
        return Resolution(effective, status, normalized if successor else None)

    def parent_of(self, technique_id: str) -> Optional[str]:
        technique = self.techniques.get(technique_id)
        if technique is not None:
            return technique.parent
        return syntactic_parent(technique_id)

    def children_of(self, technique_id: str) -> tuple[str, ...]:
        """The release's sub-techniques of a technique, deprecated ones included."""
        return self._children.get(technique_id, ())

    def tactic(self, value: str) -> Optional[Tactic]:
        """A tactic by its id (TA0002) or its shortname (execution)."""
        value = value.strip()
        return self._tactics.get(value.upper()) or self._tactics.get(value.lower())

    def techniques_in(self, tactic_ids: Iterable[str]) -> set[str]:
        tactic_ids = set(tactic_ids)
        return {technique.id for technique in self.techniques.values() if tactic_ids.intersection(technique.tactics)}

    def platform_name(self, slug: str) -> str:
        return self.platforms.get(slug, slug)


def load_attack_catalog(path: Path) -> AttackCatalog:
    with open(path, encoding="utf-8") as fp:
        extract = json.load(fp)
    if extract.get("format") != FORMAT:
        raise ValueError(f"{path} is in format {extract.get('format')!r}, not {FORMAT}; "
                         "rebuild it with bin/update-attack-catalog")
    return AttackCatalog(
        release=extract["release"],
        platforms={platform["slug"]: platform["name"] for platform in extract["platforms"]},
        tactics=[Tactic(tactic["id"], tactic["shortname"], tactic["name"]) for tactic in extract["tactics"]],
        techniques=[Technique(technique_id, value["name"], value["parent"], tuple(value["tactics"]),
                              tuple(value["platforms"]), value["deprecated"])
                    for technique_id, value in extract["techniques"].items()],
        revoked=extract["revoked"],
        renamed=extract["renamed"])


@cache
def _load(release: str) -> AttackCatalog:
    return load_attack_catalog(release_path(release))


def get_attack_catalog(release: Optional[str] = None) -> AttackCatalog:
    """The release svs.attack_release names, read once per process."""
    return _load(release or get_config().svs.attack_release)
