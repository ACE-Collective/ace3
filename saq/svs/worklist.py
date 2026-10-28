"""The declared-vs-measured worklist (docs/SVS_COVERAGE.md, *The worklist*), kept in
svs_technique_worklist.

A signature is *measured* on the techniques of the catalog tests it is expected of (ignores applied,
removed tests left out). For each measured signature there is one row per technique:
- **declared**: a mitre: tag of the signature, its id resolved against the pinned ATT&CK release
  (ids that resolve to one technique share its row, in declared_as). It is *confirmed* when the
  technique is measured, or is the parent of a measured one: a tag on T1059 is confirmed by a test of
  T1059.001, a tag on T1059.001 is not confirmed by a test of T1059 or of T1059.003;
- **undeclared**: a measured technique no tag covers, for information;
- **unknown**: a tag naming an id the release doesn't have (and no test measures), for information.

Everything but the resolution is derived on every coverage refresh (refresh_worklist, called by
saq.svs.coverage.refresh_coverage under its lock, before coverage is computed), status included
(derive_status). A person resolves an unconfirmed declared row: *keep* (the tag covers something no
test reaches) or *remove* (a pull request to the signature repository will drop the tag). A tag
resolved *remove* stops counting toward coverage from the next refresh, unless it is confirmed.
resolve(), resolve_many() and reopen() take the same lock and write the resolution here; a refresh
writes it in two cases only, logged: it clears a *remove* when the tag comes back after it was gone,
and it moves a resolution to the technique an ATT&CK upgrade revoked the row's technique to.

Rows are never deleted; one the computation no longer produces is retired, and keeps its resolution.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional
from urllib.parse import urlparse

from sqlalchemy import func, select

from saq.auth import ApiAuthResult
from saq.database.model import SVSExpectation, SVSTechniqueWorklist
from saq.database.private_session import private_transaction
from saq.logging import log_audit
from saq.svs.attack import AttackCatalog, TechniqueStatus
from saq.svs.constants import WorklistKind, WorklistResolution, WorklistStatus
from saq.svs.coverage_lock import lock_refresh
from saq.svs.preconditions import NONE, Precondition
from saq.svs.signatures import SignatureTags, describe_signatures

# the statuses a person can resolve: a declared tag that measurement doesn't confirm
RESOLVABLE = (WorklistStatus.OPEN, WorklistStatus.KEPT, WorklistStatus.REMOVE_PENDING)

# {signature uuid: {technique: {(test guid, platform)}}}: what each signature is measured on
Measured = dict[str, dict[str, set[tuple[str, str]]]]


class UnknownWorklistRow(LookupError):
    """There is no such row, or it has no resolution to clear."""


class WorklistConflict(Exception):
    """The row can't be resolved in its status."""

    def __init__(self, signature_uuid: str, technique: str, status: str):
        super().__init__(f"the worklist row of signature {signature_uuid} on {technique} is {status}; only "
                         f"{', '.join(status.value for status in RESOLVABLE)} rows can be resolved")
        self.status = status


class InvalidResolution(ValueError):
    """The resolution can't be accepted as sent; the message says why."""


@dataclass(frozen=True)
class WorklistRow:
    """The derived columns of one svs_technique_worklist row; refresh_worklist compares exactly these
    (besides the key), and status and counts, which also depend on the resolution."""
    signature_uuid: str
    technique: str
    kind: str
    # JSON-serialized tag ids
    declared_as: str
    tag_present: bool
    signature_counts: bool
    measured: bool
    # JSON-serialized techniques
    measured_techniques: str
    signature_family: Optional[str]
    signature_name: Optional[str]
    # not columns: what status and counts are derived from
    confirmed: bool = False
    # the release has the technique (a confirmed tag can name an id it doesn't, like a custom atomic's)
    known: bool = True


DERIVED_COLUMNS = ("kind", "declared_as", "tag_present", "signature_counts", "measured", "measured_techniques",
                   "signature_family", "signature_name")
RESOLUTION_COLUMNS = ("resolution", "reason", "reference", "resolved_by_user_id", "resolved_at")


def derive_status(kind: str, *, produced: bool, tag_present: bool, confirmed: bool,
                  resolution: Optional[str]) -> WorklistStatus:
    """A row's status. produced: the computation produces the row now (its signature is measured,
    and for a declared row, a tag of it counts as the technique)."""
    if kind != WorklistKind.DECLARED:
        return WorklistStatus(kind) if produced else WorklistStatus.RETIRED
    if not tag_present:
        return WorklistStatus.REMOVED if resolution == WorklistResolution.REMOVE else WorklistStatus.RETIRED
    if not produced:
        return WorklistStatus.RETIRED
    if confirmed:
        return WorklistStatus.CONFIRMED
    if resolution == WorklistResolution.REMOVE:
        return WorklistStatus.REMOVE_PENDING
    if resolution == WorklistResolution.KEEP:
        return WorklistStatus.KEPT
    return WorklistStatus.OPEN


def mapping_counts(kind: str, *, tag_present: bool, signature_counts: bool, known: bool, status: str,
                   resolution: Optional[str]) -> bool:
    """The row's tag counts toward coverage as a manual mapping: it is there, its signature is enabled
    (and not a YARA rule in QA mode), the release knows its technique, and it isn't resolved remove,
    unless measurement confirms it."""
    if kind != WorklistKind.DECLARED or not tag_present or not signature_counts or not known:
        return False
    return resolution != WorklistResolution.REMOVE or status == WorklistStatus.CONFIRMED


def _covers(catalog: AttackCatalog, technique: str, candidate: str) -> bool:
    return candidate == technique or catalog.parent_of(candidate) == technique


def _declared(catalog: AttackCatalog, signature: Optional[SignatureTags]) -> dict[str, tuple[bool, list[str]]]:
    """{technique: (the release has it, the tag ids that count as it)} of a signature's tags."""
    result: dict[str, tuple[bool, list[str]]] = {}
    for declared in (signature.declared if signature is not None else ()):
        resolution = catalog.resolve(declared)
        known = resolution.status != TechniqueStatus.UNKNOWN
        result.setdefault(resolution.technique, (known, []))[1].append(declared)
    return result


def compute_worklist(catalog: AttackCatalog, tags: dict[str, SignatureTags], measured: Measured,
                     known: dict[str, tuple[Optional[str], Optional[str]]]) -> dict[tuple[str, str], WorklistRow]:
    """Every row the computation produces: those of the measured signatures. tags are
    signature_techniques(), known {uuid: (family, name)} of the measured signatures without tags."""
    rows: dict[tuple[str, str], WorklistRow] = {}
    for signature_uuid in sorted(measured):
        techniques = set(measured[signature_uuid])
        if not techniques:
            continue
        signature = tags.get(signature_uuid)
        family, name = (signature.family, signature.name) if signature is not None else \
            known.get(signature_uuid, (None, None))
        common = {"signature_uuid": signature_uuid, "measured": True,
                  "measured_techniques": json.dumps(sorted(techniques)),
                  "signature_family": family, "signature_name": name,
                  "signature_counts": signature.counts if signature is not None else False}

        covered = set()
        for technique, (release_has_it, declared_as) in sorted(_declared(catalog, signature).items()):
            matched = {candidate for candidate in techniques if _covers(catalog, technique, candidate)}
            covered |= matched
            # an id the release doesn't have is still a declaration when a test measures it
            kind = WorklistKind.DECLARED if release_has_it or matched else WorklistKind.UNKNOWN
            rows[(signature_uuid, technique)] = WorklistRow(
                technique=technique, kind=kind.value, declared_as=json.dumps(sorted(declared_as)), tag_present=True,
                confirmed=bool(matched), known=release_has_it, **common)

        for technique in sorted(techniques - covered):
            rows[(signature_uuid, technique)] = WorklistRow(
                technique=technique, kind=WorklistKind.UNDECLARED.value, declared_as="[]", tag_present=False, **common)
    return rows


def _known_signatures(session, uuids: Iterable[str]) -> dict[str, tuple[Optional[str], Optional[str]]]:
    """{uuid: (family, name)} of signatures without tags: as ACE knows them now, else as their
    expectations recorded them."""
    uuids = set(uuids)
    known = {uuid: (info.family, info.name) for uuid, info in describe_signatures(uuids).items()}
    remaining = sorted(uuids - set(known))
    if remaining:
        for uuid, family, name in session.execute(
                select(SVSExpectation.signature_uuid, SVSExpectation.signature_family, SVSExpectation.signature_name)
                .where(SVSExpectation.signature_uuid.in_(remaining))
                .order_by(SVSExpectation.decided_at.desc(), SVSExpectation.id.desc())):
            known.setdefault(uuid, (family, name))
    return known


@dataclass
class WorklistRefresh:
    # rows that aren't retired
    rows: int = 0
    changed: int = 0
    inserted: int = 0
    # (signature_uuid, technique, from_status, to_status) of each stored row whose status changed
    transitions: list[tuple[str, str, str, str]] = field(default_factory=list)
    # (signature_uuid, technique, resolution) the refresh cleared: the tag came back after a remove
    cleared: list[tuple[str, str, str]] = field(default_factory=list)
    # (signature_uuid, from_technique, to_technique, resolution) moved after an ATT&CK upgrade
    moved: list[tuple[str, str, str, str]] = field(default_factory=list)
    # (signature_uuid, technique) whose tag doesn't count because it is resolved remove
    excluded: frozenset[tuple[str, str]] = frozenset()


def _carry_forward(computed: dict[tuple[str, str], WorklistRow],
                   stored: dict[tuple[str, str], SVSTechniqueWorklist]) -> dict[tuple[str, str], tuple[str, str]]:
    """{new key: old key} of the resolutions to move: a declared row no stored resolution is on yet,
    one of whose tag ids is a stored row's technique that the computation no longer produces (an
    ATT&CK upgrade revoked it to this one)."""
    moves = {}
    taken = set()
    for key, row in computed.items():
        if row.kind != WorklistKind.DECLARED or (key in stored and stored[key].resolution is not None):
            continue
        for declared in json.loads(row.declared_as):
            old = (row.signature_uuid, declared)
            if declared != row.technique and old not in computed and old not in taken \
                    and old in stored and stored[old].resolution is not None:
                moves[key] = old
                taken.add(old)
                break
    return moves


def refresh_worklist(session, catalog: AttackCatalog, tags: dict[str, SignatureTags], measured: Measured,
                     now: datetime) -> WorklistRefresh:
    """Recomputes svs_technique_worklist in session's transaction, which holds the refresh lock;
    writes only the columns that changed. The caller logs the result once committed
    (log_worklist_refresh)."""
    computed = compute_worklist(catalog, tags, measured,
                                _known_signatures(session, set(measured) - set(tags)))
    stored = {(row.signature_uuid, row.technique): row
              for row in session.execute(select(SVSTechniqueWorklist)).scalars()}
    result = WorklistRefresh()

    moves = _carry_forward(computed, stored)
    carried: dict[tuple[str, str], dict] = {}
    for key, old in moves.items():
        previous = stored[old]
        carried[key] = {name: getattr(previous, name) for name in RESOLUTION_COLUMNS}
        result.moved.append((key[0], old[1], key[1], previous.resolution))
        for name in RESOLUTION_COLUMNS:
            setattr(previous, name, None)

    def apply(current: Optional[SVSTechniqueWorklist], values: dict, status: WorklistStatus, counts: bool,
              key: tuple[str, str]) -> SVSTechniqueWorklist:
        if current is None:
            current = SVSTechniqueWorklist(signature_uuid=key[0], technique=key[1], first_seen_at=now,
                                           status_changed_at=now, status=status.value, counts=counts, **values)
            session.add(current)
            result.changed += 1
            result.inserted += 1
            return current

        differs = [name for name in values if getattr(current, name) != values[name]]
        if current.status != status.value:
            result.transitions.append((key[0], key[1], current.status, status.value))
            current.status = status.value
            current.status_changed_at = now
            differs.append("status")
        if current.counts != counts:
            current.counts = counts
            differs.append("counts")
        for name in values:
            setattr(current, name, values[name])
        if differs:
            result.changed += 1
        return current

    written = []
    for key, row in computed.items():
        current = stored.get(key)
        # a carried resolution lands on a row that has none
        resolution_values = carried.get(key)
        if resolution_values is not None:
            resolution = resolution_values["resolution"]
        else:
            resolution = current.resolution if current is not None else None

        # the tag is back after it was gone: what was resolved about it no longer stands
        if current is not None and current.resolution == WorklistResolution.REMOVE and not current.tag_present \
                and row.tag_present:
            result.cleared.append((key[0], key[1], current.resolution))
            for name in RESOLUTION_COLUMNS:
                setattr(current, name, None)
            resolution = None

        status = derive_status(row.kind, produced=True, tag_present=row.tag_present, confirmed=row.confirmed,
                               resolution=resolution)
        counts = mapping_counts(row.kind, tag_present=row.tag_present, signature_counts=row.signature_counts,
                                known=row.known, status=status, resolution=resolution)
        values = {name: getattr(row, name) for name in DERIVED_COLUMNS}
        if resolution_values is not None:
            values.update(resolution_values)
        written.append(apply(current, values, status, counts, key))

    for key, current in stored.items():
        if key in computed:
            continue
        signature = tags.get(key[0])
        declared = _declared(catalog, signature)
        tag_present = current.kind != WorklistKind.UNDECLARED and key[1] in declared
        techniques = measured.get(key[0], {})
        values = {"tag_present": tag_present, "measured": bool(techniques),
                  "measured_techniques": json.dumps(sorted(techniques))}
        if signature is not None:
            values.update(signature_counts=signature.counts, signature_family=signature.family,
                          signature_name=signature.name)
        status = derive_status(current.kind, produced=False, tag_present=tag_present, confirmed=False,
                               resolution=current.resolution)
        counts = mapping_counts(current.kind, tag_present=tag_present,
                                signature_counts=values.get("signature_counts", current.signature_counts),
                                known=declared.get(key[1], (False, []))[0], status=status,
                                resolution=current.resolution)
        written.append(apply(current, values, status, counts, key))

    result.rows = sum(1 for row in written if row.status != WorklistStatus.RETIRED)
    result.excluded = frozenset(
        (row.signature_uuid, row.technique) for row in written
        if row.kind == WorklistKind.DECLARED and row.resolution == WorklistResolution.REMOVE
        and row.status != WorklistStatus.CONFIRMED)
    return result


def log_worklist_refresh(result: WorklistRefresh, actor: str) -> None:
    """Logs what a committed refresh did to the worklist."""
    for signature_uuid, from_technique, technique, resolution in result.moved:
        logging.info("svs worklist resolution %s of signature %s moved from %s to %s", resolution, signature_uuid,
                     from_technique, technique,
                     extra={"signature_uuid": signature_uuid, "technique": technique, "from_technique": from_technique,
                            "resolution": resolution, "actor": actor})
    for signature_uuid, technique, resolution in result.cleared:
        logging.info("svs worklist resolution %s of signature %s on %s cleared: the tag is back", resolution,
                     signature_uuid, technique,
                     extra={"signature_uuid": signature_uuid, "technique": technique, "resolution": None,
                            "cleared_resolution": resolution, "actor": actor})
    for signature_uuid, technique, from_status, to_status in result.transitions:
        logging.info("svs worklist row of signature %s on %s: %s -> %s", signature_uuid, technique, from_status,
                     to_status, extra={"signature_uuid": signature_uuid, "technique": technique,
                                       "from_status": from_status, "to_status": to_status})


#
# a person's resolutions (svs:run_manage)
#

def _validated(resolution: str, reason: Optional[str], reference: Optional[str]) -> tuple[str, str, Optional[str]]:
    try:
        resolution = WorklistResolution(resolution)
    except ValueError:
        raise InvalidResolution(f"resolution must be one of {', '.join(r.value for r in WorklistResolution)}") \
            from None
    reason = (reason or "").strip()
    if not reason:
        raise InvalidResolution("a resolution needs a reason")
    reference = (reference or "").strip() or None
    if reference is not None:
        parsed = urlparse(reference)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise InvalidResolution(f"reference {reference!r} is not an http(s) URL")
        if len(reference) > 1024:
            raise InvalidResolution("reference is longer than 1024 characters")
    return resolution.value, reason, reference


def _row(session, signature_uuid: str, technique: str) -> SVSTechniqueWorklist:
    row = session.execute(select(SVSTechniqueWorklist).where(
        SVSTechniqueWorklist.signature_uuid == signature_uuid,
        SVSTechniqueWorklist.technique == technique.strip().upper())).scalar_one_or_none()
    if row is None:
        raise UnknownWorklistRow(f"no worklist row for signature {signature_uuid} on {technique}")
    return row


def _rederive(row: SVSTechniqueWorklist, now: datetime) -> None:
    """status and counts after a person changed the resolution; the rest is as the last refresh left
    it."""
    confirmed = row.status == WorklistStatus.CONFIRMED
    produced = row.status not in (WorklistStatus.RETIRED, WorklistStatus.REMOVED)
    status = derive_status(row.kind, produced=produced, tag_present=row.tag_present, confirmed=confirmed,
                           resolution=row.resolution)
    if not confirmed:
        # a confirmed tag counts (or not) whatever its resolution
        row.counts = mapping_counts(row.kind, tag_present=row.tag_present, signature_counts=row.signature_counts,
                                    known=True, status=status, resolution=row.resolution)
    if row.status != status.value:
        row.status = status.value
        row.status_changed_at = now


def _resolve_row(row: SVSTechniqueWorklist, resolution: str, reason: str, reference: Optional[str], user_id: int,
                 now: datetime) -> None:
    if row.status not in RESOLVABLE:
        raise WorklistConflict(row.signature_uuid, row.technique, row.status)
    row.resolution = resolution
    row.reason = reason
    row.reference = reference
    row.resolved_by_user_id = user_id
    row.resolved_at = now
    _rederive(row, now)


def _audit(message: str, row_key: tuple[str, str], resolution: Optional[str], auth: Optional[ApiAuthResult],
           **fields) -> None:
    # fields name the actor and actor_user_id too, for a caller that passes no auth
    log_audit(message, auth=auth, signature_uuid=row_key[0], technique=row_key[1], resolution=resolution, **fields)


def _detached(session, row: SVSTechniqueWorklist) -> SVSTechniqueWorklist:
    """The row as written, readable once the private transaction is over."""
    session.flush()
    session.refresh(row)
    session.expunge(row)
    return row


def resolve(signature_uuid: str, technique: str, resolution: str, reason: Optional[str], user_id: int, *,
            reference: Optional[str] = None, actor: Optional[str] = None, precondition: Precondition = NONE,
            now: Optional[datetime] = None, auth: Optional[ApiAuthResult] = None) -> SVSTechniqueWorklist:
    """Resolves a declared tag measurement doesn't confirm: keep it, or remove it. A remove stops the
    tag counting toward coverage from the next refresh. Raises UnknownWorklistRow, WorklistConflict,
    InvalidResolution, StaleWrite."""
    resolution, reason, reference = _validated(resolution, reason, reference)
    now = now or datetime.now()
    with private_transaction() as session:
        lock_refresh(session)
        row = _row(session, signature_uuid, technique)
        precondition.check(row, f"the worklist row of {row.technique}")
        _resolve_row(row, resolution, reason, reference, user_id, now)
        row = _detached(session, row)

    _audit("svs worklist resolution set", (row.signature_uuid, row.technique), resolution, auth, reason=reason,
           reference=reference, status=row.status, actor=actor, actor_user_id=user_id)
    return row


@dataclass
class BulkResolution:
    done: list[tuple[str, str]] = field(default_factory=list)
    # (signature_uuid, technique) -> the row's status
    conflicts: dict[tuple[str, str], str] = field(default_factory=dict)
    unknown: list[tuple[str, str]] = field(default_factory=list)


def resolve_many(keys: Iterable[tuple[str, str]], resolution: str, reason: Optional[str], user_id: int, *,
                 reference: Optional[str] = None, actor: Optional[str] = None,
                 now: Optional[datetime] = None, auth: Optional[ApiAuthResult] = None) -> BulkResolution:
    """resolve() for each (signature_uuid, technique), in one transaction; a row that doesn't exist or
    can't be resolved is reported and left alone. Raises InvalidResolution."""
    resolution, reason, reference = _validated(resolution, reason, reference)
    now = now or datetime.now()
    result = BulkResolution()
    with private_transaction() as session:
        lock_refresh(session)
        for signature_uuid, technique in dict.fromkeys(keys):
            try:
                row = _row(session, signature_uuid, technique)
                _resolve_row(row, resolution, reason, reference, user_id, now)
            except UnknownWorklistRow:
                result.unknown.append((signature_uuid, technique))
            except WorklistConflict as e:
                result.conflicts[(signature_uuid, technique)] = e.status
            else:
                result.done.append((row.signature_uuid, row.technique))

    for key in result.done:
        _audit("svs worklist resolution set", key, resolution, auth, reason=reason, reference=reference, actor=actor,
               actor_user_id=user_id)
    return result


def reopen(signature_uuid: str, technique: str, user_id: int, *, actor: Optional[str] = None,
           precondition: Precondition = NONE, now: Optional[datetime] = None,
           auth: Optional[ApiAuthResult] = None) -> SVSTechniqueWorklist:
    """Clears a row's resolution: an unconfirmed tag is open again and counts from the next refresh.
    Raises UnknownWorklistRow (also when the row has no resolution), StaleWrite."""
    now = now or datetime.now()
    with private_transaction() as session:
        lock_refresh(session)
        row = _row(session, signature_uuid, technique)
        precondition.check(row, f"the worklist row of {row.technique}")
        if row.resolution is None:
            raise UnknownWorklistRow(f"the worklist row of signature {signature_uuid} on {technique} has no resolution")
        previous = row.resolution
        for name in RESOLUTION_COLUMNS:
            setattr(row, name, None)
        _rederive(row, now)
        row = _detached(session, row)

    _audit("svs worklist resolution cleared", (row.signature_uuid, row.technique), None, auth,
           cleared_resolution=previous, status=row.status, actor=actor, actor_user_id=user_id)
    return row


#
# reads
#

def excluded_mappings(session) -> frozenset[tuple[str, str]]:
    """(signature_uuid, technique) of the tags resolved remove that measurement doesn't confirm: they
    don't count toward coverage."""
    return frozenset(session.execute(
        select(SVSTechniqueWorklist.signature_uuid, SVSTechniqueWorklist.technique).where(
            SVSTechniqueWorklist.kind == WorklistKind.DECLARED.value,
            SVSTechniqueWorklist.resolution == WorklistResolution.REMOVE.value,
            SVSTechniqueWorklist.status != WorklistStatus.CONFIRMED.value)).tuples())


def worklist_counts(session) -> dict[str, int]:
    """{status: rows}."""
    return dict(session.execute(
        select(SVSTechniqueWorklist.status, func.count()).group_by(SVSTechniqueWorklist.status)).tuples().all())
