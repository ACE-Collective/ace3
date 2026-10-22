"""Attributing alerts to test runs (docs/SVS_RUNS.md, *Attribution*; docs/SVS.md, Part 3,
*Markers* and *Attribution and routing*).

An alert is attributed by the markers found in it. A marker attributes only when it agrees with its
run: the run is registered, the alert involves one of the run's targets, and the alert's event time
falls inside the run's attribution window [ART-4]. A marker that doesn't agree is a *mismatch*: the
alert is never routed, and nothing in it is attributed, not even by context [FR-3]. An alert with no
marker at all is attributed by context (one of its hosts is the target of exactly one run whose
window covers it) [ART-5, FR-9].

Attribution is per detection [ART-7]. A marker attributes the detections on its own branch of the
tree: the node it was found on, the nodes above it and the nodes beneath it. A marker in the alert's
own details is on the root, so it attributes every detection; so does a context attribution, which
has no per-detection signal. An alert whose every detection is attributed is routed to the test
queue (saq/svs/routing.py); one with only some is PARTIAL TEST and stays where it is.

Markers are found in:
- the tree (tree_sightings): observable values and file names, detections, and the alert's details;
- module output (record_delta_sightings): the executor hands every module's new analysis details to
  this module before it drops them from its record of the module's execution, and the markers found
  there, including the SVS_Marker YARA rule's matches in file contents, are saved on the root.

All of this is gated: nothing is scanned unless some run is registered or inside its attribution
window, and that answer is cached for a few seconds per process [FR-8]. A marker is resolved against
the runs through a cache that holds only runs that have started, whose windows and targets never
change again; a marker it doesn't have always goes to the database, so a stale cache never turns a
real test into a mismatch.

The marker router writes its own rows of svs_attributions here (source 'router'), in a transaction
of its own: a router must never break the alert insert it runs in. A person's changes (associating
an alert by hand, disassociating it, keeping a context attribution) are saq/svs/association.py's.
The router never touches a row a person wrote or removed, and every change it makes to an existing
row is conditional on the row still being its own, so a person's change that lands while it works
is never overwritten. A run a person disassociated an alert from is never attributed that alert
again, for any of its detections.
"""

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Iterator, Optional

from sqlalchemy import exists, or_, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.analysis.analysis import Analysis
from saq.analysis.detection_identity import detection_content_hash, node_identity
from saq.analysis.observable import Observable
from saq.analysis.root import EVENT_TIME_FALLBACK_QUERY_TIME, KEY_EVENT_TIME_FALLBACK, RootAnalysis
from saq.configuration.config import get_config
from saq.constants import F_FQDN, F_HOSTNAME, F_IPV4
from saq.database.model import SVSAttribution, SVSMaintenanceWindow, SVSRun, SVSSuppressedMatch, SVSTestHost
from saq.database.private_session import private_transaction, run_private_transaction
from saq.environment import get_local_timezone
from saq.observables.file import FileObservable
from saq.observables.type_hierarchy import get_type_hierarchy
from saq.svs.constants import (
    ROUTER_ACTOR,
    RUN_SIGNATURES,
    SIGHTINGS_EXTENSION,
    AttributionConfidence,
    AttributionSource,
    EventTimeSource,
    MarkerResult,
    RunEventKind,
    RunState,
    ScanPoint,
    SVSStatus,
)
from saq.svs.alert_status import derive_status
from saq.svs.hosts import InvalidTestHost, host_ips, normalize_ip, split_hostname
from saq.svs.marker_rule import MARKER_RULE_NAME
from saq.svs.markers import find_markers, find_markers_in_match
from saq.svs.result_state import mark_runs_stale
from saq.svs.run_events import new_run_event

# how deep the details walk goes; analysis details are JSON-shaped and shallow
MAX_WALK_DEPTH = 32

REMOVAL_NO_LONGER_APPLIES = "no longer attributed by the marker router"

# how many times write_attributions runs its transaction when MySQL picks it as a deadlock victim
# (1213) or it waits too long for a lock (1205): a marker alert whose write fails is never routed
WRITE_ATTEMPTS = 5


#
# what was found where
#

@dataclass(frozen=True)
class Sighting:
    """A marker found in an alert. node is the uuid of the observable it was found on (for module
    output, the observable the module analyzed), None for the root."""
    marker: str
    node: Optional[str]
    scan_point: ScanPoint
    module: Optional[str] = None

    def to_json(self) -> dict:
        return {"marker": self.marker, "node": self.node, "scan_point": self.scan_point.value, "module": self.module}

    @staticmethod
    def from_json(value: dict) -> "Sighting":
        return Sighting(marker=value["marker"], node=value.get("node"), scan_point=ScanPoint(value["scan_point"]),
                        module=value.get("module"))


def _walk_strings(value: Any, depth: int = 0) -> Iterator[str | bytes]:
    """Every str and bytes value in JSON-shaped data (dict values, list and tuple items)."""
    if depth > MAX_WALK_DEPTH:
        return
    if isinstance(value, (str, bytes)):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item, depth + 1)


def find_markers_in_data(value: Any) -> list[str]:
    """The distinct markers in JSON-shaped data. bytes are read as the marker rule's match data is
    (latin-1, NULs of UTF-16 text dropped)."""
    result = {}
    for item in _walk_strings(value):
        for marker in (find_markers_in_match(item) if isinstance(item, bytes) else find_markers(item)):
            result[marker] = None
    return list(result)


def _marker_rule_markers(details: Any) -> list[str]:
    """The markers the SVS_Marker YARA rule matched, from a YaraScanResults analysis's details."""
    if not isinstance(details, dict) or not isinstance(details.get("scan_results"), list):
        return []

    result = {}
    for entry in details["scan_results"]:
        if not isinstance(entry, dict) or entry.get("rule") != MARKER_RULE_NAME:
            continue
        for string in entry.get("strings") or []:
            # (offset, identifier, data): a tuple from the scanner, a list once saved and loaded
            if isinstance(string, (list, tuple)) and len(string) >= 3:
                for marker in find_markers_in_match(string[2]):
                    result[marker] = None
    return list(result)


def analysis_sightings(details: Any, node: Optional[str], module: Optional[str]) -> list[Sighting]:
    """The markers in a module's analysis details: the marker rule's matches are file contents,
    anything else is the module's output."""
    sightings = {}
    for marker in _marker_rule_markers(details):
        sightings.setdefault(marker, Sighting(marker, node, ScanPoint.FILE_CONTENTS, module))
    for marker in find_markers_in_data(details):
        sightings.setdefault(marker, Sighting(marker, node, ScanPoint.ANALYSIS, module))
    return list(sightings.values())


def saved_sightings(root: RootAnalysis) -> list[Sighting]:
    """The markers the executor saved on the root from module output."""
    result = []
    for value in (root.extensions or {}).get(SIGHTINGS_EXTENSION) or []:
        try:
            result.append(Sighting.from_json(value))
        except (KeyError, TypeError, ValueError):
            logging.warning("ignoring a malformed svs sighting on %s: %r", root, value)
    return result


def save_sightings(root: RootAnalysis, sightings: Iterable[Sighting]) -> int:
    """Adds sightings to the root's svs_sightings extension, without duplicates and up to
    svs.attribution.max_sightings. Returns how many were added."""
    current = saved_sightings(root)
    known = {(s.marker, s.node, s.scan_point) for s in current}
    limit = get_config().svs.attribution.max_sightings
    added = 0
    for sighting in sightings:
        key = (sighting.marker, sighting.node, sighting.scan_point)
        if key in known:
            continue
        if len(current) >= limit:
            logging.warning("%s already holds %s svs sightings; marker %s is not kept", root, limit, sighting.marker,
                            extra={"svs_marker": sighting.marker, "alert_uuid": root.uuid})
            break
        current.append(sighting)
        known.add(key)
        added += 1

    if added:
        root.set_extension(SIGHTINGS_EXTENSION, [s.to_json() for s in current])
    return added


def record_delta_sightings(root: RootAnalysis, observable: Observable, delta, module_name: Optional[str]) -> int:
    """The executor's hook (FR-19): saves the markers in the analysis details a module just
    produced (a ModuleExecutionDelta, live or replayed from the analysis cache) on the root. Only
    the details need scanning here; whatever else a module adds is in the tree. Returns how many
    sightings were added."""
    analysis = getattr(delta, "analysis", None)
    if not analysis or not analysis.get("details"):
        return 0
    if not attribution_open():
        return 0

    sightings = analysis_sightings(analysis["details"], observable.uuid if observable is not None else None,
                                   module_name)
    return save_sightings(root, sightings) if sightings else 0


def _carrier(node) -> Optional[str]:
    """The observable a detection's node stands for in the tree: the observable itself, an
    analysis's observable, None for the root."""
    if isinstance(node, RootAnalysis):
        return None
    if isinstance(node, Observable):
        return node.uuid
    if isinstance(node, Analysis) and node.observable is not None:
        return node.observable.uuid
    return None


def tree_sightings(root: RootAnalysis) -> list[Sighting]:
    """Every marker in the alert: its observables, its detections, its details, and what the
    executor saved from module output (dropped when its observable is no longer in the tree)."""
    sightings = []
    observables = {}
    for observable in root.all_observables:
        observables[observable.uuid] = observable
        for marker in find_markers(str(observable.value)):
            sightings.append(Sighting(marker, observable.uuid, ScanPoint.OBSERVABLE))
        if isinstance(observable, FileObservable) and observable.file_path:
            for marker in find_markers(observable.file_path):
                sightings.append(Sighting(marker, observable.uuid, ScanPoint.OBSERVABLE))

    for node, detection in root.detection_points_by_node():
        for marker in find_markers_in_data([detection.description, detection.details]):
            sightings.append(Sighting(marker, _carrier(node), ScanPoint.DETECTION))

    for marker in find_markers_in_data(root.details):
        sightings.append(Sighting(marker, None, ScanPoint.ROOT_DETAILS))

    for sighting in saved_sightings(root):
        if sighting.node is None or sighting.node in observables:
            sightings.append(sighting)

    return list(dict.fromkeys(sightings))


#
# the runs
#

@dataclass(frozen=True)
class TargetSnapshot:
    host: str
    fqdn: Optional[str]
    ips: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RunSnapshot:
    """What attribution needs of a run. Once the run has started none of it changes."""
    id: int
    uuid: str
    test_guid: str
    marker: str
    started_at: Optional[datetime]
    observation_ends_at: Optional[datetime]
    attribution_ends_at: Optional[datetime]
    targets: tuple[TargetSnapshot, ...] = ()
    holds_host: bool = False

    @property
    def claim_ends_at(self) -> Optional[datetime]:
        """When its claim on its hosts ends (saq.svs.runs.host_holders)."""
        return self.attribution_ends_at if self.holds_host else self.observation_ends_at

    def log_fields(self) -> dict:
        return {"svs_run": self.uuid, "svs_test": self.test_guid, "svs_marker": self.marker}

    def in_window(self, when: datetime) -> bool:
        return (self.started_at is not None and self.attribution_ends_at is not None
                and self.started_at <= when <= self.attribution_ends_at)

    def holds_host_at(self, when: datetime) -> bool:
        """Its claim on its hosts covers when."""
        return self.claim_ends_at is None or when <= self.claim_ends_at

    def is_late(self, when: datetime) -> bool:
        return self.observation_ends_at is not None and when > self.observation_ends_at


def _snapshots(session, runs: list[SVSRun]) -> list[RunSnapshot]:
    if not runs:
        return []

    host_ids = {target.test_host_id for run in runs for target in run.targets if target.test_host_id is not None}
    ips = {}
    if host_ids:
        for host in session.execute(select(SVSTestHost).where(SVSTestHost.id.in_(host_ids))).scalars():
            ips[host.id] = frozenset(host_ips(host))

    return [RunSnapshot(
        id=run.id, uuid=run.uuid, test_guid=run.test_guid, marker=run.marker, started_at=run.started_at,
        observation_ends_at=run.observation_ends_at, attribution_ends_at=run.attribution_ends_at,
        holds_host=run.holds_host,
        targets=tuple(TargetSnapshot(target.host, target.fqdn, ips.get(target.test_host_id, frozenset()))
                      for target in run.targets))
        for run in runs]


class _Caches:
    """The per-process gate and marker caches. One router serves every thread of its process."""

    def __init__(self):
        self.lock = threading.Lock()
        self.gate: Optional[tuple[float, bool]] = None
        self.markers: OrderedDict[str, RunSnapshot] = OrderedDict()

    def clear(self):
        with self.lock:
            self.gate = None
            self.markers.clear()


_caches = _Caches()


def clear_caches() -> None:
    """Forgets the gate's answer and every resolved marker (tests)."""
    _caches.clear()


def attribution_open(now: Optional[datetime] = None) -> bool:
    """True when some run is registered and not started yet, or is inside its attribution window, or
    a maintenance window was open within svs.runs.attribution_extra_hours: only then can an alert
    be attributed or closed for maintenance, so only then is anything scanned. Each process trusts its
    answer for svs.attribution.gate_cache_seconds. A registered run opens the gate before its test
    fires, so the cache never hides the start of a run."""
    ttl = get_config().svs.attribution.gate_cache_seconds
    with _caches.lock:
        if _caches.gate is not None and _caches.gate[0] > time.monotonic():
            return _caches.gate[1]

    now = now or datetime.now()
    # an alert of a maintenance window may come as late as a run's
    window_horizon = now - timedelta(hours=get_config().svs.runs.attribution_extra_hours)
    with private_transaction() as session:
        value = bool(session.execute(select(or_(
            exists().where(SVSRun.state == RunState.CREATED.value),
            exists().where(SVSRun.state.in_([state.value for state in RunState if state != RunState.CREATED]),
                           SVSRun.attribution_ends_at >= now),
            exists().where(SVSMaintenanceWindow.ends_at >= window_horizon,
                           or_(SVSMaintenanceWindow.ended_at.is_(None),
                               SVSMaintenanceWindow.ended_at >= window_horizon))))).scalar())

    with _caches.lock:
        _caches.gate = (time.monotonic() + ttl, value)
    return value


def resolve_markers(markers: Iterable[str]) -> dict[str, RunSnapshot]:
    """The run of each marker that has one. Runs that have started are cached; any other marker is
    looked up in the database every time."""
    markers = list(dict.fromkeys(markers))
    result = {}
    missing = []
    with _caches.lock:
        for marker in markers:
            snapshot = _caches.markers.get(marker)
            if snapshot is None:
                missing.append(marker)
            else:
                _caches.markers.move_to_end(marker)
                result[marker] = snapshot

    if not missing:
        return result

    with private_transaction() as session:
        runs = list(session.execute(select(SVSRun).where(SVSRun.marker.in_(missing))).scalars())
        snapshots = _snapshots(session, runs)

    size = get_config().svs.attribution.marker_cache_size
    with _caches.lock:
        for snapshot in snapshots:
            result[snapshot.marker] = snapshot
            if snapshot.started_at is not None and size > 0:
                _caches.markers[snapshot.marker] = snapshot
                _caches.markers.move_to_end(snapshot.marker)
        while len(_caches.markers) > size:
            _caches.markers.popitem(last=False)

    return result


@dataclass(frozen=True)
class MaintenanceSnapshot:
    """What attribution needs of a maintenance window (docs/SVS_RUNS.md, *Maintenance windows*)."""
    id: int
    uuid: str
    target: TargetSnapshot
    opened_at: datetime
    # when it ended, or ends
    ends_at: datetime

    def log_fields(self) -> dict:
        return {"svs_maintenance": self.uuid, "host": self.target.host}

    def covers(self, when: datetime) -> bool:
        return self.opened_at <= when <= self.ends_at


def maintenance_windows_overlapping(start: datetime, end: datetime) -> list[MaintenanceSnapshot]:
    """The maintenance windows open at some time from start to end, on any host. Never cached: a
    window ends early."""
    with private_transaction() as session:
        rows = session.execute(
            select(SVSMaintenanceWindow, SVSTestHost)
            .outerjoin(SVSTestHost, SVSTestHost.id == SVSMaintenanceWindow.test_host_id)
            # the planned end bounds the window, and is indexed
            .where(SVSMaintenanceWindow.ends_at >= start, SVSMaintenanceWindow.opened_at <= end,
                   or_(SVSMaintenanceWindow.ended_at.is_(None), SVSMaintenanceWindow.ended_at >= start))
            .order_by(SVSMaintenanceWindow.id)).all()
        return [MaintenanceSnapshot(
            id=window.id, uuid=window.uuid,
            target=TargetSnapshot(window.host, window.fqdn, frozenset(host_ips(host)) if host else frozenset()),
            opened_at=window.opened_at, ends_at=window.ended_at or window.ends_at)
            for window, host in rows]


def runs_overlapping(start: datetime, end: datetime) -> list[RunSnapshot]:
    """The runs whose attribution window overlaps start to end."""
    with private_transaction() as session:
        runs = list(session.execute(
            select(SVSRun).where(SVSRun.started_at <= end, SVSRun.attribution_ends_at >= start)
            .order_by(SVSRun.id)).scalars())
        return _snapshots(session, runs)


#
# the alert's hosts
#

@dataclass
class AlertHosts:
    """The hosts an alert involves: host names (short and fully qualified) and IPv4 addresses."""
    names: set[tuple[str, Optional[str]]] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)

    def involves(self, target: TargetSnapshot) -> bool:
        for short, qualified in self.names:
            # a fully qualified name must be the target's own when the target has one, as at
            # registration (saq.svs.hosts.match_target)
            if short == target.host and (qualified is None or target.fqdn is None or qualified == target.fqdn):
                return True
        return bool(self.ips & target.ips)

    def involves_run(self, run: RunSnapshot) -> bool:
        return any(self.involves(target) for target in run.targets)


def alert_hosts(root: RootAnalysis) -> AlertHosts:
    """The hostname and fqdn observables (and their subtypes) and the ipv4 observables of an alert."""
    hierarchy = get_type_hierarchy()
    result = AlertHosts()
    for observable in root.all_observables:
        if hierarchy.is_subtype(observable.type, F_HOSTNAME) or hierarchy.is_subtype(observable.type, F_FQDN):
            try:
                result.names.add(split_hostname(str(observable.value)))
            except InvalidTestHost:
                pass
        elif hierarchy.is_subtype(observable.type, F_IPV4):
            try:
                result.ips.add(normalize_ip(str(observable.value)))
            except InvalidTestHost:
                pass
    return result


def event_time_source(root: RootAnalysis) -> EventTimeSource:
    """Where alert_event_time's answer comes from: the event's own time, the time a hunt that couldn't
    extract it ran its query (KEY_EVENT_TIME_FALLBACK), or the alert's insert time."""
    if root.event_time is None:
        return EventTimeSource.INSERT_TIME
    if (root.extensions or {}).get(KEY_EVENT_TIME_FALLBACK) == EVENT_TIME_FALLBACK_QUERY_TIME:
        return EventTimeSource.QUERY_TIME
    return EventTimeSource.EVENT


def alert_event_time(root: RootAnalysis, inserted_at: datetime) -> datetime:
    """When the alert's event happened, as runs record time (naive, local): the root's event time
    (for a hunt, the query's event time), or when the alert was inserted [FR-9]."""
    event_time = root.event_time
    if event_time is None:
        return inserted_at
    if event_time.tzinfo is not None:
        event_time = event_time.astimezone(get_local_timezone()).replace(tzinfo=None)
    return event_time


#
# evaluation
#

@dataclass(frozen=True)
class Detection:
    content_hash: str
    # the observable the detection's node stands for, None for the root
    carrier: Optional[str]
    signature_uuid: str = ""
    signature_family: Optional[str] = None


@dataclass(frozen=True)
class MarkerJudgement:
    marker: str
    result: MarkerResult
    # where the marker was first found
    scan_point: ScanPoint
    run: Optional[RunSnapshot] = None


@dataclass(frozen=True)
class Attribution:
    run: RunSnapshot
    content_hash: str
    confidence: AttributionConfidence
    late: bool
    scan_point: Optional[ScanPoint] = None
    # the detection's signature
    signature_uuid: str = ""
    signature_family: Optional[str] = None


@dataclass(frozen=True)
class ExistingAttribution:
    """An svs_attributions row the router does not own: a person's association, or any removal a
    person made."""
    run_id: int
    content_hash: str
    confidence: AttributionConfidence
    removed: bool


@dataclass
class Evaluation:
    """What attribution makes of an alert."""
    status: Optional[SVSStatus] = None
    detections: list[Detection] = field(default_factory=list)
    judgements: list[MarkerJudgement] = field(default_factory=list)
    # what the router attributes; rows of a person are in existing
    attributions: list[Attribution] = field(default_factory=list)
    existing: list[ExistingAttribution] = field(default_factory=list)
    # set when a context attribution was refused because more than one run could claim the alert
    candidate_runs: list[RunSnapshot] = field(default_factory=list)
    # the alert's event time it was judged by, and where it came from, kept on each attribution
    event_time: Optional[datetime] = None
    event_time_source: Optional[EventTimeSource] = None
    # it has no marker and no attribution, and its event time is in a maintenance window on one of
    # its hosts: it is routed to the test queue and closed (docs/SVS_RUNS.md, *Maintenance windows*)
    maintenance: Optional[MaintenanceSnapshot] = None

    @property
    def mismatches(self) -> list[MarkerJudgement]:
        return [j for j in self.judgements if j.result != MarkerResult.ATTRIBUTED]

    @property
    def runs(self) -> list[RunSnapshot]:
        return list({a.run.id: a.run for a in self.attributions}.values())

    @property
    def confidence(self) -> Optional[AttributionConfidence]:
        if not self.attributions:
            return None
        if all(a.confidence == AttributionConfidence.CONTEXT for a in self.attributions):
            return AttributionConfidence.CONTEXT
        return AttributionConfidence.MARKER

    @property
    def routed(self) -> bool:
        """Every detection is attributed: the alert belongs in the test queue."""
        return self.status in (SVSStatus.TEST, SVSStatus.TEST_CONTEXT)


def alert_detections(root: RootAnalysis) -> list[Detection]:
    """The alert's detections, keyed as their detection_points rows are, except those of the SVS
    built-ins (RUN_SIGNATURES)."""
    result = {}
    for node, detection in root.detection_points_by_node():
        if detection.signature_uuid in RUN_SIGNATURES:
            continue
        content_hash = detection_content_hash(node_identity(node), detection)
        result.setdefault(content_hash, Detection(content_hash, _carrier(node), detection.signature_uuid or "",
                                                  detection.signature_family))
    return list(result.values())


class _Branches:
    """Which observables are above which: a parent map built once over the tree. An observable can
    have more than one parent, and a tree can have cycles."""

    def __init__(self, root: RootAnalysis):
        self.parents: dict[str, set[str]] = {}
        for analysis in root.all_analysis:
            if isinstance(analysis, RootAnalysis) or analysis.observable is None:
                continue
            for child in analysis.observables:
                if child.uuid != analysis.observable.uuid:
                    self.parents.setdefault(child.uuid, set()).add(analysis.observable.uuid)
        self._ancestors: dict[str, set[str]] = {}

    def ancestors(self, uuid: str) -> set[str]:
        if uuid not in self._ancestors:
            seen = set()
            pending = list(self.parents.get(uuid, ()))
            while pending:
                current = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                pending.extend(self.parents.get(current, ()))
            seen.discard(uuid)
            self._ancestors[uuid] = seen
        return self._ancestors[uuid]

    def same_branch(self, a: Optional[str], b: Optional[str]) -> bool:
        """a and b are on one branch: one of them is the root, they are the same observable, or
        one is above the other."""
        if a is None or b is None or a == b:
            return True
        return a in self.ancestors(b) or b in self.ancestors(a)


def removed_by_person(row: SVSAttribution) -> bool:
    """A person removed the row (disassociated the alert, or marked it not a test)."""
    return row.removed_at is not None and row.removed_by_user_id is not None


def _existing(alert_uuid: str) -> tuple[list[ExistingAttribution], set[tuple[int, str]], set[int]]:
    """The rows of a person for this alert; the (run, detection) pairs the router must leave alone
    (a person attributed or removed them); and the runs a person disassociated the alert from, which
    the router never attributes it to again, for any detection."""
    existing = []
    blocked = set()
    disassociated = set()
    associated = set()
    with private_transaction() as session:
        for row in session.execute(select(SVSAttribution).where(SVSAttribution.alert_uuid == alert_uuid)).scalars():
            if row.source == AttributionSource.MANUAL and row.removed_at is None:
                associated.add(row.run_id)
            if row.source == AttributionSource.MANUAL or removed_by_person(row):
                existing.append(ExistingAttribution(row.run_id, row.content_hash,
                                                    AttributionConfidence(row.confidence), row.removed_at is not None))
                blocked.add((row.run_id, row.content_hash))
                if removed_by_person(row):
                    disassociated.add(row.run_id)
    return existing, blocked, disassociated - associated


def context_claimant(candidates: list[RunSnapshot]) -> Optional[RunSnapshot]:
    """The one run that can claim an alert by context among the runs whose windows cover its event
    time on one of its hosts: the only one, or the latest started when every other one's claim on
    its hosts ended before that start. Registration keeps a run from starting on a host another run
    still holds (docs/SVS_RUNS.md, *One run per test host*), and a test that leaves nothing behind
    causes nothing after its claim ends, so the latest run is the one that was on the host. None
    when the claims overlap (runs registered before claims were enforced)."""
    if len(candidates) <= 1:
        return candidates[0] if candidates else None
    latest = max(candidates, key=lambda run: (run.started_at, run.id))
    if all(run.claim_ends_at is not None and run.claim_ends_at < latest.started_at
           for run in candidates if run is not latest):
        return latest
    return None


@dataclass(frozen=True)
class ContextOwner:
    """Who an event with no marker belongs to by its hosts and time: a run, a maintenance window,
    or nobody."""
    # the run context attribution gives it to (context_claimant)
    run: Optional[RunSnapshot] = None
    # the runs whose attribution window covers it on one of its hosts
    candidates: tuple[RunSnapshot, ...] = ()
    # the maintenance window it happened in (docs/SVS_RUNS.md, *Maintenance windows*); no run owns it then
    maintenance: Optional[MaintenanceSnapshot] = None


def context_owners(events: list[tuple[AlertHosts, datetime]]) -> list[ContextOwner]:
    """The owner of each (hosts, event time). Attribution, and a grouped hunt's suppression keys and
    suppressed matches, all decide ownership here so that they never disagree on it. One query for
    all the events."""
    if not events:
        return []
    start, end = min(when for _, when in events), max(when for _, when in events)
    runs = runs_overlapping(start, end)
    windows = maintenance_windows_overlapping(start, end)
    result = []
    for hosts, when in events:
        candidates = tuple(run for run in runs if run.in_window(when) and hosts.involves_run(run))
        window = next((window for window in windows if window.covers(when) and hosts.involves(window.target)), None)
        # no run holds a host while a window on it is open (saq.svs.runs.host_holders), so a run still
        # holding one of the event's hosts holds another one, and the event is the run's. A run whose
        # late attribution window still covers the event ended its claim before the window opened:
        # what happened in the window is the window's.
        if window is not None and not any(run.holds_host_at(when) for run in candidates):
            result.append(ContextOwner(maintenance=window))
        else:
            result.append(ContextOwner(context_claimant(list(candidates)), candidates))
    return result


def suppression_owners(roots: list[RootAnalysis],
                       now: Optional[datetime] = None) -> list[Optional[RunSnapshot | MaintenanceSnapshot]]:
    """For each root a grouped hunt is about to submit, the run or maintenance window that keys its
    suppression: the one context attribution would give it to, by its hosts and event time, or the
    latest started of the runs that could claim it when their claims overlap. None when neither
    covers it on one of its hosts, as for every root while the gate is closed. One query for all the
    roots."""
    if not roots or not attribution_open():
        return [None] * len(roots)

    now = now or datetime.now()
    owners = context_owners([(alert_hosts(root), alert_event_time(root, now)) for root in roots])
    return [owner.maintenance or owner.run
            or max(owner.candidates, key=lambda run: (run.started_at, run.id), default=None)
            for owner in owners]


def suppression_key(owner: RunSnapshot | MaintenanceSnapshot, group_value: str) -> str:
    """The key a grouped hunt's suppression of group_value is recorded under during a run or a
    maintenance window: the first match for each alerts, and neither a test nor a host's staging
    ever suppresses production or a run."""
    kind = "svs_maintenance" if isinstance(owner, MaintenanceSnapshot) else "svs_run"
    return f"{kind}:{owner.uuid}:{group_value}"


def evaluate(root: RootAnalysis, event_time: datetime) -> Evaluation:
    """Judges every marker in the alert against its run and attributes its detections. Reads the
    database, writes nothing; the caller checks the gate (attribution_open) first."""
    evaluation = Evaluation(detections=alert_detections(root), event_time=event_time,
                            event_time_source=event_time_source(root))
    hosts = alert_hosts(root)
    sightings = tree_sightings(root)

    first_scan_point = {}
    for sighting in sightings:
        first_scan_point.setdefault(sighting.marker, sighting.scan_point)

    resolved = resolve_markers(first_scan_point)
    for marker, scan_point in first_scan_point.items():
        run = resolved.get(marker)
        if run is None:
            result = MarkerResult.UNKNOWN
        elif not hosts.involves_run(run):
            result = MarkerResult.OTHER_HOST
        elif not run.in_window(event_time):
            result = MarkerResult.OUTSIDE_WINDOW
        else:
            result = MarkerResult.ATTRIBUTED
        evaluation.judgements.append(MarkerJudgement(marker, result, scan_point, run))

    evaluation.existing, blocked, disassociated = _existing(root.uuid)

    if evaluation.mismatches:
        # a marker that doesn't agree ends attribution for the whole alert [FR-3]
        evaluation.status = SVSStatus.MISMATCH
        return evaluation

    if not evaluation.detections:
        return evaluation

    attributions = {}
    if evaluation.judgements:
        branches = _Branches(root)
        for judgement in evaluation.judgements:
            run = judgement.run
            if run.id in disassociated:
                continue
            for sighting in sightings:
                if sighting.marker != judgement.marker:
                    continue
                for detection in evaluation.detections:
                    key = (run.id, detection.content_hash)
                    if key in attributions or key in blocked:
                        continue
                    if branches.same_branch(sighting.node, detection.carrier):
                        attributions[key] = Attribution(
                            run, detection.content_hash, AttributionConfidence.MARKER, run.is_late(event_time),
                            sighting.scan_point, detection.signature_uuid, detection.signature_family)
    else:
        owner = context_owners([(hosts, event_time)])[0]
        # a person's association still holds
        if owner.maintenance is not None and all(row.removed for row in evaluation.existing):
            evaluation.maintenance = owner.maintenance
            evaluation.status = None
            return evaluation

        run = owner.run
        if run is not None and run.id not in disassociated:
            for detection in evaluation.detections:
                if (run.id, detection.content_hash) not in blocked:
                    attributions[(run.id, detection.content_hash)] = Attribution(
                        run, detection.content_hash, AttributionConfidence.CONTEXT, run.is_late(event_time),
                        signature_uuid=detection.signature_uuid, signature_family=detection.signature_family)
        elif run is None and len(owner.candidates) > 1:
            # attributing to the wrong run teaches the wrong expectation [FR-9]
            evaluation.candidate_runs = list(owner.candidates)

    evaluation.attributions = list(attributions.values())
    evaluation.status = _status(evaluation)
    return evaluation


def _status(evaluation: Evaluation) -> Optional[SVSStatus]:
    confidences: dict[str, set[AttributionConfidence]] = {}
    for attribution in evaluation.attributions:
        confidences.setdefault(attribution.content_hash, set()).add(attribution.confidence)
    for row in evaluation.existing:
        if not row.removed:
            confidences.setdefault(row.content_hash, set()).add(row.confidence)

    return derive_status((d.content_hash for d in evaluation.detections), confidences)


#
# writing (the marker router)
#

@dataclass(frozen=True)
class RemovedAttribution:
    run_id: int
    content_hash: str
    confidence: str
    late: bool


@dataclass
class WriteResult:
    written: list[Attribution] = field(default_factory=list)
    removed: list[RemovedAttribution] = field(default_factory=list)
    # the alert had no rows of the router before this write: its first attribution
    first: bool = False


def write_attributions(alert_uuid: str, evaluation: Evaluation, now: Optional[datetime] = None) -> WriteResult:
    """Brings the router's rows for the alert in line with the evaluation, in a transaction of its
    own: adds new ones, restores ones it removed earlier, and removes the ones that no longer hold.
    Rows of a person are never touched. Logs each change and appends it to its run's event log, a
    change to a reviewed run marks the run changed since review, and every change marks the run's
    result stale. A transaction that deadlocks anyway is run again, up to WRITE_ATTEMPTS times."""
    now = now or datetime.now()
    result, runs, flagged = run_private_transaction(
        _write_attributions, alert_uuid, evaluation, now, attempts=WRITE_ATTEMPTS,
        description=f"svs attributions of alert {alert_uuid}", extra={"alert_uuid": alert_uuid})

    for attribution in result.written:
        logging.info("svs attribution written: alert %s detection %s to run %s", alert_uuid,
                     attribution.content_hash, attribution.run.uuid,
                     extra={**attribution.run.log_fields(), "alert_uuid": alert_uuid,
                            "detection": attribution.content_hash, "confidence": attribution.confidence.value,
                            "late": attribution.late, "source": AttributionSource.ROUTER.value,
                            "scan_point": attribution.scan_point.value if attribution.scan_point else None})
    for row in result.removed:
        run = runs.get(row.run_id)
        logging.info("svs attribution removed: alert %s detection %s from run %s", alert_uuid, row.content_hash,
                     run.uuid if run else row.run_id,
                     extra={**(run.log_fields() if run else {}), "alert_uuid": alert_uuid,
                            "detection": row.content_hash, "confidence": row.confidence, "late": row.late,
                            "source": AttributionSource.ROUTER.value, "reason": REMOVAL_NO_LONGER_APPLIES})
    for run_id in flagged:
        run = runs.get(run_id)
        logging.info("svs run %s changed since review: alert %s", run.uuid if run else run_id, alert_uuid,
                     extra={**(run.log_fields() if run else {}), "alert_uuid": alert_uuid})
    return result


def _lock_runs(session, alert_uuid: str, run_ids: Iterable[int]) -> None:
    """Locks, in id order, the runs a write of the alert's attributions can touch: run_ids and the
    runs of its existing rows. Every attribution row takes a shared lock on its run (the foreign
    key), and marking the run changed or stale needs an exclusive one, so two alerts of one run
    written at once would each hold the first and wait for the second: taken first, the run's lock
    makes them wait their turn instead."""
    session.execute(
        select(SVSRun.id)
        .where(or_(SVSRun.id.in_(sorted(set(run_ids))),
                   SVSRun.id.in_(select(SVSAttribution.run_id).where(SVSAttribution.alert_uuid == alert_uuid))))
        .order_by(SVSRun.id)
        .with_for_update()).all()


def _write_attributions(session, alert_uuid: str, evaluation: Evaluation,
                        now: datetime) -> tuple[WriteResult, dict[int, RunSnapshot], list[int]]:
    """write_attributions' transaction, run again whole when it deadlocks, so it changes nothing
    outside the session. Returns what it changed, the runs involved by id, and the runs it marked
    changed since review."""
    result = WriteResult()
    desired = {(a.run.id, a.content_hash): a for a in evaluation.attributions}
    runs = {a.run.id: a.run for a in evaluation.attributions}

    _lock_runs(session, alert_uuid, runs)
    rows = {(row.run_id, row.content_hash): row for row in session.execute(
        select(SVSAttribution).where(SVSAttribution.alert_uuid == alert_uuid)).scalars()}

    for key, row in rows.items():
        if row.source != AttributionSource.ROUTER or removed_by_person(row):
            continue
        attribution = desired.get(key)
        if attribution is None:
            if row.removed_at is None and _update_own_row(
                    session, row.id, SVSAttribution.removed_at.is_(None), removed_at=now,
                    removed_by=ROUTER_ACTOR, removal_reason=REMOVAL_NO_LONGER_APPLIES):
                result.removed.append(RemovedAttribution(row.run_id, row.content_hash, row.confidence, row.late))
            continue

        values = {}
        if row.removed_at is not None:
            values.update(removed_at=None, removed_by=None, removal_reason=None)
        scan_point = attribution.scan_point.value if attribution.scan_point else None
        if (row.confidence, row.late, row.scan_point) != (attribution.confidence.value, attribution.late, scan_point):
            values.update(confidence=attribution.confidence.value, late=attribution.late, scan_point=scan_point)
        if evaluation.event_time is not None and row.event_time != _to_second(evaluation.event_time):
            values.update(event_time=evaluation.event_time)
        if evaluation.event_time_source is not None and row.event_time_source != evaluation.event_time_source:
            values.update(event_time_source=evaluation.event_time_source.value)
        if values and _update_own_row(session, row.id, **values):
            result.written.append(attribution)

    for key, attribution in desired.items():
        if key in rows:
            continue
        # another process may be writing the same alert (an engine pass racing an insert, or a
        # person associating it); the unique key keeps the row that came first
        inserted = session.execute(mysql_insert(SVSAttribution).prefix_with("IGNORE").values(
            run_id=attribution.run.id, alert_uuid=alert_uuid, content_hash=attribution.content_hash,
            signature_uuid=attribution.signature_uuid, signature_family=attribution.signature_family,
            confidence=attribution.confidence.value, late=attribution.late, event_time=evaluation.event_time,
            event_time_source=evaluation.event_time_source.value if evaluation.event_time_source else None,
            source=AttributionSource.ROUTER.value, scan_point=attribution.scan_point.value if attribution.scan_point else None,
            actor=ROUTER_ACTOR, created_at=now))
        if inserted.rowcount == 1:
            result.written.append(attribution)
    result.first = bool(result.written) and all(row.source != AttributionSource.ROUTER for row in rows.values())

    removed_runs = {row.run_id for row in result.removed} - set(runs)
    if removed_runs:
        for run in _snapshots(session, list(session.execute(
                select(SVSRun).where(SVSRun.id.in_(removed_runs))).scalars())):
            runs[run.id] = run

    _add_attribution_events(session, alert_uuid, result, now)
    touched = {a.run.id for a in result.written} | {row.run_id for row in result.removed}
    flagged = flag_changed_since_review(session, touched)
    mark_runs_stale(session, run_ids=touched)

    return result, runs, flagged


def _to_second(value: datetime) -> datetime:
    """A time as a DateTime column stores it: MySQL rounds a fraction to the nearest second."""
    return (value + timedelta(microseconds=500000)).replace(microsecond=0)


def _update_own_row(session, row_id: int, *conditions, **values) -> bool:
    """Changes one of the router's rows, only while it still is the router's and no person removed
    it: a person may have taken it since it was read."""
    changed = session.execute(
        update(SVSAttribution)
        .where(SVSAttribution.id == row_id, SVSAttribution.source == AttributionSource.ROUTER.value,
               SVSAttribution.removed_by_user_id.is_(None), *conditions)
        .values(**values)
        .execution_options(synchronize_session=False))
    return changed.rowcount == 1


def _add_attribution_events(session, alert_uuid: str, result: WriteResult, now: datetime) -> None:
    """One event per run whose attributions of the alert changed, in the run's event log."""
    written: dict[int, list[dict]] = {}
    for attribution in result.written:
        written.setdefault(attribution.run.id, []).append({
            "detection": attribution.content_hash, "confidence": attribution.confidence.value,
            "late": attribution.late,
            "scan_point": attribution.scan_point.value if attribution.scan_point else None})
    for run_id, detections in written.items():
        session.add(new_run_event(run_id, RunEventKind.ATTRIBUTED, ROUTER_ACTOR, now=now,
                                  details={"alert_uuid": alert_uuid, "detections": detections}))

    removed: dict[int, list[str]] = {}
    for row in result.removed:
        removed.setdefault(row.run_id, []).append(row.content_hash)
    for run_id, detections in removed.items():
        session.add(new_run_event(run_id, RunEventKind.ATTRIBUTION_REMOVED, ROUTER_ACTOR, now=now, details={
            "alert_uuid": alert_uuid, "detections": detections, "reason": REMOVAL_NO_LONGER_APPLIES}))


def flag_changed_since_review(session, run_ids: set[int]) -> list[int]:
    """Marks the reviewed runs among run_ids as changed since review (docs/SVS.md, Part 3: a late
    alert after sign-off returns the run to Needs attention). Returns the runs it marked."""
    flagged = []
    for run_id in sorted(run_ids):
        changed = session.execute(
            update(SVSRun)
            .where(SVSRun.id == run_id, SVSRun.state == RunState.REVIEWED.value,
                   SVSRun.changed_since_review.is_(False))
            .values(changed_since_review=True)
            .execution_options(synchronize_session=False))
        if changed.rowcount:
            flagged.append(run_id)
    return flagged


def log_sightings(alert_uuid: str, evaluation: Evaluation, stage: str) -> None:
    """One record per marker found in the alert, and one for a refused context attribution
    (docs/SVS.md, Part 5, *Logging contract*)."""
    for judgement in evaluation.judgements:
        extra = {"svs_marker": judgement.marker, "alert_uuid": alert_uuid, "scan_point": judgement.scan_point.value,
                 "result": judgement.result.value, "stage": stage}
        if judgement.run is not None:
            extra.update(judgement.run.log_fields())
        if judgement.result == MarkerResult.ATTRIBUTED:
            logging.info("svs marker %s in alert %s: %s", judgement.marker, alert_uuid, judgement.result.value,
                         extra=extra)
        else:
            logging.warning("svs marker %s in alert %s does not match its run: %s", judgement.marker, alert_uuid,
                            judgement.result.value, extra=extra)

    if evaluation.candidate_runs:
        candidates = [run.uuid for run in evaluation.candidate_runs]
        logging.warning("svs context attribution of alert %s refused: %s runs could claim it", alert_uuid,
                        len(candidates), extra={"alert_uuid": alert_uuid, "candidate_runs": candidates,
                                                "stage": stage})


#
# suppressed matches (the hunter)
#

def record_suppressed_matches(hunt_uuid: str, matches: list[tuple[RootAnalysis, str]],
                              now: Optional[datetime] = None) -> list[tuple[RunSnapshot, str]]:
    """Records the runs whose attribution window covers the event time of a match (root, group_value)
    that a hunt with group_by dropped for its suppression, on one of the run's test hosts, and marks
    their results stale: the first match per run and hunt (svs_suppressed_matches). The match goes
    to the run context attribution would give it to (context_claimant), or to each of the runs when
    their claims on the host overlap, since none of them can be told apart. Nothing is read while no
    run is open, and nothing is written for a run and hunt already recorded. Returns the (run,
    group_value) recorded now."""
    if not matches or not attribution_open():
        return []

    now = now or datetime.now()
    times = [alert_event_time(root, now) for root, _ in matches]
    owners = context_owners([(alert_hosts(root), event_time) for (root, _), event_time in zip(matches, times)])
    first: dict[int, tuple[RunSnapshot, str, datetime]] = {}
    for (_, group_value), event_time, owner in sorted(zip(matches, times, owners), key=lambda item: item[1]):
        for run in [owner.run] if owner.run is not None else owner.candidates:
            if run.id not in first:
                first[run.id] = (run, group_value, event_time)
    if not first:
        return []

    with private_transaction() as session:
        recorded = set(session.execute(
            select(SVSSuppressedMatch.run_id)
            .where(SVSSuppressedMatch.hunt_uuid == hunt_uuid, SVSSuppressedMatch.run_id.in_(list(first)))).scalars())
    pending = [first[run_id] for run_id in sorted(first) if run_id not in recorded]
    if not pending:
        return []

    written = run_private_transaction(
        _write_suppressed_matches, hunt_uuid, pending, attempts=WRITE_ATTEMPTS,
        description=f"svs suppressed matches of hunt {hunt_uuid}", extra={"hunt_uuid": hunt_uuid})
    for run, group_value in written:
        logging.info("svs run %s: hunt %s suppressed a match for group_value %s", run.uuid, hunt_uuid, group_value,
                     extra={**run.log_fields(), "hunt_uuid": hunt_uuid, "group_value": group_value})
    return written


def _write_suppressed_matches(session, hunt_uuid: str,
                              pending: list[tuple[RunSnapshot, str, datetime]]) -> list[tuple[RunSnapshot, str]]:
    """record_suppressed_matches' transaction, run again whole when it deadlocks. The runs are
    locked first, in id order, as _lock_runs does for attributions, since marking them stale needs
    them after the rows' foreign keys took a shared lock on them."""
    session.execute(
        select(SVSRun.id).where(SVSRun.id.in_([run.id for run, _, _ in pending]))
        .order_by(SVSRun.id).with_for_update()).all()

    written = []
    for run, group_value, event_time in pending:
        # the hunt's previous execution, or another node's, may have recorded it meanwhile
        inserted = session.execute(mysql_insert(SVSSuppressedMatch).prefix_with("IGNORE").values(
            run_id=run.id, hunt_uuid=hunt_uuid, group_value=group_value, event_time=event_time))
        if inserted.rowcount == 1:
            written.append((run, group_value))

    mark_runs_stale(session, run_ids=[run.id for run, _ in written])
    return written
