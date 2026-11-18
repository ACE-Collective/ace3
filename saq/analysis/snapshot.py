"""Snapshot capture and diff computation for module execution tracking.

A ModuleExecutionSnapshot freezes the mutable state of an observable (and
optionally all observables) before and after a module runs. Diffing two
snapshots produces a ModuleExecutionDelta that records exactly what the
module changed.
"""

from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Optional, TYPE_CHECKING

from saq.analysis.module_execution_delta import (
    AnalysisChildrenDiff,
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.constants import F_FILE

if TYPE_CHECKING:
    from saq.analysis.observable import Observable
    from saq.analysis.root import RootAnalysis
    from saq.modules.base_module import AnalysisModule


def _detection_identity(detection) -> tuple:
    """Stable identity for a DetectionPoint, suitable for set operations."""
    return (detection.description, str(detection.details))


def _relationship_identity(rel) -> tuple:
    """Stable identity for a Relationship."""
    target_uuid = rel.target.uuid if isinstance(rel.target, Observable) else rel.target
    return (rel.r_type, target_uuid)


def _serialize_detection(detection) -> dict:
    return detection.json


def _serialize_relationship(rel) -> dict:
    """Serialize a Relationship for a delta, enriched with the target's
    (type, value, time) spec.

    ``rel.json`` carries only the target's uuid, which is per-alert — a
    cache replay onto a *different* root can never resolve it. The spec
    fields let replay re-resolve the target via
    ``root.get_observable_by_spec`` (see ``cache._apply_observable_diff``).
    The base ``{"type", "target"}`` shape is unchanged so root.json
    attribution stays backward compatible.
    """
    result = dict(rel.json)
    target = rel.target
    if isinstance(target, Observable):
        result["target_type"] = target.type
        result["target_value"] = target.value
        if target.time is not None:
            result["target_time"] = (
                target.time.isoformat()
                if isinstance(target.time, datetime)
                else str(target.time)
            )
    return result


@dataclass
class _ObservableState:
    """Frozen snapshot of one observable's mutable fields."""
    uuid: str
    tags: frozenset
    detection_ids: frozenset  # frozenset of _detection_identity tuples
    detections_by_id: dict  # identity -> detection object
    directives: frozenset
    relationship_ids: frozenset  # frozenset of _relationship_identity tuples
    relationships_by_id: dict  # identity -> relationship object
    excluded_analysis: frozenset
    limited_analysis: frozenset
    grouping_target: bool
    redirection: Optional[str]  # UUID string or None
    ignored: bool
    analysis_keys: frozenset  # set of module_path keys in observable._analysis
    # Phase 3 (Step 3.0): per-analysis `delayed` flag at capture time, used
    # to detect delayed→completed transitions on existing analysis slots.
    # Without this, delayed-analysis modules (e.g. phishkit) could never be
    # cached because the snapshot only captures the analysis dict on slot
    # transitions absent→present, missing the post-delay completion.
    analysis_delayed: dict  # module_path -> bool (only present analyses)

    @classmethod
    def capture(cls, observable: "Observable") -> "_ObservableState":
        detection_ids = set()
        detections_by_id = {}
        for d in observable.detections:
            ident = _detection_identity(d)
            detection_ids.add(ident)
            detections_by_id[ident] = d

        rel_ids = set()
        rels_by_id = {}
        for r in observable._relationships:
            ident = _relationship_identity(r)
            rel_ids.add(ident)
            rels_by_id[ident] = r

        analysis_delayed = {}
        for module_path, a in observable._analysis.items():
            # Skip bool sentinels (False = "module ran, no analysis").
            if not isinstance(a, bool) and a is not None:
                analysis_delayed[module_path] = bool(getattr(a, "delayed", False))

        return cls(
            uuid=observable.uuid,
            tags=frozenset(observable.tags),
            detection_ids=frozenset(detection_ids),
            detections_by_id=detections_by_id,
            directives=frozenset(observable._directives),
            relationship_ids=frozenset(rel_ids),
            relationships_by_id=rels_by_id,
            excluded_analysis=frozenset(observable._excluded_analysis),
            limited_analysis=frozenset(observable._limited_analysis),
            grouping_target=observable._grouping_target,
            redirection=observable._redirection,
            ignored=observable._ignored,
            analysis_keys=frozenset(observable._analysis.keys()),
            analysis_delayed=analysis_delayed,
        )


@dataclass
class ModuleExecutionSnapshot:
    """Frozen state of the analysis tree at one point in time.

    Use narrow() for typical modules (captures only the target observable + root).
    Use wide() for modules with wide_diff=True (captures all observables).
    """

    # The target observable state (always captured)
    target_observable: _ObservableState

    # Root-level state
    root_observable_uuids: frozenset
    root_tags: frozenset
    root_detection_ids: frozenset
    root_detections_by_id: dict

    # uuid of the root analysis this snapshot was captured against —
    # denormalized onto the resulting delta for log/cache provenance.
    root_uuid: str = ""

    # Wide-diff: states of all other observables (empty for narrow snapshots)
    other_observables: dict[str, _ObservableState] = field(default_factory=dict)

    # Wide-diff: each Analysis's child observable UUIDs
    # Key: (parent_observable_uuid, analysis_module_path) -> frozenset of child UUIDs
    analysis_children: dict[tuple, frozenset] = field(default_factory=dict)

    @classmethod
    def narrow(cls, root: "RootAnalysis", observable: "Observable", module: "AnalysisModule") -> "ModuleExecutionSnapshot":
        """Capture a narrow snapshot: just the target observable + root state."""
        root_det_ids = set()
        root_dets_by_id = {}
        for d in root.detections:
            ident = _detection_identity(d)
            root_det_ids.add(ident)
            root_dets_by_id[ident] = d

        return cls(
            target_observable=_ObservableState.capture(observable),
            root_observable_uuids=frozenset(o.uuid for o in root.all_observables),
            root_tags=frozenset(root.tags),
            root_detection_ids=frozenset(root_det_ids),
            root_detections_by_id=root_dets_by_id,
            root_uuid=root.uuid,
        )

    @classmethod
    def wide(cls, root: "RootAnalysis", observable: "Observable", module: "AnalysisModule") -> "ModuleExecutionSnapshot":
        """Capture a wide snapshot: all observables + root state + analysis children."""
        root_det_ids = set()
        root_dets_by_id = {}
        for d in root.detections:
            ident = _detection_identity(d)
            root_det_ids.add(ident)
            root_dets_by_id[ident] = d

        other_observables = {}
        for obs in root.all_observables:
            if obs.uuid != observable.uuid:
                other_observables[obs.uuid] = _ObservableState.capture(obs)

        # Capture each Analysis's child observable UUIDs
        analysis_children = {}
        for analysis in root.all_analysis:
            if hasattr(analysis, 'module_path') and analysis.module_path:
                # Find the observable that owns this analysis
                parent_uuid = _find_analysis_parent_uuid(root, analysis)
                if parent_uuid is not None:
                    key = (parent_uuid, analysis.module_path)
                    analysis_children[key] = frozenset(
                        o.uuid for o in analysis._observables
                    )

        return cls(
            target_observable=_ObservableState.capture(observable),
            root_observable_uuids=frozenset(o.uuid for o in root.all_observables),
            root_tags=frozenset(root.tags),
            root_detection_ids=frozenset(root_det_ids),
            root_detections_by_id=root_dets_by_id,
            root_uuid=root.uuid,
            other_observables=other_observables,
            analysis_children=analysis_children,
        )

    @staticmethod
    def diff(
        before: "ModuleExecutionSnapshot",
        after: "ModuleExecutionSnapshot",
        module: "AnalysisModule",
        observable: "Observable",
        is_resuming_delayed_module: bool = False,
    ) -> ModuleExecutionDelta:
        """Compute the delta between two snapshots.

        ``is_resuming_delayed_module`` is the executor's signal that this cycle
        is the resumption of a delayed-analysis module's own delay (see the
        analysis-capture note below).
        """
        target_diff = _diff_observable_state(before.target_observable, after.target_observable)

        # New observables added to the root
        new_obs_uuids = after.root_observable_uuids - before.root_observable_uuids
        new_observables = []
        if new_obs_uuids:
            for obs in observable.analysis_tree_manager.all_observables:
                if obs.uuid in new_obs_uuids:
                    time_str = None
                    if obs._time is not None:
                        time_str = obs._time.isoformat() if isinstance(obs._time, datetime) else str(obs._time)
                    new_observables.append(ObservableSpec(
                        uuid=obs.uuid,
                        type=obs._type,
                        value=obs.value,
                        time=time_str,
                        initial_tags=list(obs.tags),
                        initial_directives=list(obs._directives),
                        initial_detections=[_serialize_detection(d) for d in obs.detections],
                        initial_excluded_analysis=list(obs._excluded_analysis),
                        initial_limited_analysis=list(obs._limited_analysis),
                        # Phase 4 fidelity: file identity for blob-backed
                        # replay, plus the state a module commonly sets on a
                        # file it creates (OCR/QR set volatile, an
                        # R_EXTRACTED_FROM relationship, and redirection).
                        # file_path is duck-typed rather than
                        # isinstance(FileObservable) to keep this module free
                        # of saq.observables imports.
                        file_path=getattr(obs, "file_path", None) if obs._type == F_FILE else None,
                        volatile=obs.volatile,
                        initial_relationships=[
                            _serialize_relationship(r) for r in obs._relationships
                        ],
                        initial_redirection=obs._redirection,
                    ))

        # Root-level diff
        root_diff = _diff_root_state(before, after)

        # Compute module path — capture analysis_dict in two cases:
        #   (1) slot transitioned absent→present (the original case)
        #   (2) slot present in both, and the delayed-analysis module just
        #       completed (delayed→completed — Phase 3 Step 3.0)
        # Without case (2), delayed-analysis modules emit a captured analysis
        # only on the partial first call (which is refused at cache write
        # time because delayed=True), and the final post-delay completion
        # produces an empty analysis_dict.
        #
        # Case (2) cannot rely on observing `delayed` flip True→False within
        # this snapshot window: the orchestrator resets analysis.delayed=False
        # when it loads the DelayedAnalysisRequest, *before* the executor takes
        # this resuming cycle's before-snapshot (analysis_orchestrator.py). So
        # the before-snapshot already shows delayed=False and the transition is
        # invisible here. We therefore key off the executor's
        # is_resuming_delayed_module signal: on the completing cycle the slot is
        # present and no longer delayed → capture. A still-delayed intermediate
        # re-check (module re-delayed) has is_delayed=True → not captured.
        module_path = _get_module_path(module)
        analysis_dict = None
        if module_path is not None:
            before_present = module_path in before.target_observable.analysis_keys
            after_present = module_path in after.target_observable.analysis_keys
            capture = False
            if not before_present and after_present:
                capture = True
            elif before_present and after_present:
                was_delayed = before.target_observable.analysis_delayed.get(module_path, False)
                is_delayed = after.target_observable.analysis_delayed.get(module_path, False)
                capture = (was_delayed and not is_delayed) or (
                    is_resuming_delayed_module and not is_delayed
                )
            if capture:
                analysis_obj = observable.get_analysis(module_path)
                if analysis_obj and analysis_obj is not None and analysis_obj is not False:
                    analysis_dict = _serialize_analysis(analysis_obj)

        # Wide-diff: compute diffs for other observables
        other_diffs = {}
        if before.other_observables or after.other_observables:
            all_uuids = set(before.other_observables.keys()) | set(after.other_observables.keys())
            for uuid in all_uuids:
                before_state = before.other_observables.get(uuid)
                after_state = after.other_observables.get(uuid)
                if before_state is None or after_state is None:
                    # Observable was added or removed — handled by new_observables
                    continue
                diff = _diff_observable_state(before_state, after_state)
                if not diff.is_empty:
                    other_diffs[uuid] = diff

        # Wide-diff: compute analysis children diffs
        analysis_children_diffs = []
        if before.analysis_children or after.analysis_children:
            all_keys = set(before.analysis_children.keys()) | set(after.analysis_children.keys())
            for key in all_keys:
                before_children = before.analysis_children.get(key, frozenset())
                after_children = after.analysis_children.get(key, frozenset())
                added = after_children - before_children
                removed = before_children - after_children
                if added or removed:
                    parent_uuid, a_module_path = key
                    analysis_children_diffs.append(AnalysisChildrenDiff(
                        analysis_module_path=a_module_path,
                        parent_observable_uuid=parent_uuid,
                        added_child_uuids=sorted(added),
                        removed_child_uuids=sorted(removed),
                    ))

        now = datetime.now(UTC)
        return ModuleExecutionDelta(
            module_path=module_path or module.config.name,
            module_instance=module.instance,
            module_version=module.version,
            observable_uuid=observable.uuid,
            observable_type=observable._type,
            observable_value=observable.value,
            created_at=now.isoformat(),
            root_uuid=after.root_uuid or before.root_uuid,
            analysis=analysis_dict,
            target_observable_diff=target_diff,
            new_observables=new_observables,
            root_diff=root_diff,
            wide_diff=bool(before.other_observables or after.other_observables),
            other_observable_diffs=other_diffs,
            analysis_children_diffs=analysis_children_diffs,
        )


def _find_analysis_parent_uuid(root, analysis) -> Optional[str]:
    """Find the UUID of the observable that owns a given Analysis.

    Each Analysis is stored in an Observable's _analysis dict. We need to find
    which observable holds this analysis to build a stable key.
    """
    for obs in root.all_observables:
        for module_path, a in obs._analysis.items():
            if a is analysis:
                return obs.uuid
    # Analysis might be on the root itself
    return root.uuid


def _get_module_path(module) -> Optional[str]:
    """Get the module path string from an analysis module.

    Uses MODULE_PATH when possible, falls back to config.name for non-standard
    module objects (e.g., in tests).
    """
    try:
        return MODULE_PATH(module)
    except (AssertionError, AttributeError, TypeError):
        return getattr(getattr(module, 'config', None), 'name', None)


def _diff_observable_state(before: _ObservableState, after: _ObservableState) -> ObservableDiff:
    """Compute an ObservableDiff from two _ObservableState snapshots."""
    diff = ObservableDiff()

    # Tags
    added_tags = after.tags - before.tags
    removed_tags = before.tags - after.tags
    if added_tags:
        diff.added_tags = sorted(added_tags)
    if removed_tags:
        diff.removed_tags = sorted(removed_tags)

    # Detections
    added_det_ids = after.detection_ids - before.detection_ids
    removed_det_ids = before.detection_ids - after.detection_ids
    if added_det_ids:
        diff.added_detections = [
            _serialize_detection(after.detections_by_id[ident])
            for ident in sorted(added_det_ids)
        ]
    if removed_det_ids:
        diff.removed_detections = [
            _serialize_detection(before.detections_by_id[ident])
            for ident in sorted(removed_det_ids)
        ]

    # Directives
    added_dirs = after.directives - before.directives
    removed_dirs = before.directives - after.directives
    if added_dirs:
        diff.added_directives = sorted(added_dirs)
    if removed_dirs:
        diff.removed_directives = sorted(removed_dirs)

    # Relationships
    added_rels = after.relationship_ids - before.relationship_ids
    removed_rels = before.relationship_ids - after.relationship_ids
    if added_rels:
        diff.added_relationships = [
            _serialize_relationship(after.relationships_by_id[ident])
            for ident in sorted(added_rels)
        ]
    if removed_rels:
        diff.removed_relationships = [
            _serialize_relationship(before.relationships_by_id[ident])
            for ident in sorted(removed_rels)
        ]

    # Excluded analysis
    added_excl = after.excluded_analysis - before.excluded_analysis
    removed_excl = before.excluded_analysis - after.excluded_analysis
    if added_excl:
        diff.added_excluded_analysis = sorted(added_excl)
    if removed_excl:
        diff.removed_excluded_analysis = sorted(removed_excl)

    # Limited analysis
    added_lim = after.limited_analysis - before.limited_analysis
    removed_lim = before.limited_analysis - after.limited_analysis
    if added_lim:
        diff.added_limited_analysis = sorted(added_lim)
    if removed_lim:
        diff.removed_limited_analysis = sorted(removed_lim)

    # Scalar transitions
    if before.grouping_target != after.grouping_target:
        diff.grouping_target = (before.grouping_target, after.grouping_target)
    if before.redirection != after.redirection:
        diff.redirection = (before.redirection, after.redirection)
    if before.ignored != after.ignored:
        diff.ignored = (before.ignored, after.ignored)

    return diff


def _diff_root_state(before: ModuleExecutionSnapshot, after: ModuleExecutionSnapshot) -> RootDiff:
    """Compute root-level tag/detection changes."""
    diff = RootDiff()

    added_tags = after.root_tags - before.root_tags
    removed_tags = before.root_tags - after.root_tags
    if added_tags:
        diff.added_tags = sorted(added_tags)
    if removed_tags:
        diff.removed_tags = sorted(removed_tags)

    added_det_ids = after.root_detection_ids - before.root_detection_ids
    removed_det_ids = before.root_detection_ids - after.root_detection_ids
    if added_det_ids:
        diff.added_detections = [
            _serialize_detection(after.root_detections_by_id[ident])
            for ident in sorted(added_det_ids)
        ]
    if removed_det_ids:
        diff.removed_detections = [
            _serialize_detection(before.root_detections_by_id[ident])
            for ident in sorted(removed_det_ids)
        ]

    return diff


def _serialize_analysis(analysis) -> dict:
    """Serialize an Analysis object to a dict for storage in a delta.

    Captures the key fields plus the in-memory ``details`` dict so cache
    replay on a *different* alert's root can reconstruct the analysis
    without reading from the source alert's storage_dir. Does NOT capture
    child observables (those are tracked separately as ``new_observables``
    on the delta).

    Ordering invariant: this runs inside ``ModuleExecutionSnapshot.diff``
    *before* ``root.save()``, so ``analysis.details`` is still in memory
    and has not been flushed/discarded by the persistence manager.
    """
    result = {
        "module_path": analysis.module_path,
    }
    if hasattr(analysis, "summary") and analysis.summary is not None:
        result["summary"] = analysis.summary
    if hasattr(analysis, "summary_details") and analysis.summary_details:
        # Convert SummaryDetail objects to dicts so json.dumps doesn't
        # fall back to default=str (which would silently corrupt them).
        # AnalysisSerializer.deserialize reads dicts and converts back.
        result["summary_details"] = [d.to_dict() for d in analysis.summary_details]
    if hasattr(analysis, "completed"):
        result["completed"] = analysis.completed
    if hasattr(analysis, "delayed"):
        result["delayed"] = analysis.delayed
    if getattr(analysis, "error", None) is not None:
        result["error"] = analysis.error
    if hasattr(analysis, "external_details_path") and analysis.external_details_path is not None:
        result["external_details_path"] = analysis.external_details_path
    # Capture tags set on the Analysis object itself (analysis.add_tag).
    # Replay restores them through the ``analysis.json`` setter →
    # AnalysisSerializer.deserialize → BaseNode.set_json_data path. Copy
    # the list so the captured dict is isolated from later in-process
    # mutation of the live analysis. NOTE analysis-object detection
    # points, pivot_links, and llm_context_documents are deliberately NOT
    # captured yet — detections need DetectionPoint object handling in
    # set_json_data; revisit if a cacheable module starts using them.
    if getattr(analysis, "tags", None):
        result["tags"] = list(analysis.tags)
    # Capture the live in-memory details dict so cache replay can
    # rehydrate it on a different alert's storage_dir. Step 3.1 — without
    # this, Phase 2's ``_maybe_spill_details`` codepath was dead and cache
    # rows carried no usable payload.
    if hasattr(analysis, "details") and isinstance(analysis.details, dict):
        result["details"] = analysis.details
    return result
