"""The identity of a detection: what it says, and which node of the analysis tree it sits on.

A detection is stored as one `detection_points` row per `(alert_id, content_hash)`, and
`docs/SVS.md` (Part 1, *Detection identity*, DP-7) keys every analyst verdict on that same
`content_hash`. The hash therefore folds in the node the detection sits on: without it, detections
whose description does not name their object ("URL has matches on Google Safe Browsing List" on
three URLs) collapse into one row and would share one verdict.

**The formula is frozen.** Changing anything here (the node key, the separators, the details
serialization) re-keys every detection on its next sync and orphans every verdict ever written.
`tests/saq/analysis/test_detection_identity.py` pins it with literal hashes; a change that breaks
that test is a data migration, not a refactor.

Node identity:
- the root: `["root"]`;
- an observable: `["observable", type, value_sha256]`;
- an analysis: `["analysis", module_path, observable type, observable value_sha256]`, where the
  observable is the one the analysis was performed on.

`value_sha256` is the observable's key in the `observables` table (`Observable.sha256_bytes`): the
sha256 of the value for every type except `file`, whose value already is the content sha256 and is
used as it is. Observable uuids are not used, because derived observables get new ones after
`ace alert reset`; two observables with the same type and value but different times therefore
share one identity, as they share one `observables` row.
"""

import json
from dataclasses import dataclass
from typing import Optional

from saq.analysis.analysis import Analysis
from saq.analysis.base_node import BaseNode
from saq.analysis.detection_point import DetectionPoint
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.util import sha256_str

NODE_KIND_ROOT = "root"
NODE_KIND_OBSERVABLE = "observable"
NODE_KIND_ANALYSIS = "analysis"


@dataclass(frozen=True)
class NodeIdentity:
    """The node a detection sits on. For an analysis node, `type` and `value_sha256` describe the
    observable the analysis was performed on."""
    kind: str
    type: Optional[str] = None
    value_sha256: Optional[str] = None
    module_path: Optional[str] = None

    @property
    def key(self) -> str:
        """The canonical rendering of this identity that goes into the content hash."""
        if self.kind == NODE_KIND_ROOT:
            parts = [NODE_KIND_ROOT]
        elif self.kind == NODE_KIND_OBSERVABLE:
            parts = [NODE_KIND_OBSERVABLE, self.type, self.value_sha256]
        elif self.kind == NODE_KIND_ANALYSIS:
            parts = [NODE_KIND_ANALYSIS, self.module_path, self.type, self.value_sha256]
        else:
            raise ValueError(f"unknown node kind {self.kind!r}")

        return json.dumps(parts, separators=(",", ":"))


def observable_value_sha256(observable: Observable) -> str:
    """Returns the hex key of an observable's value, as the `observables` table stores it."""
    return observable.sha256_bytes.hex()


def node_identity(node: BaseNode) -> NodeIdentity:
    """Returns the identity of an analysis tree node (a RootAnalysis, an Analysis or an Observable)."""
    # RootAnalysis is an Analysis, so it is tested first
    if isinstance(node, RootAnalysis):
        return NodeIdentity(kind=NODE_KIND_ROOT)

    if isinstance(node, Observable):
        return NodeIdentity(
            kind=NODE_KIND_OBSERVABLE,
            type=node.type,
            value_sha256=observable_value_sha256(node))

    if isinstance(node, Analysis):
        observable = node.observable
        return NodeIdentity(
            kind=NODE_KIND_ANALYSIS,
            type=observable.type if observable is not None else None,
            value_sha256=observable_value_sha256(observable) if observable is not None else None,
            module_path=node.module_path)

    raise TypeError(f"cannot compute the node identity of {type(node).__name__}")


def detection_details_json(detection: DetectionPoint) -> Optional[str]:
    """Returns the canonical JSON of a detection's details, or None when it has none. This is both
    what goes into the content hash and what is stored in `detection_points.details`."""
    if not detection.details:
        return None

    return json.dumps(detection.details, sort_keys=True, default=str)


def detection_content_hash(identity: NodeIdentity, detection: DetectionPoint) -> str:
    """Returns the content hash of a detection on the node with the given identity: the key of its
    `detection_points` row and of any verdict on it."""
    return sha256_str(
        identity.key + "\n"
        + detection.signature_uuid + "\n"
        + str(detection.description) + "\n"
        + (detection_details_json(detection) or ""))
