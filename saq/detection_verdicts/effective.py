"""The effective verdict of a detection, and why it is what it is (docs/SVS.md, Part 1).

Only what an analyst explicitly said is stored (`detection_point_verdicts`). Every other verdict
is derived when it is read, from the alert's disposition class (saq/disposition.py):

```
effective(dp) =
    NULL                    if class(alert.disposition) is unclassified
    NULL                    if the alert is attributed to a test run that is not Reviewed
    FP   inherited_single   if class(alert.disposition) == fp      # overrides are masked
    override  explicit      if an override row exists              # tp alerts only
    TP   inherited_single   if the alert has detections from one signature only
    TP   inherited_multi    otherwise
```

On an FP alert the alert-level statement covers each detection directly, so its source is
`inherited_single`: an FP alert never has unconfirmed detections, and its FP labels are not
weakened when sample labels are aggregated (docs/SVS.md, Part 2, *Labels*).

The rule exists twice, as SQL expressions for listings and filters and as `compute_effective()`
in Python, and the tests check that the two agree. Nothing else may restate it.
"""

from typing import Optional

from sqlalchemy import and_, case, exists, false, literal, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from saq.configuration.config import get_config
from saq.database.model import DetectionPoint
from saq.disposition import DISPOSITION_CLASS_FP, DISPOSITION_CLASS_TP

VERDICT_TP = "tp"
VERDICT_FP = "fp"
VERDICTS = (VERDICT_TP, VERDICT_FP)

# an analyst set it, or confirmed an inherited TP
SOURCE_EXPLICIT = "explicit"
# inherited from the alert, which stated it for this detection: an FP alert, or a TP alert all of
# whose detections come from one signature
SOURCE_INHERITED_SINGLE = "inherited_single"
# inherited TP on an alert where several signatures fired, which nobody has confirmed: the weakest
# source, reported separately (docs/SVS.md, DP-2)
SOURCE_INHERITED_MULTI = "inherited_multi"
SOURCES = (SOURCE_EXPLICIT, SOURCE_INHERITED_SINGLE, SOURCE_INHERITED_MULTI)


def disposition_class_lists() -> tuple[list[str], list[str]]:
    """Returns (tp dispositions, fp dispositions) from the configuration, read on each call."""
    classification = get_config().disposition_classification
    tp = sorted(name for name, cls in classification.items() if cls == DISPOSITION_CLASS_TP)
    fp = sorted(name for name, cls in classification.items() if cls == DISPOSITION_CLASS_FP)
    return tp, fp


def compute_effective(
    disposition_class: Optional[str],
    override: Optional[str],
    multi_signature: bool,
    unreviewed_run: bool = False,
) -> tuple[Optional[str], Optional[str]]:
    """Returns (verdict, source) for one detection: the Python form of the rule.

    disposition_class is the alert's (get_disposition_class), override the stored verdict or None,
    multi_signature whether the alert has detections from more than one signature, and
    unreviewed_run whether the alert is attributed to a test run that is not Reviewed."""
    if disposition_class not in (DISPOSITION_CLASS_TP, DISPOSITION_CLASS_FP):
        return None, None

    if unreviewed_run:
        return None, None

    if disposition_class == DISPOSITION_CLASS_FP:
        return VERDICT_FP, SOURCE_INHERITED_SINGLE

    if override is not None:
        return override, SOURCE_EXPLICIT

    return VERDICT_TP, SOURCE_INHERITED_MULTI if multi_signature else SOURCE_INHERITED_SINGLE


# --- SQL ---------------------------------------------------------------------------------------
#
# Each expression takes the entities (or aliases) of the alert, the detection point and its
# LEFT JOINed verdict row:
#
#   detection_points dp
#   JOIN alerts a ON a.id = dp.alert_id
#   LEFT JOIN detection_point_verdicts v ON v.alert_id = dp.alert_id AND v.content_hash = dp.content_hash


def verdict_join_condition(dp, verdict) -> ColumnElement[bool]:
    """The ON clause that LEFT JOINs a detection to its stored verdict."""
    return and_(verdict.alert_id == dp.alert_id, verdict.content_hash == dp.content_hash)


def unreviewed_run_condition(alert) -> ColumnElement[bool]:
    """True when the alert is attributed to a test run that is not Reviewed, which gives it no
    verdicts. Test runs do not exist yet: phase 4 replaces this with the join from
    svs_attributions to svs_runs.state."""
    return false()


def other_signature_exists(dp) -> ColumnElement[bool]:
    """True when the detection's alert also has a detection from another signature. Answered from
    ix_detection_points_alert_signature."""
    other = aliased(DetectionPoint)
    return exists(
        select(literal(1))
        .where(other.alert_id == dp.alert_id)
        .where(other.signature_uuid != dp.signature_uuid))


def _class_conditions(alert) -> tuple[ColumnElement[bool], ColumnElement[bool]]:
    tp, fp = disposition_class_lists()
    return alert.disposition.in_(tp), alert.disposition.in_(fp)


def effective_verdict_expr(alert, dp, verdict) -> ColumnElement:
    """The detection's effective verdict: 'tp', 'fp' or NULL."""
    is_tp, is_fp = _class_conditions(alert)
    return case(
        (unreviewed_run_condition(alert), None),
        (is_fp, literal(VERDICT_FP)),
        (and_(is_tp, verdict.verdict.is_not(None)), verdict.verdict),
        (is_tp, literal(VERDICT_TP)),
        else_=None)


def verdict_source_expr(alert, dp, verdict) -> ColumnElement:
    """Why the effective verdict is what it is: one of SOURCES, or NULL with no verdict."""
    is_tp, is_fp = _class_conditions(alert)
    return case(
        (unreviewed_run_condition(alert), None),
        (is_fp, literal(SOURCE_INHERITED_SINGLE)),
        (and_(is_tp, verdict.verdict.is_not(None)), literal(SOURCE_EXPLICIT)),
        (and_(is_tp, other_signature_exists(dp)), literal(SOURCE_INHERITED_MULTI)),
        (is_tp, literal(SOURCE_INHERITED_SINGLE)),
        else_=None)

