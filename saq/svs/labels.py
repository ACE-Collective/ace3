"""The label of a sample: its TP/FP grade for one rule (docs/SVS.md, Part 2, *Labels*).

A sample is one (file sha256, rule uuid) pair of svs_yara_captures. Its label is never stored. It
is aggregated, when it is read, from the effective verdicts (saq.detection_verdicts.effective) of
its **contributing detections**: on each alert a capture of the pair came from, the detections of
that rule on a file node with that sha256. Every capture row contributes, whatever its state.

Each contributing detection with a verdict casts one vote of one strength, its verdict source.
The strongest strength that has any vote decides:

```
label(votes) =
    NULL, NULL              if no detection has a verdict
    tp, strength            if only TP votes at the strongest strength present
    fp, strength            if only FP votes there
    conflicted, strength    if both: the newest vote never silently wins
```

with explicit > inherited_single > inherited_multi. So an analyst's override outweighs any number
of inherited votes, and an FP alert (whose detections are inherited_single) outweighs an
unconfirmed TP from an alert where several signatures fired.

What casts no vote: a detection without a verdict (an unclassified alert, or one attributed to a
test run that is not Reviewed), and the detections of a deleted alert, which are gone with it.
The same bytes under two names in one alert are two detections, so two votes.

The rule exists twice, as SQL for listings and filters and as aggregate_label() in Python, and the
tests check that the two agree. Nothing else may restate it.
"""

from dataclasses import dataclass, fields
from typing import Optional

from sqlalchemy import Select, and_, case, func, literal, select
from sqlalchemy.sql.elements import ColumnElement

from saq.analysis.detection_identity import NODE_KIND_OBSERVABLE
from saq.constants import F_FILE
from saq.database.model import Alert, DetectionPoint, DetectionPointVerdict, SVSYaraCapture
from saq.detection_verdicts.constants import (
    SOURCE_EXPLICIT,
    SOURCE_INHERITED_MULTI,
    SOURCE_INHERITED_SINGLE,
    VERDICT_FP,
    VERDICT_TP,
)
from saq.detection_verdicts.effective import (
    effective_verdict_expr,
    verdict_join_condition,
    verdict_source_expr,
)
from saq.svs.constants import LABEL_CONFLICTED, LABEL_FP, LABEL_TP

# strongest first
STRENGTHS = (SOURCE_EXPLICIT, SOURCE_INHERITED_SINGLE, SOURCE_INHERITED_MULTI)


@dataclass(frozen=True)
class Votes:
    """The votes of a sample's contributing detections, per verdict and strength."""
    tp_explicit: int = 0
    fp_explicit: int = 0
    tp_inherited_single: int = 0
    fp_inherited_single: int = 0
    tp_inherited_multi: int = 0
    fp_inherited_multi: int = 0

    def count(self, verdict: str, strength: str) -> int:
        return getattr(self, f"{verdict}_{strength}")

    def as_dict(self) -> dict[str, int]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


# the vote columns, in Votes' field order: (column name, verdict, strength)
VOTE_COLUMNS = tuple(
    (f"{verdict}_{strength}", verdict, strength)
    for strength in STRENGTHS
    for verdict in (VERDICT_TP, VERDICT_FP))


def aggregate_label(votes: Votes) -> tuple[Optional[str], Optional[str]]:
    """Returns (label, source) for a sample's votes: the Python form of the rule."""
    for strength in STRENGTHS:
        tp = votes.count(VERDICT_TP, strength)
        fp = votes.count(VERDICT_FP, strength)
        if tp and fp:
            return LABEL_CONFLICTED, strength
        if tp:
            return LABEL_TP, strength
        if fp:
            return LABEL_FP, strength

    return None, None


# --- SQL ---------------------------------------------------------------------------------------


def contributing_detection_condition(capture, dp) -> ColumnElement[bool]:
    """The ON clause that joins a capture to its contributing detections, given its alert is
    already joined on alerts.uuid = capture.alert_uuid (dp.alert_id = alerts.id is the caller's).
    Served by ix_detection_points_alert_signature."""
    return and_(
        dp.signature_uuid == capture.rule_uuid,
        dp.node_kind == NODE_KIND_OBSERVABLE,
        dp.node_type == F_FILE,
        dp.node_value_sha256 == capture.sha256)


def contributing_votes_select() -> Select:
    """One row per contributing detection of every capture, with its effective verdict and source
    (NULL when it casts no vote)."""
    return (
        select(
            SVSYaraCapture.id.label("capture_id"),
            SVSYaraCapture.sha256,
            SVSYaraCapture.rule_uuid,
            DetectionPoint.alert_id,
            DetectionPoint.content_hash,
            effective_verdict_expr(Alert, DetectionPoint, DetectionPointVerdict).label("verdict"),
            verdict_source_expr(Alert, DetectionPoint, DetectionPointVerdict).label("verdict_source"),
        )
        .select_from(SVSYaraCapture)
        .join(Alert, Alert.uuid == SVSYaraCapture.alert_uuid)
        .join(DetectionPoint, and_(
            DetectionPoint.alert_id == Alert.id,
            contributing_detection_condition(SVSYaraCapture, DetectionPoint)))
        .outerjoin(DetectionPointVerdict, verdict_join_condition(DetectionPoint, DetectionPointVerdict)))


def sample_votes_subquery():
    """The votes of every sample that has any contributing detection: one row per (sha256,
    rule_uuid) with one count column per VOTE_COLUMNS entry."""
    votes = contributing_votes_select().subquery("contributing_votes")
    counts = [
        func.coalesce(func.sum(case(
            (and_(votes.c.verdict == verdict, votes.c.verdict_source == strength), 1),
            else_=0)), 0).label(name)
        for name, verdict, strength in VOTE_COLUMNS
    ]
    return (
        select(votes.c.sha256, votes.c.rule_uuid, *counts)
        .group_by(votes.c.sha256, votes.c.rule_uuid)
        .subquery("sample_votes"))


def _count(columns, verdict: str, strength: str) -> ColumnElement:
    # a sample with no contributing detection has no sample_votes row: its counts are NULL
    return func.coalesce(columns[f"{verdict}_{strength}"], 0)


def label_expr(columns) -> ColumnElement:
    """The label from the vote count columns (a sample_votes_subquery() row, possibly NULL):
    'tp', 'fp', 'conflicted' or NULL."""
    whens = []
    for strength in STRENGTHS:
        tp = _count(columns, VERDICT_TP, strength)
        fp = _count(columns, VERDICT_FP, strength)
        whens += [
            (and_(tp > 0, fp > 0), literal(LABEL_CONFLICTED)),
            (tp > 0, literal(LABEL_TP)),
            (fp > 0, literal(LABEL_FP)),
        ]
    return case(*whens, else_=None)


def label_source_expr(columns) -> ColumnElement:
    """The strength that decided the label, or NULL with no label."""
    whens = [
        (_count(columns, VERDICT_TP, strength) + _count(columns, VERDICT_FP, strength) > 0, literal(strength))
        for strength in STRENGTHS
    ]
    return case(*whens, else_=None)
