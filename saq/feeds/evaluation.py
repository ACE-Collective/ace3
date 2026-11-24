"""The evaluation of a watch against analysts' labels (docs/FEED_WATCHES.md, *Evaluation*).

A label says whether an entry version is relevant to a watch. It comes from the replay page, or from the
disposition of the alert a watch's decision delivered: RELEVANT or NOT_RELEVANT. The replay page's label
wins when both exist. Each watch configuration (row version, definition hash, model, prompt) is scored
on the labeled versions it decided: an alert it would have made on a not relevant entry is a false
alert, and a relevant entry it did not alert on is a missed relevant post. When the definition has a
rule, the rule alone (YARA only) is scored on the same versions. Latency and token usage cover every
question the configuration asked, labeled or not.
"""

from dataclasses import asdict, dataclass, field
from typing import Optional

from sqlalchemy import func, select

from saq.constants import DISPOSITION_NOT_RELEVANT, DISPOSITION_RELEVANT
from saq.database.model import Alert, FeedDecision, FeedDelivery, FeedLabel
from saq.database.pool import get_db
from saq.feeds.decisions import KIND_WATCH, STATUS_DECIDED, STATUS_FAILED, STATUS_PENDING, watch_version
from saq.feeds.llm import DECISION_INSUFFICIENT, DECISION_MATCH

LABEL_RELEVANT = "relevant"
LABEL_NOT_RELEVANT = "not_relevant"

PREDICTOR_DECISION = "decision"
PREDICTOR_RULE = "yara_only"

# entries looked up per query
CHUNK = 1000


@dataclass
class Score:
    predictor: str
    evaluated: int = 0
    true_positives: int = 0
    false_alerts: int = 0
    missed_relevant: int = 0
    true_negatives: int = 0
    insufficient_evidence: int = 0
    pending: int = 0
    failed: int = 0

    def add(self, predicted: Optional[bool], relevant: bool, insufficient: bool = False) -> None:
        if insufficient:
            self.insufficient_evidence += 1
        self.evaluated += 1
        if predicted and relevant:
            self.true_positives += 1
        elif predicted:
            self.false_alerts += 1
        elif relevant:
            self.missed_relevant += 1
        else:
            self.true_negatives += 1


@dataclass
class Configuration:
    watch_version: str
    watch_row_version: int
    definition_hash: str
    model: str
    prompt_hash: str
    scores: list[Score] = field(default_factory=list)
    questions_asked: int = 0
    avg_latency_ms: Optional[float] = None
    max_latency_ms: Optional[int] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    response_models: list[str] = field(default_factory=list)


@dataclass
class Evaluation:
    watch_id: int
    labeled: int
    relevant: int
    not_relevant: int
    configurations: list[Configuration]

    def to_dict(self) -> dict:
        return asdict(self)


def watch_labels(watch_id: int) -> dict[int, str]:
    """entry version id -> its label for the watch."""
    db = get_db()
    labels = {}
    for entry_id, disposition in db.execute(
            select(FeedDecision.entry_id, Alert.disposition)
            .join(FeedDelivery, FeedDelivery.id == FeedDecision.delivery_id)
            .join(Alert, Alert.uuid == FeedDelivery.root_uuid)
            .where(FeedDecision.watch_id == watch_id, FeedDecision.kind == KIND_WATCH,
                   Alert.disposition.in_((DISPOSITION_RELEVANT, DISPOSITION_NOT_RELEVANT)))).all():
        labels[entry_id] = LABEL_RELEVANT if disposition == DISPOSITION_RELEVANT else LABEL_NOT_RELEVANT

    for entry_id, label in db.execute(select(FeedLabel.entry_id, FeedLabel.label).where(FeedLabel.watch_id == watch_id)).all():
        labels[entry_id] = label
    return labels


def evaluate_watch(watch_id: int) -> Evaluation:
    db = get_db()
    labels = watch_labels(watch_id)
    configurations: dict[tuple, Configuration] = {}

    def configuration(row_version, definition_hash, model, prompt) -> Configuration:
        key = (row_version, definition_hash or "", model or "", prompt or "")
        if key not in configurations:
            configurations[key] = Configuration(
                watch_version=watch_version(row_version, definition_hash), watch_row_version=row_version,
                definition_hash=definition_hash or "", model=model or "", prompt_hash=prompt or "",
                scores=[Score(PREDICTOR_DECISION)])
        return configurations[key]

    entry_ids = list(labels)
    for start in range(0, len(entry_ids), CHUNK):
        for row in db.execute(
                select(FeedDecision.entry_id, FeedDecision.watch_row_version, FeedDecision.definition_hash,
                       FeedDecision.model, FeedDecision.prompt_hash, FeedDecision.status, FeedDecision.decision,
                       FeedDecision.yara_matched, FeedDecision.question.is_not(None).label("asks"))
                .where(FeedDecision.watch_id == watch_id, FeedDecision.kind == KIND_WATCH,
                       FeedDecision.entry_id.in_(entry_ids[start:start + CHUNK]))).all():
            config = configuration(row.watch_row_version, row.definition_hash, row.model, row.prompt_hash)
            relevant = labels[row.entry_id] == LABEL_RELEVANT
            decision_score = config.scores[0]
            if row.status == STATUS_PENDING:
                decision_score.pending += 1
            elif row.status == STATUS_FAILED:
                decision_score.failed += 1
            else:
                decision_score.add(row.decision == DECISION_MATCH, relevant, row.decision == DECISION_INSUFFICIENT)

            # the rule alone, when the definition has a question as well
            if row.yara_matched is not None and row.asks:
                rule_score = next((score for score in config.scores if score.predictor == PREDICTOR_RULE), None)
                if rule_score is None:
                    rule_score = Score(PREDICTOR_RULE)
                    config.scores.append(rule_score)
                rule_score.add(bool(row.yara_matched), relevant)

    # cost and latency of every question asked, labeled or not
    for row in db.execute(
            select(FeedDecision.watch_row_version, FeedDecision.definition_hash, FeedDecision.model,
                   FeedDecision.prompt_hash, func.count(), func.avg(FeedDecision.latency_ms),
                   func.max(FeedDecision.latency_ms), func.coalesce(func.sum(FeedDecision.prompt_tokens), 0),
                   func.coalesce(func.sum(FeedDecision.completion_tokens), 0))
            .where(FeedDecision.watch_id == watch_id, FeedDecision.kind == KIND_WATCH,
                   FeedDecision.status == STATUS_DECIDED, FeedDecision.latency_ms.is_not(None))
            .group_by(FeedDecision.watch_row_version, FeedDecision.definition_hash, FeedDecision.model,
                      FeedDecision.prompt_hash)).all():
        config = configuration(row[0], row[1], row[2], row[3])
        config.questions_asked = int(row[4])
        config.avg_latency_ms = float(row[5]) if row[5] is not None else None
        config.max_latency_ms = int(row[6]) if row[6] is not None else None
        config.prompt_tokens = int(row[7])
        config.completion_tokens = int(row[8])

    for row in db.execute(
            select(FeedDecision.watch_row_version, FeedDecision.definition_hash, FeedDecision.model,
                   FeedDecision.prompt_hash, FeedDecision.response_model)
            .where(FeedDecision.watch_id == watch_id, FeedDecision.kind == KIND_WATCH,
                   FeedDecision.response_model.is_not(None))
            .group_by(FeedDecision.watch_row_version, FeedDecision.definition_hash, FeedDecision.model,
                      FeedDecision.prompt_hash, FeedDecision.response_model)).all():
        configuration(row[0], row[1], row[2], row[3]).response_models.append(row[4])

    relevant = sum(1 for label in labels.values() if label == LABEL_RELEVANT)
    ordered = sorted(configurations.values(), key=lambda c: (c.watch_row_version or 0, c.model, c.prompt_hash), reverse=True)
    return Evaluation(watch_id=watch_id, labeled=len(labels), relevant=relevant, not_relevant=len(labels) - relevant,
                      configurations=ordered)
