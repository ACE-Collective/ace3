"""Scoring a watch against analysts' labels (docs/FEED_WATCHES.md, *Evaluation*)."""

import os

import pytest
from sqlalchemy import func, text

from saq.constants import DISPOSITION_NOT_RELEVANT, DISPOSITION_RELEVANT
from saq.database.model import FeedDecision, FeedDelivery, FeedLabel
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.feeds.evaluation import evaluate_watch
from tests.saq.feeds.conftest import make_entry, make_feed, make_watch


def _decision(entry, watch, decision, yara_matched=None, question="q", model="gemma", latency=None, tokens=(None, None),
              delivery_id=None, status="decided"):
    get_db().add(FeedDecision(
        cache_key=os.urandom(32).hex(), kind="watch", entry_id=entry.id, watch_id=watch.id, watch_row_version=1,
        definition_name=watch.definition_name, definition_hash="d" * 64, question=question, model=model, prompt_hash="p",
        yara_matched=yara_matched, status=status, decision=decision if status == "decided" else None,
        latency_ms=latency, prompt_tokens=tokens[0], completion_tokens=tokens[1], delivery_id=delivery_id,
        created_at=func.now()))
    get_db().commit()


def _alerted(root_analysis, feed, entry, disposition) -> int:
    """An alert of the entry, dispositioned; returns its delivery's id."""
    root_analysis.save()
    ALERT(root_analysis)
    db = get_db()
    db.execute(text("UPDATE alerts SET disposition = :d WHERE uuid = :u"), {"d": disposition, "u": root_analysis.uuid})
    delivery = FeedDelivery(feed_id=feed.id, identity_hash=entry.identity_hash, queue="default",
                            root_uuid=root_analysis.uuid, submission_key="k", state="staged")
    db.add(delivery)
    db.commit()
    return delivery.id


def _label(entry, watch, label):
    get_db().add(FeedLabel(entry_id=entry.id, watch_id=watch.id, label=label))
    get_db().commit()


@pytest.mark.integration
def test_false_alerts_and_missed_relevant_posts(root_analysis):
    feed = make_feed()
    watch = make_watch(feed, "exploited")
    true_match, false_alert, missed, true_miss, alerted, unlabeled = (
        make_entry(feed, identity=name) for name in ("true_match", "false_alert", "missed", "true_miss", "alerted", "unlabeled"))

    _decision(true_match, watch, "match", yara_matched=True, latency=100, tokens=(10, 2))
    _decision(false_alert, watch, "match", yara_matched=True, latency=300, tokens=(10, 2))
    _decision(missed, watch, "insufficient_evidence", yara_matched=True, latency=200, tokens=(10, 2))
    _decision(true_miss, watch, "no_match", yara_matched=False)
    _decision(unlabeled, watch, "match", yara_matched=True, latency=400, tokens=(10, 2))
    for entry, label in ((true_match, "relevant"), (false_alert, "not_relevant"), (missed, "relevant"),
                         (true_miss, "not_relevant")):
        _label(entry, watch, label)

    # an alert dispositioned NOT_RELEVANT labels what it delivered
    delivery_id = _alerted(root_analysis, feed, alerted, DISPOSITION_NOT_RELEVANT)
    _decision(alerted, watch, "match", yara_matched=True, latency=500, tokens=(10, 2), delivery_id=delivery_id)

    result = evaluate_watch(watch.id)
    assert (result.labeled, result.relevant, result.not_relevant) == (5, 2, 3)
    (configuration,) = result.configurations
    decision, rule = configuration.scores
    assert (decision.predictor, decision.evaluated, decision.true_positives, decision.false_alerts,
            decision.missed_relevant, decision.true_negatives, decision.insufficient_evidence) == \
        ("decision", 5, 1, 2, 1, 1, 1)
    # the rule alone alerts on everything it matched
    assert (rule.predictor, rule.true_positives, rule.false_alerts, rule.missed_relevant, rule.true_negatives) == \
        ("yara_only", 2, 2, 0, 1)
    # cost covers every question asked, labeled or not
    assert configuration.questions_asked == 5
    assert configuration.max_latency_ms == 500 and configuration.avg_latency_ms == 300
    assert (configuration.prompt_tokens, configuration.completion_tokens) == (50, 10)


@pytest.mark.integration
def test_a_replay_label_wins_over_the_disposition_and_pending_is_counted(root_analysis):
    feed = make_feed()
    watch = make_watch(feed, "pattern")
    entry = make_entry(feed)
    pending = make_entry(feed, identity="pending")
    _label(pending, watch, "relevant")
    _decision(pending, watch, None, status="pending")
    _label(entry, watch, "not_relevant")
    _decision(entry, watch, "match", question=None, model="",
              delivery_id=_alerted(root_analysis, feed, entry, DISPOSITION_RELEVANT))

    result = evaluate_watch(watch.id)
    assert result.labeled == 2
    scores = {configuration.model: configuration.scores for configuration in result.configurations}
    (rule_only,) = scores[""]
    assert (rule_only.false_alerts, rule_only.true_positives) == (1, 0)
    (llm,) = scores["gemma"]
    assert llm.pending == 1 and llm.evaluated == 0
