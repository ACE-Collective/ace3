"""Replays of draft definitions (docs/FEED_WATCHES.md, *Replay*)."""

import json

import pytest
from sqlalchemy import func, select, text

from saq.database.model import FeedDecision, FeedEntry, FeedReplay, FeedReplayResult
from saq.database.pool import get_db
from saq.feeds.definitions import DefinitionSet, prompt_hash
from saq.feeds.replay import finish_replays, prune_replays, run_replays
from tests.saq.feeds.conftest import EXPLOITED_RULE, LLM_MODEL, PROMPT, make_entry, make_feed

DEFINITIONS = DefinitionSet(prompt=PROMPT, prompt_hash=prompt_hash(PROMPT))
QUESTION = "Is a product we run exploited?"


def _replay(feed, yara=None, question=None) -> FeedReplay:
    db = get_db()
    replay = FeedReplay(yara=yara, question=question, feed_ids=json.dumps([feed.id]), state="queued", created_at=func.now())
    db.add(replay)
    db.commit()
    return replay


def _results(replay_id) -> dict[str, FeedReplayResult]:
    db = get_db()
    db.expire_all()
    return {entry.identity: result for result, entry in db.execute(
        select(FeedReplayResult, FeedEntry).join(FeedEntry, FeedEntry.id == FeedReplayResult.entry_id)
        .where(FeedReplayResult.replay_id == replay_id)).all()}


@pytest.mark.integration
def test_a_replay_runs_the_rule_and_asks_for_what_it_matched(monkeypatch):
    feed = make_feed()
    make_entry(feed, identity="hit", content="This flaw is actively exploited.")
    make_entry(feed, identity="miss", content="A routine update.")
    old = make_entry(feed, identity="old", content="actively exploited, long ago")
    other_feed = make_feed(name="other", url="https://other.example/feed")
    make_entry(other_feed, identity="elsewhere", content="actively exploited")
    get_db().execute(text("UPDATE feed_entries SET first_seen_at = NOW() - INTERVAL 30 DAY WHERE id = :id"), {"id": old.id})
    get_db().commit()

    replay = _replay(feed, yara=EXPLOITED_RULE, question=QUESTION)
    assert run_replays(DEFINITIONS, LLM_MODEL) == 1

    results = _results(replay.id)
    assert set(results) == {"hit", "miss"}
    assert results["hit"].yara_matched and "actively exploited" in results["hit"].yara_excerpt
    assert results["miss"].yara_matched is False and results["miss"].decision_id is None
    decision = get_db().get(FeedDecision, results["hit"].decision_id)
    assert (decision.kind, decision.status, decision.question, decision.model) == ("replay", "pending", QUESTION, LLM_MODEL)
    get_db().expire_all()
    assert get_db().get(FeedReplay, replay.id).state == "running"

    # the same draft again reuses the question it asked
    again = _replay(feed, yara=EXPLOITED_RULE, question=QUESTION)
    run_replays(DEFINITIONS, LLM_MODEL)
    assert _results(again.id)["hit"].decision_id == decision.id
    assert get_db().execute(select(func.count()).select_from(FeedDecision)).scalar() == 1

    # done once nothing it asked is pending
    get_db().execute(text("UPDATE feed_decisions SET status = 'decided', decision = 'match'"))
    get_db().commit()
    assert finish_replays() == 2
    get_db().expire_all()
    assert get_db().get(FeedReplay, replay.id).state == "done"


@pytest.mark.integration
def test_a_rule_only_replay_is_done_without_asking():
    feed = make_feed()
    make_entry(feed, identity="hit", content="actively exploited")
    replay = _replay(feed, yara=EXPLOITED_RULE)
    run_replays(DEFINITIONS, LLM_MODEL)
    get_db().expire_all()
    assert get_db().get(FeedReplay, replay.id).state == "done"
    assert get_db().execute(select(FeedDecision)).first() is None


@pytest.mark.integration
def test_a_rule_that_does_not_compile_fails_the_replay():
    feed = make_feed()
    replay = _replay(feed, yara="rule broken {")
    run_replays(DEFINITIONS, LLM_MODEL)
    get_db().expire_all()
    failed = get_db().get(FeedReplay, replay.id)
    assert failed.state == "failed" and "does not compile" in failed.error


@pytest.mark.integration
def test_old_replays_are_deleted_with_their_results():
    feed = make_feed()
    make_entry(feed, content="actively exploited")
    old = _replay(feed, yara=EXPLOITED_RULE)
    new = _replay(feed, yara=EXPLOITED_RULE)
    run_replays(DEFINITIONS, LLM_MODEL)
    get_db().execute(text("UPDATE feed_replays SET created_at = NOW() - INTERVAL 31 DAY WHERE id = :id"), {"id": old.id})
    get_db().commit()
    old_id, new_id = old.id, new.id

    assert prune_replays() == 1
    get_db().expire_all()
    assert [replay.id for replay in get_db().execute(select(FeedReplay)).scalars()] == [new_id]
    assert {result.replay_id for result in get_db().execute(select(FeedReplayResult)).scalars()} == {new_id}
    assert old_id != new_id
