"""The feed watch endpoints, /api/v2/feed-watches (docs/FEED_WATCHES.md)."""

import json
import os

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from saq.database.model import FeedDecision, FeedDefinition, FeedLabel, FeedReplay, FeedReplayResult, FeedWatch
from saq.database.pool import get_db
from tests.saq.feeds.conftest import make_entry, make_feed, make_watch

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def _definition(name, yara=None, question=None, present=True, error=None):
    get_db().add(FeedDefinition(name=name, repository="defs", path=f"definitions/{name}.yaml", content_hash="a" * 64,
                                yara=yara, question=question, present=present, error=error))
    get_db().commit()


async def test_a_watch_is_created_and_every_edit_is_a_version(client: AsyncClient):
    _definition("exploited", yara="rule r { condition: true }", question="q")
    feeds = [make_feed(name=f"feed{index}", url=f"https://f{index}.example/feed") for index in range(2)]
    response = await client.post("/feed-watches/", json={
        "name": "exploitation", "definition_name": "exploited", "feed_ids": [feed.id for feed in feeds], "queue": "intel"})
    assert response.status_code == 201, response.text
    watch = response.json()
    assert (watch["mode"], watch["version"], watch["watch_version"], watch["flag"], watch["warning"]) == \
        ("shadow", 1, "v1:aaaaaaaaaaaa", None, None)
    assert [feed["name"] for feed in watch["feeds"]] == ["feed0", "feed1"]

    edited = (await client.patch(f"/feed-watches/{watch['id']}", json={"mode": "delivering"})).json()
    assert (edited["mode"], edited["version"]) == ("delivering", 2)
    edited = (await client.patch(f"/feed-watches/{watch['id']}", json={"feed_ids": [feeds[1].id]})).json()
    assert edited["version"] == 3 and [feed["id"] for feed in edited["feeds"]] == [feeds[1].id]

    duplicate = await client.post("/feed-watches/", json={
        "name": "exploitation", "definition_name": "exploited", "feed_ids": [feeds[0].id], "queue": "intel"})
    assert duplicate.status_code == 409


async def test_a_question_only_watch_is_warned_and_a_missing_definition_flagged(client: AsyncClient):
    _definition("asked", question="Is it exploited?")
    feed = make_feed()
    watch = (await client.post("/feed-watches/", json={
        "name": "asked", "definition_name": "asked", "feed_ids": [feed.id], "queue": "default"})).json()
    assert "every entry" in watch["warning"]

    get_db().execute(FeedDefinition.__table__.update().values(present=False, error="no longer in the definitions repositories"))
    get_db().commit()
    listed = (await client.get("/feed-watches/")).json()["data"]
    assert "missing" in listed[0]["flag"]

    refused = await client.post("/feed-watches/", json={
        "name": "other", "definition_name": "asked", "feed_ids": [feed.id], "queue": "default"})
    assert refused.status_code == 422 and "not in the definitions repositories" in refused.text
    unknown_feed = await client.post("/feed-watches/", json={
        "name": "other", "definition_name": "asked", "feed_ids": [999999], "queue": "default"})
    assert unknown_feed.status_code == 422


async def test_failed_decisions_are_listed_for_the_operator(client: AsyncClient):
    feed = make_feed()
    watch = make_watch(feed, "asked")
    entry = make_entry(feed)
    for status in ("failed", "decided"):
        get_db().add(FeedDecision(cache_key=os.urandom(32).hex(), kind="watch", entry_id=entry.id, watch_id=watch.id,
                                  watch_row_version=1, definition_name="asked", definition_hash="d" * 64, status=status,
                                  attempts=3, last_error="the excerpt is not in the entry", created_at=func.now()))
    get_db().commit()

    page = (await client.get("/feed-watches/decisions", params={"status": "failed"})).json()
    assert [(item["status"], item["last_error"]) for item in page["data"]] == [("failed", "the excerpt is not in the entry")]
    watches = (await client.get("/feed-watches/")).json()["data"]
    assert watches[0]["failed_decisions"] == 1


async def test_a_replay_is_queued_and_its_results_labeled(client: AsyncClient):
    feed = make_feed()
    watch = make_watch(feed, "exploited")
    hit = make_entry(feed, identity="hit")
    miss = make_entry(feed, identity="miss")

    response = await client.post("/feed-watches/replays", json={
        "yara": "rule r { condition: true }", "question": "Is it exploited?", "feed_ids": [feed.id], "watch_id": watch.id})
    assert response.status_code == 202, response.text
    replay = response.json()
    assert replay["state"] == "queued" and replay["warning"] is None
    assert get_db().get(FeedReplay, replay["id"]).question == "Is it exploited?"

    # what the service does with it
    db = get_db()
    decision = FeedDecision(cache_key="r" * 64, kind="replay", entry_id=hit.id, question="Is it exploited?",
                            status="decided", decision="match", excerpt="exploited", created_at=func.now())
    db.add(decision)
    db.flush()
    db.add_all([FeedReplayResult(replay_id=replay["id"], entry_id=hit.id, yara_matched=True, decision_id=decision.id),
                FeedReplayResult(replay_id=replay["id"], entry_id=miss.id, yara_matched=False)])
    db.execute(FeedReplay.__table__.update().values(state="done", entry_count=2))
    db.commit()

    current = (await client.get(f"/feed-watches/replays/{replay['id']}")).json()
    assert current["counts"] == {"entries": 2, "rule_matched": 1, "asked": 1, "pending": 0, "failed": 0, "match": 1,
                                 "no_match": 0, "insufficient_evidence": 0}
    matches = (await client.get(f"/feed-watches/replays/{replay['id']}/results", params={"outcome": "match"})).json()
    assert [(item["entry"]["id"], item["matched"]) for item in matches["data"]] == [(hit.id, True)]
    misses = (await client.get(f"/feed-watches/replays/{replay['id']}/results", params={"outcome": "miss"})).json()
    assert [(item["entry"]["id"], item["matched"]) for item in misses["data"]] == [(miss.id, False)]

    assert (await client.put(f"/feed-watches/{watch.id}/labels/{hit.id}", json={"label": "relevant"})).status_code == 204
    assert (await client.put(f"/feed-watches/{watch.id}/labels/{hit.id}", json={"label": "not_relevant"})).status_code == 204
    results = (await client.get(f"/feed-watches/replays/{replay['id']}/results")).json()["data"]
    assert {item["entry"]["id"]: item["label"] for item in results} == {hit.id: "not_relevant", miss.id: None}
    assert get_db().execute(select(func.count()).select_from(FeedLabel)).scalar() == 1
    assert (await client.delete(f"/feed-watches/{watch.id}/labels/{hit.id}")).status_code == 204
    assert (await client.delete(f"/feed-watches/{watch.id}/labels/{hit.id}")).status_code == 404


async def test_a_replay_needs_a_rule_or_a_question(client: AsyncClient):
    feed = make_feed()
    response = await client.post("/feed-watches/replays", json={"yara": " ", "feed_ids": [feed.id]})
    assert response.status_code == 422
    question_only = (await client.post("/feed-watches/replays", json={"question": "q", "feed_ids": [feed.id]})).json()
    assert "every entry" in question_only["warning"]


async def test_the_evaluation_of_a_watch(client: AsyncClient):
    feed = make_feed()
    watch = make_watch(feed, "exploited")
    entry = make_entry(feed)
    get_db().add(FeedDecision(cache_key="e" * 64, kind="watch", entry_id=entry.id, watch_id=watch.id, watch_row_version=1,
                              definition_name="exploited", definition_hash="d" * 64, status="decided", decision="match",
                              created_at=func.now()))
    get_db().add(FeedLabel(entry_id=entry.id, watch_id=watch.id, label="not_relevant"))
    get_db().commit()

    evaluation = (await client.get(f"/feed-watches/{watch.id}/evaluation")).json()
    assert evaluation["labeled"] == 1
    assert evaluation["configurations"][0]["scores"][0]["false_alerts"] == 1
    assert (await client.get("/feed-watches/999999/evaluation")).status_code == 404


async def test_reading_and_writing_need_their_permissions(noperm_client: AsyncClient):
    assert (await noperm_client.get("/feed-watches/")).status_code == 403
    assert (await noperm_client.post("/feed-watches/replays", json={"question": "q", "feed_ids": [1]})).status_code == 403
