"""service_feed_watch end to end (docs/FEED_WATCHES.md)."""

import json
import logging

import pytest
import yara
from sqlalchemy import func, select

from saq.configuration.config import get_config
from saq.configuration.schema import GitRepoConfig
from saq.constants import ENV_ACE_IS_PRIMARY_NODE, SERVICE_FEED_WATCH
from saq.database.model import FeedDecision, FeedDefinition, FeedDelivery, FeedEntry, FeedReplay, IncomingWorkload
from saq.database.pool import get_db
from saq.feeds import definitions as definitions_module
from saq.feeds import decisions, poller
from saq.feeds import service as service_module
from saq.feeds.entries import ParsedEntry, ParsedFeed
from saq.feeds.service import HELD_REPORT_SECONDS, FeedWatchService
from aceapi_v2.feed_watches.service import list_watches
from tests.saq.feeds.conftest import EXPLOITED_RULE, LLM_MODEL, LLM_URL, make_entry, make_feed, make_watch, service_config
from tests.saq.helpers import wait_for_condition

URL = "https://vendor.example/feed.xml"
QUESTION = "Does this report active exploitation of Widget Server?"
ENTRY = ParsedEntry(guid="urn:adv:9", link="https://vendor.example/9", title="Widget Server flaw",
                    content="Widget Server is being actively exploited.")


@pytest.fixture
def service(definitions_repo, requests_mock, monkeypatch) -> FeedWatchService:
    definitions_repo.definition("pattern", yara=EXPLOITED_RULE)
    definitions_repo.definition("asked", yara=EXPLOITED_RULE, question=QUESTION)
    definitions_repo.commit()
    get_config().add_service_config(SERVICE_FEED_WATCH, service_config())
    monkeypatch.setattr(poller, "parse_feed", lambda body: ParsedFeed(title="Vendor", entries=[ENTRY]))
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    requests_mock.get(URL, content=b"<rss/>")
    requests_mock.post(f"{LLM_URL}/v1/chat/completions", json={"model": LLM_MODEL, "choices": [{"message": {"content": json.dumps(
        {"decision": "match", "excerpt": "Widget Server is being actively exploited", "rationale": "it says so"})}}]})
    return FeedWatchService()


def _workload() -> int:
    get_db().expire_all()
    return get_db().execute(select(func.count()).select_from(IncomingWorkload)).scalar()


@pytest.mark.integration
def test_a_new_entry_two_watches_match_becomes_one_scheduled_alert(service):
    feed = make_feed(url=URL)
    make_watch(feed, "pattern")
    make_watch(feed, "asked")

    service.start_single_threaded()

    names = {row.name: row for row in get_db().execute(select(FeedDefinition)).scalars()}
    assert set(names) == {"pattern", "asked"} and all(row.present for row in names.values())
    decisions = get_db().execute(select(FeedDecision.definition_name, FeedDecision.status, FeedDecision.decision)).all()
    assert sorted(decisions) == [("asked", "decided", "match"), ("pattern", "decided", "match")]
    (delivery,) = get_db().execute(select(FeedDelivery)).scalars().all()
    assert delivery.state == "staged"
    assert _workload() == 1


@pytest.mark.integration
def test_the_first_poll_of_a_new_feed_alerts_on_nothing(service):
    feed = make_feed(url=URL, baselined=False)
    make_watch(feed, "pattern")
    service.start_single_threaded()
    assert get_db().execute(select(FeedDecision)).first() is None
    assert _workload() == 0


@pytest.mark.integration
def test_the_service_runs_until_stopped(service, monkeypatch):
    service.config.loop_interval_seconds = 0.1
    feed = make_feed(url=URL)
    make_watch(feed, "asked")

    service.start()
    try:
        assert service.wait_for_start(5)
        assert wait_for_condition(lambda: _workload() == 1, timeout=20)
    finally:
        service.stop()
        service.wait()
    assert all(not thread.is_alive() for thread in service.threads)


@pytest.mark.integration
def test_the_service_is_idle_off_the_primary_node(service, monkeypatch):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    make_watch(make_feed(url=URL), "pattern")
    service.start()
    assert service.threads == [] and not service.collector_started
    service.stop()
    service.wait()
    assert get_db().execute(select(FeedDefinition)).first() is None


@pytest.mark.integration
def test_entries_wait_while_a_definitions_repository_has_no_checkout(service, monkeypatch, caplog):
    monkeypatch.setattr(get_config().feeds, "repositories", [*get_config().feeds.repositories, "not_cloned_yet"])
    get_config().add_git_repo_config("not_cloned_yet", GitRepoConfig(
        name="not_cloned_yet", description="unittest", local_path="/nonexistent/feed-definitions",
        git_url="https://example.invalid/x.git", update_frequency=60, branch="main"))
    make_watch(make_feed(url=URL), "pattern")

    with caplog.at_level(logging.ERROR):
        service.start_single_threaded()

    assert any("has no checkout yet" in record.getMessage() for record in caplog.records)
    (entry,) = get_db().execute(select(FeedEntry)).scalars().all()
    # not evaluated, so it is once the checkout exists
    assert entry.evaluated_at is None
    assert get_db().execute(select(FeedDecision)).first() is None


@pytest.mark.integration
def test_the_definitions_are_read_again_only_when_a_commit_moves(service, definitions_repo, monkeypatch):
    reads = []
    original = definitions_module.read_definitions
    monkeypatch.setattr(definitions_module, "read_definitions", lambda commits: reads.append(commits) or original(commits))
    assert service.definitions.refresh()
    assert not service.definitions.refresh()
    definitions_repo.definition("another", question="q")
    definitions_repo.commit()
    assert service.definitions.refresh()
    assert len(reads) == 2
    assert "another" in service.definitions.current.definitions


@pytest.mark.integration
def test_a_definitions_repository_no_section_names_is_logged_with_why(service, monkeypatch, caplog):
    monkeypatch.setattr(get_config().feeds, "repositories", [*get_config().feeds.repositories, "feed_definitons"])
    with caplog.at_level(logging.ERROR):
        service.definitions.refresh()
    (record,) = [record for record in caplog.records if record.levelname == "ERROR"]
    assert "no git_repo section is named feed_definitons" in record.getMessage()
    assert record.exc_info and record.repository == "feed_definitons"
    assert not service.definitions.complete


@pytest.mark.integration
def test_evaluation_held_for_a_checkout_is_said_again_hourly(service, monkeypatch, caplog):
    monkeypatch.setattr(get_config().feeds, "repositories", [*get_config().feeds.repositories, "not_cloned_yet"])
    get_config().add_git_repo_config("not_cloned_yet", GitRepoConfig(
        name="not_cloned_yet", description="unittest", local_path="/nonexistent/feed-definitions",
        git_url="https://example.invalid/x.git", update_frequency=60, branch="main"))
    service.definitions.refresh()

    def held() -> list:
        return [record for record in caplog.records if "no feed entry has been evaluated" in record.getMessage()]

    with caplog.at_level(logging.ERROR):
        assert service.evaluate() == 0
        assert held() == []
        # it has waited longer than a first clone takes
        service.definitions.incomplete_since -= HELD_REPORT_SECONDS + 1
        assert service.evaluate() == 0
        assert service.evaluate() == 0
    (record,) = held()
    assert record.levelname == "ERROR" and record.exc_info and record.repositories == ["not_cloned_yet"]


@pytest.mark.integration
def test_a_definition_whose_rule_does_not_compile_matches_nothing_and_is_flagged(service, definitions_repo, caplog):
    definitions_repo.definition("broken", yara="rule broken { strings: $a = condition: $a }")
    definitions_repo.commit()
    feed = make_feed(url=URL)
    broken = make_watch(feed, "broken")
    make_watch(feed, "pattern")
    make_entry(feed, content="Widget Server is being actively exploited.")

    with caplog.at_level(logging.ERROR):
        assert service.definitions.refresh()
    (record,) = [record for record in caplog.records if record.levelname == "ERROR"]
    assert "does not compile" in record.getMessage() and record.definition == "broken" and record.exc_info

    assert service.evaluate() == 1
    assert get_db().execute(select(FeedDecision.definition_name)).scalars().all() == ["pattern"]
    flags = {watch.id: watch.flag for watch in list_watches(None, 10).data}
    assert flags[broken.id].startswith("definition broken can't be used: the rule does not compile")


@pytest.mark.integration
def test_a_rule_that_times_out_is_a_scan_error(service, monkeypatch):
    service.definitions.refresh()

    def timeout(rules, fields):
        raise yara.TimeoutError("internal error: 30")

    monkeypatch.setattr(service_module, "scan_entry", timeout)
    matcher = service.definitions.matcher(LLM_MODEL)
    with pytest.raises(decisions.ScanError, match="internal error: 30"):
        matcher.scan(matcher.definitions.definitions["pattern"], {"title": "t"})


@pytest.mark.integration
def test_the_service_queues_again_a_replay_it_was_killed_running(service):
    feed = make_feed(url=URL)
    db = get_db()
    replay = FeedReplay(yara=EXPLOITED_RULE, feed_ids=json.dumps([feed.id]), state="running", created_at=func.now())
    db.add(replay)
    db.commit()
    replay_id = replay.id

    service.start()
    try:
        assert wait_for_condition(lambda: _replay_state(replay_id) == "done", timeout=20)
    finally:
        service.stop()
        service.wait()


def _replay_state(replay_id) -> str:
    get_db().expire_all()
    return get_db().get(FeedReplay, replay_id).state
