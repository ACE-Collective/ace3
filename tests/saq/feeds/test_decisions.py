"""Decisions on new entry versions, and asking the pending questions (docs/FEED_WATCHES.md, *Decisions*)."""

import json
import logging
import ssl

import pytest
import requests
from sqlalchemy import func, select, text

from saq.database.model import FeedDecision, FeedDelivery, FeedEntry
from saq.database.pool import get_db
from saq.feeds.decisions import (
    ClassifierState,
    Matcher,
    ScanError,
    classify_pending,
    evaluate_entries,
    replay_cache_key,
)
from saq.feeds.definitions import Definition, DefinitionSet, prompt_hash
from saq.feeds.matching import compile_rule, scan_entry
from tests.saq.feeds.conftest import EXPLOITED_RULE, LLM_MODEL, LLM_URL, PROMPT, make_entry, make_feed, make_watch, service_config

COMPLETIONS = f"{LLM_URL}/v1/chat/completions"
QUESTION = "Does this report active exploitation of a product we run?"
EXPLOITED_TEXT = "Widget Server is being actively exploited in the wild."


def _definitions(*definitions: Definition, prompt: str = PROMPT) -> DefinitionSet:
    return DefinitionSet(definitions={d.name: d for d in definitions}, prompt=prompt,
                         prompt_hash=prompt_hash(prompt) if prompt else None)


def _definition(name: str, yara=None, question=None) -> Definition:
    return Definition(name=name, repository="r", path=f"definitions/{name}.yaml", commit="c", yara=yara, question=question)


def _matcher(definitions: DefinitionSet, usable=None) -> Matcher:
    rules = {name: compile_rule(d.yara) for name, d in definitions.definitions.items() if d.yara}

    def scan(definition, fields):
        found = scan_entry(rules[definition.name], fields)
        return found.matched, found.field, found.excerpt

    return Matcher(definitions=definitions, usable=set(definitions.definitions) if usable is None else usable,
                   scan=scan, model=LLM_MODEL)


def _decisions() -> dict[str, FeedDecision]:
    db = get_db()
    db.expire_all()
    return {row.definition_name: row for row in db.execute(select(FeedDecision)).scalars()}


def _completion(decision="match", excerpt="Widget Server is being actively exploited"):
    return {"model": LLM_MODEL, "choices": [{"message": {"content": json.dumps(
        {"decision": decision, "excerpt": excerpt, "rationale": "the advisory says so"})}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20}}


@pytest.mark.integration
def test_each_watch_of_the_feed_decides_on_a_new_version():
    feed = make_feed()
    definitions = _definitions(
        _definition("pattern", yara=EXPLOITED_RULE),
        _definition("pattern_miss", yara='rule r { strings: $a = "ransomware" condition: $a }'),
        _definition("prefiltered", yara=EXPLOITED_RULE, question=QUESTION),
        _definition("turned_away", yara='rule r { strings: $a = "ransomware" condition: $a }', question=QUESTION),
        _definition("question_only", question=QUESTION),
        _definition("disabled", question=QUESTION),
        _definition("unusable", question=QUESTION))
    for name in definitions.definitions:
        make_watch(feed, name, enabled=name != "disabled")
    make_watch(feed, "not_in_the_repository")
    entry = make_entry(feed, content=EXPLOITED_TEXT)

    assert evaluate_entries(_matcher(definitions, usable=set(definitions.definitions) - {"unusable"})) == 1

    rows = _decisions()
    assert set(rows) == {"pattern", "pattern_miss", "prefiltered", "turned_away", "question_only"}
    assert (rows["pattern"].status, rows["pattern"].decision, rows["pattern"].yara_field) == ("decided", "match", "content")
    assert "actively exploited" in rows["pattern"].yara_excerpt
    assert (rows["pattern_miss"].status, rows["pattern_miss"].decision) == ("decided", "no_match")
    assert (rows["prefiltered"].status, rows["prefiltered"].yara_matched) == ("pending", True)
    assert rows["prefiltered"].model == LLM_MODEL and rows["prefiltered"].prompt_hash == prompt_hash(PROMPT)
    assert (rows["turned_away"].status, rows["turned_away"].decision) == ("decided", "no_match")
    assert (rows["question_only"].status, rows["question_only"].yara_matched) == ("pending", None)
    assert all(row.deliver and row.queue == "default" and row.watch_row_version == 1 for row in rows.values())

    get_db().expire_all()
    assert get_db().get(FeedEntry, entry.id).evaluated_at is not None
    # evaluated once
    assert evaluate_entries(_matcher(definitions)) == 0


@pytest.mark.integration
@pytest.mark.parametrize("failure, level", [(ScanError("timeout"), "WARNING"), (KeyError("a bug"), "ERROR")])
def test_a_rule_that_fails_on_an_entry_fails_its_decision(caplog, failure, level):
    feed = make_feed()
    definitions = _definitions(_definition("pattern", yara=EXPLOITED_RULE),
                               _definition("asked", yara=EXPLOITED_RULE, question=QUESTION))
    make_watch(feed, "pattern")
    make_watch(feed, "asked")
    entry = make_entry(feed, content=EXPLOITED_TEXT)

    def scan(definition, fields):
        raise failure

    matcher = Matcher(definitions=definitions, usable=set(definitions.definitions), scan=scan, model=LLM_MODEL)
    with caplog.at_level(logging.WARNING):
        assert evaluate_entries(matcher) == 1

    rows = _decisions()
    assert {name: row.status for name, row in rows.items()} == {"pattern": "failed", "asked": "failed"}
    assert all(row.last_error.startswith("the rule failed:") and row.decided_at is not None for row in rows.values())
    get_db().expire_all()
    assert get_db().get(FeedEntry, entry.id).evaluated_at is not None
    records = [record for record in caplog.records if "feed watch definition" in record.getMessage()]
    assert {(record.levelname, record.definition) for record in records} == {(level, "pattern"), (level, "asked")}
    assert all(bool(record.exc_info) == (level == "ERROR") for record in records)


@pytest.mark.integration
def test_a_stop_ends_the_evaluation_before_the_next_entry():
    feed = make_feed()
    make_watch(feed, "pattern")
    entry = make_entry(feed, content=EXPLOITED_TEXT)
    assert evaluate_entries(_matcher(_definitions(_definition("pattern", yara=EXPLOITED_RULE))), lambda: True) == 0
    assert get_db().execute(select(FeedDecision)).first() is None
    get_db().expire_all()
    assert get_db().get(FeedEntry, entry.id).evaluated_at is None


@pytest.mark.integration
def test_an_update_of_an_entry_that_alerted_to_the_queue_is_ignored():
    feed = make_feed()
    definitions = _definitions(_definition("pattern", yara=EXPLOITED_RULE))
    make_watch(feed, "pattern", name="to default", queue="default")
    make_watch(feed, "pattern", name="to intel", queue="intel")
    entry = make_entry(feed, content=EXPLOITED_TEXT)
    db = get_db()
    db.add(FeedDelivery(feed_id=feed.id, identity_hash=entry.identity_hash, queue="default", root_uuid="a" * 36,
                        submission_key="k", state="staged"))
    db.commit()

    evaluate_entries(_matcher(definitions))
    assert [row.queue for row in db.execute(select(FeedDecision)).scalars()] == ["intel"]


@pytest.mark.integration
def test_a_baseline_version_is_never_evaluated():
    feed = make_feed()
    make_watch(feed, "pattern")
    make_entry(feed, content=EXPLOITED_TEXT, evaluated=True, baseline=True)
    assert evaluate_entries(_matcher(_definitions(_definition("pattern", yara=EXPLOITED_RULE)))) == 0
    assert get_db().execute(select(FeedDecision)).first() is None


def _pending(feed=None) -> FeedDecision:
    feed = feed or make_feed()
    make_watch(feed, "question_only")
    make_entry(feed, content=EXPLOITED_TEXT)
    definitions = _definitions(_definition("question_only", question=QUESTION))
    evaluate_entries(_matcher(definitions))
    return _decisions()["question_only"]


@pytest.mark.integration
def test_a_valid_answer_decides(requests_mock):
    pending = _pending()
    requests_mock.post(COMPLETIONS, json=_completion())
    definitions = _definitions(_definition("question_only", question=QUESTION))
    assert classify_pending(service_config(), definitions, ClassifierState()) == 1

    row = _decisions()["question_only"]
    assert row.id == pending.id
    assert (row.status, row.decision, row.attempts) == ("decided", "match", 1)
    assert row.excerpt == "Widget Server is being actively exploited"
    assert (row.response_model, row.prompt_tokens, row.completion_tokens) == (LLM_MODEL, 100, 20)
    assert row.latency_ms is not None and not row.truncated
    sent = requests_mock.last_request.json()
    assert QUESTION in sent["messages"][0]["content"] and EXPLOITED_TEXT in sent["messages"][1]["content"]


@pytest.mark.integration
def test_an_invalid_answer_is_retried_then_fails(requests_mock, caplog):
    _pending()
    requests_mock.post(COMPLETIONS, json=_completion(excerpt="something the entry never says"))
    definitions = _definitions(_definition("question_only", question=QUESTION))

    classify_pending(service_config(), definitions, ClassifierState())
    row = _decisions()["question_only"]
    assert (row.status, row.attempts) == ("pending", 1)
    assert "not in the entry" in row.last_error
    assert row.next_attempt_at is not None

    get_db().execute(text("UPDATE feed_decisions SET next_attempt_at = NOW() - INTERVAL 1 SECOND"))
    get_db().commit()
    with caplog.at_level(logging.ERROR):
        classify_pending(service_config(), definitions, ClassifierState())
    row = _decisions()["question_only"]
    assert (row.status, row.attempts) == ("failed", 2)
    assert any(record.levelname == "ERROR" and "failed after 2 attempts" in record.getMessage() for record in caplog.records)


@pytest.mark.integration
@pytest.mark.parametrize("failure", ["connection", "server"])
def test_an_unreachable_endpoint_leaves_the_decision_pending(requests_mock, caplog, failure):
    _pending()
    if failure == "connection":
        requests_mock.post(COMPLETIONS, exc=requests.exceptions.ConnectionError("refused"))
    else:
        requests_mock.post(COMPLETIONS, status_code=502, text="bad gateway")
    definitions = _definitions(_definition("question_only", question=QUESTION))

    with caplog.at_level(logging.WARNING):
        assert classify_pending(service_config(), definitions, ClassifierState()) == 0
    row = _decisions()["question_only"]
    assert (row.status, row.attempts) == ("pending", 0)
    assert any(record.levelname == "WARNING" and "llm endpoint" in record.getMessage() for record in caplog.records)
    assert not any(record.levelname == "ERROR" for record in caplog.records)


@pytest.mark.integration
def test_a_stop_ends_the_classification_before_the_next_question(requests_mock):
    _pending()
    requests_mock.post(COMPLETIONS, json=_completion())
    definitions = _definitions(_definition("question_only", question=QUESTION))
    assert classify_pending(service_config(), definitions, ClassifierState(), lambda: True) == 0
    assert requests_mock.call_count == 0
    assert _decisions()["question_only"].status == "pending"


@pytest.mark.integration
def test_an_endpoint_certificate_that_does_not_verify_is_an_error(requests_mock, caplog):
    _pending()
    failure = requests.exceptions.SSLError("certificate verify failed")
    failure.__cause__ = ssl.SSLCertVerificationError("unable to get local issuer certificate")
    requests_mock.post(COMPLETIONS, exc=failure)
    definitions = _definitions(_definition("question_only", question=QUESTION))

    with caplog.at_level(logging.WARNING):
        assert classify_pending(service_config(), definitions, ClassifierState()) == 0
    assert _decisions()["question_only"].status == "pending"
    (record,) = [record for record in caplog.records if "llm endpoint" in record.getMessage()]
    assert record.levelname == "ERROR" and record.exc_info and record.feed_entry_id is not None


@pytest.mark.integration
def test_a_429_pauses_classification(requests_mock):
    _pending()
    requests_mock.post(COMPLETIONS, status_code=429, headers={"Retry-After": "3600"})
    definitions = _definitions(_definition("question_only", question=QUESTION))
    state = ClassifierState()

    classify_pending(service_config(retry_after_cap_seconds=60), definitions, state)
    assert requests_mock.call_count == 1
    # paused for the cap, not the hour asked for
    import time
    assert 50 < state.paused_until - time.monotonic() <= 60
    classify_pending(service_config(retry_after_cap_seconds=60), definitions, state)
    assert requests_mock.call_count == 1
    assert _decisions()["question_only"].status == "pending"


@pytest.mark.integration
def test_a_refused_key_stops_classification_until_the_configuration_changes(requests_mock, caplog):
    _pending()
    requests_mock.post(COMPLETIONS, status_code=401, text="bad key")
    definitions = _definitions(_definition("question_only", question=QUESTION))
    state = ClassifierState()

    with caplog.at_level(logging.ERROR):
        classify_pending(service_config(api_key="old"), definitions, state)
    assert any(record.levelname == "ERROR" and "refused the configured credentials" in record.getMessage()
               for record in caplog.records)
    assert "old" not in caplog.text

    classify_pending(service_config(api_key="old"), definitions, state)
    assert requests_mock.call_count == 1

    requests_mock.post(COMPLETIONS, json=_completion())
    classify_pending(service_config(api_key="new"), definitions, state)
    assert _decisions()["question_only"].status == "decided"


@pytest.mark.integration
def test_nothing_is_asked_without_a_system_prompt(requests_mock, caplog):
    _pending()
    requests_mock.post(COMPLETIONS, json=_completion())
    definitions = _definitions(_definition("question_only", question=QUESTION), prompt=None)
    state = ClassifierState()
    with caplog.at_level(logging.ERROR):
        classify_pending(service_config(), definitions, state)
        classify_pending(service_config(), definitions, state)
    assert requests_mock.call_count == 0
    assert sum("no system prompt" in record.getMessage() for record in caplog.records) == 1


@pytest.mark.integration
@pytest.mark.parametrize("change", ["model", "prompt"])
def test_a_watch_question_is_asked_under_the_configuration_it_finds(requests_mock, change):
    # the model or the prompt changed while the question waited (an endpoint outage, say)
    _pending()
    requests_mock.post(COMPLETIONS, json=_completion())
    model = "another-model" if change == "model" else LLM_MODEL
    prompt = PROMPT if change == "model" else PROMPT + " Answer conservatively."
    definitions = _definitions(_definition("question_only", question=QUESTION), prompt=prompt)

    assert classify_pending(service_config(model=model), definitions, ClassifierState()) == 1

    row = _decisions()["question_only"]
    assert (row.status, row.decision) == ("decided", "match")
    assert (row.model, row.prompt_hash) == (model, prompt_hash(prompt))
    sent = requests_mock.last_request.json()
    assert sent["model"] == model and sent["messages"][0]["content"].startswith(prompt)


@pytest.mark.integration
@pytest.mark.parametrize("change", ["model", "prompt"])
def test_a_replay_question_asked_under_another_configuration_fails(requests_mock, caplog, change):
    entry = make_entry(make_feed(), content=EXPLOITED_TEXT)
    db = get_db()
    db.add(FeedDecision(cache_key=replay_cache_key(QUESTION, prompt_hash(PROMPT), entry.id, LLM_MODEL), kind="replay",
                        entry_id=entry.id, question=QUESTION, model=LLM_MODEL, prompt_hash=prompt_hash(PROMPT),
                        status="pending", attempts=0, created_at=func.now()))
    db.commit()
    requests_mock.post(COMPLETIONS, json=_completion())
    model = "another-model" if change == "model" else LLM_MODEL
    prompt = PROMPT if change == "model" else PROMPT + " Answer conservatively."

    with caplog.at_level(logging.WARNING):
        assert classify_pending(service_config(model=model), _definitions(prompt=prompt), ClassifierState()) == 1

    db.expire_all()
    row = db.execute(select(FeedDecision)).scalar_one()
    expected = "the configured model" if change == "model" else "the system prompt"
    assert row.status == "failed" and row.last_error == f"{expected} changed before the question was asked"
    assert requests_mock.call_count == 0
    assert any(record.levelname == "WARNING" and record.feed_decision_id == row.id for record in caplog.records)
