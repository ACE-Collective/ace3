"""`ace search query` and `ace search similar` leave out test-run alerts unless --include-tests is
given, and say how many they left out (docs/SVS_RUNS.md)."""

import hashlib
import json
from argparse import Namespace
from unittest.mock import Mock

import fakeredis
import pytest

from saq.cli.commands.search import (
    _print_response,
    cli_download_model,
    cli_index,
    cli_query,
    cli_reset,
    cli_similar,
    cli_status,
)
from saq.configuration.config import get_config
from saq.database.model import Alert, Observable, ObservableMapping
from saq.database.pool import get_db
from saq.search import index, model
from saq.search.documents import SearchDocument
from saq.search.index import IndexResult
from saq.search.tasks import FAILED_TASK_KEY, TASK_KEY
from saq.search.types import AlertSearchResult, SearchHit, SearchResponse
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.unit

IPV4 = "10.9.8.7"


@pytest.fixture
def corpus():
    """One real alert and two test-run alerts (svs.queue) carrying the same ipv4 observable."""
    db = get_db()
    real, test_1, test_2 = insert_alert(), insert_alert(), insert_alert()
    db.execute(Alert.__table__.update().where(Alert.id.in_([test_1.id, test_2.id])).values(queue=get_config().svs.queue))
    observable = Observable(type="ipv4", value=IPV4.encode(), sha256=hashlib.sha256(IPV4.encode()).digest())
    db.add(observable)
    db.flush()
    for alert in (real, test_1, test_2):
        db.add(ObservableMapping(observable_id=observable.id, alert_id=alert.id))
    db.commit()
    return real, test_1, test_2


def _query_args(**kwargs) -> Namespace:
    return Namespace(**{"query": f"ipv4:{IPV4}", "limit": 20, "lane": "lexical", "json": False, "include_tests": False, **kwargs})


@pytest.mark.integration
def test_query_says_what_it_left_out(corpus, capsys):
    real, _, _ = corpus
    assert cli_query(_query_args()) == 0
    out = capsys.readouterr()
    assert "1 result(s)" in out.out and real.uuid in out.out
    assert "2 test alerts left out (--include-tests to include them)" in out.err


@pytest.mark.integration
def test_query_include_tests(corpus, capsys):
    assert cli_query(_query_args(include_tests=True)) == 0
    out = capsys.readouterr()
    assert "3 result(s)" in out.out
    assert "left out" not in out.err


@pytest.mark.integration
def test_json_carries_the_count(corpus, capsys):
    cli_query(_query_args(json=True))
    out = capsys.readouterr()
    assert '"excluded_test_alerts": 2' in out.out and "left out" not in out.err


@pytest.mark.integration
def test_similar(corpus, mock_qdrant, capsys):
    real, test_1, _ = corpus

    def groups(**kwargs):
        # the counting pass is the one restricted to the test queue
        test_pass = any(getattr(c, "key", None) == index.FIELD_QUEUE for c in kwargs["query_filter"].must or [])
        found = test_1.uuid if test_pass else real.uuid
        return Mock(groups=[Mock(id=found, hits=[Mock(score=0.9, payload={index.FIELD_KIND: "alert", index.FIELD_KEY: "header", index.FIELD_CHUNK: 0, index.FIELD_TEXT: "t", index.FIELD_TITLE: "t"})])])

    mock_qdrant.scroll.return_value = ([Mock(id="p1")], None)
    mock_qdrant.query_points_groups.side_effect = groups

    assert cli_similar(Namespace(uuid="x", limit=10, json=False, include_tests=False)) == 0
    out = capsys.readouterr()
    assert real.uuid in out.out and test_1.uuid not in out.out
    assert "1 test alert left out" in out.err

    cli_similar(Namespace(uuid="x", limit=10, json=False, include_tests=True))
    assert "left out" not in capsys.readouterr().err


def test_download_model(monkeypatch, capsys):
    monkeypatch.setattr(model, "download_model", lambda: "/data/search/models/all-minilm-l6-v2")
    monkeypatch.setattr(model, "get_model_name", lambda: "all-MiniLM-L6-v2")
    assert cli_download_model(Namespace()) == 0
    assert "all-MiniLM-L6-v2 is at /data/search/models/all-minilm-l6-v2" in capsys.readouterr().out


#
# ace search index
#

def _index_args(**kwargs) -> Namespace:
    return Namespace(**{"uuid": None, "all": False, "sync": False, "verbose": False, "storage_dir": None, **kwargs})


@pytest.fixture
def submitted(monkeypatch):
    """The alert uuids queued for the indexer, which accepts all of them."""
    uuids = []
    monkeypatch.setattr("saq.search.tasks.submit_index_task", lambda alert_uuid: uuids.append(alert_uuid) or True)
    return uuids


@pytest.mark.integration
def test_index_a_storage_dir_that_is_not_an_alert(tmp_path, submitted, capsys):
    assert cli_index(_index_args(storage_dir=str(tmp_path))) == 1
    assert "is not the storage directory of an alert" in capsys.readouterr().out
    assert submitted == []


@pytest.mark.integration
def test_index_the_alert_in_a_storage_dir(submitted, capsys):
    alert = insert_alert()

    assert cli_index(_index_args(storage_dir=alert.storage_dir)) == 0
    assert submitted == [alert.uuid]
    assert "submitted 1 of 1 alerts to the search indexer" in capsys.readouterr().out


@pytest.mark.unit
def test_index_needs_a_target(submitted, capsys):
    assert cli_index(_index_args()) == 1
    assert capsys.readouterr().out == "specify -u UUID, --all or a storage directory\n"


@pytest.mark.integration
def test_index_all_alerts_oldest_first(submitted, capsys):
    first, second = insert_alert(), insert_alert()

    assert cli_index(_index_args(all=True)) == 0
    assert submitted == [first.uuid, second.uuid]


@pytest.mark.unit
def test_index_fails_when_the_indexer_is_not_enabled(monkeypatch, capsys):
    monkeypatch.setattr("saq.search.tasks.indexer_enabled", lambda: False)

    # a script asking for an alert to be indexed must not read "nothing was queued" as success
    assert cli_index(_index_args(uuid="11111111-1111-1111-1111-111111111111")) == 1
    out = capsys.readouterr().out
    assert "submitted 0 of 1 alerts to the search indexer" in out
    assert "is service_search_indexer enabled?" in out


@pytest.mark.unit
def test_index_sync(monkeypatch, capsys):
    loaded = []
    monkeypatch.setattr(model, "download_model", lambda: loaded.append("download"))
    monkeypatch.setattr(model, "load_model", lambda: "the model")

    def index_alert(alert_uuid, model=None):
        loaded.append((alert_uuid, model))
        if alert_uuid == "skipped-uuid":
            return IndexResult(alert_uuid, skipped="not an alert")
        return IndexResult(alert_uuid, document_count=1, point_count=2, seconds=0.5, documents=[
            SearchDocument(kind="alert", key="header", text="line one\nline two", title="the header"),
            SearchDocument(kind="comment", key="1", text="x" * 200)])

    monkeypatch.setattr(index, "index_alert", index_alert)

    assert cli_index(_index_args(uuid="indexed-uuid", sync=True, verbose=True)) == 0
    assert cli_index(_index_args(uuid="skipped-uuid", sync=True)) == 0

    assert loaded == ["download", ("indexed-uuid", "the model"), "download", ("skipped-uuid", "the model")]
    lines = capsys.readouterr().out.splitlines()
    assert lines == [
        "indexed-uuid: 1 documents, 2 points, 0.50s",
        "  [alert/header] the header: 'line one\\nline two'",
        f"  [comment/1] : {'x' * 120!r}",
        "skipped-uuid: skipped (not an alert)",
    ]


#
# ace search query
#

@pytest.mark.integration
def test_query_errors_exit_non_zero(capsys):
    assert cli_query(_query_args(query="alert_date:-7dd")) == 1

    out = capsys.readouterr()
    assert out.out == ""
    assert "alert_date" in out.err


@pytest.mark.integration
def test_query_hints_at_an_exact_lookup(corpus, capsys):
    cli_query(_query_args(query=IPV4))
    assert f"use an observable type, e.g. ipv4:{IPV4}" in capsys.readouterr().err


@pytest.mark.integration
def test_query_prints_hits_and_unknown_alerts(capsys):
    alert = insert_alert()
    response = SearchResponse(query="evil", total=2, offset=0, limit=20, lanes_used=frozenset({"semantic", "lexical"}),
        timings_ms={"total": 5}, results=[
            AlertSearchResult(alert_uuid=alert.uuid, rank=1, fused_score=1.0, tier="strong", hits=[
                SearchHit(lane="semantic", kind="email", key="body", title="subject", text="first\nsecond", score=0.9)]),
            # gone from the database since it was indexed
            AlertSearchResult(alert_uuid="22222222-2222-2222-2222-222222222222", rank=2, fused_score=0.5, tier=None)])

    _print_response(response, as_json=False)

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "2 result(s) for 'evil' (lanes: lexical, semantic; {'total': 5})"
    assert lines[1] == f"  1. [strong] {alert.uuid} {alert.disposition} {alert.description}"
    assert lines[2] == "       semantic/email subject: first second"
    assert lines[3] == "  2. [-     ] 22222222-2222-2222-2222-222222222222 ? ?"


#
# ace search status and reset
#

@pytest.fixture
def task_queues(monkeypatch):
    connection = fakeredis.FakeStrictRedis()
    connection.rpush(TASK_KEY, "a", "b")
    connection.rpush(FAILED_TASK_KEY, "c")
    monkeypatch.setattr("saq.redis_client.get_redis_connection", lambda db: connection)
    return connection


@pytest.mark.unit
def test_status(mock_qdrant, task_queues, capsys):
    mock_qdrant.get_collection.return_value = Mock(payload_schema={"queue": 1, "alert_uuid": 1}, points_count=7,
                                                   indexed_vectors_count=6, status="green")

    assert cli_status(Namespace()) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["collection"] == index.collection_name()
    assert (result["exists"], result["points_count"], result["indexed_vectors_count"]) == (True, 7, 6)
    assert result["payload_indexes"] == ["alert_uuid", "queue"]
    assert (result["queued_tasks"], result["failed_tasks"]) == (2, 1)


@pytest.mark.unit
def test_reset_asks_first(mock_qdrant, task_queues, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    assert cli_reset(Namespace(yes=False)) == 1

    assert capsys.readouterr().out == "aborted\n"
    mock_qdrant.delete_collection.assert_not_called()
    assert task_queues.llen(TASK_KEY) == 2


@pytest.mark.unit
def test_reset_after_confirmation(mock_qdrant, task_queues, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt: " Yes ")

    assert cli_reset(Namespace(yes=False)) == 0

    mock_qdrant.delete_collection.assert_called_once_with(collection_name=index.collection_name())
    assert (task_queues.llen(TASK_KEY), task_queues.llen(FAILED_TASK_KEY)) == (0, 0)
    out = capsys.readouterr().out
    assert f"collection {index.collection_name()} dropped; queues purged" in out
    assert "run `ace search index --all` to rebuild" in out


@pytest.mark.unit
def test_reset_without_a_collection(mock_qdrant, task_queues, capsys):
    mock_qdrant.collection_exists.return_value = False

    assert cli_reset(Namespace(yes=True)) == 0

    assert f"collection {index.collection_name()} did not exist; queues purged" in capsys.readouterr().out
    assert task_queues.llen(TASK_KEY) == 0
