"""`ace search query` and `ace search similar` leave out test-run alerts unless --include-tests is
given, and say how many they left out (docs/SVS_RUNS.md)."""

import hashlib
from argparse import Namespace
from unittest.mock import Mock

import pytest

from saq.cli.commands.search import cli_download_model, cli_query, cli_similar
from saq.configuration.config import get_config
from saq.database.model import Alert, Observable, ObservableMapping
from saq.database.pool import get_db
from saq.search import index, model
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
