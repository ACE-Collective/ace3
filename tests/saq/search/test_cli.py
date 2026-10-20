"""`ace search query` and `ace search similar` leave out test-run alerts unless --include-tests is
given, and say how many they left out (docs/SVS_RUNS.md)."""

from argparse import Namespace

import pytest

from saq.cli.commands.search import cli_download_model, cli_query, cli_similar
from saq.search import model, query
from saq.search.types import SearchResponse

pytestmark = pytest.mark.unit


@pytest.fixture
def searched(monkeypatch):
    calls = {}

    def search(request, **kwargs):
        calls["request"] = request
        return SearchResponse(query=request.query, total=0, offset=0, limit=request.limit,
                              excluded_test_alerts=None if request.include_test_alerts else 2)

    def similar(alert_uuid, **kwargs):
        calls["similar"] = kwargs
        return SearchResponse(query=f"similar:{alert_uuid}", total=0, offset=0, limit=kwargs["limit"],
                              excluded_test_alerts=None if kwargs["include_test_alerts"] else 1)

    monkeypatch.setattr(query, "search_alerts", search)
    monkeypatch.setattr(query, "similar_alerts", similar)
    return calls


def _query_args(**kwargs) -> Namespace:
    return Namespace(**{"query": "mimikatz", "limit": 20, "lane": None, "json": False, "include_tests": False, **kwargs})


def test_query_says_what_it_left_out(searched, capsys):
    assert cli_query(_query_args()) == 0
    assert searched["request"].include_test_alerts is False
    assert "2 test alerts left out (--include-tests to include them)" in capsys.readouterr().err


def test_query_include_tests(searched, capsys):
    assert cli_query(_query_args(include_tests=True)) == 0
    assert searched["request"].include_test_alerts is True
    assert "left out" not in capsys.readouterr().err


def test_json_carries_the_count(searched, capsys):
    cli_query(_query_args(json=True))
    out = capsys.readouterr()
    assert '"excluded_test_alerts": 2' in out.out and "left out" not in out.err


def test_similar(searched, capsys):
    assert cli_similar(Namespace(uuid="x", limit=10, json=False, include_tests=False)) == 0
    assert searched["similar"]["include_test_alerts"] is False
    assert "1 test alert left out" in capsys.readouterr().err

    cli_similar(Namespace(uuid="x", limit=10, json=False, include_tests=True))
    assert searched["similar"]["include_test_alerts"] is True


def test_download_model(monkeypatch, capsys):
    monkeypatch.setattr(model, "download_model", lambda: "/data/search/models/all-minilm-l6-v2")
    monkeypatch.setattr(model, "get_model_name", lambda: "all-MiniLM-L6-v2")
    assert cli_download_model(Namespace()) == 0
    assert "all-MiniLM-L6-v2 is at /data/search/models/all-minilm-l6-v2" in capsys.readouterr().out
