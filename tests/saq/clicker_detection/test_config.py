import pytest

from saq.analysis import RootAnalysis
from saq.clicker_detection.config import (
    build_splunk_clicker_search_urls,
    get_clicker_match_values,
    get_searches_for,
    load_clicker_config,
    splunk_value_expansion,
)
from saq.constants import F_FQDN, F_URL


def _config(**searches):
    return {"splunk": {"enabled": True, "searches": searches}}


@pytest.mark.unit
def test_get_clicker_match_values_fqdn_single():
    obs = RootAnalysis().add_observable_by_spec(F_FQDN, "evil.example")
    assert get_clicker_match_values(obs) == ["evil.example"]


@pytest.mark.unit
def test_splunk_value_expansion():
    assert splunk_value_expansion(["a", "b"]) == '("a" OR "b")'
    assert splunk_value_expansion(['ab"c']) == '("ab\\"c")'  # quotes escaped


@pytest.mark.unit
def test_load_clicker_config_missing_returns_empty():
    assert load_clicker_config("/nonexistent/clicker_detection.yaml") == {}


@pytest.mark.unit
def test_get_searches_for_filters_by_type_and_enabled():
    config = _config(
        safelinks={"observable_types": ["url", "fqdn"], "query": "a"},
        proxy={"observable_types": ["url", "fqdn"], "query": "b"},
        hosts_only={"observable_types": ["fqdn"], "query": "c"},
    )
    url_searches = get_searches_for(config, "splunk", "url")
    assert [name for name, _ in url_searches] == ["safelinks", "proxy"]  # config order, fqdn-only excluded

    fqdn_searches = get_searches_for(config, "splunk", "fqdn")
    assert {name for name, _ in fqdn_searches} == {"safelinks", "proxy", "hosts_only"}

    # disabled source -> nothing
    disabled = {"splunk": {"enabled": False, "searches": {"safelinks": {"observable_types": ["url"], "query": "a"}}}}
    assert get_searches_for(disabled, "splunk", "url") == []


@pytest.mark.unit
def test_load_and_get_searches_for(tmp_path):
    path = tmp_path / "clicker_detection.yaml"
    path.write_text(
        "splunk:\n"
        "  enabled: true\n"
        "  searches:\n"
        "    safelinks:\n"
        "      observable_types: [url, fqdn]\n"
        "      query: 'index=x <O_VALUE>'\n"
    )
    config = load_clicker_config(str(path))
    assert [n for n, _ in get_searches_for(config, "splunk", "url")] == ["safelinks"]


@pytest.mark.unit
def test_build_splunk_clicker_search_urls(test_context):
    config = _config(
        safelinks={
            "observable_types": ["url"],
            "query": 'index=x sourcetype="y" <O_VALUE> <TIMESPEC>',
            "time_ranges": {"TIMESPEC": {"duration_before": "07:00:00:00", "duration_after": "00:01:00:00"}},
        },
        proxy={
            "observable_types": ["url"],
            "query": 'index=proxy <O_VALUE> <TIMESPEC>',
            "time_ranges": {"TIMESPEC": {"duration_before": "07:00:00:00", "duration_after": "00:01:00:00"}},
        },
    )
    observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
    urls = build_splunk_clicker_search_urls(config, observable)
    assert [u["name"] for u in urls] == ["safelinks", "proxy"]
    for u in urls:
        assert u["url"].startswith("https://")
        assert "q=" in u["url"]
        assert "TIMESPEC" not in u["url"]


