"""Tests for quick-filter loading, validation and caching in
app.analysis.views.session.filters."""

from unittest.mock import MagicMock

import pytest
import yaml

import app.analysis.views.session.filters as filters_mod
from app.analysis.views.session.filters import (
    FILTER_NAMES,
    get_quick_filters,
    getFilters,
    parse_quick_filters,
)


@pytest.fixture(autouse=True)
def reset_quick_filters_cache():
    """The cache lives in module globals; reset it before and after each test so tests
    don't leak cached state into one another."""
    filters_mod._quick_filters_cache = []
    filters_mod._quick_filters_mtime = None
    filters_mod._quick_filters_path = None
    yield
    filters_mod._quick_filters_cache = []
    filters_mod._quick_filters_mtime = None
    filters_mod._quick_filters_path = None


def _point_at(monkeypatch, path):
    """Makes get_quick_filters resolve to `path` (an absolute path). get_base_dir returns
    "" so os.path.join("", <abs path>) == <abs path>."""
    monkeypatch.setattr(filters_mod, "get_base_dir", lambda: "")
    cfg = MagicMock()
    cfg.gui.quick_filters_config_path = str(path)
    monkeypatch.setattr(filters_mod, "get_config", lambda: cfg)


VALID_QUICK_FILTER = """
quick_filters:
  - id: needs_research
    label: Needs Research
    filters:
      - name: Queue
        values: ["$USER_QUEUE"]
      - name: Tag
        values: ["needs_research"]
"""


@pytest.mark.integration
def test_filter_names_match_get_filters():
    """FILTER_NAMES is what quick filter config is validated against; if it drifts from
    the actual filter registry then either a valid name gets rejected or an invalid one
    reaches session['filters'] and breaks /manage. (integration: SelectFilter queries the
    database for its options.)"""
    assert set(FILTER_NAMES) == set(getFilters())


@pytest.mark.unit
def test_parses_quick_filters(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text(VALID_QUICK_FILTER)
    _point_at(monkeypatch, path)

    quick_filters = get_quick_filters()

    assert len(quick_filters) == 1
    assert quick_filters[0].id == "needs_research"
    assert quick_filters[0].label == "Needs Research"
    # not configured, so no dot
    assert quick_filters[0].indicator is False
    assert [_.name for _ in quick_filters[0].filters] == ["Queue", "Tag"]
    assert quick_filters[0].filters[0].inverted is False


@pytest.mark.unit
def test_missing_file_returns_empty(tmp_path, monkeypatch):
    _point_at(monkeypatch, tmp_path / "does_not_exist.yaml")

    assert get_quick_filters() == []


@pytest.mark.unit
def test_cache_hit_skips_reread(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text(VALID_QUICK_FILTER)
    _point_at(monkeypatch, path)

    # pin the mtime so the second call sees an unchanged file
    monkeypatch.setattr(filters_mod.os.path, "getmtime", lambda p: 1000.0)
    spy = MagicMock(wraps=yaml.safe_load)
    monkeypatch.setattr(filters_mod.yaml, "safe_load", spy)

    get_quick_filters()
    get_quick_filters()

    # parsed exactly once despite two calls
    assert spy.call_count == 1


@pytest.mark.unit
def test_reload_on_mtime_change(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text(VALID_QUICK_FILTER)
    _point_at(monkeypatch, path)

    current = {"mtime": 1000.0}
    monkeypatch.setattr(filters_mod.os.path, "getmtime", lambda p: current["mtime"])
    spy = MagicMock(wraps=yaml.safe_load)
    monkeypatch.setattr(filters_mod.yaml, "safe_load", spy)

    assert [_.id for _ in get_quick_filters()] == ["needs_research"]

    # edit the file and bump its mtime -> next call must re-read
    path.write_text(VALID_QUICK_FILTER.replace("needs_research", "renamed"))
    current["mtime"] = 2000.0

    assert [_.id for _ in get_quick_filters()] == ["renamed"]
    assert spy.call_count == 2


@pytest.mark.unit
def test_transient_parse_error_keeps_cached_copy(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text(VALID_QUICK_FILTER)
    _point_at(monkeypatch, path)

    current = {"mtime": 1000.0}
    monkeypatch.setattr(filters_mod.os.path, "getmtime", lambda p: current["mtime"])

    # prime the cache with a good copy
    assert [_.id for _ in get_quick_filters()] == ["needs_research"]

    # simulate a transient parse failure on the next (mtime-changed) read
    current["mtime"] = 2000.0
    monkeypatch.setattr(
        filters_mod.yaml, "safe_load",
        MagicMock(side_effect=yaml.YAMLError("boom")),
    )

    # the previously cached good copy is returned rather than []
    assert [_.id for _ in get_quick_filters()] == ["needs_research"]


@pytest.mark.unit
@pytest.mark.parametrize("entry,reason", [
    ({"label": "No Id", "filters": [{"name": "Queue", "values": ["default"]}]}, "missing id"),
    ({"id": "no_label", "filters": [{"name": "Queue", "values": ["default"]}]}, "missing label"),
    ({"id": "no_filters", "label": "No Filters"}, "missing filters"),
    ({"id": "empty_filters", "label": "Empty", "filters": []}, "empty filters"),
    # a typo'd name would be written straight into session['filters'] and make
    # create_filter() raise KeyError on every /manage load from then on
    ({"id": "bad_name", "label": "Bad", "filters": [{"name": "Tags", "values": ["x"]}]}, "unknown filter name"),
    ({"id": "no_values", "label": "Bad", "filters": [{"name": "Queue"}]}, "missing values"),
    ({"id": "empty_values", "label": "Bad", "filters": [{"name": "Queue", "values": []}]}, "empty values"),
    # the id goes into a URL path and a DOM attribute
    ({"id": 'has "quotes"', "label": "Bad", "filters": [{"name": "Queue", "values": ["x"]}]}, "unsafe id"),
    ({"id": "extra_key", "label": "Bad", "filters": [{"name": "Queue", "values": ["x"]}], "color": "#fff"}, "unknown key"),
])
def test_invalid_entries_are_dropped(entry, reason):
    assert parse_quick_filters({"quick_filters": [entry]}, "test.yaml") == [], reason


@pytest.mark.unit
def test_invalid_entry_does_not_drop_the_valid_ones():
    """One bad badge must not take out the whole filter bar."""
    result = parse_quick_filters({
        "quick_filters": [
            {"id": "bad", "label": "Bad", "filters": [{"name": "Nope", "values": ["x"]}]},
            {"id": "good", "label": "Good", "filters": [{"name": "Queue", "values": ["x"]}]},
        ]
    }, "test.yaml")

    assert [_.id for _ in result] == ["good"]


@pytest.mark.unit
def test_duplicate_ids_are_dropped():
    result = parse_quick_filters({
        "quick_filters": [
            {"id": "dupe", "label": "First", "filters": [{"name": "Queue", "values": ["x"]}]},
            {"id": "dupe", "label": "Second", "filters": [{"name": "Queue", "values": ["y"]}]},
        ]
    }, "test.yaml")

    assert len(result) == 1
    assert result[0].label == "First"


@pytest.mark.unit
@pytest.mark.parametrize("data", [None, [], "nope", {}, {"quick_filters": None}])
def test_unusable_config_returns_empty(data):
    assert parse_quick_filters(data, "test.yaml") == []


@pytest.mark.unit
def test_observable_values_are_type_value_pairs():
    """Every filter takes string values except Observable, whose values are
    [type, value] pairs (see TypeValueFilter.apply)."""
    result = parse_quick_filters({
        "quick_filters": [{
            "id": "obs",
            "label": "Observable",
            "filters": [{"name": "Observable", "values": [["ipv4", "1.2.3.4"]]}],
        }]
    }, "test.yaml")

    assert result[0].filters[0].values == [["ipv4", "1.2.3.4"]]


@pytest.mark.unit
def test_shipped_config_is_valid():
    """etc/gui_quick_filters.yaml is what every deployment gets by default."""
    with open("etc/gui_quick_filters.yaml", "r") as fp:
        data = yaml.safe_load(fp)

    assert [_.id for _ in parse_quick_filters(data, "etc/gui_quick_filters.yaml")] == [
        "needs_research", "unreviewed",
    ]
