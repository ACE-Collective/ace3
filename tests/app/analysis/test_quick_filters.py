"""Unit tests for the mtime-based caching in
app.analysis.views.session.filters.get_quick_filters."""

from unittest.mock import MagicMock

import pytest
import yaml

import app.analysis.views.session.filters as filters_mod
from app.analysis.views.session.filters import get_quick_filters


@pytest.fixture(autouse=True)
def reset_quick_filters_cache():
    """The cache lives in module globals; reset it before/after each test so
    tests don't leak cached state into one another."""
    filters_mod._quick_filters_cache = []
    filters_mod._quick_filters_mtime = None
    filters_mod._quick_filters_path = None
    yield
    filters_mod._quick_filters_cache = []
    filters_mod._quick_filters_mtime = None
    filters_mod._quick_filters_path = None


def _point_at(monkeypatch, path):
    """Make get_quick_filters resolve to `path` (an absolute path). get_base_dir
    returns "" so os.path.join("", <abs path>) == <abs path>."""
    monkeypatch.setattr(filters_mod, "get_base_dir", lambda: "")
    cfg = MagicMock()
    cfg.gui.quick_filters_config_path = str(path)
    monkeypatch.setattr(filters_mod, "get_config", lambda: cfg)


@pytest.mark.unit
def test_parses_quick_filters(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text("quick_filters:\n  - id: a\n    label: A\n")
    _point_at(monkeypatch, path)

    assert get_quick_filters() == [{"id": "a", "label": "A"}]


@pytest.mark.unit
def test_missing_file_returns_empty(tmp_path, monkeypatch):
    _point_at(monkeypatch, tmp_path / "does_not_exist.yaml")

    assert get_quick_filters() == []


@pytest.mark.unit
def test_cache_hit_skips_reread(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text("quick_filters:\n  - id: a\n")
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
    path.write_text("quick_filters:\n  - id: a\n")
    _point_at(monkeypatch, path)

    current = {"mtime": 1000.0}
    monkeypatch.setattr(filters_mod.os.path, "getmtime", lambda p: current["mtime"])
    spy = MagicMock(wraps=yaml.safe_load)
    monkeypatch.setattr(filters_mod.yaml, "safe_load", spy)

    assert get_quick_filters() == [{"id": "a"}]

    # edit the file and bump its mtime -> next call must re-read
    path.write_text("quick_filters:\n  - id: b\n")
    current["mtime"] = 2000.0

    assert get_quick_filters() == [{"id": "b"}]
    assert spy.call_count == 2


@pytest.mark.unit
def test_returns_distinct_objects(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text("quick_filters:\n  - id: a\n")
    _point_at(monkeypatch, path)

    first = get_quick_filters()
    # callers (e.g. manage.py) mutate the returned dicts; this must not leak
    # back into the shared cache
    first[0]["indicator_count"] = 5

    second = get_quick_filters()
    assert first is not second
    assert "indicator_count" not in second[0]


@pytest.mark.unit
def test_transient_parse_error_keeps_cached_copy(tmp_path, monkeypatch):
    path = tmp_path / "qf.yaml"
    path.write_text("quick_filters:\n  - id: a\n")
    _point_at(monkeypatch, path)

    current = {"mtime": 1000.0}
    monkeypatch.setattr(filters_mod.os.path, "getmtime", lambda p: current["mtime"])

    # prime the cache with a good copy
    assert get_quick_filters() == [{"id": "a"}]

    # simulate a transient parse failure on the next (mtime-changed) read
    current["mtime"] = 2000.0
    monkeypatch.setattr(
        filters_mod.yaml, "safe_load",
        MagicMock(side_effect=yaml.YAMLError("boom")),
    )

    # the previously cached good copy is returned rather than []
    assert get_quick_filters() == [{"id": "a"}]
