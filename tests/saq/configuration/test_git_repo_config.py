"""git_repo_* sections are registered under their name field, like database_*, remediator_*
and the other sections that carry one, not under the suffix of the section key."""
import logging

import pytest

from saq.configuration.config import get_config


def _git_repo_section(name: str) -> dict:
    return {
        "name": name,
        "description": "test repo",
        "local_path": "/path/to/repo",
        "git_url": "https://example.com/repo.git",
        "update_frequency": 60,
        "branch": "main",
    }


@pytest.mark.unit
def test_git_repo_registered_under_name(monkeypatch):
    monkeypatch.setattr(get_config().raw, "_data", {"git_repo_foo": _git_repo_section("bar")})
    get_config().load_git_repo_configs()

    assert get_config().get_git_repo_config("bar").name == "bar"
    assert [repo.name for repo in get_config().git_repos] == ["bar"]

    with pytest.raises(ValueError):
        get_config().get_git_repo_config("foo")


@pytest.mark.unit
def test_duplicate_git_repo_name_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(get_config().raw, "_data", {
        "git_repo_first": _git_repo_section("bar"),
        "git_repo_second": {**_git_repo_section("bar"), "branch": "develop"},
    })
    with caplog.at_level(logging.ERROR):
        get_config().load_git_repo_configs()

    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "git_repo_first" in errors[0].getMessage()
    assert "git_repo_second" in errors[0].getMessage()

    # the later section wins
    assert get_config().get_git_repo_config("bar").branch == "develop"


@pytest.mark.unit
def test_distinct_git_repo_names_log_nothing(monkeypatch, caplog):
    monkeypatch.setattr(get_config().raw, "_data", {
        "git_repo_first": _git_repo_section("one"),
        "git_repo_second": _git_repo_section("two"),
    })
    with caplog.at_level(logging.ERROR):
        get_config().load_git_repo_configs()

    assert not [r for r in caplog.records if r.levelno == logging.ERROR]
