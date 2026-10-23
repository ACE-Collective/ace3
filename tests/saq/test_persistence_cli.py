"""Tests for the `ace persistence` commands."""

from datetime import datetime, timedelta

import pytest

import saq.cli.commands.persistence  # registers the commands
from saq.cli.cli_main import get_cli_parser
from saq.database.model import Persistence, PersistenceSource
from saq.database.pool import get_db


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["persistence", *argv])
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


def _source(name: str) -> int:
    source = PersistenceSource(name=name)
    get_db().add(source)
    get_db().commit()
    return source.id


def _key(source_id: int, key: str, permanent: bool = False, days_old: int = 0):
    get_db().add(Persistence(source_id=source_id, uuid=key, permanent=int(permanent),
                             last_update=datetime.now() - timedelta(days=days_old)))
    get_db().commit()


def _keys(source_id: int) -> list[str]:
    get_db().expire_all()
    return sorted(key for (key,) in get_db().query(Persistence.uuid).filter(Persistence.source_id == source_id))


@pytest.fixture
def sources():
    """Two sources: alpha with a permanent and a temporal key, beta with one permanent key."""
    alpha = _source("cli_alpha")
    beta = _source("cli_beta")
    _key(alpha, "alpha_permanent", permanent=True)
    _key(alpha, "alpha_temporal")
    _key(beta, "beta_permanent", permanent=True)
    return alpha, beta


@pytest.mark.integration
def test_list_sources(sources, capsys):
    assert _ace("list", "-s", "cli_") == 0

    assert capsys.readouterr().out == "cli_alpha\ncli_beta\n"


@pytest.mark.integration
def test_list_keys(sources, capsys):
    assert _ace("list", "-s", "cli_", "-k") == 0
    assert capsys.readouterr().out == "cli_alpha alpha_permanent\ncli_beta beta_permanent\n"

    assert _ace("list", "-s", "cli_alpha", "-k", "-t") == 0
    assert capsys.readouterr().out == "cli_alpha alpha_permanent\ncli_alpha alpha_temporal\n"

    assert _ace("list", "-s", "cli_", "-n", "beta") == 0
    assert capsys.readouterr().out == "cli_beta beta_permanent\n"


@pytest.mark.integration
def test_clear_unknown_source(caplog):
    assert _ace("clear", "no_such_source", "--all") == 1

    assert "unknown persistence source no_such_source" in caplog.text


@pytest.mark.integration
def test_clear_all(sources):
    alpha, beta = sources

    assert _ace("clear", "cli_alpha", "--all") == 0

    assert _keys(alpha) == []
    assert _keys(beta) == ["beta_permanent"]


@pytest.mark.integration
def test_clear_keys(sources):
    alpha, _ = sources

    assert _ace("clear", "cli_alpha", "alpha_temporal", "missing_key") == 0

    assert _keys(alpha) == ["alpha_permanent"]


@pytest.mark.integration
def test_clear_older_than_keeps_permanent_and_recent_keys(sources):
    alpha, _ = sources
    _key(alpha, "alpha_old", days_old=10)
    _key(alpha, "alpha_old_permanent", permanent=True, days_old=10)

    assert _ace("clear", "cli_alpha", "--older-than", "5 days ago") == 0

    assert _keys(alpha) == ["alpha_old_permanent", "alpha_permanent", "alpha_temporal"]


@pytest.mark.integration
def test_clear_older_than_rejects_what_it_cannot_parse(sources, caplog):
    """An unparsable time used to compare last_update with NULL, clear nothing and exit 0."""
    alpha, _ = sources
    _key(alpha, "alpha_old", days_old=10)

    assert _ace("clear", "cli_alpha", "--older-than", "not a time") == 1

    assert "invalid --older-than 'not a time'" in caplog.text
    assert "alpha_old" in _keys(alpha)


@pytest.mark.integration
@pytest.mark.parametrize("argv", [["--all"], ["alpha_old"], ["--older-than", "5 days ago"]])
def test_dry_run_changes_nothing(sources, argv):
    alpha, _ = sources
    _key(alpha, "alpha_old", days_old=10)

    assert _ace("clear", "cli_alpha", "--dry-run", *argv) == 0

    assert _keys(alpha) == ["alpha_old", "alpha_permanent", "alpha_temporal"]
