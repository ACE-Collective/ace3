"""Tests for the `ace integration` commands."""

import os

import pytest

import saq.cli.commands.integration  # registers the commands
import saq.integration.integration_manager as integration_manager
import saq.integration.integration_util as integration_util
from saq.cli.cli_main import get_cli_parser


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["integration", *argv])
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


@pytest.fixture
def integrations(monkeypatch, tmp_path):
    """alpha (nested in a group dir, with tests) and beta (without tests), in a scratch base, tests and var dir."""
    base = tmp_path / "integrations"
    for path, has_tests in ((base / "group" / "alpha", True), (base / "beta", False)):
        path.mkdir(parents=True)
        (path / "integration.md").write_text("# integration\n")
        if has_tests:
            (path / "tests").mkdir()

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    var_dir = tmp_path / "var"
    monkeypatch.setattr(integration_util, "get_integration_base_dir", lambda: str(base))
    monkeypatch.setattr(integration_manager, "_get_tests_dir", lambda: str(tests_dir))
    monkeypatch.setattr(integration_manager, "get_integration_var_base_dir", lambda: str(var_dir))
    return tmp_path


@pytest.mark.unit
def test_disable_and_enable(integrations):
    assert _ace("disable", "alpha") == 0
    assert not integration_manager.is_integration_enabled("alpha")

    assert _ace("enable", "alpha") == 0
    assert integration_manager.is_integration_enabled("alpha")


@pytest.mark.unit
@pytest.mark.parametrize("verb", ["enable", "disable", "install"])
def test_unknown_integration_is_an_error(integrations, caplog, verb):
    assert _ace(verb, "gamma") == 1

    assert "unknown integration gamma: no integration directory with basename 'gamma'" in caplog.text
    # disabling an unknown name must not leave a var dir behind for it
    assert not os.path.exists(integrations / "var" / "gamma")


@pytest.mark.unit
def test_install_and_uninstall(integrations, capsys, caplog):
    link = integrations / "tests" / "test_external_integration_alpha"

    assert _ace("install", "alpha") == 0
    assert os.path.islink(link)
    assert os.readlink(link) == os.path.join("..", "integrations", "group", "alpha", "tests")

    assert _ace("install", "alpha") == 0
    assert capsys.readouterr().out == "integration alpha is already installed\n"

    assert _ace("uninstall", "alpha") == 0
    assert not os.path.lexists(link)

    assert _ace("uninstall", "alpha") == 1
    assert "integration alpha is not installed" in caplog.text


@pytest.mark.unit
def test_install_without_tests_dir_is_an_error(integrations, caplog):
    assert _ace("install", "beta") == 1

    assert "integration beta has no tests directory to install" in caplog.text


@pytest.mark.unit
def test_list(integrations, capsys):
    assert _ace("disable", "beta") == 0
    assert _ace("install", "alpha") == 0
    capsys.readouterr()

    assert _ace("list") == 0

    rows = {line.split()[0]: line.split()[1:] for line in capsys.readouterr().out.splitlines()[2:]}
    base = integrations / "integrations"
    assert rows == {
        "alpha": ["ENABLED", "YES", str(base / "group" / "alpha")],
        "beta": ["DISABLED", "NO", str(base / "beta")],
    }
