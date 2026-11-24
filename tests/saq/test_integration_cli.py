"""Tests for the `ace integration` commands."""

import os
import re
import subprocess
from pathlib import Path

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
    """alpha (nested in a group dir) and beta, in a scratch base and var dir."""
    base = tmp_path / "integrations"
    for path in (base / "group" / "alpha", base / "beta"):
        path.mkdir(parents=True)
        (path / "integration.md").write_text("# integration\n")

    var_dir = tmp_path / "var"
    monkeypatch.setattr(integration_util, "get_integration_base_dir", lambda: str(base))
    monkeypatch.setattr(integration_manager, "get_integration_var_base_dir", lambda: str(var_dir))
    return tmp_path


@pytest.mark.unit
def test_disable_and_enable(integrations):
    assert _ace("disable", "alpha") == 0
    assert not integration_manager.is_integration_enabled("alpha")

    assert _ace("enable", "alpha") == 0
    assert integration_manager.is_integration_enabled("alpha")


@pytest.mark.unit
@pytest.mark.parametrize("verb", ["enable", "disable"])
def test_unknown_integration_is_an_error(integrations, caplog, verb):
    assert _ace(verb, "gamma") == 1

    assert "unknown integration gamma: no integration directory with basename 'gamma'" in caplog.text
    # disabling an unknown name must not leave a var dir behind for it
    assert not os.path.exists(integrations / "var" / "gamma")


@pytest.mark.unit
def test_list(integrations, capsys):
    assert _ace("disable", "beta") == 0
    capsys.readouterr()

    assert _ace("list") == 0

    output = capsys.readouterr().out
    rows = {line.split()[0]: line.split()[1:] for line in output.splitlines()[2:]}
    base = integrations / "integrations"
    assert rows == {
        "alpha": ["ENABLED", str(base / "group" / "alpha")],
        "beta": ["DISABLED", str(base / "beta")],
    }

    # the daily log rotation reads the enabled integrations' names and directories from this table
    rotate_logs = (Path(__file__).resolve().parents[2] / "etc" / "cron" / "daily" / "rotate-logs").read_text()
    program = re.search(r"ace integration list \| awk '([^']+)'", rotate_logs).group(1)
    awk = subprocess.run(["awk", program], input=output, capture_output=True, text=True, check=True, timeout=10)
    assert awk.stdout == f"alpha {base / 'group' / 'alpha'}\n"
