"""Tests for the `ace integration` commands."""

import re
import subprocess
from pathlib import Path

import pytest

import saq.cli.commands.integration  # registers the commands
import saq.integration.integration_util as integration_util
from saq.cli.cli_main import get_cli_parser
from saq.environment import get_global_runtime_settings
from tests.saq.helpers import configure_integrations


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["integration", *argv])
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


def _block(name: str, enabled: bool) -> str:
    return (f"integration_{name}:\n  name: {name}\n  enabled: {str(enabled).lower()}\n"
            f"  description: {name}\n  python_module: {name}\n")


@pytest.fixture
def integrations(monkeypatch, tmp_path):
    """alpha (nested in a group dir, enabled), beta (disabled), gamma (one section of each) and
    delta (no section), in a scratch base dir, with the configuration loaded from them."""
    base = tmp_path / "integrations"
    blocks = {
        base / "group" / "alpha": _block("alpha", True),
        base / "beta": _block("beta", False),
        base / "gamma": _block("gamma_on", True) + _block("gamma_off", False),
        base / "delta": "",
    }
    monkeypatch.setattr(get_global_runtime_settings(), "integration_config_paths", [])
    monkeypatch.delenv("SAQ_CONFIG_PATHS", raising=False)
    for path, body in blocks.items():
        (path / "etc").mkdir(parents=True)
        (path / "etc" / "saq.integration.yaml").write_text(body)
        (path / "integration.md").write_text("# integration\n")
        get_global_runtime_settings().integration_config_paths.append(str(path / "etc" / "saq.integration.yaml"))

    monkeypatch.setattr(integration_util, "get_integration_base_dir", lambda: str(base))
    configure_integrations(monkeypatch)
    return base


@pytest.mark.unit
@pytest.mark.parametrize("verb", ["enable", "disable"])
def test_the_marker_commands_are_gone(verb, capsys):
    # enabled: in the integration_<name>: section is the only switch
    with pytest.raises(SystemExit) as e:
        get_cli_parser().parse_args(["integration", verb, "alpha"])

    assert e.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.unit
def test_list(integrations, capsys):
    assert _ace("list") == 0

    output = capsys.readouterr().out
    rows = sorted(tuple(line.split()) for line in output.splitlines()[2:])
    assert rows == sorted([
        ("alpha", "ENABLED", str(integrations / "group" / "alpha")),
        ("beta", "DISABLED", str(integrations / "beta")),
        ("gamma_on", "ENABLED", str(integrations / "gamma")),
        ("gamma_off", "DISABLED", str(integrations / "gamma")),
        ("delta", "UNDECLARED", str(integrations / "delta")),
    ])

    # the daily log rotation reads the directories of the integrations that are on from this table
    rotate_logs = (Path(__file__).resolve().parents[2] / "etc" / "cron" / "daily" / "rotate-logs").read_text()
    program = re.search(r"ace integration list \| awk '([^']+)'", rotate_logs).group(1)
    awk = subprocess.run(["awk", program], input=output, capture_output=True, text=True, check=True, timeout=10)
    assert sorted(awk.stdout.splitlines()) == sorted(
        str(integrations / name) for name in ("group/alpha", "gamma", "delta"))
