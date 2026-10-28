import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "bin" / "manage-requirements.py"

pytestmark = pytest.mark.unit


def _load_script():
    # the hyphen in the file name keeps it from being imported by name
    spec = importlib.util.spec_from_file_location("manage_requirements", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = _load_script()


@pytest.fixture
def pip_freeze(monkeypatch):
    def _set(output: str):
        monkeypatch.setattr(script.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["pip", "freeze"], returncode=0, stdout=output, stderr=""))
    return _set


def test_pins_a_package_pip_freeze_spells_differently(pip_freeze):
    # pip freeze writes the name as the package's metadata spells it (diff_cover 11 has an underscore)
    pip_freeze("diff_cover==11.0.0\nPyJWT==2.15.1\nfakeredis==2.40.0\n")

    lines = script.generate_pinned_lines(["diff-cover", "pyjwt", "fakeredis[lua]", "# a comment"],
                                         script.get_installed_versions())

    assert lines == ["diff-cover==11.0.0", "pyjwt==2.15.1", "fakeredis[lua]==2.40.0", "# a comment"]


def test_check_finds_an_outdated_package_pip_freeze_spells_differently(pip_freeze, tmp_path, monkeypatch, capsys):
    pip_freeze("diff_cover==11.0.0\n")
    pinned = tmp_path / "requirements-pinned.txt"
    pinned.write_text("diff-cover==10.6.0\n")
    monkeypatch.setattr(script, "PINNED_FILE", pinned)

    with pytest.raises(SystemExit) as exit_info:
        script.do_check()

    assert exit_info.value.code == 1
    assert capsys.readouterr().out == "diff-cover: pinned 10.6.0, installed 11.0.0\n"
