import io
import json

import pytest

import saq.cli.commands  # noqa: F401
from saq.cli.cli_main import get_cli_parser
from saq.configuration.encryption import decrypt_password, encrypt_password, export_encrypted_passwords
from saq.crypto import InvalidPasswordError, get_aes_key, set_encryption_password
from saq.environment import get_global_runtime_settings


def _run(*argv):
    args = get_cli_parser().parse_args(["encryption", *argv])
    with pytest.raises(SystemExit) as exit_info:
        args.func(args)
    return exit_info.value.code


@pytest.fixture
def prompts(monkeypatch):
    """Answers getpass prompts in order."""
    answers = []
    monkeypatch.setattr("getpass.getpass", lambda prompt="": answers.pop(0))
    return answers


@pytest.fixture
def restore_password():
    yield
    # the conftest sets "test"; every test that changes it puts it back
    for password in ("changed", "test"):
        try:
            set_encryption_password("test", old_password=password)
            return
        except InvalidPasswordError:
            continue


@pytest.mark.integration
def test_test_password(prompts):
    assert _run("test", "-p", "test") == 0
    assert _run("test", "-p", "wrong") == 1
    prompts.append("test")
    assert _run("test") == 0


@pytest.mark.integration
def test_test_password_not_set(monkeypatch):
    monkeypatch.setattr("saq.crypto.encryption_key_set", lambda: False)

    assert _run("test", "-p", "test") == 2


@pytest.mark.integration
def test_change_password(prompts, restore_password, capsys):
    aes_key = get_aes_key("test")
    # a wrong current password asks again; so do new passwords that don't match
    prompts.extend(["wrong", "test", "changed", "typo", "test", "changed", "changed"])

    assert _run("set") == 0

    assert "ERROR: invalid password" in capsys.readouterr().out
    assert get_aes_key("changed") == aes_key
    assert prompts == []


@pytest.mark.integration
def test_change_password_with_password_option(prompts, restore_password):
    aes_key = get_aes_key("test")
    prompts.append("test")

    assert _run("set", "-p", "changed") == 0

    assert get_aes_key("changed") == aes_key


@pytest.mark.integration
def test_encrypt_and_decrypt_file(tmp_path, prompts):
    source = tmp_path / "plain.txt"
    source.write_bytes(b"secret data")

    assert _run("encrypt", str(source), str(tmp_path / "system.enc")) == 0
    assert _run("decrypt", str(tmp_path / "system.enc"), str(tmp_path / "system.txt")) == 0
    assert (tmp_path / "system.txt").read_bytes() == b"secret data"

    assert _run("encrypt", str(source), str(tmp_path / "password.enc"), "--password", "hunter2") == 0
    assert _run("decrypt", str(tmp_path / "password.enc"), str(tmp_path / "password.txt"), "--password", "hunter2") == 0
    assert (tmp_path / "password.txt").read_bytes() == b"secret data"

    prompts.extend(["hunter3", "hunter3", "hunter3"])
    assert _run("encrypt", str(source), str(tmp_path / "prompt.enc"), "--prompt") == 0
    # --prompt used to require a value
    assert _run("decrypt", str(tmp_path / "prompt.enc"), str(tmp_path / "prompt.txt"), "--prompt") == 0
    assert (tmp_path / "prompt.txt").read_bytes() == b"secret data"

    prompts.extend(["hunter3", "typo"])
    assert _run("encrypt", str(source), str(tmp_path / "mismatch.enc"), "--prompt") == 1
    assert not (tmp_path / "mismatch.enc").exists()


@pytest.mark.integration
def test_config_passwords(tmp_path, prompts, capsys):
    value_file = tmp_path / "value.txt"
    value_file.write_text("from a file\n")

    assert _run("config", "list") == 0
    assert capsys.readouterr().out == "no passwords have been encrypted\n"

    assert _run("config", "set", "api.key", "--value", "from the command line") == 0
    assert _run("config", "set", "api.file", "--load-from-file", str(value_file)) == 0
    prompts.extend(["typed", "typo", "typed", "typed"])
    assert _run("config", "set", "api.prompt") == 0

    assert decrypt_password("api.key") == "from the command line"
    assert decrypt_password("api.file") == "from a file"
    assert decrypt_password("api.prompt") == "typed"

    assert _run("config", "list") == 0
    assert capsys.readouterr().out == "api.file = from a file\napi.key = from the command line\napi.prompt = typed\n"

    assert _run("config", "delete", "api.prompt") == 0
    assert capsys.readouterr().out == "password deleted\n"
    # deleting what isn't there is an error
    assert _run("config", "delete", "api.prompt") == 1
    assert capsys.readouterr().out == "ERROR: unable to delete password\n"


@pytest.mark.integration
def test_config_set_without_encryption_key(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)

    assert _run("config", "set", "api.key", "--value", "x") == 1


@pytest.mark.integration
def test_config_export_and_import(tmp_path, monkeypatch, capsys):
    encrypt_password("api.key", "value one")
    encrypt_password("api.other", "value two")

    assert _run("config", "export", str(tmp_path / "export.json")) == 0
    assert json.loads((tmp_path / "export.json").read_text()) == {"api.key": "value one", "api.other": "value two"}

    # exporting to stdout used to close it
    assert _run("config", "export", "-") == 0
    print("stdout is still open")
    assert capsys.readouterr().out == json.dumps({"api.key": "value one", "api.other": "value two"}) + \
        "\nstdout is still open\n"

    (tmp_path / "import.json").write_text(json.dumps({"api.key": "replaced"}))
    assert _run("config", "import", str(tmp_path / "import.json")) == 0
    stdin = io.StringIO(json.dumps({"api.new": "from stdin"}))
    monkeypatch.setattr("sys.stdin", stdin)
    assert _run("config", "import", "-") == 0
    assert not stdin.closed

    assert export_encrypted_passwords() == {"api.key": "replaced", "api.new": "from stdin", "api.other": "value two"}
