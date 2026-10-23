import logging

import pytest

import saq.cli.commands  # noqa: F401
from saq.cli.cli_main import get_cli_parser
from saq.constants import (
    INSTANCE_TYPE_PRODUCTION,
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING_COLLECTORS,
    NODE_STATUS_RUNNING,
)
from saq.configuration import get_config
from saq.database.model import Company
from saq.database.pool import get_db
from saq.database.util.node import get_node_expected_state, get_node_status, set_node_status
from saq.environment import get_global_runtime_settings


def _run(*argv):
    args = get_cli_parser().parse_args(list(argv))
    with pytest.raises(SystemExit) as exit_info:
        args.func(args)
    return exit_info.value.code


def _company_names():
    get_db().expire_all()
    return {c.name for c in get_db().query(Company).all()}


@pytest.fixture
def answers(monkeypatch):
    replies = []
    monkeypatch.setattr("builtins.input", lambda prompt="": replies.pop(0))
    return replies


@pytest.mark.integration
def test_company_add_list_delete(answers, capsys):
    assert _run("company", "add", "42", "acme") == 0
    assert "acme" in _company_names()

    assert _run("company", "list") == 0
    assert "42\tacme" in capsys.readouterr().out.splitlines()

    # it asks twice
    answers.extend(["Y", "n"])
    assert _run("company", "delete", "acme") == 0
    answers.append("n")
    assert _run("company", "delete", "acme") == 0
    assert "acme" in _company_names()

    # this used to raise AttributeError on saq.INSTANCE_TYPE
    answers.extend(["Y", "Y"])
    assert _run("company", "delete", "acme") == 0
    assert "acme" not in _company_names()


@pytest.mark.integration
def test_company_delete_on_production(answers, monkeypatch):
    monkeypatch.setattr(get_config().global_settings, "instance_type", INSTANCE_TYPE_PRODUCTION)
    assert _run("company", "add", "42", "acme") == 0

    answers.extend(["Y", "Y", "yes"])
    assert _run("company", "delete", "acme") == 0
    assert "acme" in _company_names()

    answers.extend(["Y", "Y", "YES"])
    assert _run("company", "delete", "acme") == 0
    assert "acme" not in _company_names()


@pytest.fixture
def node_id():
    node_id = get_global_runtime_settings().saq_node_id
    assert node_id is not None
    set_node_status(node_id, NODE_STATUS_RUNNING)
    return node_id


@pytest.mark.integration
def test_node_status(node_id, capsys):
    assert _run("node", "status") == 0

    out = capsys.readouterr().out
    assert f"(id {node_id})" in out
    assert f"status:   {NODE_STATUS_RUNNING}" in out
    assert "workload: 0" in out


@pytest.mark.integration
def test_node_drain_and_resume(node_id):
    assert _run("node", "drain") == 0
    assert get_node_status(node_id) == NODE_STATUS_DRAINING_COLLECTORS
    assert get_node_expected_state(node_id) == "offline"

    assert _run("node", "resume") == 0
    assert get_node_status(node_id) == NODE_STATUS_RUNNING
    assert get_node_expected_state(node_id) == "online"

    # a running node has nothing to resume
    assert _run("node", "resume") == 1


@pytest.mark.integration
def test_node_drain_already_drained(node_id):
    # a shutdown script must be able to drain twice
    set_node_status(node_id, NODE_STATUS_DRAINED)

    assert _run("node", "drain", "--wait") == 0


@pytest.mark.integration
def test_node_drain_wait(node_id, monkeypatch):
    # the engine finishes the drain while the command waits
    monkeypatch.setattr("saq.cli.commands.node.time.sleep", lambda seconds: set_node_status(node_id, NODE_STATUS_DRAINED))

    assert _run("node", "drain", "--wait") == 0


@pytest.mark.integration
def test_node_drain_wait_times_out(node_id, monkeypatch, caplog):
    monkeypatch.setattr("saq.cli.commands.node.time.sleep", lambda seconds: None)

    assert _run("node", "drain", "--wait", "--timeout", "0.2") == 1
    assert any(r.levelno == logging.WARNING and "did not finish draining" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_node_commands_need_a_node(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "saq_node_id", None)

    assert _run("node", "status") == 1
