"""The /cli routes and the node-to-node /engine/cli route."""

from datetime import datetime

import pytest
from sqlalchemy import select, text

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.cli import service
from saq.configuration.config import get_config
from saq.configuration.schema import ConfigApiKey
from saq.database.model import CliExecution, Nodes
from saq.database.pool import get_db
from saq.environment import get_global_runtime_settings
from saq.util import sha256_str
from tests.aceapi_v2.conftest import api_key_client

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def _auth(user) -> ApiAuthResult:
    return ApiAuthResult(auth_type="user", auth_name=user.username, auth_user_id=user.id)


def _add_node(name: str, *, is_primary: bool = False) -> int:
    session = get_db()
    if is_primary:
        session.execute(text("UPDATE nodes SET is_primary = 0"))
    node = Nodes(name=name, location=f"{name}:443", company_id=1, last_update=datetime.now(),
                 is_primary=is_primary, status="running")
    session.add(node)
    session.commit()
    return node.id


def _local_node() -> int:
    name = get_global_runtime_settings().saq_node
    node_id = get_db().execute(select(Nodes.id).where(Nodes.name == name)).scalar_one_or_none()
    return node_id if node_id is not None else _add_node(name)


@pytest.fixture
def dispatched(monkeypatch):
    calls = []
    monkeypatch.setattr(service.ace_api, "start_cli_execution",
                        lambda i, **kwargs: calls.append((i, kwargs["remote_host"])))
    return calls


async def test_run_on_the_primary_node_by_default(client, test_user, dispatched):
    primary = _add_node("node-p", is_primary=True)
    _add_node("node-q")

    response = await client.post("/cli/executions", json={"command": "ace node list"})

    assert response.status_code == 202, response.text
    (execution,) = response.json()["data"]
    assert execution["node_id"] == primary
    assert execution["node_name"] == "node-p"
    assert execution["command"] == "node list"
    assert execution["username"] == test_user.username
    assert execution["status"] == "pending"
    assert execution["timeout_seconds"] == 300
    assert dispatched == [(execution["id"], "node-p:443")]


async def test_run_on_every_selected_node(client, dispatched):
    a, b = _add_node("node-a"), _add_node("node-b")

    response = await client.post("/cli/executions", json={
        "command": "cas verify", "node_ids": [a, b], "timeout_seconds": 10})

    assert response.status_code == 202, response.text
    executions = response.json()["data"]
    assert sorted(e["node_name"] for e in executions) == ["node-a", "node-b"]
    assert {e["timeout_seconds"] for e in executions} == {10}
    assert sorted(host for _, host in dispatched) == ["node-a:443", "node-b:443"]


async def test_a_node_that_cannot_be_reached_is_failed_in_the_answer(client, monkeypatch):
    a = _add_node("node-a")

    def _refuse(*args, **kwargs):
        raise service.requests.ConnectionError("connection refused")

    monkeypatch.setattr(service.ace_api, "start_cli_execution", _refuse)
    response = await client.post("/cli/executions", json={"command": "node list", "node_ids": [a]})

    assert response.status_code == 202
    (execution,) = response.json()["data"]
    assert execution["status"] == "failed"
    assert "unable to reach node node-a" in execution["error"]


@pytest.mark.parametrize("body", [
    {"command": "-u admin node list"},
    {"command": "user add bob --password hunter2"},
    {"command": "ace"},
    {"command": ""},
    {"command": "node list", "timeout_seconds": 0},
    {"command": "node list", "timeout_seconds": 3601},
    {"command": "node list", "node_ids": []},
])
async def test_invalid_requests(client, dispatched, body):
    _add_node("node-p", is_primary=True)
    response = await client.post("/cli/executions", json=body)
    assert response.status_code == 422, response.text
    assert dispatched == []


async def test_unknown_node(client, dispatched):
    response = await client.post("/cli/executions", json={"command": "node list", "node_ids": [999999]})
    assert response.status_code == 404
    assert dispatched == []


async def test_follow_an_execution_and_list_history(client, dispatched):
    a = _add_node("node-a")
    first = (await client.post("/cli/executions", json={"command": "node list", "node_ids": [a]})).json()["data"][0]
    second = (await client.post("/cli/executions", json={"command": "cas verify", "node_ids": [a]})).json()["data"][0]

    response = await client.get(f"/cli/executions/{first['id']}")
    assert response.status_code == 200
    assert response.json()["command"] == "node list"
    assert "output" in response.json()

    page = (await client.get("/cli/executions", params={"limit": 1})).json()
    assert [e["id"] for e in page["data"]] == [second["id"]]
    assert "output" not in page["data"][0]
    page = (await client.get("/cli/executions", params={"limit": 1, "cursor": page["next_cursor"]})).json()
    assert [e["id"] for e in page["data"]] == [first["id"]]
    assert page["next_cursor"] is None

    assert (await client.get("/cli/executions/999999999")).status_code == 404
    assert (await client.get("/cli/executions", params={"cursor": "garbage"})).status_code == 400


async def test_cli_needs_cli_execute(noperm_client):
    assert (await noperm_client.get("/cli/executions")).status_code == 403
    assert (await noperm_client.get("/cli/executions/1")).status_code == 403
    assert (await noperm_client.post("/cli/executions", json={"command": "node list"})).status_code == 403
    assert (await noperm_client.post("/engine/cli/1")).status_code == 403


async def test_engine_route_runs_the_command_on_this_node(client, test_user):
    (execution_id,) = service.create_executions(_auth(test_user), ["--help"], [_local_node()], 60)

    response = await client.post(f"/engine/cli/{execution_id}")

    assert response.status_code == 202, response.text
    assert response.json() == {"id": execution_id, "status": "running"}
    # the in-process transport runs the background task before it answers
    execution = (await client.get(f"/cli/executions/{execution_id}")).json()
    assert execution["status"] == "completed"
    assert execution["exit_code"] == 0
    assert "usage:" in execution["output"]

    # a row runs once
    assert (await client.post(f"/engine/cli/{execution_id}")).status_code == 409


async def test_engine_route_reports_a_failing_command(client, test_user):
    (execution_id,) = service.create_executions(
        _auth(test_user), ["no-such-command"], [_local_node()], 60)

    assert (await client.post(f"/engine/cli/{execution_id}")).status_code == 202

    execution = (await client.get(f"/cli/executions/{execution_id}")).json()
    assert execution["status"] == "completed"
    assert execution["exit_code"] == 2
    assert "invalid choice" in execution["output"]


async def test_engine_route_refuses_another_nodes_execution(client, test_user):
    (execution_id,) = service.create_executions(_auth(test_user), ["--help"], [_add_node("node-a")], 60)

    response = await client.post(f"/engine/cli/{execution_id}")

    assert response.status_code == 409
    session = get_db()
    session.expire_all()
    assert session.get(CliExecution, execution_id).status == "pending"


async def test_a_config_key_cannot_record_a_run(_override_db_session, monkeypatch, dispatched):
    """A config key has no user to attribute the run to, even with cli:execute in its scope."""
    key = "5b0c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"
    monkeypatch.setattr(get_config(), "apikeys", {"cli": ConfigApiKey(key=sha256_str(key), scope=["cli:execute"])})
    _add_node("node-p", is_primary=True)

    async with api_key_client(key) as client:
        response = await client.post("/cli/executions", json={"command": "node list"})

    assert response.status_code == 403
    assert dispatched == []
