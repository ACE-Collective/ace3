"""The node-to-node endpoints must be reachable with the *shipped* automation key scope.

Regression guard for the outage introduced when etc/saq.default.yaml's `automation` key was narrowed
to `alert:create`, on the strength of a hand-written comment claiming that was the entire runtime
surface of node-to-node calls. It was not: saq/engine/workload_manager/database.py
::transfer_work_target also calls ace_api.download() and ace_api.clear(), so every cross-node work
transfer 403'd in production.

Why the rest of the suite cannot catch this: tests authenticate with keys that can reach every
endpoint the suite exercises. These tests instead build a key carrying the scope
etc/saq.default.yaml actually ships, so they fail if that scope stops covering the node-to-node
surface.

tests/saq/test_permission_catalog.py::TestNodeToNodeScope is the fast static counterpart; this file
proves the real request path, dependency and all, actually returns 200.
"""

import json
import os
import uuid

import pytest
import yaml
from httpx import AsyncClient

from saq.configuration.config import get_config
from saq.configuration.schema import ConfigApiKey
from saq.database.util.locking import acquire_lock
from saq.environment import get_base_dir
from saq.util import sha256_str
from tests.aceapi_v2.conftest import api_key_client
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

# Any uuid works -- only its sha256 is compared against the config entry.
AUTOMATION_API_KEY = "1e0dbf1a-6f1b-4d1e-9e1c-2f2b1f0a55aa"


def _shipped_automation_scope() -> list[str]:
    """The scope etc/saq.default.yaml actually ships for apikeys.automation.

    Read from the file rather than restated here on purpose: that is what makes these tests bite
    when the shipped scope changes. safe_load is fine -- `file:` values are plain strings at the
    YAML level and are resolved later by the config layer.
    """
    with open(os.path.join(get_base_dir(), "etc", "saq.default.yaml")) as fp:
        data = yaml.safe_load(fp)

    entry = data["apikeys"]["automation"]
    assert isinstance(entry, dict), (
        "apikeys.automation uses the deprecated bare-string form, which bypasses permission checks "
        "entirely. Never resolve a scope failure by reverting to it."
    )
    return list(entry["scope"])


@pytest.fixture
def automation(_override_db_session, monkeypatch):
    """A client authenticated as the production `automation` config key, with exactly the shipped
    scope.

    Replaces the whole apikeys dict rather than adding to it, so a request cannot fall through to a
    permissive key and pass for the wrong reason.
    """
    monkeypatch.setattr(get_config(), "apikeys", {
        "automation": ConfigApiKey(key=sha256_str(AUTOMATION_API_KEY), scope=_shipped_automation_scope()),
    })
    return api_key_client(AUTOMATION_API_KEY)


def _saved_root():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = {"hello": "world"}
    root.save()
    return root


@pytest.mark.asyncio
async def test_download_allowed_by_shipped_automation_scope(automation):
    """GET /api/v2/engine/download/{uuid} -- the exact call transfer_work_target() makes, and the
    exact 403 seen in production."""
    root = _saved_root()

    async with automation as client:
        assert (await client.get(f"/engine/download/{root.uuid}")).status_code == 200


@pytest.mark.asyncio
async def test_clear_allowed_by_shipped_automation_scope(automation):
    """POST /api/v2/engine/clear/{uuid}/{lock_uuid} -- the second node-to-node call in
    transfer_work_target. It is best-effort there (a logged warning), so a 403 would silently leak a
    stale copy on the remote node instead of erroring."""
    root = _saved_root()
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(root.uuid, lock_uuid)

    async with automation as client:
        assert (await client.post(f"/engine/clear/{root.uuid}/{lock_uuid}")).status_code == 200


@pytest.mark.asyncio
async def test_upload_allowed_by_shipped_automation_scope(automation):
    """POST /api/v2/engine/upload/{uuid}: collectors (remote_node.py), node drain (drain.py) and
    alert distribution (maintenance.py) all reach it with the same key. An auth failure is decided
    before the body is read, so an auth regression shows up here as 403 rather than as a 422 about
    the missing archive."""
    async with automation as client:
        response = await client.post(f"/engine/upload/{uuid.uuid4()}", data={"upload_modifiers": "{}"})

    assert response.status_code != 403


@pytest.mark.asyncio
async def test_submit_allowed_by_shipped_automation_scope(automation):
    """POST /api/v2/analysis/ with alert:create."""
    async with automation as client:
        response = await client.post("/analysis/", data={"analysis": json.dumps({
            "analysis_mode": "analysis", "description": "node to node", "observables": [], "tags": []})})

    assert response.status_code == 201


@pytest.mark.asyncio
async def test_automation_scope_still_denies_out_of_scope_endpoints(automation):
    """The automation scope must be a real narrowing, not a bypass.

    Guards against "fixing" a future scope failure with scope: ["*:*"] or by reverting to the
    bare-string form -- either would make the tests above pass vacuously. Reading an alert
    (GET /api/v2/alerts/{uuid}) requires alert:read, which the node key must not have: it shares the
    alert major with the key's alert:create, so this also fails if the scope is widened to alert:*.
    """
    async with automation as client:
        assert (await client.get(f"/alerts/{uuid.uuid4()}")).status_code == 403


@pytest.mark.asyncio
async def test_cli_start_allowed_by_shipped_automation_scope(automation):
    """POST /api/v2/engine/cli/{id}: the node that took a GUI CLI request starts each node's run
    with the same key (aceapi_v2/cli/service.py::dispatch_execution). An unknown id is a 404, so
    anything but a 403 means the scope let the request through."""
    async with automation as client:
        assert (await client.post("/engine/cli/999999999")).status_code == 404


@pytest.mark.asyncio
async def test_automation_scope_cannot_request_cli_executions(automation):
    """engine:cli only starts a run a user with cli:execute recorded; the node key itself must
    never be able to record one."""
    async with automation as client:
        response = await client.post("/cli/executions", json={"command": "node list"})

    assert response.status_code == 403
