"""The node-to-node engine endpoints must be reachable with the *shipped* automation key scope.

Regression guard for the outage introduced when etc/saq.default.yaml's `automation` key was narrowed
to `alert:create`, on the strength of a hand-written comment claiming that was the entire runtime
surface of node-to-node calls. It was not: saq/engine/workload_manager/database.py
::transfer_work_target also calls ace_api.download() and ace_api.clear(), so every cross-node work
transfer 403'd in production.

Why the rest of the suite cannot catch this: tests authenticate with the shared `test` key from
etc/saq.unittest.default.yaml, which carries a "*:*" scope so it can reach every endpoint the suite
exercises. These tests instead build a key carrying the scope etc/saq.default.yaml actually ships,
so they fail if that scope stops covering the node-to-node surface.

tests/saq/test_permission_catalog.py::TestNodeToNodeScope is the fast static counterpart; this file
proves the real Flask request path, decorator and all, actually returns 200.
"""

import os
import uuid

import pytest
import yaml
from flask import url_for

from saq.configuration.config import get_config
from saq.configuration.schema import ConfigApiKey
from saq.database.util.locking import acquire_lock
from saq.environment import get_base_dir
from saq.util import sha256_str
from tests.saq.helpers import create_root_analysis

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
def automation_api_key(monkeypatch):
    """Authenticate as the production `automation` config key, with exactly the shipped scope.

    Replaces the whole apikeys dict rather than adding to it, so a request cannot fall through to
    the suite's permissive `test` key and pass for the wrong reason.
    """
    monkeypatch.setattr(
        get_config(),
        "apikeys",
        {
            "automation": ConfigApiKey(
                key=sha256_str(AUTOMATION_API_KEY),
                scope=_shipped_automation_scope(),
            )
        },
    )
    return {"x-ace-auth": AUTOMATION_API_KEY}


@pytest.mark.integration
def test_download_allowed_by_shipped_automation_scope(test_client, automation_api_key):
    """GET /api/engine/download/<uuid> -- the exact call transfer_work_target() makes, and the exact
    403 seen in production."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = {"hello": "world"}
    root.save()

    result = test_client.get(
        url_for("engine.download", uuid=root.uuid), headers=automation_api_key
    )
    assert result.status_code == 200


@pytest.mark.integration
def test_clear_allowed_by_shipped_automation_scope(test_client, automation_api_key):
    """GET /api/engine/clear/<uuid>/<lock_uuid> -- the second node-to-node call in
    transfer_work_target (database.py:230).

    This one was latent: it never surfaced in production only because download() raises first inside
    the same try block, and because the clear() call is best-effort (logged warning), a 403 there
    silently leaks a stale copy on the remote node instead of erroring.
    """
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.save()

    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(root.uuid, lock_uuid)

    result = test_client.get(
        url_for("engine.clear", uuid=root.uuid, lock_uuid=lock_uuid), headers=automation_api_key
    )
    assert result.status_code == 200


@pytest.mark.integration
def test_upload_allowed_by_shipped_automation_scope(test_client, automation_api_key):
    """POST /api/engine/upload/<uuid>.

    Passed before and after the fix. Present so that a future narrowing of the automation scope
    cannot silently break collectors (remote_node.py), node drain (drain.py) or alert distribution
    (maintenance.py), all of which reach this endpoint with the same key.
    """
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.save()

    # a missing/!=200 auth failure aborts before any payload validation, so an auth regression shows
    # up here as 403 rather than as a 400 about the upload body
    result = test_client.post(url_for("engine.upload", uuid=root.uuid), headers=automation_api_key)
    assert result.status_code != 403


@pytest.mark.integration
def test_automation_scope_still_denies_out_of_scope_endpoints(test_client, automation_api_key):
    """The automation scope must be a real narrowing, not a bypass.

    Guards against "fixing" a future scope failure with scope: ["*:*"] or by reverting to the
    bare-string form -- either would make the three tests above pass vacuously. get_archived_email
    requires email:read (aceapi/email.py), which the node key must not have.
    """
    result = test_client.get(
        "/email/get_archived_email",
        query_string={"message_id": "<test@example.com>"},
        headers=automation_api_key,
    )
    assert result.status_code == 403
