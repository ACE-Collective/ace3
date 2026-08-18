"""live smoke test for aceapi-v2-client

this test talks to a running ACE API v2 instance. it is skipped unless the
``ACE_API_BASE_URL`` and ``ACE_API_KEY`` environment variables are set, so it
never blocks installs or offline test runs.

api keys are scoped, so the key you point this at matters. ``test_health_ping``,
``test_common_ping_authenticated`` and ``test_list_my_api_keys`` only need a
valid key, but ``test_list_observable_types`` additionally needs the key to carry
``observable:read`` -- an inherit-scoped key belonging to a privileged user
satisfies all four.

example:
    ACE_API_BASE_URL=https://ace-http/api/v2 \\
    ACE_API_KEY=60eeab2c-aced-47a5-b9a5-fd47c8c927b5 \\
    ACE_API_VERIFY_SSL=false \\
    pytest tests/test_smoke.py -v
"""

import os

import pytest

from aceapi_v2_client.auth import authenticated_client
from aceapi_v2_client.api.health import ping_health_ping_get
from aceapi_v2_client.api.common import ping_common_ping_get
from aceapi_v2_client.api.observables import (
    list_observable_types_observable_types_get,
)
from aceapi_v2_client.api.users import list_my_api_keys_users_me_apikeys_get

BASE_URL = os.environ.get("ACE_API_BASE_URL")
API_KEY = os.environ.get("ACE_API_KEY")
VERIFY_SSL = os.environ.get("ACE_API_VERIFY_SSL", "true").lower() not in (
    "0",
    "false",
    "no",
)

pytestmark = pytest.mark.skipif(
    not (BASE_URL and API_KEY),
    reason="set ACE_API_BASE_URL and ACE_API_KEY to run the live smoke test",
)


@pytest.fixture
def client():
    return authenticated_client(BASE_URL, API_KEY, verify_ssl=VERIFY_SSL)


def test_health_ping(client):
    # health/ping requires no auth but should work with a client too
    result = ping_health_ping_get.sync(client=client)
    assert result is not None
    assert result.result == "pong"


def test_common_ping_authenticated(client):
    # common/ping requires authentication; a 200 confirms the api key works
    response = ping_common_ping_get.sync_detailed(client=client)
    assert response.status_code == 200


def test_list_observable_types(client):
    # exercises a real data endpoint that returns parsed models. this endpoint is
    # permission-gated on observable:read, so a narrowly scoped key gets a 403
    # here even though the preceding tests pass.
    response = list_observable_types_observable_types_get.sync_detailed(client=client)
    assert response.status_code == 200
    assert response.parsed is not None


def test_list_my_api_keys(client):
    # self-service key listing: metadata only, never the secret. needs no
    # particular scope, so it doubles as a check that the key itself is live.
    response = list_my_api_keys_users_me_apikeys_get.sync_detailed(client=client)
    assert response.status_code == 200
    assert response.parsed is not None
    for key in response.parsed:
        # the plaintext key is display-once at creation and must never come back
        assert not hasattr(key, "api_key")
