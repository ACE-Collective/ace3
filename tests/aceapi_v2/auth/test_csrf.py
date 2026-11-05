"""CSRF protection for cookie-authenticated writes against aceapi_v2.

Cookie auth is the only CSRF-exposed path: a browser attaches cookies automatically, but an
attacker's page cannot make it send an `x-ace-auth` header or a bearer token.

TODO: Remove this file when the Flask GUI (and with it cookie auth) is retired.
"""

import pytest
from httpx import AsyncClient

from saq.database.model import User
from tests.aceapi_v2.conftest import make_flask_session_cookie

pytestmark = pytest.mark.integration

# any state-changing endpoint will do; the unittest user holds *:*
WRITE_PATH = "/observables/interesting"
WRITE_BODY = {"observable_type": "ipv4", "observable_value": "10.11.12.13", "is_interesting": True}
READ_PATH = "/observable-types/"


class TestCookieWriteRequiresSameOrigin:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("headers, status", [
        ({"sec-fetch-site": "same-origin"}, 200),
        # a typed URL or a bookmark, not a cross-site request
        ({"sec-fetch-site": "none"}, 200),
        ({"sec-fetch-site": "cross-site"}, 403),
        ({"sec-fetch-site": "same-site"}, 403),
        # the test client's base_url is http://test, so Host is "test"
        ({"origin": "http://test"}, 200),
        ({"origin": "https://evil.example.com"}, 403),
        # cookie auth exists only for the browser GUI, and a write with neither signal is not a
        # request shape we recognise
        ({}, 403),
    ], ids=["same-origin", "user-navigation", "cross-site", "same-site", "matching-origin", "foreign-origin",
            "no-browser-signal"])
    async def test_a_cookie_write_needs_a_same_origin_signal(
        self, unauth_client: AsyncClient, test_user: User, headers, status
    ):
        unauth_client.cookies.set("session", make_flask_session_cookie(test_user.id))
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY, headers=headers)
        assert r.status_code == status


class TestUnaffectedPaths:
    @pytest.mark.asyncio
    async def test_cookie_reads_are_unaffected(self, unauth_client: AsyncClient, test_user: User):
        unauth_client.cookies.set("session", make_flask_session_cookie(test_user.id))
        assert (await unauth_client.get(READ_PATH)).status_code == 200

    @pytest.mark.asyncio
    async def test_bearer_token_write_allowed_even_from_foreign_origin(self, client: AsyncClient):
        """Header auth cannot be triggered cross-site, so it skips the check entirely: even an
        Origin the check would refuse is allowed."""
        r = await client.patch(WRITE_PATH, json=WRITE_BODY, headers={"origin": "https://evil.example.com"})
        assert r.status_code == 200
