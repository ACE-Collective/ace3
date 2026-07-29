"""CSRF protection for cookie-authenticated writes against aceapi_v2.

Cookie auth is the only CSRF-exposed path: a browser attaches cookies automatically, but an
attacker's page cannot make it send an `x-ace-auth` header or a bearer token.

TODO: Remove this file when the Flask GUI (and with it cookie auth) is retired.
"""

import hashlib

import pytest
from httpx import AsyncClient
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.ext.asyncio import AsyncSession

from saq.configuration import get_config
from saq.database.model import User

pytestmark = pytest.mark.integration

# any state-changing endpoint will do; the unittest user holds *:*
WRITE_PATH = "/observables/interesting"
WRITE_BODY = {"observable_type": "ipv4", "observable_value": "10.11.12.13", "is_interesting": True}
READ_PATH = "/observable-types/"


def _make_flask_session_cookie(user_id) -> str:
    s = URLSafeTimedSerializer(
        get_config().gui.secret_key,
        salt="cookie-session",
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    )
    return s.dumps({"_user_id": str(user_id)})


class TestCookieWriteRequiresSameOrigin:
    @pytest.mark.asyncio
    async def test_same_origin_sec_fetch_site_is_allowed(self, unauth_client: AsyncClient, test_user: User):
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY, headers={"sec-fetch-site": "same-origin"})
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_user_initiated_navigation_is_allowed(self, unauth_client: AsyncClient, test_user: User):
        """sec-fetch-site: none means a typed URL or bookmark, not a cross-site request."""
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY, headers={"sec-fetch-site": "none"})
        assert r.status_code == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
    async def test_cross_site_sec_fetch_site_is_rejected(self, unauth_client: AsyncClient, test_user: User, fetch_site):
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY, headers={"sec-fetch-site": fetch_site})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_matching_origin_is_allowed(self, unauth_client: AsyncClient, test_user: User):
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        # the test client's base_url is http://test, so Host is "test"
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY, headers={"origin": "http://test"})
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_foreign_origin_is_rejected(self, unauth_client: AsyncClient, test_user: User):
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY, headers={"origin": "https://evil.example.com"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_write_without_any_browser_signal_is_rejected(self, unauth_client: AsyncClient, test_user: User):
        """Cookie auth exists only for the browser GUI; a cookie write with no Origin and no
        Sec-Fetch-Site is not a request shape we recognise."""
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        r = await unauth_client.patch(WRITE_PATH, json=WRITE_BODY)
        assert r.status_code == 403


class TestUnaffectedPaths:
    @pytest.mark.asyncio
    async def test_cookie_reads_are_unaffected(self, unauth_client: AsyncClient, test_user: User):
        unauth_client.cookies.set("session", _make_flask_session_cookie(test_user.id))
        assert (await unauth_client.get(READ_PATH)).status_code == 200

    @pytest.mark.asyncio
    async def test_bearer_token_writes_are_exempt(self, client: AsyncClient):
        """Header auth cannot be triggered cross-site, so it skips the check entirely -- no Origin,
        no Sec-Fetch-Site, still allowed."""
        r = await client.patch(WRITE_PATH, json=WRITE_BODY)
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_bearer_token_write_allowed_even_from_foreign_origin(self, client: AsyncClient):
        r = await client.patch(WRITE_PATH, json=WRITE_BODY, headers={"origin": "https://evil.example.com"})
        assert r.status_code == 200
