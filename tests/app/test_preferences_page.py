"""The analyst preferences page (main.preferences)."""

import json
import re

import pytest
from flask import url_for

from saq.permissions.user import add_user_permission

pytestmark = pytest.mark.integration


def test_preferences_page_requires_login(app):
    with app.test_client() as client:
        response = client.get(url_for("main.preferences"))
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


def test_preferences_page_renders_profile_and_columns(web_client, analyst):
    response = web_client.get(url_for("main.preferences"))
    assert response.status_code == 200
    html = response.data.decode()

    # profile form, saved through the v2 API from the browser
    assert 'data-api-url="/api/v2/users/me"' in html
    assert 'value="john"' in html
    assert '<option value="UTC" selected>' in html
    assert 'name="queue"' in html

    # the same column chooser the manage page uses
    assert 'data-preference-url="/api/v2/users/me/preferences/manage_columns"' in html
    assert 'id="column_chooser_date"' in html
    assert 'js/manage_columns.js' in html
    assert 'js/preferences.js' in html


def test_navbar_links_to_preferences(web_client, analyst):
    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert url_for("main.preferences") in html


def _key_catalog(html: str) -> set[tuple[str, str]]:
    """The (major, minor) pairs the API key scope picker offers."""
    match = re.search(r'<script id="my_api_key_catalog_json" type="application/json">(.*?)</script>', html, re.S)
    assert match, "no scope picker catalog on the page"
    return {(entry["major"], entry["minor"]) for entry in json.loads(match.group(1))}


def test_api_keys_card_lets_a_user_with_user_self_manage_their_keys(web_client, analyst):
    html = web_client.get(url_for("main.preferences")).data.decode()

    assert 'data-api-url="/api/v2/users/me/apikeys"' in html
    assert 'data-can-manage="true"' in html
    assert 'id="btn_new_my_api_key"' in html
    assert 'js/preferences_api_keys.js' in html

    offered = _key_catalog(html)
    # the config-derived ai:<backend> entries are offered too
    assert {("signature", "read"), ("signature", "download"), ("ai", "fake")} <= offered
    # user:self as a scope would grant a key nothing: no API key can reach those routes
    assert ("user", "self") not in offered


def test_api_keys_card_only_lists_keys_without_user_self(web_client, analyst):
    add_user_permission(analyst, "user", "self", "DENY")

    html = web_client.get(url_for("main.preferences")).data.decode()
    assert 'data-api-url="/api/v2/users/me/apikeys"' in html
    assert 'data-can-manage="false"' in html
    assert 'id="btn_new_my_api_key"' not in html
    assert 'id="my_api_key_catalog_json"' not in html
    assert "Ask an administrator" in html


def test_scope_picker_offers_only_what_the_user_holds(web_client, analyst):
    add_user_permission(analyst, "secret", "*", "DENY")

    offered = _key_catalog(web_client.get(url_for("main.preferences")).data.decode())
    assert ("alert", "read") in offered
    assert not {pair for pair in offered if pair[0] == "secret"}
