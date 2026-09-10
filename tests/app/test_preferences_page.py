"""The analyst preferences page (main.preferences)."""

import pytest
from flask import url_for

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
