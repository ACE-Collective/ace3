"""The GUI theme: how the stored preference reaches the rendered page."""

import logging
import re

import pytest
from flask import url_for

from aceapi_v2.sync import run_async_with_session
from aceapi_v2.user_preferences import service
from aceapi_v2.user_preferences.schemas import PREFERENCE_KEY_THEME
from saq.database.model import UserPreference
from saq.database.pool import get_db
from tests.saq.helpers import count_queries

pytestmark = pytest.mark.integration


def _set_theme(analyst_id, mode):
    run_async_with_session(service.set_preference, analyst_id, PREFERENCE_KEY_THEME, {"mode": mode})


def _html_attributes(html: str) -> tuple[str, str]:
    tag = re.search(r"<html[^>]*>", html).group(0)
    return (re.search(r'data-ace-theme="([a-z]+)"', tag).group(1),
            re.search(r'data-bs-theme="([a-z]+)"', tag).group(1))


def test_default_is_system(web_client, analyst):
    html = web_client.get(url_for("analysis.manage")).data.decode()
    # the server renders light; the inline resolver in core.html switches a dark OS to dark
    assert _html_attributes(html) == ("system", "light")
    assert 'matchMedia("(prefers-color-scheme: dark)")' in html


@pytest.mark.parametrize("mode, bs_theme", [
    ("system", "light"),
    ("light", "light"),
    ("dark", "dark"),
    ("jd", "light"),
])
def test_stored_mode_is_rendered(web_client, analyst, mode, bs_theme):
    _set_theme(analyst, mode)
    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert _html_attributes(html) == (mode, bs_theme)
    # the navbar marks the current choice
    assert re.search(rf'class="dropdown-item active" data-theme-mode="{mode}"', html)


def test_unreadable_stored_theme_falls_back_to_system(web_client, analyst, caplog):
    get_db().add(UserPreference(user_id=analyst, key=PREFERENCE_KEY_THEME, value_json='{"mode": "neon"}'))
    get_db().commit()
    with caplog.at_level(logging.WARNING):
        html = web_client.get(url_for("analysis.manage")).data.decode()
    assert _html_attributes(html) == ("system", "light")
    assert any("preference theme is unreadable" in record.getMessage() for record in caplog.records)


def test_login_page_follows_the_system(app):
    with app.test_client() as client:
        html = client.get(url_for("auth.login")).data.decode()
    assert _html_attributes(html) == ("system", "light")
    # an anonymous visitor has nowhere to save a choice
    assert 'id="theme-switcher"' not in html


def test_navbar_offers_every_theme(web_client, analyst):
    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'id="theme-switcher"' in html
    for mode in ("system", "light", "dark", "jd"):
        assert f'data-theme-mode="{mode}"' in html
    assert "\U0001F474 JD" in html


def test_preferences_page_has_appearance_choices(web_client, analyst):
    _set_theme(analyst, "jd")
    html = web_client.get(url_for("main.preferences")).data.decode()
    assert "Appearance" in html
    for mode in ("system", "light", "dark", "jd"):
        assert f'id="theme_mode_{mode}"' in html
    assert re.search(r'id="theme_mode_jd" value="jd"\s+checked', html)


def test_theme_is_looked_up_once_per_page(web_client, analyst):
    """core.html, the navbar and the preferences page all ask for the theme; it is read once."""
    with count_queries() as statements:
        response = web_client.get(url_for("main.preferences"))
    assert response.status_code == 200
    theme_reads = [s for s in statements if "FROM user_preferences" in s]
    # the preferences page also reads manage_columns for its column chooser
    assert len(theme_reads) == 2
