import logging

import pytest
from flask import url_for

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.gui.alert import KEY_ALERT_TEMPLATE, GUIAlert, GUIAlertPresenter, get_selectable_alert_templates


@pytest.fixture
def custom_templates(tmp_path, monkeypatch):
    """Two custom template directories, as a site that adds its own views to the stock ones has."""
    for directory, names in {"custom": ["hunter.html", "hunter_splunk.html"], "site": ["mail_box.html"]}.items():
        (tmp_path / directory).mkdir()
        for name in names:
            (tmp_path / directory / name).write_text("")
    monkeypatch.setattr(get_config().custom_alerts, "template_dir", str(tmp_path))
    monkeypatch.setattr(get_config().custom_alerts, "dirs", ["custom", "site"])
    monkeypatch.setattr(get_config(), "custom_alerts_backward_compatibility", {"legacy": "analysis/custom/legacy.html"})
    return tmp_path


def _template_for(alert_type, extensions=None):
    return GUIAlertPresenter(RootAnalysis(alert_type=alert_type, extensions=extensions or {})).template_path


@pytest.mark.unit
@pytest.mark.parametrize("alert_type, expected", [
    ("hunter - splunk", "custom/hunter_splunk.html"),
    # the most specific template that exists wins
    ("hunter - splunk - aws", "custom/hunter_splunk.html"),
    ("hunter - qradar", "custom/hunter.html"),
    # templates come from every configured directory, and spaces count as separators
    ("mail box", "site/mail_box.html"),
    ("legacy", "analysis/custom/legacy.html"),
    ("manual", "analysis/alert.html"),
    (None, "analysis/alert.html"),
])
def test_custom_template_is_chosen_by_alert_type(custom_templates, alert_type, expected):
    assert _template_for(alert_type) == expected


@pytest.mark.unit
def test_template_set_on_the_alert_wins(custom_templates):
    assert _template_for("hunter - splunk", {KEY_ALERT_TEMPLATE: "analysis/custom/http.html"}) == "analysis/custom/http.html"


@pytest.mark.unit
def test_unreadable_template_directory_is_logged(custom_templates, monkeypatch, caplog):
    monkeypatch.setattr(get_config().custom_alerts, "dirs", ["custom", "missing"])
    root = RootAnalysis(alert_type="hunter - splunk")

    with caplog.at_level(logging.ERROR):
        assert GUIAlertPresenter(root).template_path == "analysis/alert.html"

    records = [r for r in caplog.records if getattr(r, "alert_uuid", None) == root.uuid]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None


@pytest.mark.unit
def test_selectable_templates_are_the_standard_template_and_the_listed_ones(custom_templates, monkeypatch):
    # templates found in custom_alerts.dirs are not offered: most read details only their own alert type has
    monkeypatch.setattr(get_config().custom_alerts, "selectable_templates",
                        ["analysis/custom/saq_debug.html", "analysis/alert.html"])

    assert get_selectable_alert_templates() == ["analysis/alert.html", "analysis/custom/saq_debug.html"]


@pytest.mark.unit
def test_listed_template_the_gui_cannot_load_is_left_out_and_reported(monkeypatch, caplog):
    monkeypatch.setattr(get_config().custom_alerts, "selectable_templates", ["no_such/template.html"])

    with caplog.at_level(logging.ERROR):
        assert get_selectable_alert_templates() == ["analysis/alert.html"]

    records = [r for r in caplog.records if getattr(r, "template", None) == "no_such/template.html"]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    # without a traceback ErrorReportHandler writes no error report
    assert records[0].exc_info is not None


@pytest.mark.unit
def test_selectable_templates_without_custom_alert_config(monkeypatch):
    monkeypatch.setattr(get_config(), "custom_alerts", None)
    assert get_selectable_alert_templates() == ["analysis/alert.html"]


def _alert(**kwargs):
    values = {"alert_type": "no such type", "description": "an alert", "tool": "some tool"}
    values.update(kwargs)
    return GUIAlert(**values)


@pytest.mark.unit
def test_icon_from_a_blueprint_file():
    alert = _alert(icon_blueprint_name="static", icon_blueprint_path="images/alert_icons/splunk.png")
    assert alert.icon == url_for("static", filename="images/alert_icons/splunk.png")


@pytest.mark.unit
def test_icon_from_a_missing_blueprint_falls_back_and_is_logged(caplog):
    alert = _alert(uuid="11111111-1111-1111-1111-111111111111",
                   icon_blueprint_name="no_such_blueprint.static", icon_blueprint_path="icon.png")

    with caplog.at_level(logging.ERROR):
        assert alert.icon == url_for("static", filename="images/alert_icons/default.png")

    records = [r for r in caplog.records if getattr(r, "alert_uuid", None) == alert.uuid]
    assert len(records) == 1
    assert records[0].exc_info is not None


@pytest.mark.unit
def test_icon_from_a_url():
    assert _alert(icon_url="https://icons.example/hunt.png").icon == "https://icons.example/hunt.png"


@pytest.mark.unit
@pytest.mark.parametrize("fields, favicons, expected", [
    # an icon file named after the alert type
    ({"alert_type": "splunk"}, {}, "splunk"),
    # otherwise a configured favicon named in the description, then the tool, then the alert type
    ({"description": "Phish_Kit detected"}, {"phish": "x", "tool": "x"}, "phish"),
    ({"tool": "Mail Tool"}, {"tool": "x"}, "tool"),
    ({"alert_type": "brand new"}, {"brand": "x"}, "brand"),
    ({}, {}, "default"),
])
def test_legacy_icon(monkeypatch, fields, favicons, expected):
    monkeypatch.setattr(get_config(), "gui_favicons", favicons)
    assert _alert(**fields).legacy_icon == expected
