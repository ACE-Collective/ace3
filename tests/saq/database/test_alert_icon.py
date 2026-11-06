import pytest

from saq.configuration.config import get_config
from saq.gui.alert import GUIAlert


@pytest.fixture
def alert_icons(tmp_path, monkeypatch):
    """points the GUI at an alert_icons directory under tmp_path holding the given .png files"""
    icon_dir = tmp_path / "app" / "static" / "images" / "alert_icons"
    icon_dir.mkdir(parents=True)
    monkeypatch.setattr("saq.gui.alert.get_base_dir", lambda: str(tmp_path))

    def _create(*file_names):
        for file_name in file_names:
            (icon_dir / file_name).write_bytes(b"")

    return _create


def create_test_alert(alert_type="test", tool="test_tool", description="test description"):
    """helper to create a test GUIAlert instance without database"""
    return GUIAlert(
        uuid="test-uuid",
        storage_dir="/tmp/test",
        location="test",
        alert_type=alert_type,
        tool=tool,
        tool_instance="test_instance",
        description=description
    )


@pytest.mark.unit
def test_icon_matches_alert_type_file(alert_icons):
    """test icon returns alert_type when matching .png file exists in alert_icons directory"""
    alert = create_test_alert(alert_type="mailbox")

    alert_icons('default.png', 'mailbox.png', 'splunk.png')

    assert alert.legacy_icon == "mailbox"


@pytest.mark.unit
def test_icon_matches_alert_type_token(alert_icons, monkeypatch):
    """test icon matches token from alert_type when description and tool don't match"""
    alert = create_test_alert(alert_type="manual analysis", tool="test tool", description="some description")

    monkeypatch.setattr(get_config(), "gui_favicons", {'manual': 'manual_icon', 'analysis': 'analysis_icon'})

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['manual', 'analysis']


@pytest.mark.unit
def test_icon_returns_default_when_no_matches(alert_icons, monkeypatch):
    """test icon returns 'default' when no tokens match available favicons"""
    alert = create_test_alert(alert_type="custom", tool="custom_tool", description="custom description")

    monkeypatch.setattr(get_config(), "gui_favicons", {'splunk': 'splunk_icon', 'virustotal': 'vt_icon'})

    alert_icons('default.png')

    assert alert.legacy_icon == "default"


@pytest.mark.unit
def test_icon_token_matching_case_insensitive(alert_icons, monkeypatch):
    """test icon token matching is case insensitive"""
    alert = create_test_alert(description="VirusTotal Detection")

    monkeypatch.setattr(get_config(), "gui_favicons", {'virustotal': 'vt_icon'})

    alert_icons('default.png')

    assert alert.legacy_icon == "virustotal"


@pytest.mark.unit
def test_icon_splits_description_by_space_and_underscore(alert_icons, monkeypatch):
    """test icon splits description tokens by both space and underscore"""
    alert = create_test_alert(description="virus_total detection")

    monkeypatch.setattr(get_config(), "gui_favicons", {'virus': 'virus_icon', 'total': 'total_icon'})

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['virus', 'total']


@pytest.mark.unit
def test_icon_prefers_description_over_tool(alert_icons, monkeypatch):
    """test icon prefers description token matches over tool token matches"""
    alert = create_test_alert(tool="manual tool", description="splunk detection")

    monkeypatch.setattr(get_config(), "gui_favicons", {'splunk': 'splunk_icon', 'manual': 'manual_icon'})

    alert_icons('default.png')

    assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_prefers_tool_over_alert_type(alert_icons, monkeypatch):
    """test icon prefers tool token matches over alert_type token matches"""
    alert = create_test_alert(alert_type="manual check", tool="splunk hunter", description="some description")

    monkeypatch.setattr(get_config(), "gui_favicons", {'splunk': 'splunk_icon', 'manual': 'manual_icon'})

    alert_icons('default.png')

    assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_reads_the_alert_icons_shipped_with_the_gui():
    """the icons directory legacy_icon lists is the one the GUI serves them from"""
    assert create_test_alert(alert_type="mailbox").legacy_icon == "mailbox"
