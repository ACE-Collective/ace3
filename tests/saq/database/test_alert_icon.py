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
def test_icon_no_matching_alert_type_file(alert_icons, monkeypatch):
    """test icon falls back to token matching when alert_type file doesn't exist"""
    alert = create_test_alert(alert_type="custom_alert", description="test splunk alert")

    monkeypatch.setattr(get_config(), "gui_favicons", {"splunk": "splunk_icon"})

    alert_icons('default.png', 'mailbox.png', 'splunk.png')

    assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_matches_description_token(alert_icons, monkeypatch):
    """test icon matches token from description when no alert_type file exists"""
    alert = create_test_alert(description="virustotal detection alert")

    monkeypatch.setattr(get_config(), "gui_favicons", {'virustotal': 'vt_icon', 'detection': 'det_icon'})

    alert_icons('default.png', 'mailbox.png')

    icon = alert.legacy_icon
    assert icon in ['virustotal', 'detection']


@pytest.mark.unit
def test_icon_matches_tool_token(alert_icons, monkeypatch):
    """test icon matches token from tool when description doesn't match"""
    alert = create_test_alert(tool="splunk hunter", description="no matching tokens here")

    monkeypatch.setattr(get_config(), "gui_favicons", {'splunk': 'splunk_icon', 'hunter': 'hunter_icon'})

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['splunk', 'hunter']


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
def test_icon_with_empty_gui_favicons(alert_icons, monkeypatch):
    """test icon returns default when gui_favicons config is empty"""
    alert = create_test_alert()

    monkeypatch.setattr(get_config(), "gui_favicons", {})

    alert_icons('default.png')

    assert alert.legacy_icon == "default"


@pytest.mark.unit
def test_icon_with_special_characters_in_description(alert_icons, monkeypatch):
    """test icon handles special characters in description gracefully"""
    alert = create_test_alert(description="splunk: detection (high priority)")

    monkeypatch.setattr(get_config(), "gui_favicons", {'splunk': 'splunk_icon', 'detection': 'det_icon'})

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['splunk', 'detection']


@pytest.mark.unit
def test_icon_alert_type_with_hyphen(alert_icons):
    """test icon handles alert_type with hyphens in filename"""
    alert = create_test_alert(alert_type="hunter - splunk - crowdstrike")

    alert_icons('default.png', 'hunter - splunk - crowdstrike.png')

    assert alert.legacy_icon == "hunter - splunk - crowdstrike"


@pytest.mark.unit
def test_icon_pop_returns_single_value(alert_icons, monkeypatch):
    """test icon returns a single value when multiple tokens match"""
    alert = create_test_alert(description="splunk virustotal manual")

    monkeypatch.setattr(get_config(), "gui_favicons", {
        'splunk': 'splunk_icon',
        'virustotal': 'vt_icon',
        'manual': 'manual_icon'
    })

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['splunk', 'virustotal', 'manual']
    assert isinstance(icon, str)


@pytest.mark.unit
def test_icon_handles_empty_alert_type(alert_icons, monkeypatch):
    """test icon handles empty alert_type gracefully"""
    alert = create_test_alert(alert_type="", tool="splunk")

    monkeypatch.setattr(get_config(), "gui_favicons", {'splunk': 'splunk_icon'})

    alert_icons('default.png')

    assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_handles_single_word_alert_type(alert_icons):
    """test icon handles single word alert_type correctly"""
    alert = create_test_alert(alert_type="splunk")

    alert_icons('default.png', 'splunk.png')

    assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_splits_tool_by_space(alert_icons, monkeypatch):
    """test icon splits tool tokens by space"""
    alert = create_test_alert(tool="hunter collector", description="test")

    monkeypatch.setattr(get_config(), "gui_favicons", {'hunter': 'hunter_icon', 'collector': 'collector_icon'})

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['hunter', 'collector']


@pytest.mark.unit
def test_icon_splits_alert_type_by_space(alert_icons, monkeypatch):
    """test icon splits alert_type tokens by space"""
    alert = create_test_alert(alert_type="manual upload", tool="test", description="test")

    monkeypatch.setattr(get_config(), "gui_favicons", {'manual': 'manual_icon', 'upload': 'upload_icon'})

    alert_icons('default.png')

    icon = alert.legacy_icon
    assert icon in ['manual', 'upload']


@pytest.mark.unit
def test_icon_reads_the_alert_icons_shipped_with_the_gui():
    """the icons directory legacy_icon lists is the one the GUI serves them from"""
    assert create_test_alert(alert_type="mailbox").legacy_icon == "mailbox"
