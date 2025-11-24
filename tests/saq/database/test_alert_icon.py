import pytest
from unittest.mock import patch

from saq.gui.alert import GUIAlert


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
def test_icon_matches_alert_type_file():
    """test icon returns alert_type when matching .png file exists in alert_icons directory"""
    alert = create_test_alert(alert_type="mailbox")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png', 'mailbox.png', 'splunk.png']
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "mailbox"
        mock_listdir.assert_called_once()


@pytest.mark.unit
def test_icon_no_matching_alert_type_file():
    """test icon falls back to token matching when alert_type file doesn't exist"""
    alert = create_test_alert(alert_type="custom_alert", description="test splunk alert")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png', 'mailbox.png', 'splunk.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_matches_description_token():
    """test icon matches token from description when no alert_type file exists"""
    alert = create_test_alert(description="virustotal detection alert")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png', 'mailbox.png']
        mock_config.return_value = {'gui_favicons': {'virustotal': 'vt_icon', 'detection': 'det_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['virustotal', 'detection']


@pytest.mark.unit
def test_icon_matches_tool_token():
    """test icon matches token from tool when description doesn't match"""
    alert = create_test_alert(tool="splunk hunter", description="no matching tokens here")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon', 'hunter': 'hunter_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['splunk', 'hunter']


@pytest.mark.unit
def test_icon_matches_alert_type_token():
    """test icon matches token from alert_type when description and tool don't match"""
    alert = create_test_alert(alert_type="manual analysis", tool="test tool", description="some description")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'manual': 'manual_icon', 'analysis': 'analysis_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['manual', 'analysis']


@pytest.mark.unit
def test_icon_returns_default_when_no_matches():
    """test icon returns 'default' when no tokens match available favicons"""
    alert = create_test_alert(alert_type="custom", tool="custom_tool", description="custom description")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon', 'virustotal': 'vt_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "default"


@pytest.mark.unit
def test_icon_token_matching_case_insensitive():
    """test icon token matching is case insensitive"""
    alert = create_test_alert(description="VirusTotal Detection")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'virustotal': 'vt_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "virustotal"


@pytest.mark.unit
def test_icon_splits_description_by_space_and_underscore():
    """test icon splits description tokens by both space and underscore"""
    alert = create_test_alert(description="virus_total detection")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'virus': 'virus_icon', 'total': 'total_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['virus', 'total']


@pytest.mark.unit
def test_icon_prefers_description_over_tool():
    """test icon prefers description token matches over tool token matches"""
    alert = create_test_alert(tool="manual tool", description="splunk detection")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon', 'manual': 'manual_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_prefers_tool_over_alert_type():
    """test icon prefers tool token matches over alert_type token matches"""
    alert = create_test_alert(alert_type="manual check", tool="splunk hunter", description="some description")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon', 'manual': 'manual_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_with_empty_gui_favicons():
    """test icon returns default when gui_favicons config is empty"""
    alert = create_test_alert()

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "default"


@pytest.mark.unit
def test_icon_with_special_characters_in_description():
    """test icon handles special characters in description gracefully"""
    alert = create_test_alert(description="splunk: detection (high priority)")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon', 'detection': 'det_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['splunk', 'detection']


@pytest.mark.unit
def test_icon_alert_type_with_hyphen():
    """test icon handles alert_type with hyphens in filename"""
    alert = create_test_alert(alert_type="hunter - splunk - crowdstrike")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png', 'hunter - splunk - crowdstrike.png']
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "hunter - splunk - crowdstrike"


@pytest.mark.unit
def test_icon_pop_returns_single_value():
    """test icon returns a single value when multiple tokens match"""
    alert = create_test_alert(description="splunk virustotal manual")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {
            'gui_favicons': {
                'splunk': 'splunk_icon',
                'virustotal': 'vt_icon',
                'manual': 'manual_icon'
            }
        }
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['splunk', 'virustotal', 'manual']
        assert isinstance(icon, str)


@pytest.mark.unit
def test_icon_handles_empty_alert_type():
    """test icon handles empty alert_type gracefully"""
    alert = create_test_alert(alert_type="", tool="splunk")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'splunk': 'splunk_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_handles_single_word_alert_type():
    """test icon handles single word alert_type correctly"""
    alert = create_test_alert(alert_type="splunk")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png', 'splunk.png']
        mock_base_dir.return_value = '/opt/ace'

        assert alert.legacy_icon == "splunk"


@pytest.mark.unit
def test_icon_splits_tool_by_space():
    """test icon splits tool tokens by space"""
    alert = create_test_alert(tool="hunter collector", description="test")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'hunter': 'hunter_icon', 'collector': 'collector_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['hunter', 'collector']


@pytest.mark.unit
def test_icon_splits_alert_type_by_space():
    """test icon splits alert_type tokens by space"""
    alert = create_test_alert(alert_type="manual upload", tool="test", description="test")

    with patch('saq.gui.alert.os.listdir') as mock_listdir, \
         patch('saq.gui.alert.get_config') as mock_config, \
         patch('saq.gui.alert.get_base_dir') as mock_base_dir:
        mock_listdir.return_value = ['default.png']
        mock_config.return_value = {'gui_favicons': {'manual': 'manual_icon', 'upload': 'upload_icon'}}
        mock_base_dir.return_value = '/opt/ace'

        icon = alert.legacy_icon
        assert icon in ['manual', 'upload']
