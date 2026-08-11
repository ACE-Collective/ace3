import uuid

import pytest

from saq.database.model import Alert, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.gui.icon import IconConfiguration, KEY_ICON_CONFIGURATION
from tests.saq.helpers import create_root_analysis, insert_alert

from sqlalchemy import inspect

@pytest.mark.integration
def test_load_alert():
    # since we're storing the data in two places (json and database)
    # make sure that when we load() and Alert we don't immediately make it "dirty" to the ORM

    alert = insert_alert()
    alert_id = alert.id
    get_db().close()
    assert not get_db().dirty

    for alert in get_db().query(Alert).filter(Alert.id == alert_id):
        assert not get_db().dirty
        alert.load()
        assert not get_db().dirty

@pytest.mark.integration
def test_alert_log_error_on_load(caplog):
    # the log_error_on_load flag set on an Alert should propagate to the
    # RootAnalysis created by load() and produce an ERROR log message
    alert = insert_alert()
    alert_id = alert.id
    get_db().close()

    for alert in get_db().query(Alert).filter(Alert.id == alert_id):
        # default is False, so no error is logged
        alert.load()
        assert not [r for r in caplog.records if r.levelname == "ERROR"]

        # with the flag set, load() logs an error
        alert.set_log_error_on_load(True)
        alert.load()
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(error_records) == 1
        assert alert.storage_dir in error_records[0].getMessage()

@pytest.mark.integration
def test_insert_alert_name_too_long():
    # make an alert with a description that is too long
    root_analysis = create_root_analysis(desc = 'A' * 1025)
    root_analysis.save()
    ALERT(root_analysis)
    alert = load_alert(root_analysis.uuid)
    assert alert is not None

    assert len(alert.description) == 1024

@pytest.mark.integration
def test_sync_icon_configuration_blueprint():
    # sync() should mirror a blueprint icon configuration into the icon_* columns
    root_analysis = create_root_analysis(uuid=str(uuid.uuid4()))
    root_analysis.initialize_storage()
    root_analysis.set_extension(KEY_ICON_CONFIGURATION, {
        "blueprint_file_location": {"name": "my_blueprint", "path": "images/custom.png"}})
    root_analysis.save()
    ALERT(root_analysis)

    alert = load_alert(root_analysis.uuid)
    assert alert.icon_blueprint_name == "my_blueprint"
    assert alert.icon_blueprint_path == "images/custom.png"
    assert alert.icon_url is None

@pytest.mark.integration
def test_sync_icon_configuration_url():
    # sync() should mirror a url icon configuration into the icon_url column
    root_analysis = create_root_analysis(uuid=str(uuid.uuid4()))
    root_analysis.initialize_storage()
    root_analysis.set_extension(KEY_ICON_CONFIGURATION, {"url": "https://example.com/icon.png"})
    root_analysis.save()
    ALERT(root_analysis)

    alert = load_alert(root_analysis.uuid)
    assert alert.icon_url == "https://example.com/icon.png"
    assert alert.icon_blueprint_name is None
    assert alert.icon_blueprint_path is None

@pytest.mark.integration
def test_sync_icon_configuration_long_data_url():
    # icon_url must accept data urls well beyond the old 1024 char limit
    long_data_url = "data:image/png;base64," + ("A" * 5000)
    root_analysis = create_root_analysis(uuid=str(uuid.uuid4()))
    root_analysis.initialize_storage()
    root_analysis.set_extension(KEY_ICON_CONFIGURATION, {"url": long_data_url})
    root_analysis.save()
    ALERT(root_analysis)

    alert = load_alert(root_analysis.uuid)
    assert alert.icon_url == long_data_url

@pytest.mark.integration
def test_sync_icon_configuration_none():
    # an alert with no icon configuration leaves the icon_* columns NULL
    alert = insert_alert()
    assert alert.icon_blueprint_name is None
    assert alert.icon_blueprint_path is None
    assert alert.icon_url is None

@pytest.mark.integration
def test_apply_icon_configuration_writes_only_on_change():
    # apply_icon_configuration should not dirty a column when the value is unchanged
    root_analysis = create_root_analysis(uuid=str(uuid.uuid4()))
    root_analysis.initialize_storage()
    root_analysis.set_extension(KEY_ICON_CONFIGURATION, {"url": "https://example.com/icon.png"})
    root_analysis.save()
    ALERT(root_analysis)

    alert = load_alert(root_analysis.uuid)

    # applying the same configuration registers no change
    alert.apply_icon_configuration(IconConfiguration(url="https://example.com/icon.png"))
    assert not inspect(alert).attrs.icon_url.history.has_changes()

    # applying a different configuration does register a change
    alert.apply_icon_configuration(IconConfiguration(url="https://example.com/other.png"))
    assert inspect(alert).attrs.icon_url.history.has_changes()