import os
from unittest.mock import Mock, patch

import pytest

from saq.configuration.config import get_config
from saq.constants import F_EMAIL_ADDRESS, F_EMAIL_FROM, F_EMAIL_REPLY_TO, F_TEST
from saq.database.model import ObservableDetection
from saq.database.pool import get_db
from saq.database.util.observable_detection import create_observable_detection
from saq.observables.export.config import ObservableExportConfig
from saq.observables.export.manager import get_observable_exports, run_exports
from saq.observables.export.splunk_kvstore import SplunkKVStoreExport, SplunkKVStoreExportConfig
from saq.observables.type_hierarchy import get_type_hierarchy


def splunk_export(**overrides) -> SplunkKVStoreExport:
    """The configured splunk target, with any settings overridden for the test."""
    config = get_config().get_observable_export_config("splunk").model_copy(
        update={"collection": "test_collection", **overrides})
    return SplunkKVStoreExport(config)


@pytest.fixture
def email_type_hierarchy():
    """Pins the email subtype -> email_address edges the subtype tests rely on.

    etc/observable_types.yaml already declares these in dev and CI, but snapshotting the in-memory
    parent map keeps the tests from depending on which YAML the run happened to load."""
    hierarchy = get_type_hierarchy()
    parent_snapshot = dict(hierarchy._parent)
    hierarchy._parent[F_EMAIL_REPLY_TO] = F_EMAIL_ADDRESS
    hierarchy._parent[F_EMAIL_FROM] = F_EMAIL_ADDRESS
    hierarchy._ancestors_cache.clear()
    try:
        yield hierarchy
    finally:
        hierarchy._parent = parent_snapshot
        hierarchy._ancestors_cache.clear()


@pytest.fixture
def mock_splunk(monkeypatch):
    """Stands in for the splunk client. Yields the mock so tests can assert on the calls."""
    client = Mock()
    client.kvstore_query.return_value = []
    monkeypatch.setattr(
        "saq.splunk.SplunkClient", Mock(return_value=client))
    return client


@pytest.fixture
def state_dir(tmpdir, monkeypatch) -> str:
    """Isolates the export state so a test does not inherit another run's fingerprint."""
    path = str(tmpdir / "state")
    monkeypatch.setattr("saq.observables.export.state.get_state_dir", lambda: path)
    return path


@pytest.fixture
def no_detections():
    get_db().query(ObservableDetection).delete()
    get_db().commit()


#
# configuration
#

@pytest.mark.unit
def test_config_class_is_the_subclass():
    # the config block carries collection/export_list/etc, so the target has to declare its own model
    assert SplunkKVStoreExport.get_config_class() is SplunkKVStoreExportConfig
    assert issubclass(SplunkKVStoreExportConfig, ObservableExportConfig)


@pytest.mark.unit
def test_configured_settings_are_loaded():
    config = get_config().get_observable_export_config("splunk")
    assert isinstance(config, SplunkKVStoreExportConfig)
    assert config.max_export == 500
    assert "fqdn" in config.export_list
    # both the generic type and the legacy one detections may still carry
    assert "ip" in config.export_list
    assert "ipv4" in config.export_list


@pytest.mark.unit
def test_disabled_by_default():
    # a stock install has no splunk to publish to, so it must not run unless asked for
    assert get_config().get_observable_export_config("splunk").enabled is False
    assert "splunk" not in [export.name for export in get_observable_exports()]


@pytest.mark.unit
def test_named_explicitly_runs_even_though_disabled():
    assert [export.name for export in get_observable_exports(["splunk"])] == ["splunk"]


#
# building the export list and documents
#

@pytest.mark.unit
def test_build_export_list_filters_by_type_only():
    export = splunk_export(export_list=["fqdn", "ip"])

    export_list = export.build_export_list({
        "fqdn": [{"id": 1, "value": "evil.example.com"}],
        # no minimum length here, unlike yara -- a lookup keyed on type and value tolerates it
        "ip": [{"id": 2, "value": "::1"}],
        "url": [{"id": 3, "value": "http://not-configured.example.com"}],
    })

    assert {(entry.type, entry.id) for entry in export_list} == {("fqdn", 1), ("ip", 2)}


@pytest.mark.unit
def test_build_export_list_includes_subtypes(email_type_hierarchy):
    export = splunk_export(export_list=[F_EMAIL_ADDRESS])

    export_list = export.build_export_list({
        F_EMAIL_REPLY_TO: [{"id": 1, "value": "reply@example.com"}],
        F_EMAIL_FROM: [{"id": 2, "value": "from@example.com"}],
        F_EMAIL_ADDRESS: [{"id": 3, "value": "plain@example.com"}],
    })

    assert {(entry.type, entry.id) for entry in export_list} == {
        (F_EMAIL_ADDRESS, 1), (F_EMAIL_ADDRESS, 2), (F_EMAIL_ADDRESS, 3)}


@pytest.mark.unit
def test_build_export_list_most_specific_configured_type_wins(email_type_hierarchy):
    export = splunk_export(export_list=[F_EMAIL_ADDRESS, F_EMAIL_REPLY_TO])

    export_list = export.build_export_list({
        F_EMAIL_REPLY_TO: [{"id": 1, "value": "reply@example.com"}],
    })

    # exported once, under the more specific of the two configured types -- a duplicate would
    # collide on _key in the kv store
    documents = export.build_documents(export_list)
    assert [document["_key"] for document in documents] == ["1"]
    assert documents[0]["type"] == F_EMAIL_REPLY_TO


@pytest.mark.unit
def test_document_reports_the_configured_type_for_a_subtype(email_type_hierarchy):
    export = splunk_export(export_list=[F_EMAIL_ADDRESS])
    export_list = export.build_export_list({
        F_EMAIL_REPLY_TO: [{"id": 7, "value": "Reply@example.com"}]})

    # a search filtering the lookup on type="email_address" has to find it
    assert export.build_documents(export_list) == [{
        "_key": "7",
        "id": 7,
        "type": F_EMAIL_ADDRESS,
        "value": "*reply@example.com*",
    }]


@pytest.mark.unit
def test_document_shape():
    export = splunk_export(export_list=["fqdn"])
    export_list = export.build_export_list({"fqdn": [{"id": 7, "value": "EVIL.example.com"}]})

    assert export.build_documents(export_list) == [{
        "_key": "7",
        "id": 7,
        "type": "fqdn",
        # lowercased and wrapped in wildcards so the collection works as a lookup
        "value": "*evil.example.com*",
    }]


@pytest.mark.unit
def test_document_escapes_a_literal_asterisk():
    export = splunk_export(export_list=["url"])
    export_list = export.build_export_list({"url": [{"id": 1, "value": "http://x.com/a*b"}]})

    # the * in the value has to stay literal rather than becoming a wildcard
    assert export.build_documents(export_list)[0]["value"] == "*http://x.com/a\\*b*"


#
# publishing
#

@pytest.mark.unit
def test_publish_requires_a_collection(mock_splunk):
    export = splunk_export(collection="", export_list=["fqdn"])
    export_list = export.build_export_list({"fqdn": [{"id": 1, "value": "evil.example.com"}]})

    # publishing into a collection named "" would report success while going nowhere
    with pytest.raises(ValueError, match="no collection configured"):
        export.publish(export_list)


@pytest.mark.unit
def test_publish_saves_documents(mock_splunk):
    export = splunk_export(export_list=["fqdn"])
    export.publish(export.build_export_list({"fqdn": [{"id": 1, "value": "evil.example.com"}]}))

    mock_splunk.kvstore_batch_save.assert_called_once()
    collection, documents = mock_splunk.kvstore_batch_save.call_args[0]
    assert collection == "test_collection"
    assert documents[0]["_key"] == "1"
    mock_splunk.kvstore_delete.assert_not_called()


@pytest.mark.unit
def test_publish_deletes_only_the_stale_documents(mock_splunk):
    mock_splunk.kvstore_query.return_value = [
        {"_key": "1"}, {"_key": "2"}, {"_key": "3"}]

    export = splunk_export(export_list=["fqdn"])
    export.publish(export.build_export_list({"fqdn": [
        {"id": 2, "value": "b.example.com"},
        {"id": 3, "value": "c.example.com"},
    ]}))

    mock_splunk.kvstore_delete.assert_called_once_with(
        "test_collection", {"_key": {"$in": ["1"]}})

    # 2 and 3 are still saved -- batch_save is keyed, so re-saving them is the upsert
    _, documents = mock_splunk.kvstore_batch_save.call_args[0]
    assert sorted(document["_key"] for document in documents) == ["2", "3"]


@pytest.mark.unit
def test_publish_chunks_at_max_export(mock_splunk):
    export = splunk_export(export_list=["fqdn"], max_export=500)
    detections = [{"id": i, "value": f"host{i}.example.com"} for i in range(1001)]

    export.publish(export.build_export_list({"fqdn": detections}))

    assert mock_splunk.kvstore_batch_save.call_count == 3
    sizes = [len(call[0][1]) for call in mock_splunk.kvstore_batch_save.call_args_list]
    assert sizes == [500, 500, 1]


@pytest.mark.unit
def test_publish_chunks_deletes_too(mock_splunk):
    mock_splunk.kvstore_query.return_value = [{"_key": str(i)} for i in range(1001)]

    export = splunk_export(export_list=["fqdn"], max_export=500)
    export.publish(export.build_export_list({}))

    assert mock_splunk.kvstore_delete.call_count == 3


@pytest.mark.unit
def test_publish_empty_list_clears_the_collection(mock_splunk):
    mock_splunk.kvstore_query.return_value = [{"_key": "1"}, {"_key": "2"}]

    export = splunk_export(export_list=["fqdn"])
    export.publish(export.build_export_list({}))

    mock_splunk.kvstore_delete.assert_called_once_with(
        "test_collection", {"_key": {"$in": ["1", "2"]}})
    mock_splunk.kvstore_batch_save.assert_not_called()


@pytest.mark.unit
def test_publish_propagates_failures(mock_splunk):
    mock_splunk.kvstore_batch_save.side_effect = RuntimeError("splunk is down")

    export = splunk_export(export_list=["fqdn"])
    export_list = export.build_export_list({"fqdn": [{"id": 1, "value": "evil.example.com"}]})

    with pytest.raises(RuntimeError):
        export.publish(export_list)


#
# through the manager
#

@pytest.mark.integration
def test_failed_publish_is_not_recorded_as_success(no_detections, state_dir, monkeypatch):
    """A publish that raises must leave the fingerprint unwritten so the next run retries."""
    create_observable_detection(F_TEST, "evil_value", None)

    client = Mock()
    client.kvstore_query.return_value = []
    client.kvstore_batch_save.side_effect = RuntimeError("splunk is down")
    monkeypatch.setattr("saq.splunk.SplunkClient", Mock(return_value=client))
    monkeypatch.setattr(
        get_config().get_observable_export_config("splunk"), "collection", "test_collection")
    monkeypatch.setattr(
        get_config().get_observable_export_config("splunk"), "export_list", [F_TEST])

    assert run_exports(["splunk"]) == os.EX_SOFTWARE

    from saq.observables.export.state import read_fingerprint
    assert read_fingerprint("splunk") is None


@pytest.mark.integration
def test_successful_publish_then_skip(no_detections, state_dir, monkeypatch):
    create_observable_detection(F_TEST, "evil_value", None)

    client = Mock()
    client.kvstore_query.return_value = []
    monkeypatch.setattr("saq.splunk.SplunkClient", Mock(return_value=client))
    monkeypatch.setattr(
        get_config().get_observable_export_config("splunk"), "collection", "test_collection")
    monkeypatch.setattr(
        get_config().get_observable_export_config("splunk"), "export_list", [F_TEST])

    assert run_exports(["splunk"]) == os.EX_OK
    assert client.kvstore_batch_save.call_count == 1

    # nothing changed, so the second run must not touch splunk at all
    assert run_exports(["splunk"]) == os.EX_OK
    assert client.kvstore_batch_save.call_count == 1
    assert client.kvstore_query.call_count == 1
