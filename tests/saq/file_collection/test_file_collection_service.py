import pytest

from saq.configuration.config import get_config
from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.file_collection.database import queue_file_collection
from saq.file_collection.file_collector import FileCollector
from saq.file_collection.manager import FileCollectionManager
from saq.file_collection.service import FileCollectionService, FileCollectionServiceConfig
from saq.file_collection.types import FileCollectionStatus, FileCollectionWorkItem, FileCollectorResult, FileCollectorStatus
from tests.saq.helpers import wait_for_condition


class ConfiguredFileCollector(FileCollector):
    """A collector the service loads from a file_collector_* section."""

    def collect(self, target: FileCollectionWorkItem) -> FileCollectorResult:
        return FileCollectorResult(
            status=FileCollectorStatus.SUCCESS,
            message="collected",
            collected_file_path=f"/collected/{target.id}",
            collected_file_sha256="0" * 64,
        )


@pytest.fixture
def file_collector_sections(monkeypatch):
    """Replaces the file_collector_* sections of the config with one per given name."""
    raw = get_config().raw._data
    for key in [key for key in raw if key.startswith("file_collector_")]:
        monkeypatch.delitem(raw, key)

    def _load(*names: str):
        for name in names:
            monkeypatch.setitem(raw, f"file_collector_{name}", {
                "name": name,
                "display_name": name,
                "description": f"{name} for testing",
                "observable_type": F_FILE_LOCATION,
                "python_module": __name__,
                "python_class": "ConfiguredFileCollector",
            })
        get_config().load_file_collector_configs()

    return _load


@pytest.fixture
def service_config(monkeypatch):
    """The shipped config has no service_file_collection section; integrations provide it."""
    config = FileCollectionServiceConfig(
        name="file_collection",
        python_module="saq.file_collection.service",
        python_class="FileCollectionService",
        description="file collection",
        enabled=True,
    )
    monkeypatch.setattr("saq.file_collection.service.get_service_config", lambda name: config)
    return config


def _status(collection_id: int) -> str:
    get_db().expire_all()
    return get_db().query(FileCollection).filter(FileCollection.id == collection_id).one().status


@pytest.mark.integration
def test_start_single_threaded_collects_everything_due(db_alert, file_collector_sections, service_config):
    file_collector_sections("collector_a", "collector_b")
    ids = [
        queue_file_collection("collector_a", F_FILE_LOCATION, "host@/a1", db_alert.uuid),
        queue_file_collection("collector_a", F_FILE_LOCATION, "host@/a2", db_alert.uuid),
        queue_file_collection("collector_b", F_FILE_LOCATION, "host@/b1", db_alert.uuid),
    ]

    service = FileCollectionService()
    service.start_single_threaded()

    assert [_status(collection_id) for collection_id in ids] == [FileCollectionStatus.COMPLETED.value] * 3

    # `ace service start` stops and waits for the service after it returns
    service.stop()
    service.wait()


@pytest.mark.integration
def test_start_single_threaded_stops_on_shutdown(db_alert, file_collector_sections, service_config, monkeypatch):
    file_collector_sections("collector_a")
    ids = [queue_file_collection("collector_a", F_FILE_LOCATION, f"host@/a{n}", db_alert.uuid) for n in range(3)]
    # shutdown is requested (as a signal would) while the first item is being worked
    checks = iter([False])
    monkeypatch.setattr("saq.queue_service.is_shutting_down", lambda: next(checks, True))

    service = FileCollectionService()
    service.start_single_threaded()

    assert [_status(collection_id) for collection_id in ids].count(FileCollectionStatus.COMPLETED.value) == 1
    service.stop()
    service.wait()


@pytest.mark.integration
def test_service_lifecycle(db_alert, file_collector_sections, service_config):
    file_collector_sections("collector_a")
    collection_id = queue_file_collection("collector_a", F_FILE_LOCATION, "host@/a1", db_alert.uuid)

    service = FileCollectionService()
    service.start()
    try:
        assert service.wait_for_start(5)
        wait_for_condition(lambda: _status(collection_id) == FileCollectionStatus.COMPLETED.value)
    finally:
        service.stop()
        service.wait()

    assert all(not worker_thread.is_alive() for worker in service.manager.workers.values() for worker_thread in worker.worker_threads)
    assert not service.manager.collector.collector_thread.is_alive()


@pytest.mark.unit
def test_service_passes_config_to_manager(service_config, file_collector_sections):
    file_collector_sections()
    service_config.lock_timeout_seconds = 11
    service_config.initial_retry_delay_seconds = 12
    service_config.max_retry_delay_seconds = 13
    service_config.max_collection_time_seconds = 14

    collector = FileCollectionService().create_manager().collector

    assert (collector.lock_timeout_seconds, collector.initial_retry_delay_seconds, collector.max_retry_delay_seconds, collector.max_collection_time_seconds) == (11, 12, 13, 14)


@pytest.mark.unit
def test_load_workers(file_collector_sections):
    file_collector_sections("collector_a", "collector_b")

    manager = FileCollectionManager()
    manager.load_workers()

    assert set(manager.workers) == {"collector_a", "collector_b"}
    assert all(isinstance(worker.file_collector, ConfiguredFileCollector) for worker in manager.workers.values())
    assert set(manager.collector.listeners) == {"collector_a", "collector_b"}


@pytest.mark.unit
def test_load_workers_rejects_duplicate_names(file_collector_sections):
    file_collector_sections("collector_a")

    manager = FileCollectionManager()
    manager.load_workers()

    with pytest.raises(ValueError, match="worker collector_a already exists"):
        manager.load_workers()


