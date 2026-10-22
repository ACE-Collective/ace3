import pytest

from saq.configuration.config import get_config
from saq.configuration.schema import RemediatorConfig
from saq.constants import F_TEST
from saq.remediation.collector import RemediationCollector
from saq.remediation.manager import RemediationManager
from saq.remediation.worker import RemediationWorker
from tests.saq.remediation.test_remediator import TestRemediator


@pytest.fixture
def manager():
    return RemediationManager()


@pytest.fixture
def test_worker():
    """Creates a test RemediationWorker for testing."""
    return RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="test_worker",
            display_name="Test Worker",
            description="Test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))


@pytest.fixture
def another_test_worker():
    """Creates another test RemediationWorker with a different name."""
    return RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="another_worker",
            display_name="Another Worker",
            description="Another test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))


@pytest.mark.unit
def test_remediation_manager(manager):
    assert not manager.workers
    assert isinstance(manager.collector, RemediationCollector)


@pytest.mark.unit
def test_add_worker(manager, test_worker):
    """Test adding a worker to the manager."""
    manager.add_worker(test_worker)

    # verify worker was added
    assert "test_worker" in manager.workers
    assert manager.workers["test_worker"] == test_worker

    # verify collector was registered
    assert "test_worker" in manager.collector.listeners


@pytest.mark.unit
def test_add_worker_duplicate_name(manager, test_worker):
    """Test that adding a worker with a duplicate name raises ValueError."""
    manager.add_worker(test_worker)

    # create another worker with the same name
    duplicate_worker = RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="test_worker",  # same name
            display_name="Test Worker",
            description="Test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))

    # should raise ValueError
    with pytest.raises(ValueError, match="worker test_worker already exists"):
        manager.add_worker(duplicate_worker)


@pytest.mark.unit
def test_add_multiple_workers(manager, test_worker, another_test_worker):
    """Test adding multiple workers with different names."""
    manager.add_worker(test_worker)
    manager.add_worker(another_test_worker)

    # verify both workers were added
    assert len(manager.workers) == 2
    assert "test_worker" in manager.workers
    assert "another_worker" in manager.workers
    assert manager.workers["test_worker"] == test_worker
    assert manager.workers["another_worker"] == another_test_worker


@pytest.fixture
def remediator_sections(monkeypatch):
    """Replaces the remediator_* sections of the real config with the given ones and reloads them."""
    raw = get_config().raw._data
    for key in [key for key in raw if key.startswith("remediator_")]:
        monkeypatch.delitem(raw, key)

    def _load(sections: dict):
        for key, value in sections.items():
            monkeypatch.setitem(raw, key, value)
        get_config().load_remediator_configs()

    return _load


def _remediator_section(name: str) -> dict:
    return {
        "name": name,
        "display_name": name.replace("_", " ").title(),
        "description": f"{name} for testing",
        "observable_type": F_TEST,
        "python_module": "tests.saq.remediation.test_remediator",
        "python_class": "TestRemediator",
    }


@pytest.mark.unit
def test_load_workers(manager, remediator_sections):
    """Test loading workers from configuration."""
    remediator_sections({
        "remediator_config_worker_1": _remediator_section("config_worker_1"),
        "remediator_config_worker_2": _remediator_section("config_worker_2"),
    })

    manager.load_workers()

    assert set(manager.workers) == {"config_worker_1", "config_worker_2"}
    assert all(isinstance(worker.remediator, TestRemediator) for worker in manager.workers.values())
    assert set(manager.collector.listeners) == {"config_worker_1", "config_worker_2"}


@pytest.mark.unit
def test_load_workers_empty_config(manager, remediator_sections):
    """Test loading workers when configuration has no remediators."""
    remediator_sections({})

    manager.load_workers()

    assert len(manager.workers) == 0
