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
def remediation_worker():
    """Creates a test RemediationWorker for testing."""
    return RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="remediation_worker",
            display_name="Test Worker",
            description="Test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))


@pytest.mark.unit
def test_remediation_manager(manager):
    assert not manager.workers
    assert isinstance(manager.collector, RemediationCollector)


@pytest.mark.unit
def test_add_worker(manager, remediation_worker):
    """Test adding a worker to the manager."""
    manager.add_worker(remediation_worker)

    # verify worker was added
    assert "remediation_worker" in manager.workers
    assert manager.workers["remediation_worker"] == remediation_worker

    # verify collector was registered
    assert "remediation_worker" in manager.collector.listeners


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
