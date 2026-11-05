import pytest

from saq.configuration.schema import RemediatorConfig
from saq.remediation.remediator import load_remediator_from_config
from saq.remediation.types import RemediationAction, RemediationWorkItem, RemediatorResult, RemediatorStatus
from tests.saq.remediation.test_remediator import TestRemediator

pytestmark = pytest.mark.unit


class TestRemediatorClass:
    """Tests for the Remediator class properties and methods."""

    def test_remediate_remove_action(self):
        """Test remediate method with REMOVE action calls remove method."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)
        work_item = RemediationWorkItem(
            id=1,
            action=RemediationAction.REMOVE,
            name="test_remediator",
            type="ipv4",
            key="192.168.1.1",
        )

        result = remediator.remediate(work_item)

        assert isinstance(result, RemediatorResult)
        assert result.status == RemediatorStatus.SUCCESS
        assert result.message == "TestRemediator.remove"
        assert result.restore_key == "restore_key"

    def test_remediate_restore_action(self):
        """Test remediate method with RESTORE action calls restore method."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)
        work_item = RemediationWorkItem(
            id=1,
            action=RemediationAction.RESTORE,
            name="test_remediator",
            type="ipv4",
            key="192.168.1.1",
            restore_key="restore_key",
        )

        result = remediator.remediate(work_item)

        assert isinstance(result, RemediatorResult)
        assert result.status == RemediatorStatus.SUCCESS
        assert result.message == "TestRemediator.restore"
        assert result.restore_key is None

    def test_remediate_invalid_action(self):
        """Test remediate method with invalid action raises ValueError."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)
        # Create a work item with an invalid action by manually setting it
        work_item = RemediationWorkItem(
            id=1,
            action=RemediationAction.REMOVE,
            name="test_remediator",
            type="ipv4",
            key="192.168.1.1",
        )
        # Manually override the action to something invalid
        work_item.action = "invalid_action"

        with pytest.raises(ValueError, match="invalid action"):
            remediator.remediate(work_item)


class TestLoadRemediatorFromConfig:
    """Tests for the load_remediator_from_config function."""

    def test_load_valid_remediator(self):
        """Test loading a valid remediator from config."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = load_remediator_from_config(config)

        assert remediator is not None
        assert remediator.name == "test_remediator"
        assert remediator.observable_type == "ipv4"
        assert remediator.config == config

    def test_load_remediator_invalid_module(self):
        """Test loading a remediator with an invalid module raises ModuleNotFoundError."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.nonexistent_module",
            python_class="TestRemediator",
        )

        with pytest.raises(ModuleNotFoundError):
            load_remediator_from_config(config)

    def test_load_remediator_invalid_class(self):
        """Test loading a remediator with an invalid class raises AttributeError."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="NonexistentClass",
        )

        with pytest.raises(AttributeError):
            load_remediator_from_config(config)
