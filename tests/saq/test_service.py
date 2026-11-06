import pytest

from saq.configuration.config import get_config
from saq.configuration.schema import ServiceConfig
from saq.constants import (
    INSTANCE_TYPE_PRODUCTION,
    INSTANCE_TYPE_UNITTEST,
)
from saq.service import (
    ACEServiceInterface,
    DisabledService,
    load_service_by_name,
    service_valid_for_instance,
)


class MockService(ACEServiceInterface):
    """Mock service for testing."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.waited = False

    def start(self):
        self.started = True

    def wait_for_start(self, timeout: float = 5) -> bool:
        return True

    def start_single_threaded(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def wait(self):
        self.waited = True


@pytest.mark.unit
class TestServiceValidForInstance:
    """Tests for service_valid_for_instance function."""

    def test_service_valid_no_instance_types_configured(self):
        """test that service is valid when no instance types are configured"""
        get_config().add_service_config("test_service", ServiceConfig(
            name="test_service", 
            description="test service",
            enabled=True,
            python_module="test.module", 
            python_class="TestClass"))

        result = service_valid_for_instance("test_service")
        assert result is True

    def test_service_valid_matching_instance_type_any(self):
        """test that service is valid when instance type matches"""
        get_config().add_service_config("test_service", ServiceConfig(
            name="test_service", 
            description="test service",
            enabled=True,
            python_module="test.module", 
            python_class="TestClass",
            instance_types=["ANY"]))

        result = service_valid_for_instance("test_service")

        assert result is True

    def test_service_valid_matching_instance_type(self):
        """test that service is valid when instance type matches"""
        get_config().add_service_config("test_service", ServiceConfig(
            name="test_service", 
            description="test service",
            enabled=True,
            python_module="test.module", 
            python_class="TestClass",
            instance_types=[INSTANCE_TYPE_UNITTEST]))

        result = service_valid_for_instance("test_service")

        assert result is True

    def test_service_invalid_non_matching_instance_type(self):
        """test that service is invalid when instance type does not match"""
        get_config().add_service_config("test_service", ServiceConfig(
            name="test_service", 
            description="test service",
            enabled=True,
            python_module="test.module", 
            python_class="TestClass",
            instance_types=[INSTANCE_TYPE_PRODUCTION]))

        result = service_valid_for_instance("test_service")

        assert result is False

    def test_service_valid_with_multiple_instance_types(self):
        """test that service is valid when one of multiple instance types matches"""
        get_config().add_service_config("test_service", ServiceConfig(
            name="test_service", 
            description="test service",
            enabled=True,
            python_module="test.module", 
            python_class="TestClass",
            instance_types=[INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_UNITTEST]))

        result = service_valid_for_instance("test_service")

        assert result is True

@pytest.mark.unit
class TestLoadServiceByName:
    """Tests for load_service_by_name function."""

    def test_load_service_by_name_success(self):
        """test that load_service_by_name successfully loads a service"""
        config = get_config()
        config.add_service_config("test_service", ServiceConfig(
            name="test_service", 
            description="test service",
            enabled=True,
            python_module="tests.saq.test_service", 
            python_class="MockService"))

        service = load_service_by_name("test_service")

        assert isinstance(service, MockService)

    def test_load_service_by_name_fails_invalid_instance_type(self):
        """test that load_service_by_name fails for invalid instance type"""
        config = get_config()
        config.add_service_config("invalid_service", ServiceConfig(
            name="invalid_service", 
            description="invalid service",
            enabled=True,
            python_module="tests.saq.test_service", 
            python_class="MockService",
            instance_types=[INSTANCE_TYPE_PRODUCTION]))

        assert isinstance(load_service_by_name("invalid_service"), DisabledService)

    def test_load_service_by_name_nonexistent_service(self):
        """test that load_service_by_name raises error for non-existent service"""
        with pytest.raises(ValueError, match="service config for nonexistent_service not found"):
            load_service_by_name("nonexistent_service")

    def test_load_service_by_name_invalid_module(self):
        """test that load_service_by_name raises error when module cannot be loaded"""
        config = get_config()
        config.add_service_config("bad_module", ServiceConfig(
            name="bad_module", 
            description="bad module",
            python_module="invalid.module", 
            python_class="TestClass",
            enabled=True))

        with pytest.raises(ModuleNotFoundError):
            load_service_by_name("bad_module")

    def test_load_service_by_name_invalid_class(self):
        """test that load_service_by_name raises error when class cannot be found"""
        config = get_config()
        config.add_service_config("bad_class", ServiceConfig(
            name="bad_class", 
            description="bad class",
            python_module="tests.saq.test_service", 
            python_class="NonExistentClass",
            enabled=True))

        with pytest.raises(AttributeError):
            load_service_by_name("bad_class")
