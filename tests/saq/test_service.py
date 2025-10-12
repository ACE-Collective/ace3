import pytest

from saq.configuration.config import get_config
from saq.constants import (
    CONFIG_SERVICE_CLASS,
    CONFIG_SERVICE_INSTANCE_TYPES,
    CONFIG_SERVICE_MODULE,
    INSTANCE_TYPE_PRODUCTION,
    INSTANCE_TYPE_UNITTEST,
)
from saq.service import (
    ACEServiceInterface,
    load_service,
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
        config = get_config()
        config.add_section("service_test_service")
        config["service_test_service"][CONFIG_SERVICE_MODULE] = "test.module"
        config["service_test_service"][CONFIG_SERVICE_CLASS] = "TestClass"

        result = service_valid_for_instance("test_service")

        assert result is True

    def test_service_valid_matching_instance_type(self):
        """test that service is valid when instance type matches"""
        config = get_config()
        config.add_section("service_test_service")
        config["service_test_service"][CONFIG_SERVICE_MODULE] = "test.module"
        config["service_test_service"][CONFIG_SERVICE_CLASS] = "TestClass"
        config["service_test_service"][CONFIG_SERVICE_INSTANCE_TYPES] = [INSTANCE_TYPE_UNITTEST]

        result = service_valid_for_instance("test_service")

        assert result is True

    def test_service_invalid_non_matching_instance_type(self):
        """test that service is invalid when instance type does not match"""
        config = get_config()
        config.add_section("service_test_service")
        config["service_test_service"][CONFIG_SERVICE_MODULE] = "test.module"
        config["service_test_service"][CONFIG_SERVICE_CLASS] = "TestClass"
        config["service_test_service"][CONFIG_SERVICE_INSTANCE_TYPES] = [INSTANCE_TYPE_PRODUCTION]

        result = service_valid_for_instance("test_service")

        assert result is False

    def test_service_valid_with_multiple_instance_types(self):
        """test that service is valid when one of multiple instance types matches"""
        config = get_config()
        config.add_section("service_test_service")
        config["service_test_service"][CONFIG_SERVICE_MODULE] = "test.module"
        config["service_test_service"][CONFIG_SERVICE_CLASS] = "TestClass"
        config["service_test_service"][CONFIG_SERVICE_INSTANCE_TYPES] = [INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_UNITTEST]

        result = service_valid_for_instance("test_service")

        assert result is True

    def test_service_valid_raises_error_for_nonexistent_service(self):
        """test that service_valid_for_instance raises error for non-existent service"""
        with pytest.raises(RuntimeError, match="configuration section service_nonexistent_service not found"):
            service_valid_for_instance("nonexistent_service")


@pytest.mark.unit
class TestLoadService:
    """Tests for load_service function."""

    def test_load_service_success(self):
        """test that load_service successfully loads and wraps a service"""
        service = load_service("tests.saq.test_service", "MockService")

        assert service is not None
        assert hasattr(service, "start")
        assert hasattr(service, "stop")
        assert hasattr(service, "wait")
        assert hasattr(service, "wait_for_start")
        assert hasattr(service, "start_single_threaded")

    def test_load_service_adapter_wraps_correctly(self):
        """test that loaded service adapter correctly wraps the underlying service"""
        service = load_service("tests.saq.test_service", "MockService")

        service.start()
        assert service.service.started is True

        service.stop()
        assert service.service.stopped is True

        service.wait()
        assert service.service.waited is True

    def test_load_service_wait_for_start(self):
        """test that wait_for_start works on loaded service"""
        service = load_service("tests.saq.test_service", "MockService")

        result = service.wait_for_start(timeout=1)

        assert result is True

    def test_load_service_invalid_module(self):
        """test that load_service raises error for invalid module"""
        with pytest.raises(ModuleNotFoundError):
            load_service("invalid.module.name", "TestClass")

    def test_load_service_invalid_class(self):
        """test that load_service raises error for invalid class"""
        with pytest.raises(AttributeError):
            load_service("tests.saq.test_service", "NonExistentClass")


@pytest.mark.unit
class TestLoadServiceByName:
    """Tests for load_service_by_name function."""

    def test_load_service_by_name_success(self):
        """test that load_service_by_name successfully loads a service"""
        config = get_config()
        config.add_section("service_test_service")
        config["service_test_service"][CONFIG_SERVICE_MODULE] = "tests.saq.test_service"
        config["service_test_service"][CONFIG_SERVICE_CLASS] = "MockService"

        service = load_service_by_name("test_service")

        assert service is not None
        assert hasattr(service, "start")
        assert hasattr(service, "stop")

    def test_load_service_by_name_with_instance_type_validation(self):
        """test that load_service_by_name validates instance type"""
        config = get_config()
        config.add_section("service_valid_service")
        config["service_valid_service"][CONFIG_SERVICE_MODULE] = "tests.saq.test_service"
        config["service_valid_service"][CONFIG_SERVICE_CLASS] = "MockService"
        config["service_valid_service"][CONFIG_SERVICE_INSTANCE_TYPES] = [INSTANCE_TYPE_UNITTEST]

        service = load_service_by_name("valid_service")

        assert service is not None

    def test_load_service_by_name_fails_invalid_instance_type(self):
        """test that load_service_by_name fails for invalid instance type"""
        config = get_config()
        config.add_section("service_invalid_service")
        config["service_invalid_service"][CONFIG_SERVICE_MODULE] = "tests.saq.test_service"
        config["service_invalid_service"][CONFIG_SERVICE_CLASS] = "MockService"
        config["service_invalid_service"][CONFIG_SERVICE_INSTANCE_TYPES] = [INSTANCE_TYPE_PRODUCTION]

        with pytest.raises(
            RuntimeError, match="service invalid_service is not valid for the current instance type"
        ):
            load_service_by_name("invalid_service")

    def test_load_service_by_name_nonexistent_service(self):
        """test that load_service_by_name raises error for non-existent service"""
        with pytest.raises(RuntimeError, match="configuration section service_nonexistent_service not found"):
            load_service_by_name("nonexistent_service")

    def test_load_service_by_name_invalid_module(self):
        """test that load_service_by_name raises error when module cannot be loaded"""
        config = get_config()
        config.add_section("service_bad_module")
        config["service_bad_module"][CONFIG_SERVICE_MODULE] = "invalid.module"
        config["service_bad_module"][CONFIG_SERVICE_CLASS] = "TestClass"

        with pytest.raises(ModuleNotFoundError):
            load_service_by_name("bad_module")

    def test_load_service_by_name_invalid_class(self):
        """test that load_service_by_name raises error when class cannot be found"""
        config = get_config()
        config.add_section("service_bad_class")
        config["service_bad_class"][CONFIG_SERVICE_MODULE] = "tests.saq.test_service"
        config["service_bad_class"][CONFIG_SERVICE_CLASS] = "NonExistentClass"

        with pytest.raises(AttributeError):
            load_service_by_name("bad_class")
