import importlib
from typing import Optional, Protocol


from saq.configuration.config import get_config, get_config_value, get_config_value_as_list
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_TYPE, CONFIG_SERVICE_CLASS, CONFIG_SERVICE_INSTANCE_TYPES, CONFIG_SERVICE_MODULE

class ACEServiceInterface(Protocol):
    def start(self):
        ...

    def wait_for_start(self, timeout: float = 5) -> bool:
        ...

    def start_single_threaded(self):
        ...

    def stop(self):
        ...

    def wait(self):
        ...

class ACEServiceAdapter(ACEServiceInterface):
    def __init__(self, service: ACEServiceInterface):
        self.service = service
        
    def start(self):
        self.service.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.service.wait_for_start(timeout)

    def start_single_threaded(self):
        self.service.start_single_threaded()

    def stop(self):
        self.service.stop()

    def wait(self):
        self.service.wait()

def _get_service_section_name(service_name: str) -> str:
    return f"service_{service_name}"

def service_valid_for_instance(name: str) -> bool:
    """Returns True if the service (specified by name) is valud for the current instance type.
    NOTE if the service does not have any instance types configured, then it is valid for all instance types."""

    service_section_name = _get_service_section_name(name)
    if service_section_name not in get_config():
        raise RuntimeError(f"configuration section {service_section_name} not found")

    instance_type = get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_TYPE)
    if instance_type is None:
        raise RuntimeError("missing instance type is global config?")

    valid_service_instance_types = get_config_value_as_list(service_section_name, CONFIG_SERVICE_INSTANCE_TYPES)
    if not valid_service_instance_types:
        return True

    return instance_type in valid_service_instance_types
        
def load_service(_module: str, _class: str) -> ACEServiceInterface:
    module = importlib.import_module(_module)
    class_definition = getattr(module, _class)
    return ACEServiceAdapter(class_definition())

def load_service_by_name(name: str) -> ACEServiceInterface:
    service_section_name = _get_service_section_name(name)
    if service_section_name not in get_config():
        raise RuntimeError(f"configuration section {service_section_name} not found")

    if not service_valid_for_instance(name):
        raise RuntimeError(f"service {name} is not valid for the current instance type")

    return load_service(get_config_value(service_section_name, CONFIG_SERVICE_MODULE), get_config_value(service_section_name, CONFIG_SERVICE_CLASS))
