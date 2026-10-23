
from typing import Type
from pydantic import Field
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_REMEDIATION
from saq.remediation.manager import RemediationManager
from saq.service import ACEServiceInterface


class RemediationServiceConfig(ServiceConfig):
    lock_timeout_seconds: int = Field(..., description="the lock timeout in seconds for the remediation service")
    delay_time_seconds: int = Field(..., description="the delay time in seconds for the remediation service")

class RemediationService(ACEServiceInterface):
    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return RemediationServiceConfig

    def _create_manager(self) -> RemediationManager:
        config = get_service_config(SERVICE_REMEDIATION)
        return RemediationManager(lock_timeout_seconds=config.lock_timeout_seconds, delay_time_seconds=config.delay_time_seconds)

    def start(self):
        self.manager = self._create_manager()
        self.manager.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout)
    
    def start_single_threaded(self):
        self.manager = self._create_manager()
        self.manager.start_single_threaded()

    def stop(self):
        self.manager.stop()
    
    def wait(self):
        self.manager.wait()
