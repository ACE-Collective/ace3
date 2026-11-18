
from typing import Type
from pydantic import Field
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_REMEDIATION
from saq.queue_service import QueueService
from saq.remediation.manager import RemediationManager


class RemediationServiceConfig(ServiceConfig):
    lock_timeout_seconds: int = Field(..., description="the lock timeout in seconds for the remediation service")
    delay_time_seconds: int = Field(..., description="the delay time in seconds for the remediation service")

class RemediationService(QueueService):
    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return RemediationServiceConfig

    def create_manager(self) -> RemediationManager:
        config = get_service_config(SERVICE_REMEDIATION)
        return RemediationManager(lock_timeout_seconds=config.lock_timeout_seconds, delay_time_seconds=config.delay_time_seconds)
