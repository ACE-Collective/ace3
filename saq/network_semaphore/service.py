from typing import Type
from saq.configuration.schema import ServiceConfig
from saq.network_semaphore.config import NetworkSemaphoreConfig
from saq.network_semaphore.server import NetworkSemaphoreServer
from saq.service import ACEServiceInterface


class NetworkSemaphoreService(ACEServiceInterface):
    def __init__(self):
        self.server = NetworkSemaphoreServer()

    def start(self):
        self.server.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.server.wait_for_start(timeout)

    def start_single_threaded(self):
        raise NotImplementedError("NetworkSemaphoreService does not support single threaded mode")

    def stop(self):
        self.server.stop()

    def wait(self):
        self.server.wait()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return NetworkSemaphoreConfig