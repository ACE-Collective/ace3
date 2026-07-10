import asyncio
import signal
from typing import Type

from pydantic import Field
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_CRON
from saq.service import ACEServiceInterface

from yacron.cron import Cron

class ACECronConfig(ServiceConfig):
    cron_config_path: str = Field(..., description="the path to the cron configuration file")


async def _run_cron(cron: Cron):
    # add_signal_handler requires the running loop, and only works on the main thread
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, cron.signal_shutdown)
    loop.add_signal_handler(signal.SIGTERM, cron.signal_shutdown)
    try:
        await cron.run()
    finally:
        loop.remove_signal_handler(signal.SIGINT)
        loop.remove_signal_handler(signal.SIGTERM)


class ACECronService(ACEServiceInterface):
    def start(self):
        cron = Cron(get_service_config(SERVICE_CRON).cron_config_path)
        asyncio.run(_run_cron(cron))

    def wait_for_start(self, timeout: float = 5) -> bool:
        return True

    def start_single_threaded(self):
        return self.start()

    def stop(self):
        pass

    def wait(self):
        pass

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ACECronConfig