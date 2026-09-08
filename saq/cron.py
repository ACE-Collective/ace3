import asyncio
import signal
from typing import Type

from pydantic import Field
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_CRON
from saq.service import ACEServiceInterface
from saq.shutdown import get_shutdown_coordinator

from yacron.cron import Cron

class ACECronConfig(ServiceConfig):
    cron_config_path: str = Field(..., description="the path to the cron configuration file")


async def _run_cron(cron: Cron):
    # add_signal_handler requires the running loop, and only works on the main thread.
    #
    # these replace the ShutdownCoordinator's handlers for as long as cron is running, so
    # without the wrapper below the coordinator would not learn about the signal until
    # cron.run() had already returned. that matters because yacron shuts down "after
    # currently running jobs finish" -- an unbounded wait that nothing was timing. telling
    # the coordinator first arms its watchdog, so a long-running job can no longer hold
    # the container past its stop grace period.
    loop = asyncio.get_running_loop()

    def _handle_shutdown_signal():
        get_shutdown_coordinator().request_shutdown("received shutdown signal")
        cron.signal_shutdown()

    loop.add_signal_handler(signal.SIGINT, _handle_shutdown_signal)
    loop.add_signal_handler(signal.SIGTERM, _handle_shutdown_signal)
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