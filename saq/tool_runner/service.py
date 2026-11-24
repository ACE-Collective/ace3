"""The ACE service wrapper for the tool runner (docs/TOOL_SANDBOX.md)."""

from pydantic import Field

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_TOOL_RUNNER
from saq.service import ACEServiceInterface
from saq.shutdown import get_shutdown_coordinator
from saq.tool_runner.client import get_socket_path
from saq.tool_runner.server import ToolRunnerServer


class ToolRunnerServiceConfig(ServiceConfig):
    socket_dir: str = Field(..., description="directory of the unix socket every ACE process of the node runs its sandboxed tools through (relative to DATA_DIR)")
    io_timeout: float = Field(..., gt=0, description="how long (in seconds) the runner waits for a client to send its request")


class ToolRunnerService(ACEServiceInterface):

    def __init__(self):
        self.server = ToolRunnerServer(get_socket_path(), get_service_config(SERVICE_TOOL_RUNNER).io_timeout)

    def start(self):
        self.server.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.server.wait_for_start(timeout)

    def start_single_threaded(self):
        # the runs are threads either way: this runs the service in the foreground until a signal
        self.server.start()
        while not get_shutdown_coordinator().wait_for_shutdown(1):
            pass

        self.server.stop()
        # bounded: once stopped, it waits STOP_SECONDS at most
        self.server.wait_until_stopped()

    def stop(self):
        self.server.stop()

    def wait(self):
        # until stop(), and STOP_SECONDS after it; ace service start bounds the call once it has stopped
        self.server.wait_until_stopped()

    @classmethod
    def get_config_class(cls) -> type[ServiceConfig]:
        return ToolRunnerServiceConfig
