"""service_svs's configuration (saq.svs.service). Kept apart from the service so the configuration
loader can check it when the configuration is read, in every process, without importing the
service: a lease a heartbeat can't keep is refused then, not only when service_svs starts."""

from pydantic import Field, model_validator

from saq.configuration.schema import ServiceConfig
from saq.sandbox.runner import LAUNCHER_STOP_SECONDS

# what a stopping worker needs beyond the sandbox launcher's own stop: release its claim
SHUTDOWN_MARGIN_SECONDS = 5


class SVSServiceConfig(ServiceConfig):
    poll_interval_seconds: float = Field(default=5, gt=0, description="how long an idle worker waits before it looks for a queued validation again")
    heartbeat_interval_seconds: int = Field(default=30, gt=0, description="how often a worker running a validation renews its lease")
    lease_seconds: int = Field(default=300, gt=0, description="how long a lease lasts without a heartbeat; after that another worker may take the validation over")
    max_attempts: int = Field(default=3, ge=1, description="how many times a validation is claimed before one whose worker stopped heartbeating is failed instead")

    @model_validator(mode="after")
    def _timings_fit(self) -> "SVSServiceConfig":
        if self.heartbeat_interval_seconds * 3 > self.lease_seconds:
            raise ValueError(
                f"heartbeat_interval_seconds ({self.heartbeat_interval_seconds}) times 3 must not exceed "
                f"lease_seconds ({self.lease_seconds}): one late heartbeat must not lose the lease")

        if self.shutdown_deadline_seconds < LAUNCHER_STOP_SECONDS + SHUTDOWN_MARGIN_SECONDS:
            raise ValueError(
                f"shutdown_deadline_seconds ({self.shutdown_deadline_seconds}) must be at least "
                f"{LAUNCHER_STOP_SECONDS + SHUTDOWN_MARGIN_SECONDS}: a stopping worker cancels its scan "
                "and releases its validation")
        return self
