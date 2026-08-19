import importlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from saq.remediation.external.types import ProbeOutcome, ProbeTarget

if TYPE_CHECKING:
    from saq.configuration.schema import ExternalRemediationProbeConfig


class ExternalRemediationProbe(ABC):
    """Vendor-specific class that, given a target observable, asks an external
    system whether it has remediated that target.

    Concrete subclasses live in integration repos. The polling loop,
    locking, persistence, and timeline integration all sit in
    core ACE and treat probes as opaque ``probe(target)`` callables.
    """

    def __init__(self, config: "ExternalRemediationProbeConfig"):
        self.config = config

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def observable_type(self) -> str:
        """The observable type a row must carry for this probe to handle it."""
        return self.config.observable_type

    @property
    def initial_delay_seconds(self) -> int:
        return self.config.initial_delay_seconds

    @property
    def max_delay_seconds(self) -> int:
        return self.config.max_delay_seconds

    @property
    def max_retries(self) -> int:
        return self.config.max_retries

    @property
    def deadline_seconds(self) -> int:
        return self.config.deadline_seconds

    @property
    def supersede_grace_seconds(self) -> int:
        # getattr so minimal test-double configs don't have to declare it
        return getattr(self.config, "supersede_grace_seconds", 43200)

    @property
    def thread_count(self) -> int:
        return self.config.thread_count

    @abstractmethod
    def probe(self, target: ProbeTarget) -> ProbeOutcome:
        """One attempt to determine whether the external system has remediated
        ``target``. Implementations should be idempotent and side-effect-free
        against the external system (read-only queries only)."""
        ...


def load_probe_from_config(config: "ExternalRemediationProbeConfig") -> ExternalRemediationProbe:
    """Instantiate the probe class referenced by ``config.python_module`` /
    ``python_class``. Mirrors :func:`load_file_collector_from_config`."""
    module = importlib.import_module(config.python_module)
    cls = getattr(module, config.python_class)
    return cls(config)


def get_probe_by_name(name: str) -> ExternalRemediationProbe:
    """Instantiate the probe registered under ``name`` in the ACE config.

    Used by analysis modules that want to run a probe synchronously (e.g. as
    the first attempt before a background poll takes over). Raises
    ``ValueError`` when ``name`` isn't registered."""
    from saq.configuration import get_config
    return load_probe_from_config(get_config().get_external_remediation_probe_config(name))
