import importlib
import logging
import os
from typing import Generator, Optional, Type, override

from saq.analysis.root import Submission
from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.submission_file_manager import SubmissionFileManager
from saq.collectors.hunter.correlation.sources import load_query_sources_from_config
from saq.collectors.hunter.manager import HuntManager
from saq.configuration import get_config
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_HUNTER, ExecutionMode
from saq.environment import get_data_dir
from saq.service import ACEServiceInterface

# the most submissions a single call to HunterCollector.collect() will yield
# bounded so the collection loop keeps coming back around to report status and check
# for shutdown even when the hunt managers are producing faster than we can schedule
MAX_SUBMISSIONS_PER_COLLECTION = 32

# log the depth of the submission queue once it is at least this deep
# a backlog here means the hunt managers are outrunning the (single) collection thread
SUBMISSION_QUEUE_DEPTH_LOG_THRESHOLD = 50

class HunterCollector(Collector):
    """Collector that collects submissions staged by the hunt managers.

    The staging directory is the queue. Hunt managers serialize each submission and atomically
    rename it into place, so anything found here survived whatever killed the previous process."""

    # collect() hands back at most MAX_SUBMISSIONS_PER_COLLECTION of what is staged, so a pass
    # that scheduled work usually leaves more behind and should be followed immediately
    collect_until_empty = True

    def __init__(self, file_manager: Optional[SubmissionFileManager] = None):
        super().__init__()
        # assigned by HunterService once the CollectorService that owns the staging
        # directories has been constructed
        self.file_manager = file_manager

    @override
    def collect(self) -> Generator[Submission, None, None]:
        """Collect submissions the hunt managers have staged.

        Yields up to MAX_SUBMISSIONS_PER_COLLECTION per call so the collection loop keeps coming
        back around to report status and check for shutdown even when the hunt managers are
        producing faster than we can schedule."""
        depth = len(self.file_manager.list_staged_submissions())
        if depth >= SUBMISSION_QUEUE_DEPTH_LOG_THRESHOLD:
            logging.info("hunter submission queue depth is %d", depth)

        yield from self.file_manager.iter_staged_submissions(limit=MAX_SUBMISSIONS_PER_COLLECTION)

class HunterServiceConfig(CollectorServiceConfiguration):
    """Hunter adds nothing to the base collector service config. Note that how often each hunt type
    reloads its rules comes from hunt_type_NAME.update_frequency, not from here."""

class HunterService(ACEServiceInterface):
    """Service that hosts and manages detection hunts for ACE."""
    def __init__(self):
        self.collector = HunterCollector()
        self.collector_service = CollectorService(self.collector, config=get_service_config(SERVICE_HUNTER))

        # the collector service owns the staging directories. the hunt managers stage into them
        # and the collector reads them back out, so both sides share one SubmissionFileManager
        self.collector.file_manager = self.collector_service.file_manager
        self.hunt_managers: dict[str, HuntManager] = {} # key = hunt_type, value = HuntManager

    @override
    def start(self):
        self.load_hunt_managers()
        self.start_hunt_managers()
        self.collector_service.start()

    @override
    def wait_for_start(self, timeout: float = 5) -> bool:
        for manager in self.hunt_managers.values():
            if not manager.wait_for_startup(timeout):
                return False

        if not self.collector_service.wait_for_start(timeout):
            return False

        return True

    @override
    def start_single_threaded(self):
        self.load_hunt_managers(execution_mode=ExecutionMode.SINGLE_SHOT)
        for manager in self.hunt_managers.values():
            manager.start_single_threaded()

        self.collector_service.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    @override
    def stop(self):
        self.stop_hunt_managers()
        self.collector_service.stop()

    @override
    def wait(self):
        for manager in self.hunt_managers.values():
            manager.wait()

        self.collector_service.wait()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return HunterServiceConfig

    def hunt_managers_loaded(self) -> bool:
        """Returns True if the hunt managers have been loaded, False otherwise."""
        return len(self.hunt_managers) > 0

    def add_hunt_manager(self, hunt_manager: HuntManager):
        """Adds a hunt manager to the service."""
        if hunt_manager.hunt_type in self.hunt_managers:
            raise RuntimeError(f"hunt manager {hunt_manager} already exists for hunt type {hunt_manager.hunt_type}")

        self.hunt_managers[hunt_manager.hunt_type] = hunt_manager

    def load_hunt_managers(self, execution_mode: ExecutionMode = ExecutionMode.CONTINUOUS):
        """Loads all configured hunt managers."""
        logging.info("loading hunt managers")

        load_query_sources_from_config()

        for hunt_type_config in get_config().hunt_types:

            # A non-schedulable type legitimately has no rule_dirs — its manager exists only so the
            # validation API can load a submitted hunt through it. HuntTypeConfig already rejects
            # the other three combinations.
            if hunt_type_config.schedulable and not hunt_type_config.rule_dirs:
                logging.error(f"config section {hunt_type_config.name} does not define rule_dirs")
                continue

            hunt_type = hunt_type_config.name

            # make sure the class definition for this hunt is valid
            module_name = hunt_type_config.python_module
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error(f"unable to import hunt module {module_name}: {e}")
                continue

            class_name = hunt_type_config.python_class
            try:
                class_definition = getattr(_module, class_name)
            except AttributeError:
                logging.error("class {} does not exist in module {} in hunt {} config".format(
                              class_name, module_name, hunt_type))
                continue

            logging.debug(f"loading hunt manager for {hunt_type} class {class_definition}")
            self.add_hunt_manager(
                HuntManager(file_manager=self.collector_service.file_manager,
                            hunt_type=hunt_type, 
                            rule_dirs=hunt_type_config.rule_dirs,
                            hunt_cls=class_definition,
                            concurrency_limit=hunt_type_config.concurrency_limit,
                            persistence_dir=os.path.join(get_data_dir(), get_config().collection.persistence_dir),
                            update_frequency=hunt_type_config.update_frequency,
                            config = hunt_type_config,
                            execution_mode=execution_mode))

        if not self.hunt_managers_loaded():
            logging.error("no hunt managers configured")
        else:
            logging.info(f"loaded {len(self.hunt_managers)} hunt managers")

    def start_hunt_managers(self):
        """Starts the hunt managers."""
        logging.info("starting hunt managers")
        for manager in self.hunt_managers.values():
            manager.start()

    def stop_hunt_managers(self):
        """Stops the hunt managers."""
        logging.info("stopping hunt managers")
        for manager in self.hunt_managers.values():
            manager.stop()