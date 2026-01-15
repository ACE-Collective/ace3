import importlib
import logging
import os
from queue import Empty, Queue
from typing import Generator, Type, override

from pydantic import Field


from saq.analysis.root import Submission
from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.hunter.manager import HuntManager
from saq.configuration import get_config
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_HUNTER, ExecutionMode
from saq.environment import get_data_dir
from saq.service import ACEServiceInterface

class HunterCollector(Collector):
    """Collector that collects submissions from the hunt managers."""
    def __init__(self, submission_queue: Queue):
        super().__init__()
        self.submission_queue = submission_queue

    @override
    def collect(self) -> Generator[Submission, None, None]:
        """Collect submissions from the hunt managers."""
        try:
            yield self.submission_queue.get(block=True, timeout=1)
        except Empty:
            pass

class HunterServiceConfig(CollectorServiceConfiguration):
    update_frequency: int = Field(..., description="The frequency in seconds between updates of the hunt managers.")

class HunterService(ACEServiceInterface):
    """Service that hosts and manages detection hunts for ACE."""
    def __init__(self):
        self.submission_queue = Queue()
        self.collector = HunterCollector(self.submission_queue)
        self.collector_service = CollectorService(self.collector, config=get_service_config(SERVICE_HUNTER))
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

        for hunt_type_config in get_config().hunt_types:

            if not hunt_type_config.rule_dirs:
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
                HuntManager(submission_queue=self.submission_queue,
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