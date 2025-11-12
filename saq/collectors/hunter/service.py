import importlib
import logging
from queue import Empty, Queue
from typing import Generator, override


from saq.analysis.root import Submission
from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.hunter.manager import HuntManager
from saq.configuration import get_config, get_config_value
from saq.constants import CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR, ExecutionMode
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

class HunterService(ACEServiceInterface):
    """Service that hosts and manages detection hunts for ACE."""
    def __init__(self):
        self.submission_queue = Queue()
        self.collector = HunterCollector(self.submission_queue)
        self.collector_service = CollectorService(self.collector, config=CollectorServiceConfiguration.from_config(get_config()['service_hunter']))
        self.hunt_managers = {} # key = hunt_type, value = HuntManager

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

        for section_name in get_config().sections():
            if not section_name.startswith('hunt_type_'):
                continue

            section = get_config()[section_name]

            if 'rule_dirs' not in section:
                logging.error(f"config section {section} does not define rule_dirs")
                continue

            hunt_type = section_name[len('hunt_type_'):]

            # make sure the class definition for this hunt is valid
            module_name = section['module']
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error(f"unable to import hunt module {module_name}: {e}")
                continue

            class_name = section['class']
            try:
                class_definition = getattr(_module, class_name)
            except AttributeError:
                logging.error("class {} does not exist in module {} in hunt {} config".format(
                              class_name, module_name, section))
                continue

            logging.debug(f"loading hunt manager for {hunt_type} class {class_definition}")
            self.add_hunt_manager(
                HuntManager(submission_queue=self.submission_queue,
                            hunt_type=hunt_type, 
                            rule_dirs=[_.strip() for _ in section['rule_dirs'].split(',')],
                            hunt_cls=class_definition,
                            concurrency_limit=section.get('concurrency_limit', fallback=None),
                            persistence_dir=get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR),
                            update_frequency=section.getint('update_frequency', fallback=60),
                            config = section,
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