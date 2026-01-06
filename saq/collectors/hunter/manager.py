import logging
import os
import os.path
from queue import Queue
import threading


from saq.configuration.config import get_config
from saq.configuration.schema import HuntTypeConfig
from saq.constants import ExecutionMode
from saq.error import report_exception
from saq.network_semaphore import NetworkSemaphoreClient
from saq.util import local_time, abs_path
from saq.util.hashing import sha256
from saq.collectors.hunter.base_hunter import Hunt, InvalidHuntTypeError

CONCURRENCY_TYPE_NETWORK_SEMAPHORE = 'network_semaphore'
CONCURRENCY_TYPE_LOCAL_SEMAPHORE = 'local_semaphore'

class HuntManager:
    """Manages the hunting for a single hunt type."""
    def __init__(self,
                 submission_queue,
                 hunt_type,
                 rule_dirs,
                 hunt_cls,
                 concurrency_limit,
                 persistence_dir,
                 update_frequency,
                 config: HuntTypeConfig,
                 execution_mode: ExecutionMode = ExecutionMode.CONTINUOUS):

        assert isinstance(submission_queue, Queue)
        assert isinstance(hunt_type, str)
        assert isinstance(rule_dirs, list)
        assert issubclass(hunt_cls, Hunt)
        assert concurrency_limit is None or isinstance(concurrency_limit, int) or isinstance(concurrency_limit, str)
        assert isinstance(persistence_dir, str)
        assert isinstance(update_frequency, int)
        assert isinstance(execution_mode, ExecutionMode)

        # reference to the submission queue (used to send the Submission objects)
        self.submission_queue = submission_queue

        # primary execution thread
        self.manager_thread = None

        # event that is set when the manager thread has started
        self.manager_startup_event = threading.Event()

        # thread that handles tracking changes made to the hunts loaded from yaml
        self.update_manager_thread = None

        # event that is set when the update manager thread has started
        self.update_manager_startup_event = threading.Event()

        # shutdown valve
        self.manager_control_event = threading.Event()
        self.wait_control_event = threading.Event()

        # control signal to reload the hunts (set by SIGHUP indirectly)
        self.reload_hunts_flag = False

        # the type of hunting this manager manages
        self.hunt_type = hunt_type

        # the list of directories that contain the hunt configuration yaml files for this type of hunt
        self.rule_dirs = rule_dirs

        # the class used to instantiate the rules in the given rules directories
        self.hunt_cls = hunt_cls
        
        # when loaded from config, store the entire config so it available to Hunts
        self.config = config

        # the list of Hunt objects that are being managed
        self._hunts: list[Hunt] = []

        # acquire this lock before making any modifications to the hunts
        self.hunt_lock = threading.RLock()

        # the yaml files that failed to load
        self.failed_yaml_files = {} # key = yaml_path, value = (os.path.getmtime(), os.path.getsize(), sha256 of file content)

        # the yaml files that we skipped
        self.skipped_yaml_files = set() # key = yaml_path

        # the type of concurrency contraint this type of hunt uses (can be None)
        # use the set_concurrency_limit() function to change it
        self.concurrency_type = None

        # the local threading.Semaphore if the type is CONCURRENCY_TYPE_LOCAL_SEMAPHORE
        # or the string name of the network semaphore if tye type is CONCURRENCY_TYPE_NETWORK_SEMAPHORE
        self.concurrency_semaphore = None

        if concurrency_limit is not None:
            self.set_concurrency_limit(concurrency_limit)

        # this is set to True if load_hunts_from_config() is called
        # and used when reload_hunts_flag is set
        self.hunts_loaded_from_config = False

        # how often do we check to see if the hunts have been modified?
        self.update_frequency = update_frequency

        # controls how hunts are executed
        self.execution_mode = execution_mode

        # so we don't spam the logs with the same message over and over
        self.last_hunt_status_message = None

    def __str__(self):
        return f"Hunt Manager({self.hunt_type})"

    @property
    def hunts(self):
        """Returns a sorted copy of the list of hunts in execution order."""
        return sorted([_ for _ in self._hunts], key=lambda x: x.next_execution_time or local_time())

    def get_hunts(self, spec):
        """Returns the hunts that match the given specification, where spec is a function that takes a Hunt
           as it's single parameter and return True or False if it should be included in the results."""
        return [hunt for hunt in self._hunts if spec(hunt)]

    def get_hunt(self, spec):
        """Returns the first hunt that matches the given specification, where spec is a function that takes a Hunt
          as it's single parameter and return True or False if it should be included in the results.
          Returns None if no hunts are matched."""
        result = self.get_hunts(spec)
        if not result:
            return None

        return result[0]

    def get_hunt_by_name(self, name):
        """Returns the Hunt with the given name, or None if the hunt does not exist."""
        for hunt in self._hunts:
            if hunt.name == name:
                return hunt

        return None

    def is_valid_instance_type(self, hunt: Hunt) -> bool:
        """Returns True if the given hunt is valid for the current instance type (ignoring case)."""
        instance_type = get_config().global_settings.instance_type
        return (
            any(instance_type.lower() == t.lower() for t in hunt.instance_types)
        )

    def signal_reload(self):
        """Signals to this manager that the hunts should be reloaded.
           The work takes place on the manager thread."""
        logging.debug("received signal to reload hunts")
        self.reload_hunts_flag = True
        self.wait_control_event.set()

    def reload_hunts(self):
        """Reloads the hunts. This is called when reload_hunts_flag is set to True.
           If the hunts were loaded from the configuration then the current Hunt objects
           are discarded and new ones are loaded from configuration.
           Otherwise this function does nothing."""

        self.reload_hunts_flag = False
        if not self.hunts_loaded_from_config:
            logging.debug(f"{self} received signal to reload but hunts were not loaded from configuration")
            return

        logging.info(f"{self} reloading hunts")

        # first cancel any currently executing hunts
        self.cancel_hunts()
        self.clear_hunts()
        self.load_hunts_from_config()

    def start(self):
        if self.execution_mode == ExecutionMode.CONTINUOUS:
            self.start_multi_threaded()
        else:
            self.start_single_threaded()

    def start_multi_threaded(self):
        self.manager_control_event.clear()
        self.load_hunts_from_config()
        self.manager_thread = threading.Thread(target=self.loop, name=f"Hunt Manager {self.hunt_type}")
        self.manager_thread.start()
        self.update_manager_thread = threading.Thread(target=self.update_loop, 
                                                      name=f"Hunt Manager Updater {self.hunt_type}")
        self.update_manager_thread.start()

    def wait_for_startup(self, timeout: float = 5) -> bool:
        """Waits for the hunt manager to start up.
           Returns True if the hunt manager started up, False if it did not."""
        if not self.manager_startup_event.wait(timeout):
            return False

        if not self.update_manager_startup_event.wait(timeout):
            return False

        return True

    def start_single_threaded(self):
        logging.info(f"starting {self} in single threaded mode")
        self.manager_control_event.clear()
        self.load_hunts_from_config()
        self.execute()

    def stop(self):
        logging.info(f"stopping {self}")
        self.manager_control_event.set()
        self.wait_control_event.set()

        for hunt in self.hunts:
            try:
                hunt.cancel()
            except Exception:
                logging.error("unable to cancel hunt {hunt}: {e}")
                report_exception()

    def wait(self, *args, **kwargs):
        self.manager_control_event.wait(*args, **kwargs)
        for hunt in self._hunts:
            hunt.wait(*args, **kwargs)

        if self.manager_thread:
            self.manager_thread.join()

        if self.update_manager_thread:
            self.update_manager_thread.join()

    def update_loop(self):
        logging.info(f"started update manager for {self}")
        self.update_manager_startup_event.set()
        while not self.manager_control_event.is_set():
            try:
                self.manager_control_event.wait(timeout=self.update_frequency)
                if not self.manager_control_event.is_set():
                    self.check_hunts()
            except Exception as e:
                logging.error(f"uncaught exception {e}")
                report_exception()

        logging.info(f"stopped update manager for {self}")

    def check_hunts(self):
        """Checks to see if any existing hunts have been modified, created or deleted."""
        logging.debug("checking for hunt modifications")
        trigger_reload = False
        with self.hunt_lock:
            # have any hunts been modified?
            for hunt in self._hunts:
                if hunt.is_modified:
                    logging.info(f"detected modification to {hunt}")
                    trigger_reload = True

            # if any hunts failed to load last time, check to see if they were modified
            for ini_path, (mtime, file_size, sha256_hash) in self.failed_yaml_files.items():
                try:
                    # go from easiest computation to most expensive
                    if os.path.getmtime(ini_path) != mtime:
                        logging.info(f"detected modification (by mtime) to failed ini file {ini_path}")
                        trigger_reload = True
                    elif os.path.getsize(ini_path) != file_size:
                        logging.info(f"detected modification (by size) to failed ini file {ini_path}")
                        trigger_reload = True
                    elif sha256(ini_path) != sha256_hash:
                        logging.info(f"detected modification (by hash) to failed ini file {ini_path}")
                        trigger_reload = True
                except Exception as e:
                    logging.error(f"unable to check failed ini file {ini_path}: {e}")

            # are there any new hunts?
            existing_yaml_paths = set([hunt.file_path for hunt in self._hunts])
            for yaml_path in self._list_hunt_yaml():
                if ( yaml_path not in existing_yaml_paths 
                        and yaml_path not in self.failed_yaml_files
                        and yaml_path not in self.skipped_yaml_files ):
                    logging.info(f"detected new hunt yaml {yaml_path}")
                    trigger_reload = True

        if trigger_reload:
            self.signal_reload()

    def loop(self):
        logging.debug(f"started {self}")
        self.manager_startup_event.set()
        while not self.manager_control_event.is_set():
            try:
                self.execute()
                self.wait_control_event.wait(1.0)
                self.wait_control_event.clear()
            except Exception as e:
                logging.error(f"uncaught exception {e}")
                report_exception()
                self.manager_control_event.wait(timeout=1)

            if self.reload_hunts_flag:
                self.reload_hunts()

        logging.debug(f"stopped {self}")

    def execute(self):
        # the next one to run should be the first in our list
        disabled_count = 0
        invalid_instance_type_count = 0
        suppressed_count = 0
        running_count = 0
        ready_count = 0
        idle_count = 0

        for hunt in self.hunts:
            if not hunt.enabled:
                disabled_count += 1
                continue

            if not self.is_valid_instance_type(hunt):
                invalid_instance_type_count += 1
                continue

            if hunt.suppressed:
                suppressed_count += 1
                continue

            if hunt.running:
                running_count += 1
                continue

            if hunt.ready:
                ready_count += 1
                self.execute_hunt(hunt)
            else:
                idle_count += 1

        hunt_status_message = f"hunt status: ({disabled_count} disabled) ({invalid_instance_type_count} invalid instance type) ({suppressed_count} suppressed) ({running_count} running) ({ready_count} ready) ({idle_count} idle)"
        if hunt_status_message != self.last_hunt_status_message:
            logging.info(hunt_status_message)
            self.last_hunt_status_message = hunt_status_message

    def execute_hunt(self, hunt):
        # are we ready to run another one of these types of hunts?
        # NOTE this will BLOCK until a semaphore is ready OR this manager is shutting down
        start_time = local_time()
        hunt.semaphore = self.acquire_concurrency_lock()

        if self.manager_control_event.is_set():
            if hunt.semaphore is not None:
                hunt.semaphore.release()
            return

        # keep track of how long it's taking to acquire the resource
        if hunt.semaphore is not None:
            self.record_semaphore_acquire_time(local_time() - start_time)

        # if we're in single shot mode then execute the hunt on the current thread
        if self.execution_mode == ExecutionMode.SINGLE_SHOT:
            self.execute_threaded_hunt(hunt)
            return

        # otherwise we start the execution of the hunt on a new thread
        hunt.execution_thread = threading.Thread(target=self.execute_threaded_hunt, 
                                                 args=(hunt,),
                                                 name=f"Hunt Execution {hunt}")
        hunt.execution_thread.start()

        # wait for the signal that the hunt has started
        # this will block for a short time to ensure we don't wrap back around before the 
        # execution lock is acquired
        hunt.startup_barrier.wait()

    def execute_threaded_hunt(self, hunt):
        try:
            submissions = hunt.execute_with_lock(execution_mode=self.execution_mode)
            if submissions:
                hunt.last_alert_time = local_time()
        except Exception as e:
            logging.error(f"uncaught exception: {e}")
            report_exception()
        finally:
            self.release_concurrency_lock(hunt.semaphore)
            # at this point this hunt has finished and is eligible to execute again
            self.wait_control_event.set()

        if submissions is not None:
            for submission in submissions:
                self.submission_queue.put(submission)

    def cancel_hunts(self):
        """Cancels all the currently executing hunts."""
        for hunt in self._hunts: # order doesn't matter here
            try:
                if hunt.running:
                    logging.info(f"cancelling {hunt}")
                    hunt.cancel()
                    hunt.wait()
            except Exception:
                logging.info(f"unable to cancel {hunt}: {e}")

    def set_concurrency_limit(self, limit):
        """Sets the concurrency limit for this type of hunt.
           If limit is a string then it's considered to be the name of a network semaphore.
           If limit is an integer then a local threading.Semaphore is used."""
        try:
            # if the limit value is an integer then it's a local semaphore
            self.concurrency_type = CONCURRENCY_TYPE_LOCAL_SEMAPHORE
            self.concurrency_semaphore = threading.Semaphore(int(limit))
            logging.debug(f"concurrency limit for {self.hunt_type} set to local limit {limit}")
        except ValueError:
            # otherwise it's the name of a network semaphore
            self.concurrency_type = CONCURRENCY_TYPE_NETWORK_SEMAPHORE
            self.concurrency_semaphore = limit
            logging.debug(f"concurrency limit for {self.hunt_type} set to "
                          f"network semaphore {self.concurrency_semaphore}")

    def acquire_concurrency_lock(self):
        """Acquires a concurrency lock for this type of hunt if specified in the configuration for the hunt.
           Returns a NetworkSemaphoreClient object if the concurrency_type is CONCURRENCY_TYPE_NETWORK_SEMAPHORE
           or a reference to the threading.Semaphore object if concurrency_type is CONCURRENCY_TYPE_LOCAL_SEMAPHORE.
           Immediately returns None if non concurrency limits are in place for this type of hunt."""

        if self.concurrency_type is None:
            return None

        result = None
        start_time = local_time()
        if self.concurrency_type == CONCURRENCY_TYPE_NETWORK_SEMAPHORE:
            logging.debug(f"acquiring network concurrency semaphore {self.concurrency_semaphore} "
                          f"for hunt type {self.hunt_type}")
            result = NetworkSemaphoreClient(cancel_request_callback=self.manager_control_event.is_set)
                                                                # make sure we cancel outstanding request 
                                                                # when shutting down
            result.acquire(self.concurrency_semaphore)
        else:
            logging.debug(f"acquiring local concurrency semaphore for hunt type {self.hunt_type}")
            while not self.manager_control_event.is_set():
                if self.concurrency_semaphore.acquire(blocking=True, timeout=0.1):
                    result = self.concurrency_semaphore
                    break

        if result is not None:
            total_seconds = (local_time() - start_time).total_seconds()
            logging.debug(f"acquired concurrency semaphore for hunt type {self.hunt_type} in {total_seconds} seconds")

        return result

    def release_concurrency_lock(self, semaphore):
        if semaphore is not None:
            # both types of semaphores support this function call
            logging.debug(f"releasing concurrency semaphore for hunt type {self.hunt_type}")
            semaphore.release()

    def load_hunts_from_config(self, hunt_filter=lambda hunt: True):
        """Loads the hunts from the configuration settings.
           Returns True if all of the hunts were loaded correctly, False if any errors occurred.
           The hunt_filter paramter defines an optional lambda function that takes the Hunt object
           after it is loaded and returns True if the Hunt should be added, False otherwise.
           This is useful for unit testing."""
        for hunt_config_file_path in self._list_hunt_yaml():
            try:
                logging.info(f"loading hunt from {hunt_config_file_path}")
                hunt = self.hunt_cls(manager=self, hunt_config_file_path=hunt_config_file_path)

                if hunt_filter(hunt):
                    logging.debug(f"loaded {hunt} from {hunt_config_file_path}")
                    self.add_hunt(hunt)
                else:
                    logging.debug(f"not loading {hunt} (hunt_filter returned False)")

            except InvalidHuntTypeError as e:
                report_exception()
                self.skipped_yaml_files.add(hunt_config_file_path)
                logging.warning(f"skipping {hunt_config_file_path} for {self}: {e}")
                continue
            except Exception as e:
                logging.error(f"unable to load hunt from {hunt_config_file_path}: {e}")
                report_exception()
                try:
                    self.failed_yaml_files[hunt_config_file_path] = (
                        os.path.getmtime(hunt_config_file_path),
                        os.path.getsize(hunt_config_file_path),
                        sha256(hunt_config_file_path)
                    )
                except Exception as e:
                    logging.error(f"unable to get mtime for {hunt_config_file_path}: {e}")

        # remember that we loaded the hunts from the configuration file
        # this is used when we receive the signal to reload the hunts
        self.hunts_loaded_from_config = True

    def add_hunt(self, hunt):
        assert isinstance(hunt, Hunt)
        if hunt.type != self.hunt_type:
            raise ValueError(f"hunt {hunt} has wrong type for {self.hunt_type}")

        with self.hunt_lock:
            # make sure this hunt doesn't already exist
            for _hunt in self._hunts:
                if _hunt.name == hunt.name:
                    raise KeyError(f"duplicate hunt {hunt.name}")

            self._hunts.append(hunt)

        self.wait_control_event.set()
        return hunt

    def clear_hunts(self):
        """Removes all hunts."""
        with self.hunt_lock:
            self._hunts = []
            self.failed_yaml_files = {}
            self.skipped_yaml_files = set()

        self.wait_control_event.set()

    def remove_hunt(self, hunt):
        assert isinstance(hunt, Hunt)

        with self.hunt_lock:
            self._hunts.remove(hunt)

        self.wait_control_event.set()
        return hunt

    def _list_hunt_yaml(self) -> list[str]:
        """Returns the list of yaml files for hunts in self.rule_dirs."""
        result = []
        for rule_dir in self.rule_dirs:
            rule_dir = abs_path(rule_dir)
            if not os.path.isdir(rule_dir):
                logging.error(f"rules directory {rule_dir} specified for {self} is not a directory")
                continue

            # load each .yaml file found in this rules directory
            logging.debug(f"searching {rule_dir} for hunt configurations")
            for root, dirnames, filenames in os.walk(rule_dir):
                for hunt_config in filenames:
                    if not hunt_config.endswith('.yaml'):
                        continue

                    # skip the template.yaml file
                    if hunt_config == "template.yaml":
                        continue

                    # skip include files
                    if hunt_config.endswith('.include.yaml'):
                        continue

                    result.append(os.path.join(root, hunt_config))

        return result

    def record_semaphore_acquire_time(self, time_delta):
        pass
