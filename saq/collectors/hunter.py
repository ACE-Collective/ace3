# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System
#

# How this works:
# A HunterCollector reads the config and loads all the sections that start with hunt_type_
# each of these configuration settings defines a "hunt type" (example: qradar, splunk, etc...)
# each section looks like this:
# [hunt_type_TYPE]
# module = path.to.module
# class = HuntClass
# rule_dirs = hunts/dir1,hunts/dir2
# concurrency_limit = LIMIT
# 
# TYPE is some unique string that identifies the type of the hunt
# the module and class settings define the class that will be used that extends saq.collector.hunter.Hunt
# rule_dirs contains a list of directories to load rules yaml formatted rules from
# and concurrency_limit defines concurrency constraints (see below)
#
# Each of these "types" is managed by a HuntManager which loads the Hunt-based rules and manages the execution
# of these rules, apply any concurrency constraints required.
#

import datetime
import importlib
import logging
import os
import os.path
import pickle
from queue import Empty, Queue
import shutil
import threading
from typing import Generator, override
from croniter import croniter
import yaml

import pytz

from saq.analysis.root import Submission
from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.configuration import get_config, get_config_value
from saq.constants import ANALYSIS_MODE_CORRELATION, CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR, QUEUE_DEFAULT, ExecutionMode
from saq.environment import get_data_dir
from saq.error import report_exception
from saq.network_semaphore import NetworkSemaphoreClient
from saq.service import ACEServiceInterface
from saq.util import local_time, create_timedelta, abs_path
from saq.util.hashing import sha256

class InvalidHuntTypeError(ValueError):
    pass

def get_hunt_state_dir(hunt_type: str, hunt_name: str) -> str:
    "Returns the path to the directory that contains persitence information about this hunt."""
    return os.path.join(get_data_dir(), get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR), 'hunt', hunt_type, hunt_name)

def write_persistence_data(hunt_type: str, hunt_name: str, value_name: str, value):
    """Writes the given persistence data for this hunt."""
    hunt_state_dir = get_hunt_state_dir(hunt_type, hunt_name)
    os.makedirs(hunt_state_dir, exist_ok=True)
    # two step process in case it dies in the middle of this
    temp_path = os.path.join(hunt_state_dir, f'{value_name}.tmp')
    with open(temp_path, 'wb') as fp:
        pickle.dump(value, fp)

    # atomic operation
    shutil.move(temp_path, os.path.join(hunt_state_dir, value_name))

def read_persistence_data(hunt_type: str, hunt_name: str, value_name: str):
    """Reads the given persistence data for this hunt. Returns the value, or None if the data does not exist."""
    target_path = os.path.join(get_hunt_state_dir(hunt_type, hunt_name), value_name)
    if not os.path.exists(target_path):
        return None

    with open(target_path, 'rb') as fp:
        return pickle.load(fp)

class Hunt:
    """Abstract class that represents a single hunt."""

    def __init__(
            self, 
            enabled=None, 
            name=None, 
            description=None,
            manager=None,
            alert_type=None,
            analysis_mode=None,
            frequency=None, 
            playbook_url=None,
            tags=[]):

        self.enabled = enabled
        self.name = name
        self.description = description
        self.manager = manager
        self.alert_type = alert_type
        self.analysis_mode = analysis_mode
        self.frequency = frequency
        self.playbook_url = playbook_url
        self.tags = tags
        self.cron_schedule = None
        self.queue = QUEUE_DEFAULT

        # a datetime.timedelta that represents how long to suppress until this hunt starts to fire again
        self.suppression = None

        # the thread this hunt is currently executing on, or None if it is not currently executing
        self.execution_thread = None

        # a threading.RLock that is held while executing
        self.execution_lock = threading.RLock()

        # a way for the controlling thread to wait for the hunt execution thread to start
        self.startup_barrier = threading.Barrier(2)

        # if this is True then we're executing the Hunt outside of normal operations
        # in that case we don't want to record any of the execution time stamps
        self.manual_hunt = False

        # this property maps to the "tool_instance" property of alerts
        # this shows where the alert came from
        # by default we use localhost
        # subclasses might use the address or url they are hitting for their queries
        self.tool_instance = 'localhost'

        # when we load from a yaml file we record the last modified time of the file
        self.file_path = None
        self.last_mtime = None

    @property
    def hunt_state_dir(self) -> str:
        "Returns the path to the directory that contains persitence information about this hunt."""
        return os.path.join(get_data_dir(), get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR), 'hunt', self.type, self.name)

    @property
    def type(self):
        if self.manager is not None:
            return self.manager.hunt_type or None
        else:
            return None

    @property
    def suppressed(self):
        """Returns True if this hunt is currently suppressed."""
        if not self.last_alert_time:
            return False

        if not self.suppression:
            return False

        return local_time() < self.last_alert_time + self.suppression

    @property
    def suppression_end(self):
        """Returns the time at which suppression for this hunt ends, or None if the hunt is not currently suppressed."""
        if not self.suppressed:
            return None

        return self.last_alert_time + self.suppression

    @property
    def last_executed_time(self):
        # if we don't already have this value then load it from persistence storage
        if hasattr(self, '_last_executed_time'):
            return self._last_executed_time
        else:
            self._last_executed_time = read_persistence_data(self.type, self.name, 'last_executed_time')
            if self._last_executed_time is not None and self._last_executed_time.tzinfo is None:
                self._last_executed_time = pytz.utc.localize(self._last_executed_time)

            return self._last_executed_time

    @last_executed_time.setter
    def last_executed_time(self, value):
        if value.tzinfo is None:
            value = pytz.utc.localize(value)

        self._last_executed_time = value
        write_persistence_data(self.type, self.name, 'last_executed_time', value)
        logging.debug(f"last executed time for {self} set to {self._last_executed_time}")

    @property
    def last_alert_time(self):
        # if we don't already have this value then load it from persistence storage
        if hasattr(self, '_last_alert_time'):
            return self._last_alert_time
        else:
            self._last_alert_time = read_persistence_data(self.type, self.name, 'last_alert_time')
            if self._last_alert_time is not None and self._last_alert_time.tzinfo is None:
                self._last_alert_time = pytz.utc.localize(self._last_alert_time)

            return self._last_alert_time

    @last_alert_time.setter
    def last_alert_time(self, value):
        if value.tzinfo is None:
            value = pytz.utc.localize(value)

        self._last_alert_time = value
        write_persistence_data(self.type, self.name, 'last_alert_time', value)

    def __str__(self):
        return f"Hunt({self.name}[{self.type}])"

    def cancel(self):
        """Called when the hunt needs to be cancelled, such as when the system is shutting down.
           This must be safe to call even if the hunt is not currently executing."""
        logging.warning(f"called cancel on hunt {self} but {self.type} does not support cancel")

    def execute_with_lock(self, execution_mode: ExecutionMode):
        # we use this lock to determine if a hunt is running, and, to wait for execution to complete.
        logging.debug(f"waiting for execution lock on {self}")
        self.execution_lock.acquire()

        # remember the last time we started execution
        #self.last_executed_time = local_time()

        if execution_mode == ExecutionMode.CONTINUOUS:
            # notify the manager that this is now executing
            # this releases the manager thread to continue processing hunts
            logging.debug(f"clearing barrier for {self}")
            self.startup_barrier.wait()

        submission_list = None

        try:
            logging.info(f"executing {self}")
            start_time = local_time()
            result = self.execute()
            self.record_execution_time(local_time() - start_time)
            # remember the last time we started execution
            self.last_executed_time = local_time()
            return result
        except Exception as e:
            logging.error(f"{self} failed: {e}")
            report_exception()
            self.record_hunt_exception(e)
        finally:
            self.startup_barrier.reset()
            self.execution_lock.release()

    def execute(self):
        """Called to execute the hunt. Returns a list of zero or more saq.collector.Submission objects."""
        raise NotImplementedError()

    def wait(self, *args, **kwargs):
        """Waits for the hunt to complete execution. If the hunt is not running then it returns right away.
           Returns False if a timeout is set and the lock is not released during that timeout.
           Additional parameters are passed to execution_lock.acquire()."""
        result = self.execution_lock.acquire(*args, **kwargs)
        if result:
            self.execution_lock.release()

        if self.execution_thread:
            logging.debug(f"waiting for {self} to complete execution")
            if not self.execution_thread.join(5):
                logging.error(f"timeout waiting for {self} to complete execution")
                return False

        return result

    @property
    def running(self):
        """Returns True if the hunt is currently executing, False otherwise."""
        # when the hunt is executing it will have this lock enabled
        result = self.execution_lock.acquire(blocking=False)
        if result:
            self.execution_lock.release()
            return False

        return True

    def load_from_yaml(self, path) -> dict:
        """loads the settings for the hunt from a yaml formatted file. this function must return the 
           dictionary object used to load the settings."""
        with open(path, 'r') as fp:
            config = yaml.safe_load(fp)

        rule_config = config['rule']

        # is this a supported type?
        if rule_config['type'] != self.type:
            raise InvalidHuntTypeError(rule_config['type'])

        self.enabled = rule_config['enabled']

        # if we don't pass the name then we create it from the name of the yaml file
        self.name = rule_config.get(
                'name', 
                (os.path.splitext(os.path.basename(path))[0]).replace('_', ' ').title())

        self.description = rule_config['description']
        # if we don't pass an alert type then we default to the type field
        self.alert_type = rule_config.get('alert_type', f'hunter - {self.type}')
        self.analysis_mode = rule_config.get('analysis_mode', ANALYSIS_MODE_CORRELATION)

        # frequency can be either a timedelta or a crontab entry
        self.frequency = None
        if ':' in rule_config['frequency']:
            self.frequency = create_timedelta(rule_config['frequency'])

        # suppression must be either empty for a time range
        self.suppression = None
        if 'suppression' in rule_config and rule_config['suppression']:
            self.suppression = create_timedelta(rule_config['suppression'])

        self.cron_schedule = None
        if self.frequency is None:
            self.cron_schedule = rule_config.get('cron_schedule', rule_config['frequency'])
            # make sure this crontab entry parses
            croniter(self.cron_schedule)

        self.tags = rule_config['tags']
        self.queue = rule_config['queue'] if 'queue' in rule_config else QUEUE_DEFAULT
        self.playbook_url = rule_config.get('playbook_url', None)

        self.file_path = path
        self.last_mtime = os.path.getmtime(path)
        return config

    @property
    def is_modified(self):
        """"Returns True if this hunt has been modified since it has been loaded."""
        return self.yaml_is_modified

    @property
    def yaml_is_modified(self):
        """returns True if this hunt was loaded from a yaml file and that file has been modified since we loaded it."""
        if self.file_path is None:
            return False
        try:
            return self.last_mtime != os.path.getmtime(self.file_path)
        except FileNotFoundError:
            return True
        except Exception as e:
            logging.error(f"unable to check last modified time of {self.file_path}: {e}")
            return False

    @property
    def ready(self):
        """Returns True if the hunt is ready to execute, False otherwise."""
        # if it's already running then it's not ready to run again
        if self.running:
            return False

        # if we haven't executed it yet then it's ready to go
        if self.last_executed_time is None:
            return True

        # otherwise we're not ready until it's past the next execution time
        return local_time() >= self.next_execution_time

    @property
    def next_execution_time(self):
        """Returns the next time this hunt should execute."""
        # are we supressing alerts for this hunt?
        if self.suppression_end:
            # we don't even look until supression has ended
            logging.info(f"hunt {self} is suppressed until {self.suppression_end}")
            return self.suppression_end

        # if using cron schedule instead of frequency
        if self.cron_schedule is not None:
            if self.last_executed_time is None:
                cron_parser = croniter(self.cron_schedule, local_time())
                logging.info(f"initialized last_executed_time (cron) for {self} to {self.last_executed_time}")
                return cron_parser.get_prev(datetime.datetime)

            cron_parser = croniter(self.cron_schedule, self.last_executed_time)
            result = cron_parser.get_next(datetime.datetime)
            if not result:
                logging.error(f"hunt {self} has a bad cron schedule {self.cron_schedule}")
                return local_time()

            return result

        # if using frequency instead of cron shedule
        else:
            # if it hasn't executed at all yet
            if self.last_executed_time is None:
                # assume it executed the last time it was supposed to
                return local_time() - self.frequency

            return self.last_executed_time + self.frequency

    def record_execution_time(self, time_delta):
        """Record the amount of time it took to execute this hunt."""
        pass

    def record_hunt_exception(self, exception):
        """Record the details of a failed hunt."""
        pass

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
                 config,
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
        self._hunts = []

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
        suppressed_count = 0
        running_count = 0
        ready_count = 0
        idle_count = 0

        for hunt in self.hunts:
            if not hunt.enabled:
                disabled_count += 1
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

        hunt_status_message = f"hunt status: {disabled_count} disabled {suppressed_count} suppressed {running_count} running {ready_count} ready {idle_count} idle"
        if hunt_status_message != self.last_hunt_status_message:
            logging.info(hunt_status_message)
            self.last_hunt_status_message = hunt_status_message
        #logging.info(f"hunt status: {disabled_count} disabled {suppressed_count} suppressed {running_count} running {ready_count} ready {idle_count} idle")


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
                    logging.info("cancelling {hunt}")
                    hunt.cancel()
                    hunt.wait()
            except Exception:
                logging.info("unable to cancel {hunt}: {e}")

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
        for hunt_config in self._list_hunt_yaml():
            hunt = self.hunt_cls(manager=self)
            logging.debug(f"loading hunt from {hunt_config}")
            try:
                hunt.load_from_yaml(hunt_config)

                if hunt_filter(hunt):
                    logging.debug(f"loaded {hunt} from {hunt_config}")
                    self.add_hunt(hunt)
                else:
                    logging.debug(f"not loading {hunt} (hunt_filter returned False)")

            except InvalidHuntTypeError as e:
                report_exception()
                self.skipped_yaml_files.add(hunt_config)
                logging.debug(f"skipping {hunt_config} for {self}: {e}")
                continue
            except Exception as e:
                logging.error(f"unable to load hunt {hunt}: {e}")
                report_exception()
                try:
                    self.failed_yaml_files[hunt_config] = (
                        os.path.getmtime(hunt_config),
                        os.path.getsize(hunt_config),
                        sha256(hunt_config)
                    )
                except Exception as e:
                    logging.error(f"unable to get mtime for {hunt_config}: {e}")

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

    def _list_hunt_yaml(self):
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

                    result.append(os.path.join(root, hunt_config))

        return result

    def record_semaphore_acquire_time(self, time_delta):
        pass

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
