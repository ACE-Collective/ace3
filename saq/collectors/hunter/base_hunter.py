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
import logging
import os
import os.path
import pickle
import shutil
import threading
from typing import TYPE_CHECKING, Optional
from croniter import croniter
from pydantic import BaseModel, Field, field_validator

import pytz

from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration import get_config_value
from saq.constants import ANALYSIS_MODE_CORRELATION, CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR, QUEUE_DEFAULT, ExecutionMode
from saq.environment import get_data_dir
from saq.error import report_exception
from saq.util import local_time, create_timedelta
from saq.util.time import is_timedelta_string

if TYPE_CHECKING:
    from saq.collectors.hunter.manager import HuntManager

class HuntConfig(BaseModel):
    uuid: str = Field(..., description="The UUID of the hunt. This must be unique across all signatures in all repositories.")
    name: str = Field(..., description="The name of the hunt. This must be unique to the hunt type.")
    type_: str = Field(..., alias="type", description="The type of the hunt. Must be one of the supported hunt types.")
    enabled: bool = Field(..., description="Whether the hunt is enabled. If disabled, the hunt will not be executed.")
    instance_types: list[str] = Field(default_factory=list, description="The instance types this hunt will run on. Valid values are: production, development, qa.")
    description: str = Field(..., description="The description of the hunt. This is a long description that explains what this hunt is looking for.")
    alert_type: str = Field(..., description="The alert type of the hunt. This is used to categorize the alert in ACE when it is displayed.")
    analysis_mode: str = Field(default=ANALYSIS_MODE_CORRELATION, description="The analysis mode of the hunt. Review the configuration to get a list of valid values.")
    frequency: str = Field(..., description="The frequency of the hunt. This is the time between executions of the hunt. Can be specified in HH:MM:SS format or as a cron schedule string.")
    queue: str = Field(default=QUEUE_DEFAULT, description="The queue to submit alerts to.")
    suppression: Optional[str] = Field(default=None, description="The suppression of the hunt. This is the time to suppress alerts after one fires. Can be specified in HH:MM:SS format.")
    playbook_url: Optional[str] = Field(default=None, description="This is the url of the playbook that will be used to investigate the alert.")
    tags: list[str] = Field(default_factory=list, description="These are tags that will be added to the alert in ACE when it is displayed.")
    pivot_links: list[dict] = Field(default_factory=list, description="These are links that will be displayed in ACE when the alert is displayed.")

    @field_validator("frequency")
    @classmethod
    def validate_frequency(cls, value: str) -> str:
        if not value:
            raise ValueError("frequency must not be empty")

        if is_timedelta_string(value):
            return value

        try:
            croniter(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("frequency must be a timedelta string or a valid cron expression") from exc

        return value

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

    def __init__(self, manager: Optional["HuntManager"] = None, config: Optional[HuntConfig] = None):

        self.manager = manager
        self.config = config

        # the thread this hunt is currently executing on, or None if it is not currently executing
        self.execution_thread = None

        # a threading.RLock that is held while executing
        self.execution_lock = threading.RLock()

        # a way for the controlling thread to wait for the hunt execution thread to start
        self.startup_barrier = threading.Barrier(2)

        # if this is True then we're executing the Hunt outside of normal operations
        # in that case we don't want to record any of the execution time stamps
        # XXX do we still need this?
        self.manual_hunt = False

        # this property maps to the "tool_instance" property of alerts
        # this shows where the alert came from
        # by default we use localhost
        # subclasses might use the address or url they are hitting for their queries
        self.tool_instance = 'localhost'

        # when we load from a yaml file we record the last modified time of the file
        self.file_path = None
        self.last_mtime = None

    #
    # configuration-based properties
    #

    @property
    def uuid(self) -> str:
        return self.config.uuid

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def type(self) -> str:
        return self.config.type_

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def instance_types(self) -> list[str]:
        return self.config.instance_types

    @property
    def description(self) -> str:
        return self.config.description

    @property
    def alert_type(self) -> str:
        return self.config.alert_type

    @property
    def analysis_mode(self) -> str:
        return self.config.analysis_mode

    @property
    def frequency(self) -> Optional[datetime.timedelta]:
        if not self.config.frequency:   
            return None

        if is_timedelta_string(self.config.frequency):
            return create_timedelta(self.config.frequency)

        # otherwise assume it's a cron schedule
        return None

    @property
    def cron_schedule(self) -> Optional[str]:
        """Returns the cron schedule string, or None if the frequency is not a cron schedule string."""
        if not self.config.frequency:
            return None

        if is_timedelta_string(self.config.frequency):
            return None
        else:
            return self.config.frequency

    @property
    def queue(self) -> str:
        return self.config.queue

    @property
    def suppression(self) -> Optional[datetime.timedelta]:
        if not self.config.suppression:
            return None

        return create_timedelta(self.config.suppression)

    @property
    def playbook_url(self) -> Optional[str]:
        return self.config.playbook_url

    @property
    def tags(self) -> list[str]:
        return self.config.tags

    @property
    def pivot_links(self) -> list[dict]:
        return self.config.pivot_links

    #
    # runtime state
    #

    @property
    def hunt_state_dir(self) -> str:
        "Returns the path to the directory that contains persitence information about this hunt."""
        return os.path.join(get_data_dir(), get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR), 'hunt', self.type, self.name)

    #@property
    #def type(self):
        #if self.manager is not None:
            #return self.manager.hunt_type or None
        #else:
            #return None

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

    #
    # misc
    #

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
                # NOTE this can also happen if the hunter is being shut down
                logging.warning(f"timeout waiting for {self} to complete execution")
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

    def load_hunt_config(self, path: str) -> HuntConfig:
        return load_from_yaml(path, HuntConfig)

    def load_hunt(self, path: str) -> HuntConfig:
        self.config = self.load_hunt_config(path)

        self.file_path = path
        self.last_mtime = os.path.getmtime(path)

        return self.config

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
        if self.frequency:
            # if it hasn't executed at all yet
            if self.last_executed_time is None:
                # assume it executed the last time it was supposed to
                return local_time() - self.frequency

            return self.last_executed_time + self.frequency

        elif self.cron_schedule:
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

        else:
            raise ValueError(f"hunt {self} has an invalid frequency or cron schedule {self.frequency or self.cron_schedule}")

    def record_execution_time(self, time_delta):
        """Record the amount of time it took to execute this hunt."""
        pass

    def record_hunt_exception(self, exception):
        """Record the details of a failed hunt."""
        pass
