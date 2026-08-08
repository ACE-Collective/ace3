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
import hashlib
import logging
import os
import os.path
import pickle
import shutil
import threading
import time
import uuid
from typing import TYPE_CHECKING, Optional

import pytz
from croniter import croniter
from pydantic import BaseModel, Field, field_validator

from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT, ExecutionMode
from saq.environment import get_data_dir
from saq.error import report_exception
from saq.error.remote import RemoteApiError
from saq.gui.icon import IconConfiguration
from saq.query.config import SummaryDetailConfig
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.util import create_timedelta, local_time
from saq.util.time import is_timedelta_string

if TYPE_CHECKING:
    from saq.collectors.hunter.manager import HuntManager

# how long Hunt.wait() lets an execution thread unwind once the hunt has released its
# execution lock, when the caller did not specify its own timeout.
EXECUTION_THREAD_JOIN_GRACE = 5

# the most bytes of the hunt name we keep in its persistence directory name. the filesystem limit
# is 255 bytes per component; the remainder leaves room for the digest suffix we append when a name
# has to be truncated.
MAX_HUNT_STATE_DIR_NAME_BYTES = 200


class HuntConfig(BaseModel):
    model_config = {"extra": "forbid"}

    uuid: str = Field(..., description="The UUID of the hunt. This must be unique across all signatures in all repositories.")
    name: str = Field(..., description="The name of the hunt. This must be unique to the hunt type.")
    type_: str = Field(..., alias="type", description="The type of the hunt. Must be one of the supported hunt types.")
    enabled: bool = Field(..., description="Whether the hunt is enabled. If disabled, the hunt will not be executed.")
    instance_types: list[str] = Field(default_factory=list, description="The instance types this hunt will run on. Valid values are: production, development, qa.")
    author: list[str] = Field(default_factory=list, description="Author(s) of the hunt. Accepts a single string or a list of strings in YAML; always normalized to a list.")
    description: str = Field(..., description="The description of the hunt. This is a long description that explains what this hunt is looking for.")
    alert_type: str = Field(..., description="The alert type of the hunt. This is used to categorize the alert in ACE when it is displayed.")
    analysis_mode: str = Field(default=ANALYSIS_MODE_CORRELATION, description="The analysis mode of the hunt. Review the configuration to get a list of valid values.")
    frequency: str = Field(..., description="The frequency of the hunt. This is the time between executions of the hunt. Can be specified in HH:MM:SS format or as a cron schedule string.")
    queue: str = Field(default=QUEUE_DEFAULT, description="The queue to submit alerts to.")
    suppression: Optional[str] = Field(default=None, description="The suppression of the hunt. This is the time to suppress alerts after one fires. Can be specified in HH:MM:SS format.")
    playbook_url: Optional[str] = Field(default=None, description="This is the url of the playbook that will be used to investigate the alert.")
    tags: list[str] = Field(default_factory=list, description="These are tags that will be added to the alert in ACE when it is displayed.")
    pivot_links: list[dict] = Field(default_factory=list, description="These are links that will be displayed in ACE when the alert is displayed.")
    icon_configuration: Optional[IconConfiguration] = Field(default=None, description="The icon to use for the hunt.")
    alert_template: Optional[str] = Field(default=None, description="The template to use to display the alert in ACE.")
    summary_details: list[SummaryDetailConfig] = Field(default_factory=list, description="Summary details to add to submissions. Each definition generates one or more SummaryDetail objects per submission.")

    @field_validator("author", mode="before")
    @classmethod
    def normalize_author(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value

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

def hunt_state_dir_name(hunt_name: str) -> str:
    """Returns the directory name used to store the persistence data for a hunt with this name.

       A hunt name is analyst-facing text that ends up as a single path component: it can contain
       path separators, and it can be a jinja template hundreds of characters long (query hunts
       render the name per event to title their alerts). Both of those break the filesystem - a
       component over 255 bytes raises OSError(ENAMETOOLONG) on the makedirs() in
       write_persistence_data(), and a separator writes the state somewhere else entirely.

       A name that is already short and separator free maps to itself, so hunts keep using the
       directory they already have."""
    result = hunt_name
    for separator in (os.sep, os.altsep, "\0"):
        if separator:
            result = result.replace(separator, "_")

    encoded = result.encode("utf-8")
    if len(encoded) <= MAX_HUNT_STATE_DIR_NAME_BYTES:
        return result

    # truncate on a character boundary (errors="ignore" drops a partial character at the end)
    # and disambiguate with a digest of the original name, since two long names can share a
    # prefix and would otherwise collide on the same state directory
    truncated = encoded[:MAX_HUNT_STATE_DIR_NAME_BYTES].decode("utf-8", errors="ignore")
    digest = hashlib.sha256(hunt_name.encode("utf-8")).hexdigest()[:16]
    return f"{truncated}.{digest}"

def get_hunt_state_dir(hunt_type: str, hunt_name: str) -> str:
    "Returns the path to the directory that contains persitence information about this hunt."""
    return os.path.join(get_data_dir(), get_config().collection.persistence_dir, 'hunt', hunt_type,
                        hunt_state_dir_name(hunt_name))

def write_persistence_data(hunt_type: str, hunt_name: str, value_name: str, value):
    """Writes the given persistence data for this hunt."""
    hunt_state_dir = get_hunt_state_dir(hunt_type, hunt_name)
    os.makedirs(hunt_state_dir, exist_ok=True)
    # two step process in case it dies in the middle of this
    temp_path = os.path.join(hunt_state_dir, f"{value_name}.{uuid.uuid4().hex}.tmp")
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

def delete_persistence_data(hunt_type: str, hunt_name: str, value_name: str) -> bool:
    """Deletes the given persistence data for this hunt.
       Returns True if a file was removed, False if there was nothing to remove."""
    target_path = os.path.join(get_hunt_state_dir(hunt_type, hunt_name), value_name)
    try:
        os.remove(target_path)
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        logging.warning("unable to delete persistence data %s: %s", target_path, e)
        return False

class Hunt:
    """Abstract class that represents a single hunt."""

    def __init__(
        self,
        manager: Optional["HuntManager"] = None,
        config: Optional[HuntConfig] = None,
        hunt_config_file_path: Optional[str] = None):

        self.manager = manager
        
        # when we load from a yaml file we record the last modified time of the file
        # will be set by load_hunt if loading from file
        self.file_path = None
        self.last_mtime = None

        # signature_version (git commit hash of this hunt's rule_dir git_dir, or
        # SIGNATURE_VERSION_UNKNOWN) used when emitting the hunt's detection point.
        # set by the HuntManager after load from the rule_dir's resolved commit.
        self.signature_version: str = SIGNATURE_VERSION_UNKNOWN
        
        # track all files that make up this hunt configuration (main file + included files)
        # maps file path -> modification time (None if we couldn't get the mtime)
        self.included_files: dict[str, float | None] = {}
        
        if config is not None:
            self.config = config
        elif hunt_config_file_path is not None:
            self.config = self.load_hunt(hunt_config_file_path)
        else:
            raise ValueError("either config or hunt_config_file_path must be provided")

        # the thread this hunt is currently executing on, or None if it is not currently executing
        self.execution_thread = None

        # a threading.RLock that is held while executing
        self.execution_lock = threading.RLock()

        # a way for the controlling thread to wait for the hunt execution thread to start
        self.startup_barrier = threading.Barrier(2)

        # the logging transaction id of the most recent execute_with_lock() call
        # the transaction id context exits when execute_with_lock() returns, so this is how
        # the hunt manager re-enters it to log the queueing of the submissions that run produced
        self.last_transaction_id: Optional[str] = None

        # if this is True then we're executing the Hunt outside of normal operations
        # in that case we don't want to record any of the execution time stamps
        # XXX do we still need this?
        self.manual_hunt = False

        # this property maps to the "tool_instance" property of alerts
        # this shows where the alert came from
        # by default we use localhost
        # subclasses might use the address or url they are hitting for their queries
        self.tool_instance = 'localhost'

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

    @property
    def icon_configuration(self) -> Optional[IconConfiguration]:
        return self.config.icon_configuration

    @property
    def alert_template(self) -> Optional[str]:
        return self.config.alert_template

    #
    # runtime state
    #

    @property
    def hunt_state_dir(self) -> str:
        "Returns the path to the directory that contains persitence information about this hunt."""
        return get_hunt_state_dir(self.type, self.name)

    #@property
    #def type(self):
        #if self.manager is not None:
            #return self.manager.hunt_type or None
        #else:
            #return None

    @property
    def group_by(self) -> Optional[str]:
        """The field used to group results into separate alerts, or None if the hunt is not grouped.
           Subclasses (e.g. QueryHunt) override this; the base class has no concept of grouping."""
        return None

    @property
    def suppressed(self):
        """Returns True if this hunt is currently suppressed."""
        # grouped hunts manage suppression per group_value inside process_query_results,
        # so the hunt as a whole is never globally suppressed
        if self.group_by is not None:
            return False

        if not self.last_alert_time:
            return False

        if not self.suppression:
            return False

        return local_time() < self.last_alert_time + self.suppression

    @property
    def suppression_end(self):
        """Returns the time at which suppression for this hunt ends, or None if the hunt is not currently suppressed."""
        # grouped hunts do not have a single hunt-level suppression window
        if self.group_by is not None:
            return None

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

    @property
    def last_alert_times(self) -> dict[str, datetime.datetime]:
        """Per-group last alert times, used when group_by is configured.
           Returns a dict mapping group_by value -> last alert time (tz-aware UTC).
           Independent of the singular last_alert_time which is used for ungrouped hunts."""
        if hasattr(self, '_last_alert_times'):
            return self._last_alert_times

        loaded = read_persistence_data(self.type, self.name, 'last_alert_times')
        if loaded is None:
            self._last_alert_times = {}
        else:
            # ensure tz info is preserved across legacy pickles where datetimes may be naive
            self._last_alert_times = {
                k: (pytz.utc.localize(v) if v.tzinfo is None else v)
                for k, v in loaded.items()
            }

        return self._last_alert_times

    @last_alert_times.setter
    def last_alert_times(self, value: dict[str, datetime.datetime]):
        normalized = {
            k: (pytz.utc.localize(v) if v.tzinfo is None else v)
            for k, v in value.items()
        }
        self._last_alert_times = normalized
        write_persistence_data(self.type, self.name, 'last_alert_times', normalized)

    def get_last_alert_time(self, group_value: Optional[str]) -> Optional[datetime.datetime]:
        """Returns the last alert time for the given group_value, or None if no alert has been recorded.
           When group_value is None, returns the singular hunt-level last_alert_time."""
        if group_value is None:
            return self.last_alert_time

        return self.last_alert_times.get(group_value)

    def set_last_alert_time(self, value: datetime.datetime, group_value: Optional[str]):
        """Sets the last alert time for the given group_value.
           When group_value is None, sets the singular hunt-level last_alert_time.

           NOTE: This records the value in memory only - call save_last_alert_times() once when done
           to persist."""
        if group_value is None:
            self.last_alert_time = value
            return

        if value.tzinfo is None:
            value = pytz.utc.localize(value)

        # access through the property to ensure _last_alert_times is loaded, then mutate in
        # place. in place matters: a hunt can be re-dispatched while the previous run is still
        # post-processing (execute_with_lock releases execution_lock before the manager records
        # alert times), and the old copy-modify-write dropped the other run's updates.
        self.last_alert_times[group_value] = value
        self._last_alert_times_dirty = True

    def is_group_suppressed(self, group_value: str) -> bool:
        """Returns True if alerts for the given group_value are currently suppressed."""
        if not self.suppression:
            return False

        last = self.get_last_alert_time(group_value)
        if not last:
            return False

        return local_time() < last + self.suppression

    def prune_expired_last_alert_times(self):
        """Drops entries from last_alert_times whose suppression window has already ended.
           Mutates in memory only - call save_last_alert_times() to persist. No-op if
           suppression is not configured or the dict is empty. Intended to be called explicitly
           (not as a side effect of a setter).

           This is what bounds the dict: entries cannot outlive the suppression window."""
        if not self.suppression:
            return

        current = self.last_alert_times
        if not current:
            return

        now = local_time()
        suppression = self.suppression

        # snapshot the items before deciding what to drop
        expired = [k for k, v in dict(current).items() if now >= v + suppression]

        if not expired:
            return

        # remove key by key rather than assigning a rebuilt dict: a rebuilt dict would discard
        # any entry a concurrent run inserted after the snapshot was taken
        for key in expired:
            current.pop(key, None)

        self._last_alert_times_dirty = True

        logging.debug(
            "pruned %s expired last_alert_times entries for hunt %s (uuid=%s, type=%s)",
            len(expired), self.name, self.uuid, self.type,
        )

    def save_last_alert_times(self):
        """Persists last_alert_times if anything changed since the last save.
           This is the single write per hunt run that replaces the old per-group writes."""
        if not getattr(self, '_last_alert_times_dirty', False):
            return

        # snapshot before pickling. dict(...) is atomic under the GIL, so a concurrently
        # re-dispatched run inserting entries cannot make pickle.dump raise
        # "dictionary changed size during iteration"
        snapshot = dict(self.last_alert_times)
        write_persistence_data(self.type, self.name, 'last_alert_times', snapshot)
        self._last_alert_times_dirty = False

    def discard_suppression_state(self):
        """Drops any persisted per-group alert times for a hunt that does not configure
           suppression. Nothing reads that state (is_group_suppressed and
           prune_expired_last_alert_times both return before reading it when suppression is
           unset), so this reclaims whatever a previous version of this code left on disk.
           Cheap no-op after the first call."""
        if getattr(self, '_suppression_state_discarded', False):
            return

        self._last_alert_times = {}
        self._last_alert_times_dirty = False
        self._suppression_state_discarded = True

        if delete_persistence_data(self.type, self.name, 'last_alert_times'):
            logging.info(
                "discarded persisted suppression state for unsuppressed hunt %s (uuid=%s, type=%s)",
                self.name, self.uuid, self.type,
            )

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
        # correlate every log line for this hunt run under a fresh transaction id
        from saq.logging import transaction_id
        with transaction_id() as current_transaction_id:
            # remember it so the hunt manager can log the queueing of our submissions
            # under the same transaction id (this context exits before that happens)
            self.last_transaction_id = current_transaction_id

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
            start_time = local_time()
            result_status = "success"

            try:
                logging.info(f"executing {self}")
                result = self.execute()
                self.record_execution_time(local_time() - start_time)
                return result
            except RemoteApiError as e:
                result_status = "remote_api_error"
                logging.warning(f"{self} failed (remote API error): {e}")
                self.record_hunt_exception(e)
            except Exception as e:
                result_status = "error"
                logging.error(f"{self} failed: {e}")
                report_exception()
                self.record_hunt_exception(e)
            finally:
                try:
                    self.last_executed_time = local_time()
                    end_time = local_time()
                    logging.info(
                        "completed hunt %s (uuid=%s, type=%s) status=%s started=%s completed=%s duration=%.2fs",
                        self.name, self.uuid, self.type, result_status, start_time, end_time,
                        (end_time - start_time).total_seconds(),
                    )
                    self.startup_barrier.reset()
                except Exception as e:
                    logging.error("unable to finalize hunt %s (uuid=%s, type=%s): %s",
                                  self.name, self.uuid, self.type, e)
                    report_exception()
                finally:
                    self.execution_lock.release()

    def execute(self):
        """Called to execute the hunt. Returns a list of zero or more saq.collector.Submission objects."""
        raise NotImplementedError()

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Waits for the hunt to finish executing. If the hunt is not running then it returns
           right away. Returns True if the hunt is no longer executing, False if it was still
           executing when the timeout expired.

           timeout is the total budget shared between acquiring the execution lock and joining
           the execution thread. Passing None waits indefinitely for the lock and then allows
           the thread EXECUTION_THREAD_JOIN_GRACE seconds to unwind.

           NOTE a caller that must not block indefinitely has to pass a timeout. A hunt that
           does not honor cancellation (see cancel()) will otherwise hold this forever."""
        if timeout is None:
            acquired = self.execution_lock.acquire()
            join_timeout = EXECUTION_THREAD_JOIN_GRACE
        else:
            deadline = time.monotonic() + timeout
            acquired = self.execution_lock.acquire(timeout=timeout)
            join_timeout = max(0.0, deadline - time.monotonic())

        if not acquired:
            logging.warning("timeout waiting for execution lock on %s after %ss", self, timeout)
            return False

        self.execution_lock.release()

        if self.execution_thread:
            logging.debug(f"waiting for {self} to complete execution")
            # NOTE Thread.join() always returns None, so its return value says nothing about
            # whether the thread finished -- is_alive() is what actually answers that.
            self.execution_thread.join(join_timeout)
            if self.execution_thread.is_alive():
                # NOTE this can also happen if the hunter is being shut down
                logging.warning(f"timeout waiting for {self} to complete execution")
                return False

        return True

    @property
    def running(self):
        """Returns True if the hunt is currently executing, False otherwise."""
        # when the hunt is executing it will have this lock enabled
        result = self.execution_lock.acquire(blocking=False)
        if result:
            self.execution_lock.release()
            return False

        return True

    def load_hunt_config(self, path: str) -> tuple[HuntConfig, set[str]]:
        return load_from_yaml(path, HuntConfig)

    def load_hunt(self, path: str) -> HuntConfig:
        self.config, included_file_paths = self.load_hunt_config(path)

        self.file_path = path
        self.last_mtime = os.path.getmtime(path)
        
        # track modification times for all files that make up this hunt configuration
        self.included_files = {}
        for file_path in included_file_paths:
            try:
                self.included_files[file_path] = os.path.getmtime(file_path)
            except (OSError, FileNotFoundError) as e:
                logging.warning(f"unable to get modification time for included file {file_path}: {e}")
                # store None to indicate we couldn't get the mtime
                self.included_files[file_path] = None

        return self.config

    @property
    def is_modified(self):
        """"Returns True if this hunt has been modified since it has been loaded."""
        return self.yaml_is_modified

    @property
    def yaml_is_modified(self):
        """returns True if this hunt was loaded from a yaml file and that file or any included file has been modified since we loaded it."""
        if self.file_path is None:
            return False
        
        # check the main file
        try:
            if self.last_mtime != os.path.getmtime(self.file_path):
                return True
        except FileNotFoundError:
            return True
        except Exception as e:
            logging.error(f"unable to check last modified time of {self.file_path}: {e}")
            return False
        
        # check all included files
        for file_path, stored_mtime in self.included_files.items():
            try:
                current_mtime = os.path.getmtime(file_path)
                if stored_mtime is None or stored_mtime != current_mtime:
                    return True
            except FileNotFoundError:
                # if an included file was deleted, consider it modified
                return True
            except Exception as e:
                logging.error(f"unable to check last modified time of included file {file_path}: {e}")
                # on error, conservatively assume it's modified
                return True
        
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
