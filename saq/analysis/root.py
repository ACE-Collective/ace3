from datetime import datetime
import gc
import json
import logging
import os
import time
import traceback
from typing import TYPE_CHECKING, Callable, Optional, Union
from uuid import uuid4

from saq.analysis.analysis import Analysis
from saq.analysis.analysis_tree.analysis_tree_manager import AnalysisTreeManager
from saq.analysis.dependency import AnalysisDependency
from saq.analysis.event_bus import AnalysisEventBus
from saq.analysis.file_manager.file_manager_factory import create_file_manager
from saq.analysis.module_execution_delta import ModuleExecutionDelta
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.serialize.observable_serializer import KEY_TYPE as KEY_OBSERVABLE_TYPE
from saq.analysis.serialize.root_serializer import KEY_OBSERVABLE_STORE, RootAnalysisSerializer
from saq.constants import F_FILE, QUEUE_DEFAULT
from saq.environment import get_global_runtime_settings, get_local_timezone, get_temp_dir
from saq.util import parse_event_time
from saq.util.time import local_time

if TYPE_CHECKING:
    from saq.observables.file import FileObservable

# supported extension keys
KEY_PLAYBOOK_URL = 'playbook_url'
KEY_TRANSACTION_ID = 'transaction_id'
# collector-layer submission metadata. these live on the root (rather than on Submission) because
# a staged submission is reconstructed from disk after a restart, and only the root is serialized.
KEY_SUBMISSION_KEY = 'submission_key'
KEY_GROUP_ASSIGNMENTS = 'group_assignments'
KEY_GROUP_VALUE = 'group_value'
KEY_QUEUED_AT = 'queued_at'

class RootAnalysis(Analysis):
    """Root of analysis. Also see saq.database.Alert."""

    def __init__(self, *args,
                 tool=None, 
                 tool_instance=None, 
                 alert_type=None, 
                 desc=None, 
                 event_time=None, 
                 action_counters=None,
                 details=None, 
                 name=None,
                 remediation=None,
                 state=None,
                 location=None,
                 storage_dir=None,
                 company_name=None,
                 company_id=None,
                 analysis_mode=None,
                 queue=None,
                 instructions=None,
                 analysis_failures=None,
                 extensions=None,
                 **kwargs):

        super().__init__(*args, **kwargs)

        # we set this to True by default so that the details are saved to disk
        # if they ended up getting loaded, the loader sets this to False
        self.details_modified = True

        self._analysis_mode = analysis_mode
        self._original_analysis_mode = analysis_mode
        self._tool = tool
        self._tool_instance = tool_instance
        self._alert_type = alert_type
        self._queue = queue if queue else QUEUE_DEFAULT
        self._description = desc
        self._instructions = instructions
        self._extensions = extensions
        self._analysis_failures = analysis_failures if analysis_failures else {}
        self._event_time = event_time
        self._name = name
        self._remediation = remediation
        self.details = details or {}
        self._action_counters = action_counters if action_counters else {}
        self._location = location if location else get_global_runtime_settings().saq_node
        self._state = state if state else {}
        self._company_name = get_global_runtime_settings().company_name
        self._company_id = get_global_runtime_settings().company_id

        # set to True after load() is called
        self.is_loaded = False

        # when True, calling load() logs an ERROR with a stack trace
        self.log_error_on_load = False

        # we keep track of when delayed initially starts here
        # to allow for eventual timeouts when something is wrong
        # key = analysis_module:observable_uuid
        # value = datetime of when the first analysis request was made
        self.delayed_analysis_tracking = {} 

        # per-module execution deltas recorded by the executor
        self._module_executions: list[ModuleExecutionDelta] = []

        # centralized event management system
        self.event_bus = AnalysisEventBus()
        
        # set up global event propagation using the event bus
        self.event_bus.setup_global_event_propagation(self)

        # XXX: refactor - the RootAnalysis should depend entirely on the FileManager for storage_dir stuff
        # so it should not know about the storage_dir at all

        # if the storage_dir is not set then we use a temporary directory
        if not storage_dir:
            logging.warning("storage_dir is not set, using temporary directory")
            storage_dir = os.path.join(get_temp_dir(), self.uuid)
        
        # initialize file manager if storage_dir is set
        # if not it gets set automatically when the file_manager property is accessed
        self.file_manager = create_file_manager(storage_dir)

        # initialize analysis tree manager
        self._analysis_tree_manager = AnalysisTreeManager(
            self.event_bus,
            self.file_manager,
            self
        )

    def is_on_detection_path(self) -> bool:
        """The RootAnalysis is never considered to be on the detection path."""
        return False

    @property
    def module_executions(self) -> list[ModuleExecutionDelta]:
        return self._module_executions

    def record_module_execution(self, delta: ModuleExecutionDelta):
        self._module_executions.append(delta)

    def _fire_global_events(self, source, event_type, *args, **kwargs):
        """Fires EVENT_GLOBAL_* events. Delegates to the AnalysisEventBus."""
        self.event_bus.fire_global_events(source, event_type, *args, **kwargs)
        
    #
    # the json property is used for internal storage
    #

    @property
    def json(self):
        return RootAnalysisSerializer.serialize(self)

    @json.setter
    def json(self, value):
        RootAnalysisSerializer.deserialize(self, value)

    @property
    def analysis_mode(self):
        return self._analysis_mode

    @property
    def original_analysis_mode(self):
        return self._original_analysis_mode

    @analysis_mode.setter
    def analysis_mode(self, value):
        assert value is None or ( isinstance(value, str) and value )
        self._analysis_mode = value
        if self._original_analysis_mode is None:
            self._original_analysis_mode = value

    def override_analysis_mode(self, value):
        """Change the analysis mode and disregard current values.
           This has the effect of setting both the analysis mode and original analysis mode."""
        assert value is None or ( isinstance(value, str) and value )
        self._analysis_mode = value
        self._original_analysis_mode = value

    @property
    def tool(self):
        """The name of the tool that generated the alert (ex: splunk)."""
        return self._tool

    @tool.setter
    def tool(self, value):
        assert value is None or isinstance(value, str)
        self._tool = value

    @property
    def tool_instance(self):
        """The instance of the tool that generated the alert (ex: the hostname of the sensor)."""
        return self._tool_instance

    @tool_instance.setter
    def tool_instance(self, value):
        assert value is None or isinstance(value, str)
        self._tool_instance = value

    @property
    def alert_type(self):
        """The type of the alert (ex: splunk - ipv4 search)."""
        return self._alert_type

    @alert_type.setter
    def alert_type(self, value):
        assert value is None or isinstance(value, str)
        self._alert_type = value

    @property
    def queue(self):
        """The queue the alert will appear in (ex: external, internal)."""
        return self._queue

    @queue.setter
    def queue(self, value):
        assert isinstance(value, str)
        self._queue = value

    @property
    def instructions(self):
        """A free form string value that gives the analyst instructions on what
        this alert is about and/or how to analyze the data contained in the
        alert."""
        return self._instructions

    @instructions.setter
    def instructions(self, value):
        self._instructions = value

    @property
    def extensions(self) -> dict:
        """Free form dictionary that can contain anything. Used to extend data contained in ice alerts."""
        return self._extensions

    @extensions.setter
    def extensions(self, value: dict):
        assert value is None or isinstance(value, dict)
        self._extensions = value

    def set_extension(self, name: str, value):
        if self._extensions is None:
            self._extensions = {}

        self._extensions[name] = value

    def set_optional_extension(self, name: str, value):
        """Records an extension only when it has a value, removing it otherwise.

        Absence and None mean the same thing for these keys, so this keeps a None from being
        serialized into every root as a meaningless entry."""
        if value is None:
            if self._extensions is not None:
                self._extensions.pop(name, None)

            return

        self.set_extension(name, value)

    @property
    def playbook_url(self):
        """Returns a url to a playbook for this alert, or None if not defined."""
        if not self._extensions:
            return None

        return self._extensions.get(KEY_PLAYBOOK_URL, None)

    @playbook_url.setter
    def playbook_url(self, value):
        self.set_extension(KEY_PLAYBOOK_URL, value)

    @property
    def transaction_id(self):
        """Returns the logging transaction id (see saq.logging) of the context that created this
        RootAnalysis, or None if it was not recorded. Used to correlate the resulting alert with the
        log lines emitted by whatever produced it (for example a single hunt execution)."""
        if not self._extensions:
            return None

        return self._extensions.get(KEY_TRANSACTION_ID, None)

    @transaction_id.setter
    def transaction_id(self, value):
        self.set_extension(KEY_TRANSACTION_ID, value)

    @property
    def submission_key(self):
        """Returns the deduplication key of the Submission this root belongs to, or None.
        Stored here rather than only on Submission so it survives the trip through the staging
        directory (see SubmissionFileManager.stage_submission)."""
        if not self._extensions:
            return None

        return self._extensions.get(KEY_SUBMISSION_KEY, None)

    @submission_key.setter
    def submission_key(self, value):
        self.set_optional_extension(KEY_SUBMISSION_KEY, value)

    @property
    def group_assignments(self):
        """Returns the list of RemoteNodeGroup names this submission is limited to, or None for
        all configured groups."""
        if not self._extensions:
            return None

        return self._extensions.get(KEY_GROUP_ASSIGNMENTS, None)

    @group_assignments.setter
    def group_assignments(self, value):
        self.set_optional_extension(KEY_GROUP_ASSIGNMENTS, value)

    @property
    def group_value(self):
        """Returns the group_by value that produced this submission, or None if the hunt is not
        grouped. Used by the hunt manager to record per-group suppression windows."""
        if not self._extensions:
            return None

        return self._extensions.get(KEY_GROUP_VALUE, None)

    @group_value.setter
    def group_value(self, value):
        self.set_optional_extension(KEY_GROUP_VALUE, value)

    @property
    def queued_at(self) -> Optional[float]:
        """Returns the wall clock (epoch seconds) at which this submission was staged for
        collection, or None. Wall clock rather than time.monotonic() specifically so it remains
        meaningful after the process that staged it has died."""
        if not self._extensions:
            return None

        return self._extensions.get(KEY_QUEUED_AT, None)

    @queued_at.setter
    def queued_at(self, value: float):
        self.set_optional_extension(KEY_QUEUED_AT, value)

    @property
    def analysis_failures(self):
        """Returns a dict of recorded analysis failures. 
        key = MODULE_PATH(analysis)
        value = {
            key = observable.type:observable.value
            value = error_message or None
        }"""
        return self._analysis_failures

    @analysis_failures.setter
    def analysis_failures(self, value):
        assert value is None or isinstance(value, dict)
        self._analysis_failures = value

    def set_analysis_failed(self, module, observable_type, observable_value, error_message=None):
        assert observable_type is None or isinstance(observable_type, str)
        assert observable_value is None or isinstance(observable_value, str)

        logging.debug(f"setting analysis failed for {module} {observable_type} {observable_value} {error_message}")

        module = MODULE_PATH(module)

        if module not in self.analysis_failures:
            self.analysis_failures[module] = {}

        self.analysis_failures[module][_get_failed_analysis_key(observable_type, observable_value)] = error_message

    def is_analysis_failed(self, module, observable):
        module_path = MODULE_PATH(module)
        try:
            return _get_failed_analysis_key(observable.type, observable.value) in self.analysis_failures[module_path]
        except KeyError:
            return False

    def get_analysis_failed_message(self, module, observable):
        module_path = MODULE_PATH(module)
        try:
            return self.analysis_failures[module_path][_get_failed_analysis_key(observable.type, observable.value)]
        except KeyError:
            return None

    @property
    def description(self):
        """A brief one line description of the alert (ex: high_pdf_xor_kernel32 match in email attachment)."""
        return self._description

    @description.setter
    def description(self, value):
        assert value is None or isinstance(value, str)
        self._description = value

    @property
    def event_time(self):
        """Returns a datetime object representing the time this event was created or occurred."""
        return self._event_time

    @event_time.setter
    def event_time(self, value):
        """Sets the event_time. Accepts a datetime object or a string in the format %Y-%m-%d %H:%M:%S %z."""
        if value is None:
            self._event_time = None
        elif isinstance(value, datetime):
            # if we didn't specify a timezone then we use the timezone of the local system
            if value.tzinfo is None:
                value = get_local_timezone().localize(value)
            self._event_time = value
        elif isinstance(value, str):
            self._event_time = parse_event_time(value)
        else:
            raise ValueError("event_time must be a datetime object or a string in the format "
                             "%Y-%m-%d %H:%M:%S %z but you passed {}".format(type(value).__name__))

    @property
    def event_time_datetime(self):
        """This returns the same thing as event_time. It remains for backwards compatibility."""
        return self._event_time

    # override the summary property of the Analysis object to reflect the description
    @property
    def summary(self):
        return self.description

    @summary.setter
    def summary(self, value):
        """This does nothing, but it does get called when you assign to the json property."""
        pass

    @property
    def action_counters(self):
        """A dict() with generic key:value pairs used by the modules to limit specific actions."""
        return self._action_counters

    @action_counters.setter
    def action_counters(self, value):
        assert value is None or isinstance(value, dict)
        self._action_counters = value

    def get_action_counter(self, value):
        """Get the current value of an action counter.  Returns 0 if the action counter doesn't exist yet."""
        try:
            return self.action_counters[value]
        except KeyError:
            return 0

    def increment_action_counter(self, value):
        """Increment the value of an action counter.  Creates a new one if needed."""
        if value not in self.action_counters:
            self.action_counters[value] = 0

        self.action_counters[value] += 1
        logging.debug("action counter {} for {} incremented to {}".format(value, self, self.action_counters[value]))

    @property
    def observable_store(self):
        """Hash of the actual Observable objects generated during the analysis of this Alert.  key = uuid, value = Observable."""
        return self.analysis_tree_manager.observable_registry.store

    @property
    def storage_dir(self) -> str:
        """The base storage directory for output."""
        return self.file_manager.storage_dir

    @property
    def hardcopy_dir(self) -> str:
        """Returns the path to the hardcopy directory. File content is stored here by sha256 hash."""
        return self.file_manager.hardcopy_dir

    @property
    def file_dir(self) -> str:
        """Returns the path to the files directory. File references to hard copies are stored here by relative path."""
        return self.file_manager.file_dir

    def initialize_storage(self):
        """Initialize storage directories using FileManager."""
        if not self.file_manager:
            raise RuntimeError("FileManager is not initialized")

        self.file_manager.initialize_storage()

    @property
    def location(self):
        """Returns the FQDN of the host that contains this analysis."""
        return self._location

    @location.setter
    def location(self, value):
        assert isinstance(value, str)
        self._location = value

    @property
    def json_path(self):
        """Path to the JSON file that stores this alert."""
        return self.file_manager.json_path

    @property
    def name(self):
        """An optional property that defines a name for an alert.  
           Used to track and document analyst response instructions."""
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def remediation(self):
        """A list of remediation actions that are possible for this alert."""
        return self._remediation

    @remediation.setter
    def remediation(self, value):
        assert value is None or isinstance(value, list)
        self._remediation = value

    @property
    def state(self):
        """A free form dict that can store any value. Used by AnalysisModules to maintain state."""
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def whitelisted(self):
        for observable in self.all_observables:
            if observable.whitelisted:
                return True

        for analysis in self.all_non_root_analysis:
            if analysis.whitelisted:
                return True

        if self.has_tag("whitelisted"):
            return True

        return False

    def whitelist(self):
        self.add_tag("whitelisted")

    @property
    def company_name(self):
        """The organzaition this analysis belongs to."""
        return self._company_name

    @company_name.setter
    def company_name(self, value):
        self._company_name = value

    @property
    def company_id(self):
        return self._company_id

    @company_id.setter
    def company_id(self, value):
        self._company_id = value

    @property
    def submission_json_path(self):
        """Returns the path used to store the submission JSON data."""
        return self.file_manager.submission_json_path

    def record_submission(self, analysis, files):
        """Records the current submission data as it was received."""
        assert isinstance(analysis, dict)
        assert isinstance(files, list)

        self.file_manager.record_submission(analysis, files)

    @property
    def submission(self):
        """Returns the submission data recorded for this analysis, or None if that data is not available."""
        if hasattr(self, '_submission'):
            return self._submission

        self._submission = self.file_manager.load_submission()
        return self._submission

    @property
    def delayed(self):
        """Returns True if any delayed analysis is outstanding."""
        for observable in self.all_observables:
            for analysis in observable.all_analysis:
                if analysis.delayed:
                    return True

        return False

    @delayed.setter
    def delayed(self, value):
        """This is computed so this value is thrown away."""
        # this will (attempt to be) set when the object is loaded from JSON
        pass

    def get_delayed_analysis_start_time_key(self, observable, analysis_module) -> str:
        """Returns the key for the delayed analysis start time."""
        return '{}:{}'.format(analysis_module.config.name, observable.uuid)

    def initialize_delayed_analysis_start_time(self, observable, analysis_module) -> datetime:
        """Sets the start time for the delayed analysis to the current time if not already set.
        Returns the start time."""
        start_time = self.get_delayed_analysis_start_time(observable, analysis_module)
        if start_time is None:
            start_time = self.set_delayed_analysis_start_time(observable, analysis_module)
        
        return start_time

    def get_delayed_analysis_start_time(self, observable, analysis_module) -> Optional[datetime]:
        """Returns the time of the first attempt to delay analysis for this analysis module and observable, or None otherwise."""
        key = self.get_delayed_analysis_start_time_key(observable, analysis_module)
        return self.delayed_analysis_tracking.get(key)

    def set_delayed_analysis_start_time(self, observable, analysis_module) -> datetime:
        """Called by the engine when we need to start tracking delayed analysis for a given observable."""
        # if this is the first time we've delayed analysis (for this analysis module and observable)
        # then we want to remember when we started so we can eventually time out
        key = self.get_delayed_analysis_start_time_key(observable, analysis_module)
        start_time = self.get_delayed_analysis_start_time(observable, analysis_module)
        if start_time is None:
            start_time = local_time()
            self.delayed_analysis_tracking[key] = start_time
            return start_time
        else:
            return start_time

    def add_dependency(self, source_observable, source_analysis, source_analysis_instance, target_observable, target_analysis, target_analysis_instance):
        """Add a dependency between analysis objects. Delegates to the dependency manager."""
        return self.analysis_tree_manager.dependency_manager.add_dependency(source_observable, source_analysis, source_analysis_instance, 
                                                     target_observable, target_analysis, target_analysis_instance)

    def remove_dependency(self, dep):
        """Remove a dependency. Delegates to the dependency manager."""
        self.analysis_tree_manager.dependency_manager.remove_dependency(dep)

    @property
    def active_dependencies(self) -> list[AnalysisDependency]:
        """Returns the list of AnalysisDependency objects that have not failed, are not delayed, and not resolved.
           The list is returned in the order they should be handled."""
        return self.analysis_tree_manager.dependency_manager.active_dependencies

    @property
    def all_dependencies(self):
        """Returns the list of all AnalysisDependency objects."""
        return self.analysis_tree_manager.dependency_manager.all_dependencies
    
    @property
    def dependency_tracking(self):
        """Returns the list of all AnalysisDependency objects. Backward compatibility property."""
        return self.analysis_tree_manager.dependency_manager.dependency_tracking

    def create_submission(self):
        """Creates a new Submission object for this RootAnalysis."""
        return Submission(self)

    # XXX: refactor
    def schedule(self):
        from saq.database.util.workload import add_workload
        add_workload(self)

    def save(self):
        """Saves the Alert to disk. Resolves AttachmentLinks into Attachments. Note that this does not insert the Alert into the system."""
        return RootAnalysisSerializer.save_to_disk(self)

    def set_log_error_on_load(self, value=True):
        """Sets the log_error_on_load flag, controlling whether load() logs an ERROR."""
        assert isinstance(value, bool)
        self.log_error_on_load = value

    def load(self):
        """Loads the Alert object from the JSON file.  Note that this does NOT load the details property."""
        if self.log_error_on_load:
            logging.error("load() called on root analysis %s when log_error_on_load is set\n%s",
                          self.storage_dir, "".join(traceback.format_stack()))
        return RootAnalysisSerializer.load_from_disk(self)

    def flush(self):
        """Calls Analysis.flush on all Analysis objects in this RootAnalysis."""

        # ensure storage directories exist
        if self.file_manager:
            self.file_manager.ensure_storage_directories()

        for analysis in self.all_analysis:
            self.analysis_tree_manager.flush_analysis_details(analysis)

        freed_items = gc.collect()

    def reset(self):
        """Removes analysis, dispositions and any observables that did not originally come with the alert."""
        from saq.database import acquire_lock, release_lock, LockedException

        lock_uuid = str(uuid4())
        try:
            if not acquire_lock(self.uuid, lock_uuid):
                raise LockedException(self)

            return self._reset()

        finally:
            if lock_uuid:
                release_lock(self.uuid, lock_uuid)

    def _reset(self):
        from saq.observables import FileObservable

        logging.info("resetting {}".format(self))

        # NOTE that we do not clear the details that came with Alert
        # clear external details storage for all analysis (except self)
        for _analysis in self.all_non_root_analysis:
            self.analysis_tree_manager.reset_analysis_details(_analysis)

        # remove analysis objects from all observables
        for o in self.observables:
            o.clear_analysis()

        # remove observables from the observable_store that didn't come with the original alert
        #import pdb; pdb.set_trace()
        original_uuids = set([o.uuid for o in self.observables])
        remove_list = []
        for uuid in list(self.analysis_tree_manager.observable_registry.store.keys()):
            if uuid not in original_uuids:
                remove_list.append(uuid)

        for uuid in remove_list:
            # if the observable is a F_FILE then try to also delete the file
            observable = self.analysis_tree_manager.get_observable_by_id(uuid)
            if isinstance(observable, FileObservable):
                if observable.exists:
                    self.file_manager.delete_file(observable.full_path)

            self.analysis_tree_manager.observable_registry.remove(uuid)

        # remove tags from observables
        # NOTE there's currently no way to know which tags originally came with the alert
        for o in self.observables:
            o.clear_tags()

        # clear the action counters
        self.action_counters = {} 

        # clear the state
        # this also clears any pre/post analysis module tracking
        self.state = {}

        # remove any empty directories left behind
        if self.file_manager:
            self.file_manager.cleanup_empty_directories()

    def archive(self):
        """Removes the details of analysis and external files.  Keeps observables and tags."""
        logging.info("archiving {}".format(self))

        # NOTE that we do not clear the details that came with Alert
        # clear external details storage for all analysis (except self)
        for _analysis in self.all_non_root_analysis:
            self.analysis_tree_manager.reset_analysis_details(_analysis)

        retained_files = set()
        for observable in self.all_observables:
            # skip the ones that came with the alert
            if observable in self.observables:
                continue

            if observable.type == F_FILE:
                file_path = getattr(observable, 'full_path', None)
                if file_path and os.path.exists(file_path):
                    logging.debug("deleting observable file {}".format(file_path))

                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logging.error("unable to remove {}: {}".format(file_path, str(e)))

        # use file manager for archiving
        if self.file_manager:
            self.file_manager.archive_files(retained_files)

    def copy(self, dest_dir) -> "RootAnalysis":
        """Makes a copy of this RootAnalysis by copying the storage directory to the target directory.
        Returns a new loaded RootAnalysis object from the new storage directory."""
        assert isinstance(dest_dir, str) and dest_dir

        if os.path.exists(dest_dir):
            raise RuntimeError(f"until to move {self}: destination directory {dest_dir} already exists")

        # make sure we're serialized to storage first
        self.save()

        # use file manager to copy storage
        if self.file_manager:
            self.file_manager.copy_storage(dest_dir)

        root = RootAnalysis(storage_dir=dest_dir)
        root.load()
        return root

    def duplicate(self) -> "RootAnalysis":
        # make sure we're serialized to storage first
        self.save()

        # create a new uuid for the new root analysis
        new_uuid = str(uuid4())

        # use temp space to store this
        target_dir = os.path.join(get_temp_dir(), new_uuid)  # noqa: F821

        logging.debug(f"duplicating root {self.uuid} @ {self.storage_dir} to {new_uuid} @ {target_dir}")
        
        # use file manager to copy storage
        if self.file_manager:
            self.file_manager.copy_storage(target_dir)
        
        root = RootAnalysis(uuid=new_uuid, storage_dir=target_dir)
        root.load()
        root.uuid = new_uuid
        root.save()
        return root

    def move(self, dest_dir: str) -> bool:
        """Moves the storage_dir of this RootAnalysis to another directory."""
        assert isinstance(dest_dir, str) and dest_dir
        assert self.storage_dir

        # we must be locked for this to work
        #if not self.is_locked():
            #raise RuntimeError("tried to move unlocked analysis {}".format(self))

        if os.path.exists(dest_dir):
            raise RuntimeError(f"unable to move {self}: destination directory {dest_dir} already exists")

        # make sure we're serialized to storage first
        self.save()

        # use file manager to move storage
        if self.file_manager:
            self.file_manager.move_storage(dest_dir)

        logging.debug(f"moved {self} from {self.storage_dir} to {dest_dir}")
        #self.storage_dir = dest_dir
        self.save() # save with the new storage_dir set
        return True

    def delete(self):
        """Deletes everything contained in the storage_dir and marks this RootAnalysis as deleted."""
        self.file_manager.delete_storage()

    def __str__(self):
        return "RootAnalysis({})".format(self.uuid)

    def iterate_all_references(self, target: Union[Analysis, Observable]):
        return self.analysis_tree_manager.iterate_all_references(target)

    @property   
    def all_analysis(self):
        """Returns the list of all Analysis performed for this Alert."""
        return self.analysis_tree_manager.all_analysis

    @property   
    def all_non_root_analysis(self):
        """Returns the list of all Analysis performed for this Alert."""
        return self.analysis_tree_manager.all_non_root_analysis

    def get_analysis_by_type(self, a_type):
        """Returns the list of all Analysis of a given type()."""
        return self.analysis_tree_manager.get_analysis_by_type(a_type)

    @property
    def all_observables(self) -> list[Observable]:
        """Returns the list of all Observables discovered for this Alert."""
        return self.analysis_tree_manager.all_observables

    def get_observables_by_type(self, o_type: str) -> list[Observable]:
        """Returns the list of Observables that match the given type."""
        return self.analysis_tree_manager.get_observables_by_type(o_type)

    def find_observable(self, criteria: Callable[[Observable], bool]) -> Optional[Observable]:
        return self.analysis_tree_manager.find_observable(criteria)

    def find_observables(self, criteria: Callable[[Observable], bool]) -> list[Observable]:
        return self.analysis_tree_manager.find_observables(criteria)

    @property
    def all(self) -> list[Union[Analysis, Observable]]:
        """Returns the list of all Observables and Analysis for this RootAnalysis."""
        return self.analysis_tree_manager.all_objects

    @property
    def all_tags(self):
        """Return all unique tags for the entire Alert."""
        return self.analysis_tree_manager.get_all_tags()

    def get_observable(self, uuid):
        """Returns the Observable object for the given uuid."""
        return self.analysis_tree_manager.get_observable_by_id(uuid)

    def get_observable_by_spec(self, o_type, o_value, o_time=None):
        """Returns the Observable object by type and value, and optionally time, or None if it cannot be found."""
        return self.analysis_tree_manager.get_observable_by_spec(o_type, o_value, o_time)

    @property
    def all_detection_points(self):
        """Returns all DetectionPoint objects found in any DetectableObject in the heiarchy."""
        result = []
        for a in self.all_analysis:
            result.extend(a.detections)
        for o in self.all_observables:
            result.extend(o.detections)

        return result

    def has_detections(self):
        """Returns True if this RootAnalysis could become an Alert (has at least one DetectionPoint somewhere.)"""
        if self.has_detection_points():
            return True
        for a in self.all_analysis:
            if a.has_detection_points():
                return True
        for o in self.all_observables:
            if o.has_detection_points():
                return True

    def create_file_path(self, relative_path: str) -> str:
        """Creates a file path relative to the file subdirectory of the root analysis.
        Creates any required subdirectories."""
        return self.file_manager.create_file_path(relative_path)

def load_root(dir: str) -> RootAnalysis:
    """Loads the RootAnalysis from the given directory. Returns the new RootAnalysis."""
    root = RootAnalysis(storage_dir=dir)
    root.load()
    root.load_details()
    return root

def load_file_observable(storage_dir: str, observable_uuid: str) -> Optional["FileObservable"]:
    """Returns a single detached FileObservable from a saved RootAnalysis, or None.

    load_root() rehydrates every observable and analysis in the alert, which on a large
    one costs hundreds of milliseconds -- wasted work for a caller that only needs one
    file's location on disk (see app/analysis/views/image.py, which the alert page hits
    once per image it renders).

    The returned observable is detached: it has a file manager, so path/exists/mime_type
    work, but it is not attached to a RootAnalysis and its analysis tree is not built.
    Anything that needs to walk analyses must use load_root() instead.

    Returns None if the alert has no readable JSON, or the uuid is not a file observable
    in it.
    """
    # local import: saq.observables.file imports from saq.analysis, so a module-level
    # import here is circular (same reason as analysis_tree_manager.py)
    from saq.observables.file import FileObservable

    file_manager = create_file_manager(storage_dir)

    try:
        with open(file_manager.json_path, 'r') as fp:
            parsed_json = json.load(fp)
    except (OSError, ValueError) as e:
        logging.warning("unable to read %s: %s", file_manager.json_path, e)
        return None

    observable_json = (parsed_json.get(KEY_OBSERVABLE_STORE) or {}).get(observable_uuid)
    if not observable_json:
        return None

    if observable_json.get(KEY_OBSERVABLE_TYPE) != F_FILE:
        return None

    observable = FileObservable.from_json(observable_json)
    observable.inject_file_manager(file_manager)
    return observable

def _get_failed_analysis_key(observable_type, observable_value):
    """Utility function that returns the key used to look up if analysis failed or not."""
    return f'{observable_type}:{observable_value}'

class Submission:
    def __init__(
        self,
        root: RootAnalysis,
        group_assignments: Optional[list]=None,
        key: Optional[str]=None,
    ):
        self.root = root

        # key, group_assignments and group_value are all stored on the root rather than here,
        # so they survive being staged to disk and reconstructed after a restart. only assign
        # when a value was actually supplied - reconstructing a Submission from a loaded root
        # (Submission(root)) must not wipe what came back off disk.
        if key is not None:
            self.key = key

        if group_assignments is not None:
            self.group_assignments = group_assignments

        # XXX this is a hack for now...
        self.files_prepared = False # sets set to True once we've "prepared" the files

    @property
    def key(self) -> Optional[str]:
        """The deduplication key for this submission, or None if it is not deduplicated."""
        return self.root.submission_key

    @key.setter
    def key(self, value: Optional[str]):
        self.root.submission_key = value

    @property
    def group_assignments(self) -> Optional[list]:
        """List of RemoteNodeGroup.name values. Empty or None means send to all configured groups."""
        return self.root.group_assignments

    @group_assignments.setter
    def group_assignments(self, value: Optional[list]):
        self.root.group_assignments = value

    @property
    def group_value(self) -> Optional[str]:
        """The group_by value that produced this submission, or None if the hunt is not grouped."""
        return self.root.group_value

    @group_value.setter
    def group_value(self, value: Optional[str]):
        self.root.group_value = value

    @property
    def queued_time(self) -> Optional[float]:
        """Wall clock (epoch seconds) at which this submission was staged for collection.
        Stored on the root so it survives the staging directory round trip."""
        return self.root.queued_at

    @queued_time.setter
    def queued_time(self, value: Optional[float]):
        self.root.queued_at = value

    @property
    def queue_age(self) -> Optional[float]:
        """Returns the number of seconds since this submission was queued, or None if it
        was never stamped with queued_time. Clamped at zero because this is wall clock and a
        clock adjustment between staging and collection could otherwise report a negative age."""
        if self.queued_time is None:
            return None

        return max(0.0, time.time() - self.queued_time)

    def __str__(self):
        return f"Submission({self.root} ({self.root.analysis_mode}))"