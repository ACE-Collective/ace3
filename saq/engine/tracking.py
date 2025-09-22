from datetime import datetime
import os
import pickle
import shutil
from typing import Optional, Union
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.environment import get_data_dir
from saq.modules.interfaces import AnalysisModuleInterface


TRACKER_MESSAGE_TYPE_WORK_TARGET = "work_target"
TRACKER_MESSAGE_TYPE_MODULE = "module"
TRACKER_MESSAGE_TYPE_CLEAR_MODULE = "clear_module"
TRACKER_MESSAGE_TYPE_CLEAR_TARGET = "clear_target"


class TrackingMessage:
    """Utility class used to track what is currently being processed in the child process."""

    def __init__(self, type):
        self.type = type

    def __str__(self):
        return f"TrackingMessage({self.type})"


class WorkTargetTrackingMessage(TrackingMessage):
    """A message indicating that analysis has started on a given target.
    The target can be either a storage directory or a DelayedAnalysisRequest."""

    def __init__(self, target):
        super().__init__(TRACKER_MESSAGE_TYPE_WORK_TARGET)
        if isinstance(target, DelayedAnalysisRequest):
            self.target = target.storage_dir

        self.target = target

    def __str__(self):
        return f"WorkTargetTrackingMessage({self.target})"


class AnalysisModuleTrackingMessage(TrackingMessage):
    """A message indicating that analysis has started by the given module on the given observable.
    Args:
         module_path: the result of MODULE_PATH
         observable_id: Observable.uuid
         maximum_analysis_time: the maximum amount of time (in seconds) the module is allowed to execute
         observable_type: Observable.type
         observable_value: Observable.value

     NOTE: We pass the type and value here because the analysis process may not have written the
     observable to storage before crashing.
    """

    def __init__(
        self,
        module_path,
        observable_id,
        maximum_analysis_time,
        observable_type,
        observable_value,
    ):
        super().__init__(TRACKER_MESSAGE_TYPE_MODULE)
        self.module_path = module_path
        self.observable_id = observable_id
        self.maximum_analysis_time = maximum_analysis_time
        self.observable_type = observable_type
        self.observable_value = observable_value
        self.start_time = datetime.now()

    def __str__(self):
        return (
            f"AnalysisModuleTrackingMessage(module={self.module_path},"
            f"observable_id={self.observable_id}"
            f"maximum_analysis_time={self.maximum_analysis_time}"
            f"observable_type={self.observable_type}"
            f"observable_value={self.observable_value})"
        )
    
class TrackingMessageManager:

    def __init__(self, name: str):
        #
        # we keep track of what is currently being worked on by reporting it to the Worker class
        # from the Engine class that is executing from worker_loop
        #

        self.name = name
        self.tracking_dir = os.path.join(get_data_dir(), "var", "tracking", name)
        os.makedirs(self.tracking_dir, exist_ok=True)

        self.target_tracking_path = os.path.join(self.tracking_dir, "target")
        self.module_tracking_path = os.path.join(self.tracking_dir, "module")
        
    def track_current_work_target(self, target: Union[RootAnalysis, DelayedAnalysisRequest]):
        assert isinstance(target, (RootAnalysis, DelayedAnalysisRequest))
        with open(self.target_tracking_path, "wb") as fp:
            pickle.dump(target.storage_dir, fp)

        # new target means we're starting a new analysis
        self.clear_module_tracking()

    def get_current_work_target(self) -> Optional[str]:
        if not os.path.exists(self.target_tracking_path):
            return None

        with open(self.target_tracking_path, "rb") as fp:
            return pickle.load(fp)

    def clear_target_tracking(self):
        if os.path.exists(self.target_tracking_path):
            os.remove(self.target_tracking_path)

    def track_current_analysis_module(self, module: AnalysisModuleInterface, observable: Observable):
        with open(self.module_tracking_path, "wb") as fp:
            pickle.dump(
                AnalysisModuleTrackingMessage(
                    MODULE_PATH(module),
                    observable.uuid,
                    module.maximum_analysis_time,
                    observable.type,
                    observable.value,
                ),
                fp
            )
    
    def get_current_analysis_module(self) -> Optional[AnalysisModuleTrackingMessage]:
        if not os.path.exists(self.module_tracking_path):
            return None

        with open(self.module_tracking_path, "rb") as fp:
            return pickle.load(fp)

    def clear_module_tracking(self):
        if os.path.exists(self.module_tracking_path):
            os.remove(self.module_tracking_path)

def clear_all_tracking():
    tracking_dir = os.path.join(get_data_dir(), "var", "tracking")
    if os.path.exists(tracking_dir):
        shutil.rmtree(tracking_dir)
