from abc import ABC, abstractmethod
from typing import Optional

from saq.analysis.root import RootAnalysis
from saq.engine.delayed_analysis import DelayedAnalysisRequest


class WorkloadManagerInterface(ABC):
    """Interface for workload and queue operations for the analysis engine."""
    
    @property
    @abstractmethod
    def delayed_analysis_queue_size(self) -> int:
        """Returns the size of the delayed analysis queue (for this engine.)"""
        pass

    @property
    @abstractmethod
    def workload_queue_size(self) -> int:
        """Returns the size of the workload queue (for this node.)"""
        pass

    @property
    @abstractmethod
    def delayed_analysis_queue_is_empty(self) -> bool:
        """Returns True if the delayed analysis queue is empty, False otherwise."""
        pass

    @property
    @abstractmethod
    def workload_queue_is_empty(self) -> bool:
        """Returns True if the work queue is empty, False otherwise."""
        pass

    @abstractmethod
    def add_workload(self, root: RootAnalysis) -> None:
        """Add a RootAnalysis to the workload queue."""
        pass

    @abstractmethod
    def transfer_work_target(self, uuid: str, node_id: int) -> Optional[RootAnalysis]:
        """Moves the given work target from the given remote node to the local node.
        Returns the (unloaded) RootAnalysis for the object transferred."""
        pass

    @abstractmethod
    def get_delayed_analysis_work_target(self) -> Optional[DelayedAnalysisRequest]:
        """Returns the next DelayedAnalysisRequest that is ready, or None if none are ready."""
        pass

    @abstractmethod
    def get_work_target(self, priority: bool = True, local: bool = True) -> Optional[RootAnalysis]:
        """Returns the next work item available.
        
        Args:
            priority: If True, only work items with analysis_modes that match the analysis_mode_priority
            local: If True, only work items on the local node are selected. Remote work items are moved to become local.
            
        Returns:
            A valid work item, or None if none are available.
        """
        pass

    @abstractmethod
    def get_next_work_target(self):
        """Get the next available work target using priority and locality preferences."""
        pass

    @abstractmethod
    def clear_work_target(self, target):
        """Clear a work target from the database and release its lock.
        
        Args:
            target: The work target to clear (RootAnalysis or DelayedAnalysisRequest)
        """
        pass

    @abstractmethod
    def add_delayed_analysis_request(self, root, observable, analysis_module, hours, minutes, seconds) -> bool:
        """Add a delayed analysis request.

        Returns True if the request was recorded, False if it was not."""
        pass

    @abstractmethod
    def clear_delayed_analysis_requests(self, root):
        """Clear all delayed analysis requests for the given RootAnalysis object."""
        pass 