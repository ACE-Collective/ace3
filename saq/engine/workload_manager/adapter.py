from typing import Optional

from saq.analysis.root import RootAnalysis
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.workload_manager.interface import WorkloadManagerInterface


class WorkloadManagerAdapter(WorkloadManagerInterface):
    """Adapter that implements WorkloadManagerInterface and delegates to WorkloadManager."""
    
    def __init__(
        self,
        workload_manager: WorkloadManagerInterface,
    ):
        """Initialize the WorkloadManagerAdapter.
        
        Args:
            workload_manager: Any implementation of WorkloadManagerInterface to delegate operations to
        """
        self._workload_manager = workload_manager

    @property
    def delayed_analysis_queue_size(self) -> int:
        """Returns the size of the delayed analysis queue (for this engine.)"""
        return self._workload_manager.delayed_analysis_queue_size

    @property
    def workload_queue_size(self) -> int:
        """Returns the size of the workload queue (for this node.)"""
        return self._workload_manager.workload_queue_size

    @property
    def delayed_analysis_queue_is_empty(self) -> bool:
        """Returns True if the delayed analysis queue is empty, False otherwise."""
        return self._workload_manager.delayed_analysis_queue_is_empty

    @property
    def workload_queue_is_empty(self) -> bool:
        """Returns True if the work queue is empty, False otherwise."""
        return self._workload_manager.workload_queue_is_empty

    def add_workload(self, root: RootAnalysis) -> None:
        """Add a RootAnalysis to the workload queue."""
        return self._workload_manager.add_workload(root)

    def transfer_work_target(self, uuid: str, node_id: int) -> Optional[RootAnalysis]:
        """Moves the given work target from the given remote node to the local node.
        Returns the (unloaded) RootAnalysis for the object transferred."""
        return self._workload_manager.transfer_work_target(uuid, node_id)

    def get_delayed_analysis_work_target(self) -> Optional[DelayedAnalysisRequest]:
        """Returns the next DelayedAnalysisRequest that is ready, or None if none are ready."""
        return self._workload_manager.get_delayed_analysis_work_target()

    def get_work_target(self, priority: bool = True, local: bool = True) -> Optional[RootAnalysis]:
        """Returns the next work item available.
        
        Args:
            priority: If True, only work items with analysis_modes that match the analysis_mode_priority
            local: If True, only work items on the local node are selected. Remote work items are moved to become local.
            
        Returns:
            A valid work item, or None if none are available.
        """
        return self._workload_manager.get_work_target(priority, local)

    def get_next_work_target(self):
        """Get the next available work target using priority and locality preferences."""
        return self._workload_manager.get_next_work_target()

    def clear_work_target(self, target):
        """Clear a work target from the database and release its lock.
        
        Args:
            target: The work target to clear (RootAnalysis or DelayedAnalysisRequest)
        """
        return self._workload_manager.clear_work_target(target)

    def add_delayed_analysis_request(self, root, observable, analysis_module, hours, minutes, seconds) -> bool:
        """Add a delayed analysis request.

        Returns True if the request was recorded, False if it was not."""
        return self._workload_manager.add_delayed_analysis_request(root, observable, analysis_module, hours, minutes, seconds)

    def clear_delayed_analysis_requests(self, root):
        """Clear all delayed analysis requests for the given RootAnalysis object."""
        return self._workload_manager.clear_delayed_analysis_requests(root) 