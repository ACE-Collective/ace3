import logging
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from saq.analysis.root import RootAnalysis
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.lock_manager.interface import LockManagerInterface
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.workload_manager.interface import WorkloadManagerInterface


class MemoryWorkloadManager(WorkloadManagerInterface):
    """Manages workload and queue operations for the analysis engine keeping
    everything in memory instead of using the database."""

    def __init__(
        self,
        configuration_manager: ConfigurationManager,
        node_manager: NodeManagerInterface,
        lock_manager: LockManagerInterface,
        analysis_mode_priority: Optional[str] = None,
    ):
        """Initialize the MemoryWorkloadManager.
        
        Args:
            configuration_manager: ConfigurationManager instance for loading configuration
            node_manager: NodeManager instance for loading node configuration
            lock_manager: Distributed lock manager for acquiring/releasing work item locks
            analysis_mode_priority: Primary analysis mode for this worker
        """
        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config
        self.node_manager = node_manager
        self.lock_manager = lock_manager
        self.analysis_mode_priority = analysis_mode_priority
        
        # In-memory storage for workload items
        # Structure: {uuid: (root_analysis, node_id, analysis_mode, insert_date, company_id, storage_dir)}
        self._workload_items = {}
        
        # In-memory storage for delayed analysis requests
        # Structure: {id: DelayedAnalysisRequest}
        self._delayed_analysis_items = {}
        self._delayed_analysis_counter = 0
        
        # Track current node ID (simulating G_SAQ_NODE_ID)
        self._current_node_id = 1
        self._current_company_id = 1

    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        return self.config.local_analysis_modes
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        return self.config.excluded_analysis_modes

    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from."""
        return self.node_manager.target_nodes

    @property
    def delayed_analysis_queue_size(self) -> int:
        """Returns the size of the delayed analysis queue (for this engine.)"""
        count = 0
        return len(self._delayed_analysis_items)

    @property
    def workload_queue_size(self) -> int:
        """Returns the size of the workload queue (for this node.)"""
        count = 0
        for uuid, (root, node_id, analysis_mode, insert_date, company_id, storage_dir) in self._workload_items.items():
            # Apply same filtering logic as database version
            if node_id != self._current_node_id:
                continue
                
            if company_id != self._current_company_id:
                continue
                    
            if self.local_analysis_modes:
                if analysis_mode not in self.local_analysis_modes:
                    continue
                    
            count += 1
        return count

    @property
    def delayed_analysis_queue_is_empty(self) -> bool:
        """Returns True if the delayed analysis queue is empty, False otherwise."""
        return self.delayed_analysis_queue_size == 0

    @property
    def workload_queue_is_empty(self) -> bool:
        """Returns True if the work queue is empty, False otherwise."""
        return self.workload_queue_size == 0

    def add_workload(self, root: RootAnalysis) -> None:
        """Add a RootAnalysis to the workload queue."""
        assert isinstance(root, RootAnalysis)
        # Store workload item in memory
        self._workload_items[root.uuid] = (
            root,
            self._current_node_id,
            root.analysis_mode,
            datetime.now(),
            getattr(root, 'company_id', self._current_company_id),
            root.storage_dir
        )
        
        logging.info("added {} to workload with analysis mode {} company_id {}".format(
            root.uuid, root.analysis_mode, getattr(root, 'company_id', self._current_company_id)))

    def transfer_work_target(self, uuid: str, node_id: int) -> Optional[RootAnalysis]:
        """Moves the given work target from the given remote node to the local node.
        Returns the (unloaded) RootAnalysis for the object transferred."""
        # In memory implementation, we don't actually transfer between nodes
        # Just update the node_id to simulate transfer
        if uuid in self._workload_items:
            root, old_node_id, analysis_mode, insert_date, company_id, storage_dir = self._workload_items[uuid]
            # Update to local node
            self._workload_items[uuid] = (
                root,
                self._current_node_id,
                analysis_mode,
                insert_date,
                company_id,
                storage_dir
            )
            logging.info(f"transferred work item {uuid} from node {old_node_id} to local node {self._current_node_id}")
            return RootAnalysis(uuid=uuid, storage_dir=storage_dir)
        
        logging.error(f"work item {uuid} not found for transfer")
        return None

    def get_delayed_analysis_work_target(self) -> Optional[DelayedAnalysisRequest]:
        """Returns the next DelayedAnalysisRequest that is ready, or None if none are ready."""
        now = datetime.now()
        
        # Find ready delayed analysis items, sorted by delayed_until
        ready_items = []
        for request_id, request in self._delayed_analysis_items.items():
            # Check if ready and not locked
            if request.next_analysis <= now:
                # Check if not locked
                if not self.lock_manager.acquire_lock(request.uuid):
                    continue
                    
                ready_items.append((request.next_analysis, request_id, request))
        
        # Sort by delayed_until (next_analysis) and return first
        if ready_items:
            ready_items.sort(key=lambda x: x[0])
            _, request_id, request = ready_items[0]
            
            # Release locks for items we didn't select
            for _, other_id, other_request in ready_items[1:]:
                self.lock_manager.release_lock(other_request.uuid)
                
            return request
            
        return None

    def get_work_target(self, priority: bool = True, local: bool = True) -> Optional[RootAnalysis]:
        """Returns the next work item available.
        
        Args:
            priority: If True, only work items with analysis_modes that match the analysis_mode_priority
            local: If True, only work items on the local node are selected. Remote work items are moved to become local.
            
        Returns:
            A valid work item, or None if none are available.
        """
        # Build list of eligible work items
        eligible_items = []
        
        for uuid, (root, node_id, analysis_mode, insert_date, company_id, storage_dir) in self._workload_items.items():
            # Apply filtering logic
            if self.analysis_mode_priority and priority:
                if analysis_mode != self.analysis_mode_priority:
                    continue
                    
            if local:
                if node_id != self._current_node_id:
                    continue
            else:
                # Remote work - check company_id
                if company_id != self._current_company_id:
                    continue
                    
            if self.local_analysis_modes:
                if analysis_mode not in self.local_analysis_modes:
                    continue
            elif self.excluded_analysis_modes:
                if analysis_mode in self.excluded_analysis_modes:
                    continue
                    
            # Target nodes filtering (for non-local)
            if self.target_nodes:
                # In memory version, we don't have actual node names, so skip this check
                pass
                
            eligible_items.append((uuid, root, node_id, analysis_mode, insert_date, company_id, storage_dir))
        
        # Randomize order (like database version with RAND())
        random.shuffle(eligible_items)
        
        # Try to acquire lock for first available item
        for uuid, root, node_id, analysis_mode, insert_date, company_id, storage_dir in eligible_items[:128]:  # Limit like database version
            if not self.lock_manager.acquire_lock(uuid):
                continue
                
            # Double-check item still exists (race condition check)
            if uuid not in self._workload_items:
                logging.info(f"workload item for {uuid} was already processed")
                self.lock_manager.release_lock(uuid)
                continue
                
            # Handle remote work transfer
            if node_id != self._current_node_id:
                return self.transfer_work_target(uuid, node_id)
                
            logging.info(f"got workload item uuid {uuid} for analysis mode {analysis_mode} with lock {self.lock_manager.lock_uuid}")
            return RootAnalysis(uuid=uuid, storage_dir=storage_dir, analysis_mode=analysis_mode)
            
        return None

    def get_next_work_target(self):
        """Get the next available work target using priority and locality preferences."""
        try:
            # Get any delayed analysis work that is ready to be processed
            target = self.get_delayed_analysis_work_target()
            if target:
                return target

            if self.analysis_mode_priority:
                # Get any local work with high priority
                target = self.get_work_target(priority=True, local=True)
                if target:
                    return target

                # Get any work with high priority
                target = self.get_work_target(priority=True, local=False)
                if target:
                    return target

            # Get any available local work
            target = self.get_work_target(priority=False, local=True)
            if target:
                return target

            # Get any available work
            target = self.get_work_target(priority=False, local=False)
            if target:
                return target

        except Exception as e:
            logging.error("unable to get work target: {}".format(e))

        # No work available anywhere
        return None

    def clear_work_target(self, target):
        """Clear a work target from the database and release its lock.
        
        Args:
            target: The work target to clear (RootAnalysis or DelayedAnalysisRequest)
        """
        try:
            if isinstance(target, DelayedAnalysisRequest):
                # Remove from delayed analysis items
                if target.database_id in self._delayed_analysis_items:
                    del self._delayed_analysis_items[target.database_id]
            else:
                # Remove from workload items
                if target.uuid in self._workload_items:
                    del self._workload_items[target.uuid]

            # Release the lock using the lock manager
            self.lock_manager.release_lock(target.uuid)
                
            logging.debug(f"cleared work target {target}")

        except Exception as e:
            logging.error(f"unable to clear work target {target}: {e}")

    def add_delayed_analysis_request(self, root, observable, analysis_module, hours, minutes, seconds):
        """Add a delayed analysis request."""
        # Calculate next analysis time
        next_analysis = datetime.now() + timedelta(hours=hours, minutes=minutes, seconds=seconds)
        
        # Create request with unique ID
        self._delayed_analysis_counter += 1
        request_id = self._delayed_analysis_counter
        
        request = DelayedAnalysisRequest(
            uuid=root.uuid,
            observable_uuid=observable.id,
            analysis_module=analysis_module.config_section_name,
            next_analysis=next_analysis,
            storage_dir=root.storage_dir,
            database_id=request_id
        )
        
        # Store in memory
        self._delayed_analysis_items[request_id] = request
        
        logging.info(f"added delayed analysis request for {root.uuid} observable {observable.id} module {analysis_module} at {next_analysis}")
        return request

    def clear_delayed_analysis_requests(self, root):
        """Clear all delayed analysis requests for the given RootAnalysis object."""
        to_remove = []
        for request_id, request in self._delayed_analysis_items.items():
            if request.uuid == root.uuid:
                to_remove.append(request_id)
                
        for request_id in to_remove:
            del self._delayed_analysis_items[request_id]
            
        logging.debug(f"cleared {len(to_remove)} delayed analysis requests for {root.uuid}")
