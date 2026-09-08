from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface


class LocalNodeManager(NodeManagerInterface):
    """LocalNodeManager implementation that performs no real functions because in local mode there are no nodes."""
    
    def __init__(self, configuration_manager: ConfigurationManager) -> None:
        """Initialize the LocalNodeManager with configuration.
        
        Args:
            configuration_manager: ConfigurationManager instance for loading configuration
        """
        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config

    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from. Empty in local mode."""
        return []
    
    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        return self.config.local_analysis_modes
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        return self.config.excluded_analysis_modes
    
    def should_update_node_status(self) -> bool:
        """Returns True if it's time to update node status. Always False in local mode."""
        return False
    
    def update_node_status(self) -> None:
        """Updates the last_update field of the node table for this node. No-op in local mode."""
        pass
    
    def initialize_node(self) -> None:
        """Initialize this node in the database and configure analysis modes. No-op in local mode."""
        pass

    def set_status(self, status: str) -> None:
        """Sets the status of this node in the database. No-op in local mode."""
        pass

    def clear_node_locks(self, reason: str) -> int:
        """No-op in local mode: locks are held in process and die with it."""
        return 0


    def execute_primary_node_routines(self) -> None:
        """Executes primary node routines and may become the primary node. No-op in local mode."""
        pass
    
    def update_node_status_and_execute_primary_routines(self) -> None:
        """Updates node status and executes primary node routines if needed. No-op in local mode."""
        pass