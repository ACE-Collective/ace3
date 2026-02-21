from typing import Protocol, runtime_checkable

from saq.engine.configuration_manager import ConfigurationManager


@runtime_checkable
class NodeManagerInterface(Protocol):
    """Protocol interface for NodeManager implementations."""
    
    def __init__(self, configuration_manager: ConfigurationManager) -> None:
        """Initialize the NodeManager with node configuration.
        
        Args:
            configuration_manager: ConfigurationManager instance for loading configuration
        """
        ...
    
    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from."""
        ...
    
    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        ...
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        ...
    
    def should_update_node_status(self) -> bool:
        """Returns True if it's time to update node status."""
        ...
    
    def update_node_status(self) -> None:
        """Updates the last_update field of the node table for this node."""
        ...
    
    def initialize_node(self) -> None:
        """Initialize this node in the database and configure analysis modes."""
        ...
    
    def execute_primary_node_routines(self) -> None:
        """Executes primary node routines if this node is configured as primary via the ACE_IS_PRIMARY_NODE environment variable."""
        ...
    
    def update_node_status_and_execute_primary_routines(self) -> None:
        """Updates node status and executes primary node routines if needed."""
        ...
