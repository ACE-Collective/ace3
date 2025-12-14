import logging
from typing import Optional

from saq.collectors.remote_node import RemoteNodeGroup
from saq.configuration import get_config
from saq.environment import get_global_runtime_settings


class GroupConfigurationLoader:
    """Loads RemoteNodeGroup configurations from the ACE configuration file."""
    
    def __init__(self, workload_type_id: int, service_shutdown_event, workload_repository):
        """
        Initialize the GroupConfigurationLoader.
        
        Args:
            workload_type_id: The workload type ID for the groups
            service_shutdown_event: Event for service shutdown signaling
            workload_repository: Repository for creating work distribution groups
        """
        self.workload_type_id = workload_type_id
        self.service_shutdown_event = service_shutdown_event
        self.workload_repository = workload_repository

    def load_groups(self) -> list[RemoteNodeGroup]:
        """
        Loads groups from the ACE configuration file.
        
        Returns:
            List of configured RemoteNodeGroup instances
        """
        remote_node_groups = []
        
        for collection_group_config in get_config().collection_groups:

            if not collection_group_config.enabled:
                logging.debug(f"collection group {collection_group_config.name} disabled")
                continue

            target_nodes = []
            if collection_group_config.target_nodes:
                for node in collection_group_config.target_nodes:
                    if not node:  # pragma: no cover
                        continue

                    if node == "LOCAL":
                        node = get_global_runtime_settings().saq_node

                    target_nodes.append(node)

            logging.info("loaded collection group {}".format(collection_group_config))

            remote_node_group = self._create_group(
                collection_group_config.name,
                collection_group_config.coverage,
                collection_group_config.full_delivery,
                collection_group_config.company_id,
                collection_group_config.database,
                target_nodes=target_nodes,
                thread_count=collection_group_config.thread_count
            )
            
            remote_node_groups.append(remote_node_group)
            logging.info("added {}".format(remote_node_group))
            
        return remote_node_groups

    def _create_group(
        self, 
        name: str, 
        coverage: int, 
        full_delivery: bool, 
        company_id: int, 
        database: str, 
        batch_size: Optional[int] = 32,
        target_node_as_company_id: Optional[int] = None,
        target_nodes: Optional[list] = None,
        thread_count: Optional[int] = 1
    ) -> RemoteNodeGroup:
        """
        Create a RemoteNodeGroup instance.
        
        Args:
            name: Group name
            coverage: Coverage value
            full_delivery: Whether full delivery is enabled
            company_id: Company ID
            database: Database name
            batch_size: Batch size (default: 32)
            target_node_as_company_id: Target node as company ID (optional)
            target_nodes: List of target nodes (optional)
            thread_count: Thread count (default: 1)
            
        Returns:
            Configured RemoteNodeGroup instance
        """
        group_id = self.workload_repository.create_or_get_work_distribution_group(name)

        remote_node_group = RemoteNodeGroup(
            name, 
            coverage, 
            full_delivery, 
            company_id, 
            database, 
            group_id, 
            self.workload_type_id, 
            self.service_shutdown_event, 
            batch_size=batch_size,
            target_node_as_company_id=target_node_as_company_id,
            target_nodes=target_nodes,
            thread_count=thread_count
        )
        
        return remote_node_group 