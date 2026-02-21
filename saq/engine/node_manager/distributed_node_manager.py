from datetime import datetime, timedelta
import logging
import os
import socket
from typing import Optional

from saq.configuration.config import get_config, get_engine_config
from saq.constants import ENV_ACE_IS_PRIMARY_NODE
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.database.util.locking import clear_expired_locks
from saq.database.util.node import (
    assign_node_analysis_modes,
    initialize_node,
)
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.environment import get_global_runtime_settings
from saq.error import report_exception


def update_node_status(
    location: Optional[str] = None, node_id: Optional[int] = None
):
    """Updates the last_update field of the node table for this node."""

    if location is None:
        location = get_global_runtime_settings().api_prefix

    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(
                db,
                cursor,
                """UPDATE nodes SET last_update = NOW(), location = %s WHERE id = %s""",
                (location, node_id),
                commit=True,
            )

            logging.info(
                "updated node %s (%s)", node_id, location
            )

    except Exception as e:
        logging.error(f"unable to update node {node_id} status: {e}")
        report_exception()


def translate_node(node: str) -> str:
    """Return the correct node taking node translation into account."""
    for key in get_config().node_translation.keys():
        src, target = get_config().node_translation[key].split(",")
        if node == src:
            logging.debug("translating node {} to {}".format(node, target))
            return target

    return node


class DistributedNodeManager(NodeManagerInterface):
    """Manages node status updates, primary node election, and local/cluster node configuration for the ACE cluster."""

    def __init__(self, configuration_manager: ConfigurationManager):
        """Initialize the NodeManager with node configuration.
        
        Args:
            target_nodes: List of target nodes this engine will pull work from
            local_analysis_modes: List of analysis modes this engine supports
            excluded_analysis_modes: List of analysis modes this engine excludes
        """

        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config

        # how often do we update the nodes database table for this engine (in seconds)
        self.node_status_update_frequency = get_engine_config().node_status_update_frequency

        # and then when will be the next time we make this update?
        self.next_status_update_time = None

        # we just cache the current hostname of this node here
        self.hostname = socket.gethostname()

        # determine if this node is the primary node from the environment variable
        self.is_primary_node = os.environ.get(ENV_ACE_IS_PRIMARY_NODE, "1") == "1"

    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from."""
        return self.config.target_nodes

    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        return self.config.local_analysis_modes
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        return self.config.excluded_analysis_modes

    def should_update_node_status(self) -> bool:
        """Returns True if it's time to update node status."""
        return (
            self.next_status_update_time is None
            or datetime.now() >= self.next_status_update_time
        )

    def update_node_status(self):
        """Updates the last_update field of the node table for this node."""
        update_node_status(get_global_runtime_settings().api_prefix, get_global_runtime_settings().saq_node_id)

    def initialize_node(self):
        """Initialize this node in the database and configure analysis modes."""
        # insert this engine as a node (if it isn't already)
        initialize_node()

        # assign analysis mode inclusion and exclusion settings
        assign_node_analysis_modes(
            get_global_runtime_settings().saq_node_id,
            self.local_analysis_modes,
            self.excluded_analysis_modes,
        )

        # clear any outstanding locks left over from a previous execution
        # we use the lock_owner columns of the locks table to determine if any locks are outstanding for this node
        # the format of the value of the column is node-mode-pid
        # ace-qa2.local-email-25203
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM locks WHERE lock_owner LIKE CONCAT(%s, '-%%')",
                (get_global_runtime_settings().saq_node,),
            )
            result = cursor.fetchone()
            if result:
                logging.info(f"clearing {result[0]} locks from previous execution")
                execute_with_retry(
                    db,
                    cursor,
                    "DELETE FROM locks WHERE lock_owner LIKE CONCAT(%s, '-%%')",
                    (get_global_runtime_settings().saq_node,),
                    commit=True,
                )

        # set the is_primary flag in the database based on the environment variable
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(
                db,
                cursor,
                "UPDATE nodes SET is_primary = %s WHERE id = %s",
                (1 if self.is_primary_node else 0, get_global_runtime_settings().saq_node_id),
                commit=True,
            )

        if self.is_primary_node:
            logging.info("node %s is configured as the primary node", get_global_runtime_settings().saq_node)
        else:
            logging.info("node %s is configured as a non-primary node", get_global_runtime_settings().saq_node)

    def execute_primary_node_routines(self):
        """Executes primary node routines if this node is configured as the primary node via the ACE_IS_PRIMARY_NODE environment variable."""
        try:
            if not self.is_primary_node:
                logging.debug("node %s is not primary - skipping primary node routines", get_global_runtime_settings().saq_node)
                return

            # do primary node stuff
            # clear any outstanding locks
            clear_expired_locks()

        except Exception as e:
            logging.error("error executing primary node routines: %s", e)
            report_exception()

    def update_node_status_and_execute_primary_routines(self):
        """Updates node status and executes primary node routines if needed."""
        if self.should_update_node_status():
            self.update_node_status()
            self.execute_primary_node_routines()

            # when will we do this again?
            self.next_status_update_time = datetime.now() + timedelta(
                seconds=self.node_status_update_frequency
            ) 