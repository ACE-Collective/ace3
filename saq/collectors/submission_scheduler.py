import logging
import os
from typing import List

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.remote_node import RemoteNodeGroup
from saq.collectors.submission_file_manager import SubmissionFileManager


class SubmissionScheduler:
    """Handles the orchestration of taking a Submission and preparing it for analysis."""
    
    def __init__(self, workload_repository, file_manager: SubmissionFileManager, workload_type_id: int):
        """
        Initialize the SubmissionScheduler.
        
        Args:
            workload_repository: Repository for database operations
            file_manager: Manager for file system operations
            workload_type_id: The ID of the workload type
        """
        self.workload_repository = workload_repository
        self.file_manager = file_manager
        self.workload_type_id = workload_type_id
    
    def schedule_submission(self, submission: Submission, remote_node_groups: List[RemoteNodeGroup]) -> int:
        """
        Schedule a submission for processing.
        
        This orchestrates the complete process of preparing a submission for analysis:
        1. Prepares submission files by moving them to the incoming directory
        2. Inserts the workload into the database
        3. Assigns the work to appropriate remote node groups
        
        Args:
            submission: The Submission object to schedule
            remote_node_groups: List of available RemoteNodeGroup objects
            
        Returns:
            int: The work_id assigned to this submission
        """
        assert isinstance(submission, Submission)
        assert isinstance(submission.root, RootAnalysis)
        
        logging.info(f"scheduling {submission.root.description} mode {submission.root.analysis_mode}")
        
        # Prepare the submission files using the file manager
        self.file_manager.prepare_submission_files(submission)
        
        # Insert the workload into the database
        work_id = self._insert_workload(submission, remote_node_groups)
        
        logging.info(f"scheduled {submission.root.description} mode {submission.root.analysis_mode} work_id {work_id}")
        return work_id
    
    def _insert_workload(self, submission: Submission, remote_node_groups: List[RemoteNodeGroup]) -> int:
        """
        Insert the workload into the database and assign it to remote node groups.
        
        Args:
            submission: The Submission object to insert
            remote_node_groups: List of available RemoteNodeGroup objects
            
        Returns:
            int: The work_id assigned to this submission
        """
        # Insert the workload into the database
        work_id = self.workload_repository.insert_workload(
            self.workload_type_id, 
            submission.root.analysis_mode, 
            submission.root.uuid
        )
        
        # Determine which node groups to assign this work to
        target_groups = self._determine_target_groups(submission, remote_node_groups)
        
        # Assign this work to each target group
        for remote_node_group in target_groups:
            logging.info(f"assigning {work_id} to remote node group {remote_node_group}")
            self.workload_repository.assign_work_to_group(work_id, remote_node_group.group_id)
        
        return work_id
    
    def _determine_target_groups(self, submission: Submission, remote_node_groups: List[RemoteNodeGroup]) -> List[RemoteNodeGroup]:
        """
        Determine which remote node groups should receive this submission.
        
        Args:
            submission: The Submission object
            remote_node_groups: List of available RemoteNodeGroup objects
            
        Returns:
            List[RemoteNodeGroup]: The groups that should receive this submission
        """
        # Start with all groups as candidates
        target_groups = remote_node_groups
        
        # If the submission has specific group assignments, filter to those
        if submission.group_assignments:
            target_groups = [ng for ng in remote_node_groups if ng.name in submission.group_assignments]
            
            # If filtering results in no groups, fall back to all groups
            if not target_groups:
                logging.error(f"group assignment {submission.group_assignments} does not map to any known groups")
                target_groups = remote_node_groups
        
        return target_groups 