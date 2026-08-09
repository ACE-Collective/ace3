import logging
import os
import shutil
from typing import Generator, Optional

from saq.analysis.root import RootAnalysis, Submission
from saq.configuration.config import get_config
from saq.environment import get_data_dir
from saq.util import create_directory


def get_staging_dir() -> str:
    """Returns the directory holding submissions that have been emitted but not yet collected."""
    return os.path.join(get_data_dir(), get_config().collection.staging_dir)


def get_staging_tmp_dir() -> str:
    """Returns the directory submissions are built in before being staged, creating it if needed.

    Collectors should create their RootAnalysis storage here so that publishing it is a rename
    rather than a copy, and so a submission that is still being built is never visible to the
    collection loop. This creates the directory because callers use it as an mkstemp target,
    and a collector can start producing before any CollectorService has initialized.
    """
    result = os.path.join(get_data_dir(), get_config().collection.staging_tmp_dir)
    create_directory(result)
    return result


class SubmissionFileManager:
    """Handles all file system operations for submissions.

    The staging directory is a durable queue: a root present in staging_dir is exactly one that a
    collector has emitted but that has not yet reached a terminal outcome. Submissions are built
    in staging_tmp_dir and renamed into staging_dir, so a partially written submission is never
    visible; they leave staging_dir when they are scheduled (moved to incoming_dir), found to be
    duplicates, or found to be unreadable. This is what makes queued work survive a
    hard kill - the collector process is never shut down cleanly in practice.
    """

    def __init__(self, incoming_dir: str, persistence_dir: str, staging_dir: Optional[str] = None,
                 staging_tmp_dir: Optional[str] = None, error_dir: Optional[str] = None):
        """
        Initialize the SubmissionFileManager.

        Args:
            incoming_dir: Directory where submission files are stored for processing
            persistence_dir: Directory for persistence data storage
            staging_dir: Durable queue of emitted-but-not-yet-collected submissions
            staging_tmp_dir: Where submissions are built before being renamed into staging_dir
            error_dir: Where unreadable submissions are moved so they cannot wedge the loop
        """
        self.incoming_dir = incoming_dir
        self.persistence_dir = persistence_dir
        self.staging_dir = staging_dir
        self.staging_tmp_dir = staging_tmp_dir
        self.error_dir = error_dir

    def initialize_directories(self):
        """Create required directories if they don't exist."""
        for dir_path in [self.incoming_dir, self.persistence_dir, self.staging_dir,
                         self.staging_tmp_dir, self.error_dir]:
            if dir_path:
                create_directory(dir_path)

    #
    # staging (the durable queue)
    #

    def get_staging_tmp_path(self, root_uuid: str) -> str:
        """Returns the path a submission should be built at before it is staged."""
        return os.path.join(self.staging_tmp_dir, root_uuid)

    def get_staging_path(self, root_uuid: str) -> str:
        """Returns the path of a staged submission."""
        return os.path.join(self.staging_dir, root_uuid)

    def stage_submission(self, submission: Submission) -> str:
        """Serializes the submission and atomically publishes it to the staging directory.

        The rename is the commit point: until it completes the submission is invisible to
        iter_staged_submissions(), and once it completes the submission is recoverable even if
        this process dies immediately afterwards.

        Returns the staged path.
        """
        assert isinstance(submission, Submission)
        assert isinstance(submission.root, RootAnalysis)

        # everything the collector needs (key, group_assignments, group_value, queued_at) is
        # already stored on the root, so serializing the root captures the whole submission.
        # storage_dir is not part of data.json, so relocating the directory afterwards is safe
        submission.root.save()

        # move_storage is a shutil.move, which is a plain rename while staging_tmp_dir and
        # staging_dir are on the same filesystem - that atomicity is the commit point
        target_dir = self.get_staging_path(submission.root.uuid)
        submission.root.file_manager.move_storage(target_dir)

        logging.debug("staged submission %s at %s", submission.root.uuid, target_dir)
        return target_dir

    def iter_staged_submissions(self, limit: Optional[int] = None) -> Generator[Submission, None, None]:
        """Yields the staged submissions, oldest first.

        A submission that cannot be loaded is moved to the error directory rather than being
        skipped, otherwise it would be re-read on every pass and wedge collection.
        """
        for root_uuid in self.list_staged_submissions(limit=limit):
            storage_dir = self.get_staging_path(root_uuid)
            try:
                root = RootAnalysis(storage_dir=storage_dir)
                root.load()
            except Exception as e:
                logging.error("unable to load staged submission %s: %s", root_uuid, e)
                self.quarantine_staged_submission(root_uuid)
                continue

            yield Submission(root)

    def list_staged_submissions(self, limit: Optional[int] = None) -> list[str]:
        """Returns the uuids of staged submissions, oldest first.

        Ordering is by mtime and is only approximate; the authoritative FIFO ordering is applied
        downstream by incoming_workload.id.
        """
        try:
            entries = [_ for _ in os.scandir(self.staging_dir) if _.is_dir()]
        except FileNotFoundError:
            return []

        entries.sort(key=lambda entry: entry.stat().st_mtime)
        if limit is not None:
            entries = entries[:limit]

        return [entry.name for entry in entries]

    def discard_staged_submission(self, root_uuid: str) -> bool:
        """Removes a staged submission that reached a terminal outcome without being scheduled
        (a duplicate). Without this the submission is re-collected forever."""
        target_dir = self.get_staging_path(root_uuid)
        try:
            shutil.rmtree(target_dir, ignore_errors=True)
            return True
        except Exception as e:
            logging.error("unable to discard staged submission %s: %s", target_dir, e)
            return False

    def quarantine_staged_submission(self, root_uuid: str) -> bool:
        """Moves an unreadable staged submission into the error directory for review."""
        source_dir = self.get_staging_path(root_uuid)
        target_dir = os.path.join(self.error_dir, root_uuid)

        try:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)

            shutil.move(source_dir, target_dir)
            logging.warning("moved unreadable submission %s to %s for review", root_uuid, target_dir)
            return True
        except Exception as e:
            logging.error("unable to quarantine staged submission %s: %s", source_dir, e)
            # last resort: drop it so it cannot block collection forever
            return self.discard_staged_submission(root_uuid)

    def purge_incomplete_staging(self) -> int:
        """Deletes everything in the staging temp directory and returns how many were removed.

        Anything here was mid-construction when the process died, so it is incomplete by
        definition. Only safe to call at startup, before any collector begins producing.
        """
        if not self.staging_tmp_dir:
            return 0

        removed = 0
        try:
            entries = list(os.scandir(self.staging_tmp_dir))
        except FileNotFoundError:
            return 0

        for entry in entries:
            try:
                if entry.is_dir():
                    shutil.rmtree(entry.path, ignore_errors=True)
                else:
                    os.remove(entry.path)

                removed += 1
            except Exception as e:
                logging.error("unable to remove incomplete submission %s: %s", entry.path, e)

        if removed:
            logging.warning("removed %d incomplete submissions from %s", removed, self.staging_tmp_dir)

        return removed

    #
    # incoming
    #

    def prepare_submission_files(self, submission: Submission):
        """
        Prepare submission files by saving the root and moving it to the incoming directory.

        The move out of the staging directory is what marks this submission as no longer pending.

        Args:
            submission: The Submission object to prepare
        """
        assert isinstance(submission, Submission)
        assert isinstance(submission.root, RootAnalysis)

        # Save the root and move it into the incoming dir
        submission.root.save()
        target_dir = os.path.join(self.incoming_dir, submission.root.uuid)
        submission.root.move(target_dir)

    def delete_submission_directory(self, root_uuid: str) -> bool:
        """
        Delete the submission directory for a completed workload.

        Args:
            root_uuid: The UUID of the root analysis to delete

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        target_dir = os.path.join(self.incoming_dir, root_uuid)

        try:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
                return True
            return True  # Directory doesn't exist, consider it successful
        except Exception as e:
            logging.error(f"unable to delete incoming workload directory {target_dir}: {e}")
            return False

    def get_submission_directory_path(self, root_uuid: str) -> str:
        """
        Get the path to a submission's directory.

        Args:
            root_uuid: The UUID of the root analysis

        Returns:
            str: The full path to the submission directory
        """
        return os.path.join(self.incoming_dir, root_uuid)

    def submission_directory_exists(self, root_uuid: str) -> bool:
        """
        Check if a submission directory exists.

        Args:
            root_uuid: The UUID of the root analysis

        Returns:
            bool: True if the directory exists, False otherwise
        """
        target_dir = os.path.join(self.incoming_dir, root_uuid)
        return os.path.exists(target_dir)
