import logging
import os
import shutil
from typing import Any, Optional

from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
from saq.constants import FILE_SUBDIR, HARDCOPY_SUBDIR
from saq.environment import get_base_dir
from saq.util.hashing import sha256_file
from saq.error import report_exception


class LocalFileManager(FileManagerInterface):
    """
    Handles all I/O interactions for analysis artifacts.
    """
    
    def __init__(self, storage_dir: str):
        """
        Initialize the FileManager with a storage directory.
        
        Args:
            storage_dir: The base storage directory for this analysis
        """
        self._storage_dir = storage_dir
        
    @property
    def storage_dir(self) -> str:
        """The base storage directory for output."""
        return self._storage_dir
        
    @property
    def hardcopy_dir(self) -> str:
        """Returns the path to the hardcopy directory. File content is stored here by sha256 hash."""
        return os.path.join(self._storage_dir, HARDCOPY_SUBDIR)
        
    @property
    def file_dir(self) -> str:
        """Returns the path to the files directory. File references to hard copies are stored here by relative path."""
        return os.path.join(self._storage_dir, FILE_SUBDIR)
        
    @property
    def json_path(self) -> str:
        """Path to the JSON file that stores this alert."""
        return os.path.join(get_base_dir(), self._storage_dir, 'data.json')
        
    @property
    def submission_json_path(self) -> str:
        """Returns the path used to store the submission JSON data."""
        return os.path.join(self._storage_dir, '.ace', 'submission.json')
        
    def initialize_storage(self):
        """Initialize the storage directory structure."""
        try:
            target_dir = os.path.join(get_base_dir(), self._storage_dir)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            target_dir = os.path.join(target_dir, '.ace')
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            logging.debug("initialized storage directory {}".format(target_dir))

        except Exception as e:
            logging.error("unable to initialize storage: {}".format(e))
            report_exception()
            raise e
            
    def ensure_storage_directories(self):
        """Ensure the storage and .ace directories exist."""
        # make sure the containing directory exists
        if not os.path.exists(os.path.join(get_base_dir(), self._storage_dir)):
            os.makedirs(os.path.join(get_base_dir(), self._storage_dir))

        # analysis details go into a hidden directory
        if not os.path.exists(os.path.join(get_base_dir(), self._storage_dir, '.ace')):
            os.makedirs(os.path.join(get_base_dir(), self._storage_dir, '.ace'))

    def create_file_path(self, relative_path: str) -> str:
        """
        Creates a file path relative to the file subdirectory.
        Creates any required subdirectories.
        
        Args:
            relative_path: Relative path within the file directory
            
        Returns:
            Full path to the file
        """
        if os.path.dirname(relative_path) == self.file_dir:
            return os.path.join(self.file_dir, relative_path)
        else:
            target_path = os.path.join(self.file_dir, relative_path)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            return target_path
            
    def store_file(self, source_path: Any, target_path: Optional[str] = None, move: bool = False) -> tuple[str, str]:
        """
        Store a file in the analysis storage system.
        
        Args:
            source_path: Path to the source file
            target_path: Optional target path within file_dir. If None, uses basename of source
            move: If True, move the file instead of copying
            
        Returns:
            Tuple of (sha256_hash, relative_target_path)
            
        Raises:
            FileNotFoundError: If source file doesn't exist
            Exception: If file operations fail
        """
        # Convert to string path
        source_path = str(source_path)
        
        # Check if file exists
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file does not exist: {source_path}")
            
        # Determine target path
        if source_path.startswith(self.file_dir):
            target_path = source_path
        else:
            target_path = os.path.join(self.file_dir, target_path or os.path.basename(source_path))
            
        # Ensure target directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        # Compute file hash
        sha256_hash = sha256_file(source_path)
        
        # Store in hardcopy directory
        hardcopy_path = os.path.join(self.hardcopy_dir, sha256_hash)
        os.makedirs(os.path.dirname(hardcopy_path), exist_ok=True)
        
        # Handle hardcopy storage
        if not os.path.exists(hardcopy_path):
            if move:
                try:
                    shutil.move(source_path, hardcopy_path)
                except Exception as e:
                    logging.error(f"unable to move file {source_path} to {hardcopy_path}: {e}")
                    raise e
            else:
                try:
                    # Try hard link first (fastest)
                    os.link(source_path, hardcopy_path)
                except Exception:
                    try:
                        # Fall back to copy
                        logging.debug(f"unable to hard link file {source_path} to {hardcopy_path}, falling back to copy")
                        shutil.copy(source_path, hardcopy_path)
                    except Exception as e:
                        logging.error(f"unable to copy file {source_path} to {hardcopy_path}: {e}")
                        raise e
        else:
            # Hardcopy already exists
            if move:
                # Remove source since we're moving
                os.unlink(source_path)
                
        # Create reference link
        if not os.path.exists(target_path):
            os.link(hardcopy_path, target_path)
            
        # Return hash and relative path
        relative_path = os.path.relpath(target_path, start=self.file_dir)
        return sha256_hash, relative_path
        
    def delete_file(self, file_path: str):
        """
        Delete a file from the file system.
        
        Args:
            file_path: Path to the file to delete
        """
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
                logging.debug("deleted file {}".format(file_path))
        except Exception as e:
            logging.error("unable to delete file {}: {}".format(file_path, e))
            raise e
            
    def copy_storage(self, dest_dir: str):
        """
        Copy the entire storage directory to a new location.
        
        Args:
            dest_dir: Destination directory path
            
        Raises:
            RuntimeError: If destination already exists
        """
        if os.path.exists(dest_dir):
            raise RuntimeError(f"Destination directory {dest_dir} already exists")
            
        shutil.copytree(self._storage_dir, dest_dir)
        logging.debug(f"copied storage from {self._storage_dir} to {dest_dir}")
        
    def move_storage(self, dest_dir: str):
        """
        Move the storage directory to a new location.
        
        Args:
            dest_dir: Destination directory path
            
        Raises:
            RuntimeError: If destination already exists
        """
        if os.path.exists(dest_dir):
            raise RuntimeError(f"Destination directory {dest_dir} already exists")
            
        shutil.move(self._storage_dir, dest_dir)
        logging.debug(f"moved storage from {self._storage_dir} to {dest_dir}")
        self._storage_dir = dest_dir
        
    def delete_storage(self):
        """Delete the entire storage directory and its contents."""
        try:
            if os.path.exists(self._storage_dir):
                shutil.rmtree(self._storage_dir)
                logging.debug("deleted storage directory {}".format(self._storage_dir))
        except Exception as e:
            logging.error("unable to delete storage {}: {}".format(self._storage_dir, e))
            raise e
            
    def cleanup_empty_directories(self):
        """Remove empty directories within the storage directory."""
        from subprocess import Popen
        from saq.util import abs_path
        
        logging.debug("removing empty directories inside {}".format(self._storage_dir))
        p = Popen(['find', abs_path(self._storage_dir), '-type', 'd', '-empty', '-delete'])
        p.wait()
        
    def archive_files(self, retained_files: set):
        """
        Archive by removing analysis files while keeping specified files.
        
        Args:
            retained_files: Set of file paths to retain
        """
        for dir_path, dir_names, file_names in os.walk(self._storage_dir):
            # Skip core directories
            if dir_path in [self._storage_dir, os.path.join(self._storage_dir, '.ace'), 
                           self.hardcopy_dir, self.file_dir]:
                logging.debug("skipping core directory {}".format(dir_path))
                continue
                
            # Delete untracked subdirectories
            for dir_name in dir_names:
                if dir_name == 'untracked':
                    target_untracked_dir = os.path.join(dir_path, dir_name)
                    logging.debug(f"deleting untracked directory {target_untracked_dir}")
                    try:
                        shutil.rmtree(target_untracked_dir)
                    except Exception as e:
                        logging.error(f"unable to delete untracked directory {target_untracked_dir}: {e}")
                        
            # Delete files not in retained set
            for file_name in file_names:
                file_path = os.path.join(dir_path, file_name)
                if file_path in retained_files:
                    logging.debug("skipping retained file {}".format(file_path))
                    continue
                    
                try:
                    logging.debug("deleting {}".format(file_path))
                    os.remove(file_path)
                except Exception as e:
                    logging.error("unable to remove {}: {}".format(file_path, e))
                    report_exception()
                    
        self.cleanup_empty_directories()
        
    def record_submission(self, analysis_data: dict, files: list):
        """
        Record submission data to the submission JSON file.
        
        Args:
            analysis_data: Analysis data dictionary
            files: List of file information
        """
        analysis_data['files'] = files
        with open(self.submission_json_path, 'w') as fp:
            import json
            json.dump(analysis_data, fp)
            
    def load_submission(self) -> Optional[dict]:
        """
        Load submission data from the submission JSON file.
        
        Returns:
            Submission data dictionary or None if not available
        """
        if not os.path.exists(self.submission_json_path):
            return None
            
        with open(self.submission_json_path, 'r') as fp:
            import json
            return json.load(fp)