from typing import Any, Optional

from .file_manager_interface import FileManagerInterface


class FileManagerAdapter(FileManagerInterface):
    """
    Adapter class that wraps a FileManagerInterface implementation.
    This allows for composition-based delegation and potential future extensions.
    """
    
    def __init__(self, file_manager: FileManagerInterface):
        """
        Initialize the adapter with a FileManagerInterface implementation.
        
        Args:
            file_manager: An instance that implements FileManagerInterface
        """
        self._file_manager = file_manager
        
    @property
    def storage_dir(self) -> str:
        """The base storage directory for output."""
        return self._file_manager.storage_dir
        
    @property
    def hardcopy_dir(self) -> str:
        """Returns the path to the hardcopy directory. File content is stored here by sha256 hash."""
        return self._file_manager.hardcopy_dir
        
    @property
    def file_dir(self) -> str:
        """Returns the path to the files directory. File references to hard copies are stored here by relative path."""
        return self._file_manager.file_dir
        
    @property
    def json_path(self) -> str:
        """Path to the JSON file that stores this alert."""
        return self._file_manager.json_path
        
    @property
    def submission_json_path(self) -> str:
        """Returns the path used to store the submission JSON data."""
        return self._file_manager.submission_json_path
        
    def initialize_storage(self) -> None:
        """Initialize the storage directory structure."""
        return self._file_manager.initialize_storage()
        
    def ensure_storage_directories(self) -> None:
        """Ensure the storage and .ace directories exist."""
        return self._file_manager.ensure_storage_directories()

    def create_file_path(self, relative_path: str) -> str:
        """
        Creates a file path relative to the file subdirectory.
        Creates any required subdirectories.
        
        Args:
            relative_path: Relative path within the file directory
            
        Returns:
            Full path to the file
        """
        return self._file_manager.create_file_path(relative_path)
        
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
        return self._file_manager.store_file(source_path, target_path, move)
        
    def delete_file(self, file_path: str) -> None:
        """
        Delete a file from the file system.
        
        Args:
            file_path: Path to the file to delete
        """
        return self._file_manager.delete_file(file_path)
        
    def copy_storage(self, dest_dir: str) -> None:
        """
        Copy the entire storage directory to a new location.
        
        Args:
            dest_dir: Destination directory path
            
        Raises:
            RuntimeError: If destination already exists
        """
        return self._file_manager.copy_storage(dest_dir)
        
    def move_storage(self, dest_dir: str) -> None:
        """
        Move the storage directory to a new location.
        
        Args:
            dest_dir: Destination directory path
            
        Raises:
            RuntimeError: If destination already exists
        """
        return self._file_manager.move_storage(dest_dir)
        
    def delete_storage(self) -> None:
        """Delete the entire storage directory and its contents."""
        return self._file_manager.delete_storage()
        
    def cleanup_empty_directories(self) -> None:
        """Remove empty directories within the storage directory."""
        return self._file_manager.cleanup_empty_directories()
        
    def archive_files(self, retained_files: set) -> None:
        """
        Archive by removing analysis files while keeping specified files.
        
        Args:
            retained_files: Set of file paths to retain
        """
        return self._file_manager.archive_files(retained_files)
        
    def record_submission(self, analysis_data: dict, files: list) -> None:
        """
        Record submission data to the submission JSON file.
        
        Args:
            analysis_data: Analysis data dictionary
            files: List of file information
        """
        return self._file_manager.record_submission(analysis_data, files)
        
    def load_submission(self) -> Optional[dict]:
        """
        Load submission data from the submission JSON file.
        
        Returns:
            Submission data dictionary or None if not available
        """
        return self._file_manager.load_submission()