from typing import Any, Optional, Protocol, runtime_checkable


class FileRefusedError(ValueError):
    """A path the file manager refuses to write, because it would leave the files directory. Logged
    where it is raised, so a caller that skips the file need not log it again."""


@runtime_checkable
class FileManagerInterface(Protocol):
    """
    Protocol defining the interface for file managers in the analysis system.
    """
    
    def __init__(self, storage_dir: str) -> None:
        """
        Initialize the FileManager with a storage directory.
        
        Args:
            storage_dir: The base storage directory for this analysis
        """
        ...
        
    @property
    def storage_dir(self) -> str:
        """The absolute path of the storage directory."""
        ...

    @property
    def stored_storage_dir(self) -> str:
        """The storage directory as the database records it: relative to SAQ_HOME, or absolute."""
        ...
        
    @property
    def hardcopy_dir(self) -> str:
        """Returns the path to the hardcopy directory. File content is stored here by sha256 hash."""
        ...
        
    @property
    def file_dir(self) -> str:
        """Returns the path to the files directory. File references to hard copies are stored here by relative path."""
        ...
        
    @property
    def json_path(self) -> str:
        """Path to the JSON file that stores this alert."""
        ...
        
    @property
    def submission_json_path(self) -> str:
        """Returns the path used to store the submission JSON data."""
        ...
        
    def initialize_storage(self) -> None:
        """Initialize the storage directory structure."""
        ...
        
    def ensure_storage_directories(self) -> None:
        """Ensure the storage and .ace directories exist."""
        ...

    def create_file_path(self, relative_path: str) -> str:
        """
        Creates a file path relative to the file subdirectory.
        Creates any required subdirectories.
        
        Args:
            relative_path: Relative path within the file directory
            
        Returns:
            Full path to the file

        Raises:
            FileRefusedError: If the path is not inside the file directory
        """
        ...
        
    def create_output_file(self, name: str) -> str:
        """
        Creates a new, empty file in the files directory for bytes named by an untrusted source
        and returns its full path. The name is cleaned before anything is written, so the file
        can only land inside the files directory, and a name already taken gets a _NNN suffix.

        Args:
            name: The untrusted name, which may place the file in a subdirectory

        Returns:
            Full path to the new, empty file

        Raises:
            FileRefusedError: If the path still resolves outside the file directory
        """
        ...

    def store_file(self, source_path: Any, target_path: Optional[str] = None, move: bool = False) -> tuple[str, str]:
        """
        Store a file in the analysis storage system.
        
        Args:
            source_path: Path to the source file
            target_path: Optional target path within file_dir, cleaned like a create_output_file name. If None, uses basename of source
            move: If True, move the file instead of copying
            
        Returns:
            Tuple of (sha256_hash, relative_target_path)
            
        Raises:
            FileNotFoundError: If source file doesn't exist
            FileRefusedError: If the target path is not inside the file directory
            Exception: If file operations fail
        """
        ...
        
    def delete_file(self, file_path: str) -> None:
        """
        Delete a file from the file system.
        
        Args:
            file_path: Path to the file to delete
        """
        ...
        
    def copy_storage(self, dest_dir: str) -> None:
        """
        Copy the entire storage directory to a new location.
        
        Args:
            dest_dir: Destination directory path
            
        Raises:
            RuntimeError: If destination already exists
        """
        ...
        
    def move_storage(self, dest_dir: str) -> None:
        """
        Move the storage directory to a new location.
        
        Args:
            dest_dir: Destination directory path
            
        Raises:
            RuntimeError: If destination already exists
        """
        ...
        
    def delete_storage(self) -> None:
        """Delete the entire storage directory and its contents."""
        ...
        
    def cleanup_empty_directories(self) -> None:
        """Remove empty directories within the storage directory."""
        ...
        
    def archive_files(self, retained_files: set) -> None:
        """
        Archive by removing analysis files while keeping specified files.

        Everything except the analysis's own JSON and the files in retained_files is removed,
        including file content stored by hash, so the bytes of every file that is not retained
        are freed.

        Args:
            retained_files: Set of file paths to retain
        """
        ...
        
    def record_submission(self, analysis_data: dict, files: list) -> None:
        """
        Record submission data to the submission JSON file.
        
        Args:
            analysis_data: Analysis data dictionary
            files: List of file information
        """
        ...
        
    def load_submission(self) -> Optional[dict]:
        """
        Load submission data from the submission JSON file.
        
        Returns:
            Submission data dictionary or None if not available
        """
        ...