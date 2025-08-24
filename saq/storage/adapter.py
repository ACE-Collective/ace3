from typing import Union
from pathlib import Path

from saq.storage.interface import StorageInterface


class StorageAdapter(StorageInterface):
    """
    Adapter class that wraps a StorageInterface implementation.
    This allows for composition-based delegation and potential future extensions.
    """
    
    def __init__(self, storage: StorageInterface):
        """
        Initialize the adapter with a StorageInterface implementation.
        
        Args:
            storage: An instance that implements StorageInterface
        """
        self._storage = storage
        
    def upload_file(
        self,
        local_path: Union[str, Path],
        bucket: str,
        remote_path: str
    ) -> str:
        """
        Upload a file to storage.
        
        Args:
            local_path: Path to the local file to upload
            bucket: Bucket to upload the file to
            remote_path: Remote path to upload the file to
            
        Returns:
            str: The URL or identifier of the uploaded file
            
        Raises:
            FileNotFoundError: If the source file doesn't exist
            StorageError: If upload fails
        """
        return self._storage.upload_file(local_path, bucket, remote_path)
    
    def download_file(
        self,
        bucket: str,
        remote_path: str,
        local_path: Union[str, Path]
    ) -> str:
        """
        Download a file from storage.
        
        Args:
            bucket: Bucket to download the file from
            remote_path: Remote path to download the file from
            local_path: Local path where the file should be saved
            
        Returns:
            str: The URL or identifier of the downloaded file
            
        Raises:
            FileNotFoundError: If the source file doesn't exist in storage
            StorageError: If download fails
        """
        return self._storage.download_file(bucket, remote_path, local_path)
    
    def list_objects(self, bucket: str, prefix: str = "", recursive: bool = True) -> list:
        """
        List objects in a bucket.
        
        Args:
            bucket: Bucket to list objects from
            prefix: Prefix to filter objects by
            recursive: Whether to list recursively
        """
        return self._storage.list_objects(bucket, prefix, recursive)

    def list_buckets(self) -> list:
        """
        List all available buckets.
        
        Returns:
            list: List of bucket names
        """
        return self._storage.list_buckets()

    def delete_object(self, bucket: str, remote_path: str) -> bool:
        """
        Delete an object from storage.
        """
        return self._storage.delete_object(bucket, remote_path)