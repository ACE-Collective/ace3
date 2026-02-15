"""
Local filesystem storage implementation.

This module provides a concrete implementation of the StorageInterface protocol
for storing and retrieving files using the local filesystem. Buckets are mapped
to subdirectories under a configurable base directory.
"""

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from saq.storage.error import StorageError
from saq.storage.interface import StorageInterface


class LocalStorage(StorageInterface):
    """
    Local filesystem storage implementation.

    This class implements the StorageInterface protocol by mapping buckets
    to subdirectories under a configurable base directory.
    """

    def __init__(self, base_dir: Union[str, Path]):
        """
        Initialize local storage.

        Args:
            base_dir: base directory for storage (buckets become subdirectories)
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _bucket_path(self, bucket: str) -> Path:
        """Return the filesystem path for a bucket."""
        return self.base_dir / bucket

    def _object_path(self, bucket: str, remote_path: str) -> Path:
        """Return the filesystem path for an object."""
        return self._bucket_path(bucket) / remote_path

    def upload_file(
        self,
        local_path: Union[str, Path],
        bucket: str,
        remote_path: str,
        **kwargs,
    ) -> str:
        """Upload a file to local storage."""
        local_path = Path(local_path)
        if not local_path.exists():
            raise FileNotFoundError(f"source file not found: {local_path}")

        dest = self._object_path(bucket, remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.copy2(str(local_path), str(dest))
            logging.info("uploaded %s to %s/%s", local_path, bucket, remote_path)
            return str(dest)
        except Exception as e:
            error_msg = f"failed to upload file {local_path} to {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def download_file(
        self,
        bucket: str,
        remote_path: str,
        local_path: Union[str, Path],
    ) -> object:
        """Download a file from local storage."""
        src = self._object_path(bucket, remote_path)
        if not src.exists():
            raise FileNotFoundError(f"file not found in storage: {bucket}/{remote_path}")

        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.copy2(str(src), str(local_path))
            logging.info("downloaded %s/%s to %s", bucket, remote_path, local_path)
            return str(local_path)
        except Exception as e:
            error_msg = f"failed to download file {bucket}/{remote_path} to {local_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def list_objects(self, bucket: str, prefix: str = "", recursive: bool = True) -> list:
        """List objects in a bucket."""
        bucket_dir = self._bucket_path(bucket)
        if not bucket_dir.exists():
            return []

        result = []
        search_dir = bucket_dir / prefix if prefix else bucket_dir

        if not search_dir.exists():
            return []

        try:
            if recursive:
                for path in search_dir.rglob("*"):
                    if path.is_file():
                        result.append(str(path.relative_to(bucket_dir)))
            else:
                for path in search_dir.iterdir():
                    rel = str(path.relative_to(bucket_dir))
                    if path.is_dir():
                        result.append(rel + "/")
                    else:
                        result.append(rel)
        except Exception as e:
            error_msg = f"failed to list objects in bucket {bucket}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

        return result

    def list_buckets(self) -> list:
        """List all available buckets."""
        try:
            return [
                d.name for d in self.base_dir.iterdir() if d.is_dir()
            ]
        except Exception as e:
            error_msg = f"failed to list buckets: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def delete_object(self, bucket: str, remote_path: str) -> bool:
        """Delete an object from storage."""
        obj_path = self._object_path(bucket, remote_path)
        try:
            if obj_path.exists():
                obj_path.unlink()
                logging.info("deleted %s/%s", bucket, remote_path)
            return True
        except Exception as e:
            error_msg = f"failed to delete object {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def object_exists(self, bucket: str, remote_path: str) -> bool:
        """Check if an object exists in storage."""
        return self._object_path(bucket, remote_path).exists()

    def get_object_info(self, bucket: str, remote_path: str) -> Optional[dict]:
        """Get information about an object in storage."""
        obj_path = self._object_path(bucket, remote_path)
        if not obj_path.exists():
            return None

        stat = obj_path.stat()
        return {
            "size": stat.st_size,
            "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            "etag": None,
            "content_type": None,
            "metadata": {},
        }
