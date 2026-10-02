"""
Local filesystem storage implementation.

This module provides a concrete implementation of the StorageInterface protocol
for storing and retrieving files using the local filesystem. Buckets are mapped
to subdirectories under a configurable base directory.
"""

import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from saq.storage.error import StorageError
from saq.storage.interface import StorageInterface


# in-flight writes are created next to their destination under this prefix and renamed into
# place; listings skip them
_TEMP_PREFIX = ".storage-tmp-"


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
        """Return the filesystem path for a bucket: always a direct child of base_dir."""
        if (
            not isinstance(bucket, str)
            or bucket in ("", ".", "..")
            or "/" in bucket
            or "\\" in bucket
            or "\0" in bucket
        ):
            raise StorageError(f"invalid bucket name: {bucket!r}")
        return self.base_dir / bucket

    def _confine(self, bucket: str, path: str, allow_bucket_root: bool) -> Path:
        """Resolve path under the bucket and refuse anything that leaves it (``..``, an absolute
        path, a symlink pointing elsewhere)."""
        bucket_dir = self._bucket_path(bucket)
        if os.path.isabs(path) or "\0" in path:
            raise StorageError(f"invalid object path {bucket}/{path!r}")

        resolved_bucket = bucket_dir.resolve()
        resolved = (bucket_dir / path).resolve()
        if resolved == resolved_bucket:
            if allow_bucket_root:
                return resolved
        elif resolved_bucket in resolved.parents:
            return resolved

        raise StorageError(f"object path {bucket}/{path!r} is outside of the bucket")

    def _object_path(self, bucket: str, remote_path: str) -> Path:
        """Return the filesystem path for an object, confined to its bucket."""
        return self._confine(bucket, remote_path, allow_bucket_root=False)

    @staticmethod
    def _copy_atomic(src: Path, dest: Path) -> None:
        """Copy src to dest through a temporary file in dest's directory, so dest is either the
        old file or the complete new one, never a partial copy."""
        fd, tmp_path = tempfile.mkstemp(dir=dest.parent, prefix=_TEMP_PREFIX)
        os.close(fd)
        try:
            shutil.copy2(str(src), tmp_path)
            os.replace(tmp_path, dest)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    def upload_file(
        self,
        local_path: Union[str, Path],
        bucket: str,
        remote_path: str,
    ) -> str:
        """Upload a file to local storage."""
        local_path = Path(local_path)
        if not local_path.exists():
            raise FileNotFoundError(f"source file not found: {local_path}")

        dest = self._object_path(bucket, remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._copy_atomic(local_path, dest)
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
            self._copy_atomic(src, local_path)
            logging.info("downloaded %s/%s to %s", bucket, remote_path, local_path)
            return str(local_path)
        except Exception as e:
            error_msg = f"failed to download file {bucket}/{remote_path} to {local_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def list_objects(self, bucket: str, prefix: str = "", recursive: bool = True) -> list:
        """List objects in a bucket."""
        bucket_dir = self._bucket_path(bucket)
        search_dir = self._confine(bucket, prefix, allow_bucket_root=True) if prefix else bucket_dir
        if not bucket_dir.exists() or not search_dir.exists():
            return []

        result = []

        resolved_bucket_dir = bucket_dir.resolve()
        search_dir = search_dir.resolve()

        try:
            if recursive:
                for path in search_dir.rglob("*"):
                    if path.is_file() and not path.name.startswith(_TEMP_PREFIX):
                        result.append(str(path.relative_to(resolved_bucket_dir)))
            else:
                for path in search_dir.iterdir():
                    if path.name.startswith(_TEMP_PREFIX):
                        continue
                    rel = str(path.relative_to(resolved_bucket_dir))
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
