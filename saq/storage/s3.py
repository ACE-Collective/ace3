"""
S3-compatible storage implementation using boto3.

This module provides a concrete implementation of the StorageInterface protocol
for storing and retrieving files from S3-compatible object storage (e.g. Garage, MinIO).
"""

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Union, Optional
from urllib.parse import urljoin

try:
    import boto3
    import botocore.exceptions
    from botocore.config import Config as BotoConfig
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


from saq.configuration.config import get_config
from saq.storage.interface import StorageInterface
from saq.storage.error import StorageError


def _require_boto3():
    if not HAS_BOTO3:
        raise StorageError("boto3 is required for S3 storage - install it with: pip install boto3")

@dataclass
class S3Credentials:
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None

def get_s3_credentials_from_config() -> S3Credentials:
    """Get the S3 credentials from the configuration."""
    _require_boto3()
    return S3Credentials(
        access_key=get_config().s3.access_key,
        secret_key=get_config().s3.secret_key,
        region=get_config().s3.region)

def get_s3_client(region: Optional[str] = None):
    """Returns an S3 client.

    If a self-hosted S3-compatible configuration exists (get_config().s3), returns
    a client configured with explicit endpoint and credentials for that service.

    Otherwise, returns a native AWS S3 client that uses the standard boto3
    credential chain (IAM roles, environment variables, etc.)."""
    _require_boto3()

    s3_config = get_config().s3
    if s3_config is None:
        # AWS-native path: let boto3 handle credentials via IAM roles, env vars, etc.
        return boto3.client("s3", region_name=region)

    # Self-hosted S3-compatible path (e.g. MinIO, GarageHQ)
    s3_credentials = get_s3_credentials_from_config()

    host = s3_config.host
    port = s3_config.port
    secure = s3_config.secure
    cert_check = s3_config.cert_check

    protocol = "https" if secure else "http"
    endpoint_url = f"{protocol}://{host}:{port}"

    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=s3_credentials.access_key,
        aws_secret_access_key=s3_credentials.secret_key,
        region_name=s3_credentials.region,
        verify=cert_check,
        config=BotoConfig(signature_version="s3v4"))


class S3Storage(StorageInterface):
    """
    S3-compatible storage implementation using boto3.

    This class implements the StorageInterface protocol for storing and retrieving
    files from S3-compatible object storage.
    """

    def __init__(
        self,
        host: str = "garagehq",
        port: int = 3900,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        secure: bool = False,
        region: Optional[str] = None,
        session_token: Optional[str] = None,
        config: Optional[dict] = None
    ):
        """
        Initialize the S3 storage client.

        Args:
            host: S3-compatible server hostname or IP address
            port: S3-compatible server port
            access_key: S3 access key
            secret_key: S3 secret key
            secure: Whether to use HTTPS (defaults to False for HTTP)
            region: S3 region (optional)
            session_token: Session token for temporary credentials (optional)
            config: Custom configuration dict (optional), supports 'verify' key
        """
        _require_boto3()

        self.host = host
        self.port = port
        self.secure = secure

        if not access_key or not secret_key:
            raise ValueError("access key and secret key must be provided when initializing S3Storage")

        # Get credentials from environment variables if not provided
        self.access_key = access_key
        self.secret_key = secret_key

        # Build endpoint URL
        self.endpoint = f"{host}:{port}"
        protocol = "https" if secure else "http"
        endpoint_url = f"{protocol}://{self.endpoint}"

        if config is None:
            config = {}

        verify = config.pop("verify", config.pop("cert_check", True))

        # Initialize S3 client
        try:
            self.client = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=region,
                verify=verify,
                config=BotoConfig(signature_version="s3v4"),
            )

        except botocore.exceptions.BotoCoreError as e:
            logging.error("failed to connect to s3 storage: %s", e)
            raise StorageError(f"failed to connect to s3 storage: {e}")
        except Exception as e:
            logging.error("unexpected error connecting to s3 storage: %s", e)
            raise StorageError(f"unexpected error connecting to s3 storage: {e}")

    def upload_file(
        self,
        local_path: Union[str, Path],
        bucket: str,
        remote_path: str,
        **kwargs
    ) -> str:
        """
        Upload a file to S3 storage.

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
        # Convert Path to string if needed
        local_path_str = str(local_path)

        # Check if source file exists
        if not os.path.exists(local_path_str):
            raise FileNotFoundError(f"source file not found: {local_path_str}")

        # Ensure bucket exists
        self._ensure_bucket_exists(bucket)

        try:
            # Handle metadata kwarg for boto3
            extra_args = {}
            if "metadata" in kwargs:
                extra_args["Metadata"] = kwargs.pop("metadata")

            # Upload the file
            self.client.upload_file(
                local_path_str,
                bucket,
                remote_path,
                ExtraArgs=extra_args if extra_args else None,
            )

            # Generate URL for the uploaded file
            file_url = self._generate_file_url(bucket, remote_path)

            logging.info("uploaded %s to %s/%s", local_path_str, bucket, remote_path)
            return file_url

        except botocore.exceptions.ClientError as e:
            error_msg = f"failed to upload file {local_path_str} to {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)
        except Exception as e:
            error_msg = f"unexpected error uploading file {local_path_str}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def download_file(
        self,
        bucket: str,
        remote_path: str,
        local_path: Union[str, Path]
    ) -> object:
        """
        Download a file from S3 storage.

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
        # Convert Path to string if needed
        local_path_str = str(local_path)

        # Ensure local directory exists
        local_dir = os.path.dirname(local_path_str)
        if local_dir and not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)

        try:
            # Check if object exists in storage
            try:
                self.client.head_object(Bucket=bucket, Key=remote_path)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "404":
                    raise FileNotFoundError(f"file not found in storage: {bucket}/{remote_path}")
                raise

            # Download the file
            self.client.download_file(
                bucket,
                remote_path,
                local_path_str,
            )

            logging.info("downloaded %s/%s to %s", bucket, remote_path, local_path_str)
            return local_path_str

        except FileNotFoundError:
            raise
        except botocore.exceptions.ClientError as e:
            error_msg = f"failed to download file {bucket}/{remote_path} to {local_path_str}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)
        except Exception as e:
            error_msg = f"unexpected error downloading file {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def _ensure_bucket_exists(self, bucket: str) -> None:
        """
        Ensure a bucket exists, creating it if necessary.

        Args:
            bucket: Name of the bucket to ensure exists
        """
        try:
            self.client.head_bucket(Bucket=bucket)
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("404", "NoSuchBucket"):
                try:
                    self.client.create_bucket(Bucket=bucket)
                    logging.info("created bucket: %s", bucket)
                except botocore.exceptions.ClientError as create_err:
                    error_msg = f"failed to create bucket {bucket}: {create_err}"
                    logging.error(error_msg)
                    raise StorageError(error_msg)
            else:
                error_msg = f"failed to ensure bucket {bucket} exists: {e}"
                logging.error(error_msg)
                raise StorageError(error_msg)

    def _generate_file_url(self, bucket: str, remote_path: str) -> str:
        """
        Generate a URL for a file in storage.

        Args:
            bucket: Bucket name
            remote_path: Remote path within the bucket

        Returns:
            str: URL for the file
        """
        protocol = "https" if self.secure else "http"
        base_url = f"{protocol}://{self.endpoint}"
        return urljoin(base_url, f"{bucket}/{remote_path}")

    def list_buckets(self) -> list:
        """
        List all available buckets.

        Returns:
            list: List of bucket names

        Raises:
            StorageError: If listing fails
        """
        try:
            response = self.client.list_buckets()
            return [bucket["Name"] for bucket in response.get("Buckets", [])]
        except botocore.exceptions.ClientError as e:
            error_msg = f"failed to list buckets: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)
        except Exception as e:
            error_msg = f"unexpected error listing buckets: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def list_objects(self, bucket: str, prefix: str = "", recursive: bool = True) -> list:
        """
        List objects in a bucket with optional prefix filtering.

        Args:
            bucket: Name of the bucket to list objects from
            prefix: Prefix to filter objects by (optional)
            recursive: Whether to list objects recursively (default: True)

        Returns:
            list: List of object names

        Raises:
            StorageError: If listing fails
        """
        try:
            result = []
            kwargs = {"Bucket": bucket, "Prefix": prefix}
            if not recursive:
                kwargs["Delimiter"] = "/"

            while True:
                response = self.client.list_objects_v2(**kwargs)

                # collect object keys
                for obj in response.get("Contents", []):
                    result.append(obj["Key"])

                # for non-recursive, also collect common prefixes (virtual directories)
                if not recursive:
                    for prefix_entry in response.get("CommonPrefixes", []):
                        result.append(prefix_entry["Prefix"])

                if response.get("IsTruncated"):
                    kwargs["ContinuationToken"] = response["NextContinuationToken"]
                else:
                    break

            return result
        except botocore.exceptions.ClientError as e:
            error_msg = f"failed to list objects in bucket {bucket}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def delete_object(self, bucket: str, remote_path: str) -> bool:
        """
        Delete an object from storage.

        Args:
            bucket: Name of the bucket containing the object
            remote_path: Remote path of the object to delete

        Returns:
            bool: True if deletion was successful

        Raises:
            StorageError: If deletion fails
        """
        try:
            self.client.delete_object(Bucket=bucket, Key=remote_path)
            logging.info("deleted %s/%s", bucket, remote_path)
            return True
        except botocore.exceptions.ClientError as e:
            error_msg = f"failed to delete object {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    def object_exists(self, bucket: str, remote_path: str) -> bool:
        """
        Check if an object exists in storage.

        Args:
            bucket: Name of the bucket to check
            remote_path: Remote path of the object to check

        Returns:
            bool: True if object exists, False otherwise
        """
        try:
            self.client.head_object(Bucket=bucket, Key=remote_path)
            return True
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            # For other errors, log and return False
            logging.warning("error checking if object exists %s/%s: %s", bucket, remote_path, e)
            return False

    def get_object_info(self, bucket: str, remote_path: str) -> Optional[dict]:
        """
        Get information about an object in storage.

        Args:
            bucket: Name of the bucket containing the object
            remote_path: Remote path of the object

        Returns:
            dict: Object information including size, last_modified, etag, etc.
                 Returns None if object doesn't exist
        """
        try:
            response = self.client.head_object(Bucket=bucket, Key=remote_path)
            return {
                "size": response["ContentLength"],
                "last_modified": response["LastModified"],
                "etag": response["ETag"],
                "content_type": response.get("ContentType"),
                "metadata": response.get("Metadata", {}),
            }
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return None
            error_msg = f"failed to get object info for {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)
