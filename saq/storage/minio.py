"""
MinIO storage implementation using the MinIO Python SDK.

This module provides a concrete implementation of the StorageInterface protocol
for storing and retrieving files from MinIO object storage.
"""

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Union, Optional
from urllib.parse import urljoin

from minio import Minio
from minio.error import S3Error

import requests

from saq.configuration.config import get_config_value, get_config_value_as_boolean
from saq.constants import CONFIG_MINIO, CONFIG_MINIO_ACCESS_KEY, CONFIG_MINIO_CERT_CHECK, CONFIG_MINIO_HOST, CONFIG_MINIO_PORT, CONFIG_MINIO_REGION, CONFIG_MINIO_SECRET_KEY, CONFIG_MINIO_SECURE, CONFIG_MINIO_USE_EC2_METADATA
from saq.storage.interface import StorageInterface
from saq.storage.error import StorageError

METADATA_BASE_URL = "http://169.254.169.254/latest/meta-data/"

@dataclass
class S3Credentials:
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None

def get_s3_credentials_from_config() -> S3Credentials:
    """Get the S3 credentials from the configuration."""
    return S3Credentials(
        access_key=get_config_value(CONFIG_MINIO, CONFIG_MINIO_ACCESS_KEY),
        secret_key=get_config_value(CONFIG_MINIO, CONFIG_MINIO_SECRET_KEY),
        region=get_config_value(CONFIG_MINIO, CONFIG_MINIO_REGION))

def get_s3_credentials_from_ec2_metadata() -> S3Credentials:
    """Get the EC2 metadata for the current instance."""
    metadata_url = f"{METADATA_BASE_URL}iam/security-credentials/"
    response = requests.get(metadata_url)
    response.raise_for_status()
    role_name = response.text

    metadata_url = f"{METADATA_BASE_URL}iam/security-credentials/{role_name}"
    response = requests.get(metadata_url)
    response.raise_for_status()
    credentials = response.json()

    # get the region from the EC2 metadata
    region_url = f"{METADATA_BASE_URL}placement/region"
    region_response = requests.get(region_url)
    region_response.raise_for_status()
    region = region_response.text.strip()

    return S3Credentials(
        access_key=credentials["AccessKeyId"],
        secret_key=credentials["SecretAccessKey"],
        session_token=credentials["Token"],
        region=region)

def get_minio_client() -> Minio:
    """Returns a MinIO client configured with the current configuration."""
    if get_config_value_as_boolean(CONFIG_MINIO, CONFIG_MINIO_USE_EC2_METADATA):
        s3_credentials = get_s3_credentials_from_ec2_metadata()
    else:
        s3_credentials = get_s3_credentials_from_config()

    host = get_config_value(CONFIG_MINIO, CONFIG_MINIO_HOST)
    port = get_config_value(CONFIG_MINIO, CONFIG_MINIO_PORT)
    endpoint = f"{host}:{port}"
    secure = get_config_value_as_boolean(CONFIG_MINIO, CONFIG_MINIO_SECURE)
    cert_check = get_config_value_as_boolean(CONFIG_MINIO, CONFIG_MINIO_CERT_CHECK)

    return Minio(
        endpoint=endpoint,
        access_key=s3_credentials.access_key,
        secret_key=s3_credentials.secret_key,
        secure=secure,
        cert_check=cert_check,
        region=s3_credentials.region)


class MinIOStorage(StorageInterface):
    """
    MinIO storage implementation using the MinIO Python SDK.
    
    This class implements the StorageInterface protocol for storing and retrieving
    files from MinIO object storage.
    """
    
    def __init__(
        self,
        host: str = "minio",
        port: int = 9000,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        secure: bool = False,
        region: Optional[str] = None,
        http_client: Optional[object] = None,
        credentials: Optional[object] = None,
        session_token: Optional[str] = None,
        config: Optional[dict] = None
    ):
        """
        Initialize the MinIO storage client.
        
        Args:
            host: MinIO server hostname or IP address
            port: MinIO server port
            access_key: MinIO access key (defaults to environment variable MINIO_ACCESS_KEY)
            secret_key: MinIO secret key (defaults to environment variable MINIO_SECRET_KEY)
            secure: Whether to use HTTPS (defaults to False for HTTP)
            region: MinIO region (optional)
            http_client: Custom HTTP client (optional)
            credentials: Custom credentials provider (optional)
            session_token: Session token for temporary credentials (optional)
            config: Custom configuration (optional)
        """
        self.host = host
        self.port = port
        self.secure = secure

        if not access_key or not secret_key:
            raise ValueError("access key and secret key must be provided when initializing MinIOStorage")
        
        # Get credentials from environment variables if not provided
        self.access_key = access_key
        self.secret_key = secret_key
        
        # Build endpoint URL
        self.endpoint = f"{host}:{port}"

        if config is None:
            config = {}
        
        # Initialize MinIO client
        try:
            self.client = Minio(
                endpoint=self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=secure,
                region=region,
                http_client=http_client,
                credentials=credentials,
                session_token=session_token,
                **config
            )
            
        except S3Error as e:
            logging.error(f"failed to connect to MinIO: {e}")
            raise StorageError(f"failed to connect to MinIO: {e}")
        except Exception as e:
            logging.error(f"unexpected error connecting to MinIO: {e}")
            raise StorageError(f"unexpected error connecting to MinIO: {e}")
    
    def upload_file(
        self,
        local_path: Union[str, Path],
        bucket: str,
        remote_path: str
    ) -> str:
        """
        Upload a file to MinIO storage.
        
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
            # Upload the file
            self.client.fput_object(
                bucket_name=bucket,
                object_name=remote_path,
                file_path=local_path_str
            )
            
            # Generate URL for the uploaded file
            file_url = self._generate_file_url(bucket, remote_path)
            
            logging.info(f"uploaded {local_path_str} to {bucket}/{remote_path}")
            return file_url
            
        except S3Error as e:
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
    ) -> str:
        """
        Download a file from MinIO storage.
        
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
                self.client.stat_object(bucket, remote_path)
            except S3Error as e:
                if e.code == "NoSuchKey":
                    raise FileNotFoundError(f"file not found in storage: {bucket}/{remote_path}")
                raise
            
            # Download the file
            self.client.fget_object(
                bucket_name=bucket,
                object_name=remote_path,
                file_path=local_path_str
            )
            
            # Generate URL for the downloaded file
            file_url = self._generate_file_url(bucket, remote_path)
            
            logging.info(f"downloaded {bucket}/{remote_path} to {local_path_str}")
            return file_url
            
        except FileNotFoundError:
            raise
        except S3Error as e:
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
            if not self.client.bucket_exists(bucket):
                self.client.make_bucket(bucket)
                logging.info(f"created bucket: {bucket}")
        except S3Error as e:
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
            buckets = self.client.list_buckets()
            return [bucket.name for bucket in buckets]
        except S3Error as e:
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
            objects = self.client.list_objects(bucket, prefix=prefix, recursive=recursive)
            return [obj.object_name for obj in objects]
        except S3Error as e:
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
            self.client.remove_object(bucket, remote_path)
            logging.info(f"deleted {bucket}/{remote_path}")
            return True
        except S3Error as e:
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
            self.client.stat_object(bucket, remote_path)
            return True
        except S3Error as e:
            if e.code == "NoSuchKey":
                return False
            # For other errors, log and return False
            logging.warning(f"error checking if object exists {bucket}/{remote_path}: {e}")
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
            stat = self.client.stat_object(bucket, remote_path)
            return {
                'size': stat.size,
                'last_modified': stat.last_modified,
                'etag': stat.etag,
                'content_type': stat.content_type,
                'metadata': stat.metadata
            }
        except S3Error as e:
            if e.code == "NoSuchKey":
                return None
            error_msg = f"failed to get object info for {bucket}/{remote_path}: {e}"
            logging.error(error_msg)
            raise StorageError(error_msg)
