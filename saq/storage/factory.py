"""
Storage factory for creating and configuring storage adapters.

This module provides a factory class that creates storage adapters based on
the current configuration, supporting local filesystem and S3-compatible storage.
"""

import logging
import os

from saq.configuration.config import get_config
from saq.storage.adapter import StorageAdapter
from saq.storage.error import StorageError

STORAGE_SYSTEM = None


class StorageFactory:
    """
    Factory class for creating storage adapters.

    This factory creates and configures storage adapters based on the current
    configuration. It supports local filesystem storage and S3-compatible storage.
    """

    @staticmethod
    def get_storage_system() -> StorageAdapter:
        """
        Create and return a storage adapter configured for the current storage system.

        Returns:
            StorageAdapter: A configured storage adapter

        Raises:
            StorageError: If storage creation fails due to configuration issues
        """
        global STORAGE_SYSTEM

        if STORAGE_SYSTEM is not None:
            return STORAGE_SYSTEM

        try:
            config = get_config()
            storage_config = config.storage
            target = "local"
            if storage_config is not None:
                target = storage_config.target

            if target == "s3":
                return StorageFactory._create_s3_storage(config)

            return StorageFactory._create_local_storage(config)

        except StorageError:
            raise

        except Exception as e:
            error_msg = f"failed to create storage adapter: {str(e)}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    @staticmethod
    def _create_local_storage(config) -> StorageAdapter:
        """Create a local filesystem storage adapter."""
        from saq.storage.local import LocalStorage

        base_dir = "data/storage"
        if config.storage is not None:
            base_dir = config.storage.base_dir

        # resolve relative paths against SAQ_HOME
        if not os.path.isabs(base_dir):
            saq_home = os.environ.get("SAQ_HOME", "")
            if saq_home:
                base_dir = os.path.join(saq_home, base_dir)

        storage = LocalStorage(base_dir=base_dir)
        return StorageAdapter(storage)

    @staticmethod
    def _create_s3_storage(config) -> StorageAdapter:
        """Create an S3-compatible storage adapter."""
        from saq.storage.s3 import S3Storage

        s3_config = config.s3

        host = s3_config.host
        port = s3_config.port
        access_key = s3_config.access_key
        secret_key = s3_config.secret_key

        # validate required configuration
        if not all([host, port, access_key, secret_key]):
            missing = []
            if not host:
                missing.append("host")
            if not port:
                missing.append("port")
            if not access_key:
                missing.append("access_key")
            if not secret_key:
                missing.append("secret_key")

            raise StorageError(f"missing required S3 configuration: {', '.join(missing)}")

        # convert port to integer
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            raise StorageError(f"invalid S3 port configuration: {port}")

        return StorageFactory.create_storage_with_config(
            host=host,
            port=port_int,
            access_key=access_key,
            secret_key=secret_key,
            secure=False,
        )

    @staticmethod
    def create_storage_with_config(
        host: str,
        port: int,
        access_key: str,
        secret_key: str,
        secure: bool = False,
    ) -> StorageAdapter:
        """
        Create a storage adapter with explicit S3 configuration.

        Args:
            host: S3-compatible server hostname or IP address
            port: S3-compatible server port
            access_key: S3 access key
            secret_key: S3 secret key
            secure: Whether to use HTTPS (default: False)

        Returns:
            StorageAdapter: A configured storage adapter

        Raises:
            StorageError: If storage creation fails
        """
        from saq.storage.s3 import S3Storage

        try:
            s3_storage = S3Storage(
                host=host,
                port=port,
                access_key=access_key,
                secret_key=secret_key,
                secure=secure,
            )

            storage_adapter = StorageAdapter(s3_storage)
            return storage_adapter

        except Exception as e:
            error_msg = f"failed to create storage adapter with custom config: {str(e)}"
            logging.error(error_msg)
            raise StorageError(error_msg)


def get_storage_system() -> StorageAdapter:
    """
    Convenience function to create a storage adapter.

    Returns:
        StorageAdapter: A configured storage adapter
    """
    global STORAGE_SYSTEM

    if STORAGE_SYSTEM is not None:
        return STORAGE_SYSTEM

    STORAGE_SYSTEM = StorageFactory.get_storage_system()
    return STORAGE_SYSTEM
