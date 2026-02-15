"""
Storage factory for creating and configuring storage adapters.

This module provides a factory class that creates storage adapters based on
the current configuration, currently supporting S3-compatible storage.
"""

import logging

from saq.configuration.config import get_config
from saq.storage.adapter import StorageAdapter
from saq.storage.s3 import S3Storage
from saq.storage.error import StorageError

STORAGE_SYSTEM = None


class StorageFactory:
    """
    Factory class for creating storage adapters.

    This factory creates and configures storage adapters based on the current
    configuration. It currently supports S3-compatible storage and can be extended
    to support additional storage backends in the future.
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
            s3_config = get_config().s3

            host = s3_config.host
            port = s3_config.port
            access_key = s3_config.access_key
            secret_key = s3_config.secret_key

            # Validate required configuration
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

            # Convert port to integer
            try:
                port_int = int(port)
            except (ValueError, TypeError):
                raise StorageError(f"invalid S3 port configuration: {port}")

            return StorageFactory.create_storage_with_config(
                host=host,
                port=port_int,
                access_key=access_key,
                secret_key=secret_key,
                secure=False
            )

        except StorageError:
            raise

        except Exception as e:
            error_msg = f"failed to create storage adapter: {str(e)}"
            logging.error(error_msg)
            raise StorageError(error_msg)

    @staticmethod
    def create_storage_with_config(
        host: str,
        port: int,
        access_key: str,
        secret_key: str,
        secure: bool = False
    ) -> StorageAdapter:
        """
        Create a storage adapter with explicit configuration.

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
        try:
            s3_storage = S3Storage(
                host=host,
                port=port,
                access_key=access_key,
                secret_key=secret_key,
                secure=secure
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
