"""
Storage factory for creating and configuring storage adapters.

This module provides a factory class that creates storage adapters based on
the current configuration, currently supporting MinIO storage.
"""

import logging

from saq.configuration.config import get_config
from saq.constants import (
    CONFIG_MINIO,
    CONFIG_MINIO_HOST,
    CONFIG_MINIO_PORT,
    CONFIG_MINIO_ACCESS_KEY,
    CONFIG_MINIO_SECRET_KEY,
)
from saq.storage.adapter import StorageAdapter
from saq.storage.minio import MinIOStorage
from saq.storage.error import StorageError

STORAGE_SYSTEM = None


class StorageFactory:
    """
    Factory class for creating storage adapters.
    
    This factory creates and configures storage adapters based on the current
    configuration. It currently supports MinIO storage and can be extended
    to support additional storage backends in the future.
    """
    
    @staticmethod
    def get_storage_system() -> StorageAdapter:
        """
        Create and return a storage adapter configured for the current storage system.
        
        Currently returns a MinIO storage adapter configured from the application
        configuration.
        
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
            
            if not config or CONFIG_MINIO not in config:
                raise StorageError("MinIO configuration section not found in configuration")
            
            minio_config = config[CONFIG_MINIO]
            
            # Extract MinIO configuration values
            host = minio_config.get(CONFIG_MINIO_HOST)
            port = minio_config.get(CONFIG_MINIO_PORT)
            access_key = minio_config.get(CONFIG_MINIO_ACCESS_KEY)
            secret_key = minio_config.get(CONFIG_MINIO_SECRET_KEY)
            
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
                
                raise StorageError(f"Missing required MinIO configuration: {', '.join(missing)}")
            
            # Convert port to integer
            try:
                port_int = int(port)
            except (ValueError, TypeError):
                raise StorageError(f"Invalid MinIO port configuration: {port}")

            return StorageFactory.create_storage_with_config(
                host=host,
                port=port_int,
                access_key=access_key,
                secret_key=secret_key,
                secure=False
            )
            
        except StorageError:
            # Re-raise storage errors
            raise

        except Exception as e:
            # Wrap other errors in StorageError
            error_msg = f"Failed to create storage adapter: {str(e)}"
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
        
        This method allows creating storage adapters with custom configuration
        instead of reading from the application configuration.
        
        Args:
            host: MinIO server hostname or IP address
            port: MinIO server port
            access_key: MinIO access key
            secret_key: MinIO secret key
            secure: Whether to use HTTPS (default: False)
            
        Returns:
            StorageAdapter: A configured storage adapter
            
        Raises:
            StorageError: If storage creation fails
        """
        try:
            minio_storage = MinIOStorage(
                host=host,
                port=port,
                access_key=access_key,
                secret_key=secret_key,
                secure=secure
            )
            
            storage_adapter = StorageAdapter(minio_storage)
            return storage_adapter
            
        except Exception as e:
            error_msg = f"Failed to create storage adapter with custom config: {str(e)}"
            logging.error(error_msg)
            raise StorageError(error_msg)


# Convenience function for backward compatibility
def get_storage_system() -> StorageAdapter:
    """
    Convenience function to create a storage adapter.
    
    This function provides a simple way to get a configured storage adapter
    without needing to instantiate the factory class.
    
    Returns:
        StorageAdapter: A configured storage adapter
    """
    global STORAGE_SYSTEM

    if STORAGE_SYSTEM is not None:
        return STORAGE_SYSTEM
    
    STORAGE_SYSTEM = StorageFactory.get_storage_system()
    return STORAGE_SYSTEM
