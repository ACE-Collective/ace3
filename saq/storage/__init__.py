"""
Storage module for ACE.

This module provides storage abstractions and implementations for file storage,
currently supporting MinIO object storage.
"""

from saq.storage.factory import StorageFactory, get_storage_system
from saq.storage.adapter import StorageAdapter
from saq.storage.interface import StorageInterface
from saq.storage.minio import MinIOStorage
from saq.storage.error import StorageError

__all__ = [
    'StorageFactory',
    'get_storage_system',
    'StorageAdapter',
    'StorageInterface',
    'MinIOStorage',
    'StorageError',
]
