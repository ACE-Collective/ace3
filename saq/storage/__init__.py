"""
Storage module for ACE.

This module provides storage abstractions and implementations for file storage,
currently supporting S3-compatible object storage.
"""

from saq.storage.factory import StorageFactory, get_storage_system
from saq.storage.adapter import StorageAdapter
from saq.storage.interface import StorageInterface
from saq.storage.s3 import S3Storage
from saq.storage.error import StorageError

__all__ = [
    'StorageFactory',
    'get_storage_system',
    'StorageAdapter',
    'StorageInterface',
    'S3Storage',
    'StorageError',
]
