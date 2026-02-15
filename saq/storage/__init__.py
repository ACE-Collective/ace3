"""
Storage module for ACE.

This module provides storage abstractions and implementations for file storage,
supporting local filesystem and S3-compatible object storage.
"""

from saq.storage.factory import StorageFactory, get_storage_system
from saq.storage.adapter import StorageAdapter
from saq.storage.interface import StorageInterface
from saq.storage.local import LocalStorage
from saq.storage.error import StorageError
from saq.storage.types import StorageTargetType

try:
    from saq.storage.s3 import S3Storage
except Exception:
    S3Storage = None

__all__ = [
    'StorageFactory',
    'get_storage_system',
    'StorageAdapter',
    'StorageInterface',
    'LocalStorage',
    'S3Storage',
    'StorageError',
    'StorageTargetType',
]
