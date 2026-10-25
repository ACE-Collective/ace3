"""
Storage module for ACE.

This module provides storage abstractions and implementations for file storage,
supporting local filesystem and S3-compatible object storage.
"""

from saq.storage.factory import StorageFactory, get_storage_system
from saq.storage.adapter import StorageAdapter
from saq.storage.interface import StorageBackendConfig, StorageInterface
from saq.storage.local import LocalStorage
from saq.storage.error import StorageError
from saq.storage.types import StorageTargetType

# S3Storage is not imported here: it loads boto3, and saq.storage.factory imports it when an s3 target is
# configured

__all__ = [
    'StorageFactory',
    'get_storage_system',
    'StorageAdapter',
    'StorageInterface',
    'StorageBackendConfig',
    'LocalStorage',
    'StorageError',
    'StorageTargetType',
]
