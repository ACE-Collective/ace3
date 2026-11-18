"""
Storage module for ACE.

This module provides storage abstractions and implementations for file storage,
supporting the local filesystem and pluggable backends (storage.target: custom).
"""

from saq.storage.factory import StorageFactory, get_storage_system
from saq.storage.adapter import StorageAdapter
from saq.storage.interface import StorageBackendConfig, StorageInterface
from saq.storage.local import LocalStorage
from saq.storage.error import StorageError
from saq.storage.types import StorageTargetType

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
