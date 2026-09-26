"""
Storage factory for creating and configuring storage adapters.

This module provides a factory class that creates storage adapters based on
the current configuration, supporting local filesystem storage, S3-compatible storage,
and pluggable backends loaded from configuration (storage.target: custom).
"""

import importlib
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
        # NOTE deliberately not cached here. The module-level get_storage_system() below owns the
        # cache; this method always builds a fresh adapter.
        try:
            config = get_config()
            storage_config = config.storage
            target = "local"
            if storage_config is not None:
                target = storage_config.target

            if target == "custom":
                return StorageFactory._create_custom_storage(config)

            # a backend spec paired with a built-in target is always a mistake, and a silent
            # one is how a deployment ends up believing it is writing to shared storage while
            # every node is still writing to its own disk
            if storage_config is not None and storage_config.backend is not None:
                raise StorageError(
                    f"storage.backend is configured but storage.target is {target!r}; "
                    "set storage.target to custom to use it")

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
    def _create_custom_storage(config) -> StorageAdapter:
        """Load a pluggable storage backend from storage.backend.

        Mirrors _load_blob_store() in saq/analysis/blob_store.py: import the module, resolve
        the class, validate the YAML `config:` sub-dict against the class's own Pydantic model,
        and hand that model to the constructor as its single argument.

        This exists so a deployment whose object store needs credentials the built-in s3
        backend does not model -- an IAM instance role, STS, a signing proxy -- can supply its
        own backend without that vendor's specifics landing in core.
        """
        spec = None if config.storage is None else config.storage.backend
        if spec is None:
            raise StorageError(
                "storage.target is custom but storage.backend is not configured")

        try:
            module = importlib.import_module(spec.python_module)
        except ImportError as e:
            raise StorageError(f"unable to import storage backend module {spec.python_module}: {e}")

        try:
            cls = getattr(module, spec.python_class)
        except AttributeError:
            raise StorageError(
                f"storage backend module {spec.python_module} has no class {spec.python_class}")

        # StorageInterface is a plain Protocol (not runtime_checkable), so issubclass() is not
        # available as a guard here. Requiring get_config_class() is the check that actually
        # matters: without it there is nothing to validate the backend's config against.
        if not hasattr(cls, "get_config_class"):
            raise StorageError(
                f"storage backend {spec.python_module}:{spec.python_class} does not implement "
                "get_config_class()")

        backend_config = cls.get_config_class().model_validate(spec.config)
        return StorageAdapter(cls(backend_config))

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


def reset_storage_system() -> None:
    """Drop the cached storage adapter so the next call builds a fresh one.

    The cached adapter holds a boto3 client, and a boto3 client holds a urllib3 connection pool
    with live sockets. Those are **not fork safe**: a forked child that inherits one shares the
    parent's TCP connections, which shows up as interleaved or truncated responses and hangs.

    ACE forks its engine workers (``ACE_MP_CONTEXT = multiprocessing.get_context("fork")``), and
    workers now touch storage to replicate crash reports, so this is registered below to run
    automatically in every child. Tests also call it directly to keep a cached adapter from
    leaking between them.

    **Do not add logging here.** As a fork child handler this runs inside ``os.fork()``, before
    multiprocessing's ``_bootstrap`` runs the after-forkers, so every fork-aware thread-local
    still holds the object inherited from the parent -- a root handler that talks to another
    process would be used over the *parent's* connection and both sides can block forever. Same
    constraint, and same reason, as ``saq/database/pool.py::_after_fork_in_child``. Keeping this
    function a single assignment is what makes it safe.
    """
    global STORAGE_SYSTEM
    STORAGE_SYSTEM = None


# every forked child starts with no inherited client. registering this here rather than at each
# fork site means a future consumer of saq.storage cannot reintroduce the hazard by forking
# somewhere new.
os.register_at_fork(after_in_child=reset_storage_system)
