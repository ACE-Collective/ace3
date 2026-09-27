"""CAS backends: dumb byte stores behind a small protocol (docs/CAS.md, "Backends").

A backend never decides whether an object exists; the index does. It stores bytes under a key,
gives them back, deletes them, and can list what it has for the orphan sweep. The local backend
also hands out hardlinks, which is what lets a plaintext local pool materialize an object without
a copy.
"""

import importlib
import logging
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import BinaryIO, ClassVar, Iterator, Protocol, runtime_checkable

from pydantic import BaseModel

from saq.cas.errors import BackendKeyNotFound, CASConfigError
from saq.configuration.schema import CASBackendSpec, CASConfig, CASPoolConfig
from saq.environment import get_data_dir

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TEMP_PREFIX = ".tmp-"
_COPY_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class BackendEntry:
    """One stored object as the backend sees it: its key, size in the backend and modification time.
    Every object store's list call returns all three, so the orphan sweep never has to stat twice."""

    key: str
    size: int
    mtime: float


@runtime_checkable
class CASBackend(Protocol):
    # True when the bytes live on this node only. A pool declared shared refuses such a backend.
    node_local: ClassVar[bool]

    def write(self, key: str, stream: BinaryIO) -> None:
        """Store the stream under key. Atomic: the key is either absent or complete, never partial.
        Idempotent: writing a key that exists is not an error (the content is the same by
        construction, because the key is the content's digest)."""
        ...

    def exists(self, key: str) -> bool: ...

    def open(self, key: str) -> Iterator[BinaryIO]:
        """Context manager yielding a readable binary stream. Raises BackendKeyNotFound."""
        ...

    def delete(self, key: str) -> None:
        """Remove the key. A missing key is not an error."""
        ...

    def iter_entries(self, prefix: str = "") -> Iterator[BackendEntry]:
        """List stored objects under prefix. The only operation that lists the store; used by the
        orphan sweep, never by GC."""
        ...

    # optional capability, checked with hasattr():
    # def link(self, key: str, dest: str) -> bool:
    #     """Hardlink the stored bytes to dest. Returns False when a link is not possible (e.g.
    #     across filesystems) so the caller copies instead. Local plaintext pools only."""


def is_digest(value: str) -> bool:
    return isinstance(value, str) and _DIGEST_RE.match(value) is not None


def object_key(pool: str, digest: str) -> str:
    """The backend key of an object: <pool>/<sha[:2]>/<sha[2:4]>/<sha>. Object names are plain
    (docs/CAS.md, "Encryption"): whoever can list the store learns which hashes ACE holds."""
    return f"{pool}/{digest[:2]}/{digest[2:4]}/{digest}"


def digest_from_key(key: str) -> str | None:
    """The digest an object key names, or None when the key is not one the CAS would write."""
    parts = key.split("/")
    if len(parts) != 4:
        return None

    _, shard1, shard2, digest = parts
    if not is_digest(digest) or digest[:2] != shard1 or digest[2:4] != shard2:
        return None

    return digest


def resolve_data_path(path: str) -> str:
    """CAS paths are relative to DATA_DIR (like crash_reporting.directory), absolute paths are honored."""
    if os.path.isabs(path):
        return path

    return os.path.join(get_data_dir(), path)


class LocalBackend:
    """Bytes in a directory tree under root. Writes go to a temp file in the object's own
    directory, are fsync'd and renamed into place, so a reader never sees a partial object and a
    crash leaves at most a .tmp- file that sweep_temp_files() removes."""

    node_local: ClassVar[bool] = True

    def __init__(self, root: str):
        self.root = root

    def path(self, key: str) -> str:
        return os.path.join(self.root, key)

    def write(self, key: str, stream: BinaryIO) -> None:
        final = self.path(key)
        if os.path.exists(final):
            return

        directory = os.path.dirname(final)
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=directory, prefix=_TEMP_PREFIX)
        try:
            with os.fdopen(fd, "wb") as fp:
                shutil.copyfileobj(stream, fp, _COPY_CHUNK)
                fp.flush()
                os.fsync(fp.fileno())

            # a rename over an identical existing file (two writers of the same digest) is atomic
            # and harmless; that is the if-absent tolerance
            os.rename(temp_path, final)
        except BaseException:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

            raise

        # make the rename itself durable. some filesystems (overlay, bind mounts) refuse to fsync a
        # directory; the file's own fsync already happened, so that is not fatal
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as e:
            logging.debug("unable to fsync %s: %s", directory, e)

    def exists(self, key: str) -> bool:
        return os.path.isfile(self.path(key))

    @contextmanager
    def open(self, key: str) -> Iterator[BinaryIO]:
        try:
            fp = open(self.path(key), "rb")
        except FileNotFoundError:
            raise BackendKeyNotFound(key) from None

        try:
            yield fp
        finally:
            fp.close()

    def delete(self, key: str) -> None:
        path = self.path(key)
        try:
            os.unlink(path)
        except FileNotFoundError:
            return

        # leave no empty shard directories behind (best effort, the tree is two levels deep)
        for _ in range(2):
            path = os.path.dirname(path)
            if os.path.normpath(path) == os.path.normpath(self.root):
                break

            try:
                os.rmdir(path)
            except OSError:
                break

    def iter_entries(self, prefix: str = "") -> Iterator[BackendEntry]:
        start = self.path(prefix) if prefix else self.root
        if not os.path.isdir(start):
            return

        for dirpath, _, filenames in os.walk(start):
            for name in filenames:
                if name.startswith(_TEMP_PREFIX):
                    continue

                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except FileNotFoundError:
                    continue

                yield BackendEntry(
                    key=os.path.relpath(full, self.root).replace(os.sep, "/"),
                    size=st.st_size,
                    mtime=st.st_mtime)

    def sweep_temp_files(self, older_than: float) -> int:
        """Remove .tmp- files left by a crashed write, if their mtime is before older_than (a unix
        timestamp). Returns how many were removed."""
        removed = 0
        if not os.path.isdir(self.root):
            return 0

        for dirpath, _, filenames in os.walk(self.root):
            for name in filenames:
                if not name.startswith(_TEMP_PREFIX):
                    continue

                full = os.path.join(dirpath, name)
                try:
                    if os.stat(full).st_mtime < older_than:
                        os.unlink(full)
                        removed += 1
                except FileNotFoundError:
                    continue

        return removed

    def link(self, key: str, dest: str) -> bool:
        try:
            os.link(self.path(key), dest)
            return True
        except FileExistsError:
            raise
        except OSError as e:
            logging.debug("unable to hardlink %s to %s: %s", key, dest, e)
            return False


def _load_custom_backend(pool_name: str, spec: CASBackendSpec) -> CASBackend:
    # the same python_module / python_class / config pattern saq/storage and the analysis cache use
    try:
        module = importlib.import_module(spec.python_module)
    except ImportError as e:
        raise CASConfigError(f"cas pool {pool_name}: cannot import backend module {spec.python_module}: {e}") from e

    try:
        cls = getattr(module, spec.python_class)
    except AttributeError:
        raise CASConfigError(f"cas pool {pool_name}: module {spec.python_module} has no class {spec.python_class}") from None

    if not isinstance(getattr(cls, "node_local", None), bool):
        raise CASConfigError(f"cas pool {pool_name}: backend class {spec.python_class} must declare node_local (bool)")

    get_config_class = getattr(cls, "get_config_class", None)
    if get_config_class is None:
        raise CASConfigError(f"cas pool {pool_name}: backend class {spec.python_class} must define get_config_class()")

    config_class = get_config_class()
    if not (isinstance(config_class, type) and issubclass(config_class, BaseModel)):
        raise CASConfigError(f"cas pool {pool_name}: {spec.python_class}.get_config_class() must return a pydantic model")

    try:
        backend_config = config_class.model_validate(spec.config)
    except Exception as e:
        raise CASConfigError(f"cas pool {pool_name}: invalid backend config: {e}") from e

    try:
        return cls(backend_config)
    except Exception as e:
        raise CASConfigError(f"cas pool {pool_name}: unable to construct backend {spec.python_class}: {e}") from e


def load_backend(pool_name: str, pool_config: CASPoolConfig, cas_config: CASConfig) -> CASBackend:
    """Build the backend a pool is configured with. Raises CASConfigError when a shared pool ends
    up with a node-local backend (the local case is already refused by the config schema; this
    catches a custom class that says node_local)."""
    if pool_config.backend == "local":
        root = pool_config.root if pool_config.root is not None else os.path.join(cas_config.local_root, pool_name)
        backend: CASBackend = LocalBackend(resolve_data_path(root))
    elif pool_config.backend == "custom":
        backend = _load_custom_backend(pool_name, pool_config.custom)
    else:
        raise CASConfigError(f"cas pool {pool_name}: unknown backend {pool_config.backend!r}")

    if pool_config.shared and backend.node_local:
        raise CASConfigError(f"cas pool {pool_name} is declared shared but its backend is node-local")

    return backend
