"""Exceptions raised by the content-addressed storage subsystem (docs/CAS.md)."""


class CASError(Exception):
    """Base class for every CAS error."""


class CASConfigError(CASError):
    """The CAS configuration is unusable (a pool that cannot be built, a backend that cannot be loaded)."""


class PoolNotFound(CASError):
    """No pool of that name is configured."""

    def __init__(self, pool: str):
        super().__init__(f"cas pool {pool!r} is not configured")
        self.pool = pool


class InvalidDigest(CASError):
    """The digest is not 64 lowercase hex characters."""


class ObjectNotFound(CASError):
    """The pool has no object with that digest (no index row, or the bytes are gone from under a row)."""

    def __init__(self, pool: str, digest: str):
        super().__init__(f"cas object {pool}/{digest} does not exist")
        self.pool = pool
        self.digest = digest


class DigestMismatch(CASError):
    """The caller said what digest it expected and the content hashed to something else."""

    def __init__(self, expected: str, actual: str):
        super().__init__(f"content hashed to {actual} but {expected} was expected")
        self.expected = expected
        self.actual = actual


class IntegrityError(CASError):
    """Stored bytes failed verification (sha256 mismatch for a plaintext pool, tag or key id
    failure for an encrypted pool). No plaintext was released."""


class KeyMismatch(IntegrityError):
    """An encrypted object was written under a different system key than the one loaded. The bytes
    may be intact: this is a key configuration problem, not corruption, and is reported as such."""

    def __init__(self, message: str, stored_key_id: str, loaded_key_id: str):
        super().__init__(message)
        self.stored_key_id = stored_key_id
        self.loaded_key_id = loaded_key_id


class ObjectDeleting(CASError):
    """The object is being deleted by GC or purge. A hold cannot be taken on it; put() waits for
    the row to go and re-uploads, and raises this only when that wait times out."""

    def __init__(self, pool: str, digest: str):
        super().__init__(f"cas object {pool}/{digest} is being deleted")
        self.pool = pool
        self.digest = digest


class LegalHoldActive(CASError):
    """purge() refused because a legal hold exists; it has to be released first (cas:hold)."""

    def __init__(self, pool: str, digest: str):
        super().__init__(f"cas object {pool}/{digest} is under legal hold and cannot be purged")
        self.pool = pool
        self.digest = digest


class BackendError(CASError):
    """The backend failed to read, write or delete bytes."""


class BackendKeyNotFound(BackendError):
    """The backend has no bytes under that key."""

    def __init__(self, key: str):
        super().__init__(f"backend has no object at {key!r}")
        self.key = key
