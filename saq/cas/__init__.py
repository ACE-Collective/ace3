"""Content-addressed storage (docs/CAS.md).

    from saq.cas import get_cas, Hold

    pool = get_cas().pool("svs_samples")
    digest = pool.put(src, hold=Hold("svs_capture", capture_id))
    with pool.open(digest) as stream: ...
    pool.materialize(digest, dest_path)
"""

from saq.cas.errors import (
    BackendError,
    BackendKeyNotFound,
    CASConfigError,
    CASError,
    DigestMismatch,
    IntegrityError,
    InvalidDigest,
    KeyMismatch,
    LegalHoldActive,
    ObjectDeleting,
    ObjectNotFound,
    PoolNotFound,
)
from saq.cas.hold import LEGAL_HOLD_KIND, Hold
from saq.cas.pool import CASPool, GCStats, ObjectStat, OrphanStats, VerifyStats
from saq.cas.registry import CAS, get_cas, reset_cas

__all__ = [
    "BackendError", "BackendKeyNotFound", "CAS", "CASConfigError", "CASError", "CASPool",
    "DigestMismatch", "GCStats", "Hold", "IntegrityError", "InvalidDigest", "KeyMismatch", "LEGAL_HOLD_KIND",
    "LegalHoldActive", "ObjectDeleting", "ObjectNotFound", "ObjectStat", "OrphanStats",
    "PoolNotFound", "VerifyStats", "get_cas", "reset_cas",
]
