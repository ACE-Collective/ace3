"""Authoritative catalog of the permissions ACE enforces.

The ``PERMISSION_CATALOG`` constant below is the single source of truth for the set of
``(major, minor)`` permissions the application checks with ``@require_permission`` (Flask) and the
``require_permission`` dependency (FastAPI). It is version-controlled, reviewable, and greppable.

The ``auth_permission_catalog`` database table is a *derived read-model*: it is populated from this
constant by :func:`sync_permission_catalog` (via the ``ace perm catalog sync`` CLI and an Alembic
data migration) so the management UI can render a canonical list of permissions to grant without
importing Python. The constant is authoritative; the table is a faithful projection of it.

Note that wildcard grants (e.g. ``*:*``, ``observable:*``) are legitimate values a deployment may
grant, but they are not literal catalog rows -- see :func:`is_grantable`.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogEntry:
    major: str
    minor: str
    description: str


# The authoritative set of enforced permissions. Keep this in sync with the `@require_permission`
# decorators / dependencies across `app/` and `aceapi_v2/` -- the guard test in
# tests/saq/test_permission_catalog.py asserts every enforced pair appears here.
#
# `system:read` and `lock:delete` are reserved/aspirational (present for API completeness) and are
# allowed to exist without a matching decorator.
PERMISSION_CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry("system", "read", "Read system metadata and supported types via API."),
    CatalogEntry("email", "read", "Read archived email content via API/GUI."),
    CatalogEntry("alert", "create", "Create new alerts or upload alert data via API/GUI."),
    CatalogEntry("alert", "read", "Read alert data, submissions, status, and files via API/GUI."),
    CatalogEntry("alert", "write", "Modify alerts (disposition, tags, ownership, comments)."),
    CatalogEntry("lock", "delete", "Clear processing locks on alerts or resources."),
    CatalogEntry("file_collection", "read", "Read file collection requests and history."),
    CatalogEntry("remediation", "read", "View remediation actions and history."),
    CatalogEntry("event", "read", "View events, details, and export event data."),
    CatalogEntry("event", "write", "Create and modify events."),
    CatalogEntry("observable", "read", "Query observables via the API."),
    CatalogEntry("observable", "write", "Modify observables and run observable actions."),
    CatalogEntry("whitelist", "write", "Whitelist observables."),
    CatalogEntry("user", "read", "View users, groups, and their permissions."),
    CatalogEntry("user", "write", "Create/modify users, groups, memberships, and permission grants."),
    CatalogEntry("node", "read", "Read node status and outstanding work counts via API."),
    CatalogEntry("node", "manage", "Drain and resume nodes via API."),
    CatalogEntry("detection", "read", "View observable-detection settings."),
    CatalogEntry("detection", "write", "Modify observable-detection settings."),
)

# Convenience lookups for validation and guard tests.
CATALOG_PAIRS: frozenset[tuple[str, str]] = frozenset((e.major, e.minor) for e in PERMISSION_CATALOG)
CATALOG_MAJORS: frozenset[str] = frozenset(e.major for e in PERMISSION_CATALOG)

# Characters that make a grant a wildcard pattern (fnmatch semantics, matching
# saq.permissions.logic._evaluate_permission).
_WILDCARD_CHARS = ("*", "?", "[")


def is_grantable(major: str, minor: str) -> bool:
    """Return True if (major, minor) is a sensible thing to grant.

    True when the pair is in the catalog, or when either component is a wildcard pattern (so
    ``*:*``, ``observable:*``, ``*:read`` remain grantable even though they are not catalog rows).
    Used to *warn* (not block) on likely typos when granting permissions.
    """
    if (major, minor) in CATALOG_PAIRS:
        return True
    return any(c in major or c in minor for c in _WILDCARD_CHARS)


def sync_permission_catalog(session, *, prune: bool = True) -> tuple[int, int, int]:
    """Reconcile the ``auth_permission_catalog`` table with :data:`PERMISSION_CATALOG`.

    Idempotent: inserts missing rows, updates descriptions that have changed, and (when
    ``prune=True``) deletes rows whose ``(major, minor)`` is no longer in the constant. Only ever
    touches the catalog table -- never the grant tables -- so it can never revoke anyone's access.

    The caller owns the transaction: this function flushes but does not commit, so it can be
    composed with other seed operations in a single transaction.

    Args:
        session: a synchronous SQLAlchemy ``Session``.
        prune: when True, remove catalog rows not present in the constant.

    Returns:
        (inserted, updated, pruned) counts.
    """
    # Imported here so this module stays import-light for the constant/lookups.
    from saq.database.model import AuthPermissionCatalog

    existing = {
        (row.major, row.minor): row
        for row in session.query(AuthPermissionCatalog).all()
    }

    inserted = updated = pruned = 0

    for entry in PERMISSION_CATALOG:
        row = existing.get((entry.major, entry.minor))
        if row is None:
            session.add(
                AuthPermissionCatalog(
                    major=entry.major,
                    minor=entry.minor,
                    description=entry.description,
                )
            )
            inserted += 1
        elif row.description != entry.description:
            row.description = entry.description
            updated += 1

    if prune:
        for (major, minor), row in existing.items():
            if (major, minor) not in CATALOG_PAIRS:
                session.delete(row)
                pruned += 1

    session.flush()
    return inserted, updated, pruned
