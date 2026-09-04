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
# `admin:read` is the umbrella gate for the /admin GUI area; it is enforced by the admin blueprint's
# before_request guard (app/admin/views/access.py:24) rather than a require_permission decorator, so
# it has no decorator call site. `ai:read` is enforced by the out-of-repo AI container. Every other
# entry has at least one in-repo enforcement site.
PERMISSION_CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry("admin", "read", "Access the administration area (individual actions require their own permissions)."),
    # The ai: major gates the AI investigation API (aceapi_ai). ai:alert (alert reads: the alert and
    # its version token, saq.log, package download) and ai:event (ACE Event read) are the only static
    # entries; the per-backend ai:<name> entries are DERIVED from the deployment's
    # ai_query_backend_<name> config sections (see dynamic_backend_entries), so integration-provided
    # backends surface their permission without their vendor name appearing in this open-source file.
    CatalogEntry("ai", "alert", "Read alerts (alert + version token, saq.log, package download) via the AI investigation API."),
    CatalogEntry("ai", "event", "Read ACE Events (metadata and mapped alerts) via the AI investigation API."),
    CatalogEntry("alert", "create", "Create new alerts or upload alert data via API/GUI."),
    CatalogEntry("alert", "read", "Read alert data, submissions, status, and files via API/GUI."),
    CatalogEntry("alert", "review", "Review and correct alert dispositions."),
    CatalogEntry("alert", "write", "Modify alerts (disposition, tags, ownership, comments)."),
    CatalogEntry("detection", "read", "View observable-detection settings."),
    CatalogEntry("detection", "write", "Modify observable-detection settings."),
    CatalogEntry("email", "read", "Read archived email content via API/GUI."),
    CatalogEntry("engine", "clear", "Clear a transferred work item's stale copy on a remote node (node-to-node)."),
    CatalogEntry("engine", "download", "Download a work item's storage directory from a node (node-to-node)."),
    CatalogEntry("engine", "upload", "Upload a work item's storage directory to a node (node-to-node)."),
    CatalogEntry("event", "read", "View events, details, and export event data."),
    CatalogEntry("event", "write", "Create and modify events."),
    CatalogEntry("file_collection", "read", "Read file collection requests and history."),
    CatalogEntry("hunt", "write", "Compile and execute hunts via the hunt-validation API endpoint."),
    CatalogEntry("node", "manage", "Drain and resume nodes via API."),
    CatalogEntry("node", "read", "Read node status and outstanding work counts via API."),
    CatalogEntry("observable", "read", "Query observables via the API."),
    CatalogEntry("observable", "write", "Modify observables and run observable actions."),
    CatalogEntry("remediation", "read", "View remediation actions and history."),
    CatalogEntry("secret", "read", "View encrypted-secret names and config references."),
    CatalogEntry("secret", "write", "Create, overwrite, or delete encrypted secrets."),
    CatalogEntry("system", "read", "Read system metadata and supported types via API."),
    CatalogEntry("user", "read", "View users, groups, and their permissions."),
    CatalogEntry("user", "write", "Create/modify users, groups, memberships, and permission grants."),
    CatalogEntry("whitelist", "write", "Whitelist observables."),
)

# Convenience lookups for validation and guard tests. These cover the STATIC entries only; use
# get_catalog_pairs() where the config-derived ai:<backend> entries must be included.
CATALOG_PAIRS: frozenset[tuple[str, str]] = frozenset((e.major, e.minor) for e in PERMISSION_CATALOG)
CATALOG_MAJORS: frozenset[str] = frozenset(e.major for e in PERMISSION_CATALOG)


def dynamic_backend_entries() -> tuple[CatalogEntry, ...]:
    """One ai:<name> entry per ai_query_backend_<name> config section in the loaded configuration.

    The AI API's query routes are config-driven, and so are their permissions: a deployment that
    configures a backend (its own or an integration's) gets the matching catalog entry here, with
    no code change in this file. Disabled backends are included -- their permission being grantable
    is harmless while the route does not exist, and it keeps the catalog stable across toggles.

    Returns () when the configuration is not loaded (import-time use of the static constants stays
    valid); callers that need the full catalog go through get_permission_catalog().
    """
    # imported lazily: this module must stay importable before configuration load
    from saq.configuration.config import get_config

    try:
        backends = get_config().ai_query_backends
    except Exception:
        return ()

    return tuple(
        CatalogEntry("ai", backend.name,
                     f"Run read-only {backend.name} queries via the AI investigation API.")
        for backend in sorted(backends, key=lambda b: b.name)
        if ("ai", backend.name) not in CATALOG_PAIRS
    )


def get_permission_catalog() -> tuple[CatalogEntry, ...]:
    """The full catalog: the static constant plus the config-derived ai:<backend> entries."""
    return PERMISSION_CATALOG + dynamic_backend_entries()


def get_catalog_pairs() -> frozenset[tuple[str, str]]:
    return frozenset((e.major, e.minor) for e in get_permission_catalog())

# Characters that make a grant a wildcard pattern (fnmatch semantics, matching
# saq.permissions.logic._evaluate_permission).
_WILDCARD_CHARS = ("*", "?", "[")


def is_grantable(major: str, minor: str) -> bool:
    """Return True if (major, minor) is a sensible thing to grant.

    True when the pair is in the catalog, or when either component is a wildcard pattern (so
    ``*:*``, ``observable:*``, ``*:read`` remain grantable even though they are not catalog rows).
    Used to *warn* (not block) on likely typos when granting permissions.
    """
    if (major, minor) in get_catalog_pairs():
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

    catalog = get_permission_catalog()
    catalog_pairs = frozenset((e.major, e.minor) for e in catalog)

    existing = {
        (row.major, row.minor): row
        for row in session.query(AuthPermissionCatalog).all()
    }

    inserted = updated = pruned = 0

    for entry in catalog:
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
            if (major, minor) not in catalog_pairs:
                session.delete(row)
                pruned += 1

    session.flush()
    return inserted, updated, pruned
