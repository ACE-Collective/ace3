"""Tests for the authoritative permission catalog (saq/permissions/catalog.py)."""

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from saq.database.model import AuthGroupPermission, AuthPermissionCatalog, AuthUserPermission
from saq.database.pool import get_db
from saq.permissions.catalog import (
    CATALOG_PAIRS,
    PERMISSION_CATALOG,
    is_grantable,
    sync_permission_catalog,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# Files that reference the permission decorators but are NOT enforcement call sites:
# the decorator/dependency definitions themselves (whose docstrings contain example permissions).
_GUARD_EXCLUDE = {
    REPO_ROOT / "app" / "auth" / "permissions.py",
    REPO_ROOT / "aceapi_v2" / "dependencies.py",
    REPO_ROOT / "aceapi" / "auth.py",
}

# Matches @require_permission("major", "minor") and require_permission('major', 'minor').
_REQUIRE_PERMISSION_RE = re.compile(
    r"""require_permission\(\s*["'](?P<major>[^"']+)["']\s*,\s*["'](?P<minor>[^"']+)["']"""
)

# The legacy Flask API (aceapi/) enforces with @api_auth_check("major", "minor").
_API_AUTH_CHECK_RE = re.compile(
    r"""api_auth_check\(\s*["'](?P<major>[^"']+)["']\s*,\s*["'](?P<minor>[^"']+)["']"""
)


def _enforced_permission_pairs() -> set[tuple[str, str]]:
    """Statically scan app/, aceapi_v2/ (require_permission) and aceapi/ (api_auth_check) for the
    enforced (major, minor) permission pairs."""
    pairs: set[tuple[str, str]] = set()
    for root in ("app", "aceapi_v2"):
        for path in (REPO_ROOT / root).rglob("*.py"):
            if path in _GUARD_EXCLUDE:
                continue
            for match in _REQUIRE_PERMISSION_RE.finditer(path.read_text()):
                pairs.add((match.group("major"), match.group("minor")))
    for path in (REPO_ROOT / "aceapi").rglob("*.py"):
        if path in _GUARD_EXCLUDE:
            continue
        for match in _API_AUTH_CHECK_RE.finditer(path.read_text()):
            pairs.add((match.group("major"), match.group("minor")))
    return pairs


@pytest.mark.unit
class TestCatalogGuard:
    """The catalog must contain every permission the code actually enforces (anti-drift)."""

    def test_every_enforced_permission_is_in_catalog(self):
        enforced = _enforced_permission_pairs()
        # sanity: we found some pairs at all
        assert enforced, "no require_permission() call sites were discovered — check the scanner"

        missing = {pair for pair in enforced if pair not in CATALOG_PAIRS}
        assert not missing, (
            f"these enforced permissions are missing from PERMISSION_CATALOG: {sorted(missing)}"
        )

    def test_user_edit_is_not_enforced_anymore(self):
        # The normalization dropped user:edit; nothing should still enforce it.
        assert ("user", "edit") not in _enforced_permission_pairs()


# Routes that legitimately require no permission gate: genuinely public (liveness, version, docs)
# or self-service reads keyed off the caller's own auth identity (never another user's data).
# Every OTHER FastAPI route must carry a require_permission dependency so that a scoped key (e.g.
# an ai:read key) is denied -- the scope filter lives in require_permission, so an authenticated-
# but-ungated route would be reachable by any authenticated key regardless of its scope.
_FASTAPI_PUBLIC_PATHS = {
    "/health/ping",
    "/common/ping",
    "/common/supported_api_version",
    "/users/me/apikeys",
    "/docs",
    "/redoc",
    "/openapi.json",
}


def _dependant_has_permission_dep(dependant) -> bool:
    """True if any (transitive) sub-dependency is the require_permission-produced gate."""
    for sub in dependant.dependencies:
        if getattr(sub.call, "__name__", "") == "permission_dependency":
            return True
        if _dependant_has_permission_dep(sub):
            return True
    return False


@pytest.mark.unit
class TestRouteCoverage:
    """Every FastAPI route is either permission-gated or on the reviewed public allowlist.

    This is the enforceable form of the AI-container design's "checkable property": a scoped key
    (ai:read) cannot reach any endpoint outside its scope, because every reachable endpoint runs
    require_permission, which applies the key-scope intersection.
    """

    def test_every_fastapi_route_is_gated_or_allowlisted(self):
        from fastapi.routing import APIRoute

        from aceapi_v2.application import app as fastapi_app

        ungated: list[tuple[list[str], str]] = []
        for route in fastapi_app.routes:
            if not isinstance(route, APIRoute):
                continue
            if route.path in _FASTAPI_PUBLIC_PATHS:
                continue
            if not _dependant_has_permission_dep(route.dependant):
                ungated.append((sorted(route.methods), route.path))

        assert not ungated, (
            "these FastAPI routes have no require_permission gate and are not on the reviewed "
            f"public allowlist: {sorted(ungated)}"
        )


@pytest.mark.unit
class TestIsGrantable:
    def test_catalog_pairs_are_grantable(self):
        for entry in PERMISSION_CATALOG:
            assert is_grantable(entry.major, entry.minor) is True

    def test_wildcards_are_grantable(self):
        assert is_grantable("*", "*") is True
        assert is_grantable("observable", "*") is True
        assert is_grantable("*", "read") is True
        assert is_grantable("admin_*", "*") is True

    def test_typos_are_not_grantable(self):
        assert is_grantable("usr", "read") is False
        assert is_grantable("observable", "wrote") is False


@pytest.mark.integration
class TestSyncPermissionCatalog:
    def test_sync_populates_and_is_idempotent(self):
        session = get_db()

        inserted, updated, pruned = sync_permission_catalog(session)
        session.commit()
        assert inserted == len(PERMISSION_CATALOG)
        assert updated == 0
        assert pruned == 0

        # The table now exactly mirrors the constant.
        rows = {(r.major, r.minor) for r in session.query(AuthPermissionCatalog).all()}
        assert rows == CATALOG_PAIRS

        # Second run is a no-op.
        inserted, updated, pruned = sync_permission_catalog(session)
        session.commit()
        assert (inserted, updated, pruned) == (0, 0, 0)
        assert session.query(AuthPermissionCatalog).count() == len(PERMISSION_CATALOG)

    def test_sync_updates_changed_description(self):
        session = get_db()
        # Pre-seed one entry with a stale description.
        entry = PERMISSION_CATALOG[0]
        session.add(AuthPermissionCatalog(major=entry.major, minor=entry.minor, description="stale"))
        session.commit()

        inserted, updated, pruned = sync_permission_catalog(session)
        session.commit()

        assert updated >= 1
        row = session.query(AuthPermissionCatalog).filter(
            AuthPermissionCatalog.major == entry.major,
            AuthPermissionCatalog.minor == entry.minor,
        ).one()
        assert row.description == entry.description
        # No duplicate row created.
        assert session.query(AuthPermissionCatalog).filter(
            AuthPermissionCatalog.major == entry.major,
            AuthPermissionCatalog.minor == entry.minor,
        ).count() == 1

    def test_sync_prune_removes_stale_rows(self):
        session = get_db()
        session.add(AuthPermissionCatalog(major="bogus", minor="perm", description="stale"))
        session.commit()

        # prune=False keeps the stale row.
        sync_permission_catalog(session, prune=False)
        session.commit()
        assert session.query(AuthPermissionCatalog).filter(
            AuthPermissionCatalog.major == "bogus"
        ).count() == 1

        # prune=True removes it, and touches nothing in the catalog set.
        _, _, pruned = sync_permission_catalog(session, prune=True)
        session.commit()
        assert pruned == 1
        assert session.query(AuthPermissionCatalog).filter(
            AuthPermissionCatalog.major == "bogus"
        ).count() == 0
        rows = {(r.major, r.minor) for r in session.query(AuthPermissionCatalog).all()}
        assert rows == CATALOG_PAIRS


# The exact rewrite statements from the seed_permission_catalog migration, exercised directly so a
# regression in the normalization logic fails a fast test rather than only in a live upgrade.
def _normalize_user_edit(session):
    for table, subject_col in (("auth_user_permission", "user_id"), ("auth_group_permission", "group_id")):
        session.execute(text(
            f"DELETE e FROM {table} e "
            f"JOIN {table} w "
            f"  ON w.{subject_col} = e.{subject_col} "
            f" AND w.major = 'user' AND w.minor = 'write' "
            f" AND w.effect = e.effect "
            f"WHERE e.major = 'user' AND e.minor = 'edit'"
        ))
        session.execute(text(
            f"UPDATE {table} SET minor = 'write' "
            f"WHERE major = 'user' AND minor = 'edit'"
        ))
    session.commit()


@pytest.mark.integration
class TestUserEditNormalization:
    def _make_user(self, username):
        from saq.database.model import User
        session = get_db()
        user = User()
        user.username = username
        user.email = f"{username}@example.com"
        user.password = "x"
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    def test_user_grants_normalized(self):
        session = get_db()
        # A: only user:edit ALLOW  -> becomes user:write ALLOW
        a = self._make_user("norm_a")
        session.add(AuthUserPermission(user_id=a.id, major="user", minor="edit", effect="ALLOW"))
        # B: user:edit ALLOW + user:write ALLOW (same effect) -> merged into single write ALLOW
        b = self._make_user("norm_b")
        session.add(AuthUserPermission(user_id=b.id, major="user", minor="edit", effect="ALLOW"))
        session.add(AuthUserPermission(user_id=b.id, major="user", minor="write", effect="ALLOW"))
        # C: user:edit DENY + user:write ALLOW (different effects) -> both effects preserved
        c = self._make_user("norm_c")
        session.add(AuthUserPermission(user_id=c.id, major="user", minor="edit", effect="DENY"))
        session.add(AuthUserPermission(user_id=c.id, major="user", minor="write", effect="ALLOW"))
        session.commit()

        _normalize_user_edit(session)

        def perms(uid):
            return {
                (p.minor, p.effect)
                for p in session.query(AuthUserPermission).filter(
                    AuthUserPermission.user_id == uid, AuthUserPermission.major == "user"
                ).all()
            }

        assert perms(a.id) == {("write", "ALLOW")}
        assert perms(b.id) == {("write", "ALLOW")}
        assert perms(c.id) == {("write", "ALLOW"), ("write", "DENY")}
        # No user:edit rows remain anywhere.
        assert session.query(AuthUserPermission).filter(AuthUserPermission.minor == "edit").count() == 0

    def test_group_grants_normalized(self):
        from saq.permissions import create_auth_group
        session = get_db()
        g = create_auth_group("norm_group")
        session.add(AuthGroupPermission(group_id=g.id, major="user", minor="edit", effect="ALLOW"))
        session.add(AuthGroupPermission(group_id=g.id, major="user", minor="write", effect="ALLOW"))
        session.commit()

        _normalize_user_edit(session)

        rows = {
            (p.minor, p.effect)
            for p in session.query(AuthGroupPermission).filter(
                AuthGroupPermission.group_id == g.id, AuthGroupPermission.major == "user"
            ).all()
        }
        assert rows == {("write", "ALLOW")}
        assert session.query(AuthGroupPermission).filter(AuthGroupPermission.minor == "edit").count() == 0
