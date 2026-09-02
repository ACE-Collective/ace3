"""Tests for the authoritative permission catalog (saq/permissions/catalog.py)."""

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from saq.configuration.config import get_config
from saq.database.model import AuthGroupPermission, AuthPermissionCatalog, AuthUserPermission
from saq.database.pool import get_db
from saq.permissions.catalog import (
    PERMISSION_CATALOG,
    get_catalog_pairs,
    get_permission_catalog,
    is_grantable,
    sync_permission_catalog,
)
from saq.permissions.logic import key_scope_allows, parse_permission_pattern

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


def _enforced_permission_pairs_in(path: Path) -> set[tuple[str, str]]:
    """Statically scan a single file for the (major, minor) pairs it enforces, via either
    require_permission(...) (app/, aceapi_v2/) or api_auth_check(...) (aceapi/)."""
    text = path.read_text()
    return {
        (match.group("major"), match.group("minor"))
        for regex in (_REQUIRE_PERMISSION_RE, _API_AUTH_CHECK_RE)
        for match in regex.finditer(text)
    }


def _enforced_permission_pairs() -> set[tuple[str, str]]:
    """Statically scan app/, aceapi_v2/ (require_permission) and aceapi/ (api_auth_check) for the
    enforced (major, minor) permission pairs."""
    pairs: set[tuple[str, str]] = set()
    for root in ("app", "aceapi_v2", "aceapi", "aceapi_ai"):
        for path in (REPO_ROOT / root).rglob("*.py"):
            if path in _GUARD_EXCLUDE:
                continue
            pairs |= _enforced_permission_pairs_in(path)
    return pairs


@pytest.mark.unit
class TestCatalogGuard:
    """The catalog must contain every permission the code actually enforces (anti-drift)."""

    def test_every_enforced_permission_is_in_catalog(self):
        enforced = _enforced_permission_pairs()
        # sanity: we found some pairs at all
        assert enforced, "no require_permission() call sites were discovered — check the scanner"

        missing = {pair for pair in enforced if pair not in get_catalog_pairs()}
        assert not missing, (
            f"these enforced permissions are missing from the permission catalog: {sorted(missing)}"
        )

    def test_user_edit_is_not_enforced_anymore(self):
        # The normalization dropped user:edit; nothing should still enforce it.
        assert ("user", "edit") not in _enforced_permission_pairs()


# The legacy Flask blueprint carrying ACE's node-to-node surface. engine_bp is declared in
# aceapi/blueprints.py and every one of its routes is defined in aceapi/engine.py -- nothing else
# registers a route on it, so scanning that one file yields the whole surface.
_ENGINE_MODULE = REPO_ROOT / "aceapi" / "engine.py"

# The one node-to-node call that is NOT an engine_bp route: ace_api.submit() posts to
# /api/analysis/submit (aceapi/analysis.py:80), used by saq/collectors/remote_node.py and the GUI's
# manual alert entry.
_SUBMIT_PERMISSION = ("alert", "create")


@pytest.mark.unit
class TestNodeToNodeScope:
    """The automation API key's scope must cover everything ACE's engine calls on a peer node.

    Regression guard for PR #451, which narrowed etc/saq.default.yaml's `automation` key to
    alert:create on the strength of a hand-written comment claiming that was "the entire runtime
    surface of node-to-node calls". It was not: transfer_work_target() also calls ace_api.download()
    and ace_api.clear(). Every cross-node work transfer 403'd in production until this was fixed.

    Both tests derive the required permission set by scanning the endpoints, so neither can drift
    into the hand-maintained list that caused the outage.
    """

    def test_every_engine_route_is_gated_on_the_engine_major(self):
        # /api/engine/ is machine-to-machine only. Keeping every route under one major is what
        # lets the scope be a single `engine:*` entry and makes the coverage test below total.
        enforced = _enforced_permission_pairs_in(_ENGINE_MODULE)
        assert enforced, "no api_auth_check() call sites found in aceapi/engine.py — scanner broken"

        foreign = sorted(pair for pair in enforced if pair[0] != "engine")
        assert not foreign, (
            f"these aceapi/engine.py routes are gated on a non-engine major: {foreign}. "
            f"Node-to-node endpoints must use engine:* so the automation key's scope covers them."
        )

    def test_automation_key_scope_covers_node_to_node_surface(self):
        # apikeys.automation comes from etc/saq.default.yaml and survives into the unit-test config
        # via deepmerge, so this asserts against the scope production actually ships.
        entry = get_config().apikeys["automation"]
        assert not isinstance(entry, str), (
            "apikeys.automation uses the deprecated bare-string form, which bypasses permission "
            "checks entirely. Never resolve a scope failure by reverting to it."
        )
        scope = [parse_permission_pattern(s) for s in entry.scope]

        required = _enforced_permission_pairs_in(_ENGINE_MODULE) | {_SUBMIT_PERMISSION}
        unpermitted = sorted(
            pair for pair in required if not key_scope_allows(scope, *pair)
        )
        assert not unpermitted, (
            f"etc/saq.default.yaml apikeys.automation.scope does not permit {unpermitted} — "
            f"node-to-node calls will 403 in production"
        )


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


def _iter_effective_routes(app):
    """Yield (path, methods, dependant) for every API operation on a FastAPI app.

    FastAPI's lazy router inclusion leaves _IncludedRouter wrappers (not APIRoute objects) on
    app.routes, so a plain isinstance(route, APIRoute) walk silently sees zero routes; expanding
    the effective route contexts is what actually enumerates the API surface. The effective
    dependant includes router-level dependencies merged with the route's own.
    """
    from fastapi.routing import APIRoute

    for route in app.routes:
        if isinstance(route, APIRoute):
            yield route.path, route.methods, route.dependant
        elif hasattr(route, "effective_route_contexts"):
            for context in route.effective_route_contexts():
                yield context.path, context.original_route.methods, context.dependant


def _dependant_has_permission_dep(dependant) -> bool:
    """True if any (transitive) sub-dependency is the require_permission-produced gate."""
    for sub in dependant.dependencies:
        if getattr(sub.call, "__name__", "") == "permission_dependency":
            return True
        if _dependant_has_permission_dep(sub):
            return True
    return False


def _dependant_permission_pairs(dependant) -> set[tuple[str, str]]:
    """The (major, minor) pairs of every require_permission gate reachable from the dependant."""
    pairs: set[tuple[str, str]] = set()
    for sub in dependant.dependencies:
        fn = sub.call
        if getattr(fn, "__name__", "") == "permission_dependency":
            closure = dict(zip(fn.__code__.co_freevars, fn.__closure__))
            pairs.add((closure["major"].cell_contents, closure["minor"].cell_contents))
        pairs.update(_dependant_permission_pairs(sub))
    return pairs


# The AI app's reviewed public (permission-less but authenticated where noted) allowlist:
# /health/ping is liveness; /backends is authenticated metadata-only discovery that itself reports
# per-backend authorization; the docs routes carry no data.
_AI_PUBLIC_PATHS = {
    "/health/ping",
    "/backends",
    "/docs",
    "/redoc",
    "/openapi.json",
}


def _fastapi_apps():
    from aceapi_v2.application import app as v2_app

    # imported lazily: the AI app builds its backend registry from the loaded configuration
    import aceapi_ai.application

    return [
        ("aceapi_v2", v2_app, _FASTAPI_PUBLIC_PATHS),
        ("aceapi_ai", aceapi_ai.application.app, _AI_PUBLIC_PATHS),
    ]


@pytest.mark.unit
class TestRouteCoverage:
    """Every FastAPI route in every app is either permission-gated or on its reviewed public
    allowlist.

    This is the enforceable form of the AI-container design's "checkable property": a scoped key
    cannot reach any endpoint outside its scope, because every reachable endpoint runs
    require_permission, which applies the key-scope intersection.
    """

    def test_every_fastapi_route_is_gated_or_allowlisted(self):
        ungated: list[tuple[str, list[str], str]] = []
        route_count = 0
        for app_name, fastapi_app, public_paths in _fastapi_apps():
            for path, methods, dependant in _iter_effective_routes(fastapi_app):
                route_count += 1
                if path in public_paths:
                    continue
                if not _dependant_has_permission_dep(dependant):
                    ungated.append((app_name, sorted(methods), path))

        # guard against the walk going vacuous again (see _iter_effective_routes)
        assert route_count > 40, f"route enumeration only found {route_count} routes"

        assert not ungated, (
            "these FastAPI routes have no require_permission gate and are not on their app's "
            f"reviewed public allowlist: {sorted(ungated)}"
        )

    def test_ai_query_routes_gate_exactly_their_backend(self):
        """POST /query/<name> must require exactly ai:<name> -- for every enabled backend."""
        import aceapi_ai.application
        from saq.configuration.config import get_config

        routes_by_path = {
            path: dependant
            for path, _, dependant in _iter_effective_routes(aceapi_ai.application.app)
        }

        enabled = [b.name for b in get_config().ai_query_backends if b.enabled]
        assert enabled, "no enabled ai query backends in the test configuration"

        for name in enabled:
            dependant = routes_by_path.get(f"/query/{name}")
            assert dependant is not None, f"enabled backend {name} has no /query/{name} route"
            assert _dependant_permission_pairs(dependant) == {("ai", name)}

    def test_ai_alert_and_event_routes_gate_their_static_minor(self):
        """Every /alerts/... route on the AI app requires exactly ai:alert and /events/{id} exactly
        ai:event -- and all of them exist (a renamed route must not silently drop out of the sweep)."""
        import aceapi_ai.application

        expected = {
            "/alerts/{alert_uuid}": {("ai", "alert")},
            "/alerts/{alert_uuid}/logs": {("ai", "alert")},
            "/alerts/{alert_uuid}/download": {("ai", "alert")},
            "/events/{event_ref}": {("ai", "event")},
        }
        seen = {}
        for path, _, dependant in _iter_effective_routes(aceapi_ai.application.app):
            if path.startswith(("/alerts/", "/events/")):
                seen[path] = _dependant_permission_pairs(dependant)
        assert seen == expected


@pytest.mark.unit
class TestIsGrantable:
    def test_catalog_pairs_are_grantable(self):
        for entry in PERMISSION_CATALOG:
            assert is_grantable(entry.major, entry.minor) is True

    def test_config_derived_backend_permissions_are_grantable(self):
        # the ai:<backend> entries come from the ai_query_backend_* config sections, so
        # integration-provided backends are grantable without appearing in the static constant
        assert is_grantable("ai", "fake") is True
        assert is_grantable("ai", "splunk") is True
        assert is_grantable("ai", "read") is False  # replaced by ai:alert + per-backend entries

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
        assert inserted == len(get_permission_catalog())
        assert updated == 0
        assert pruned == 0

        # The table now exactly mirrors the catalog (static + config-derived backend entries).
        rows = {(r.major, r.minor) for r in session.query(AuthPermissionCatalog).all()}
        assert rows == get_catalog_pairs()
        assert ("ai", "fake") in rows  # config-derived entry made it into the read-model

        # Second run is a no-op.
        inserted, updated, pruned = sync_permission_catalog(session)
        session.commit()
        assert (inserted, updated, pruned) == (0, 0, 0)
        assert session.query(AuthPermissionCatalog).count() == len(get_permission_catalog())

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
        assert rows == get_catalog_pairs()


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
