import logging
from functools import wraps

from flask import abort, request
from flask_login import current_user, login_required

from saq.permissions.logic import user_has_permission


def require_permission(major: str, minor: str):
    """Decorator that requires the current user to have the given permission.

    Usage:
        @require_permission("analysis", "manage")
        def view(...):
            ...

    This decorator enforces authentication (like @login_required) and aborts with 403
    if the user lacks the requested permission. DENY overrides ALLOW per
    `saq.permissions.logic.user_has_permission`.
    """

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(*args, **kwargs):
            if not user_has_permission(current_user.id, major, minor):
                logging.error(
                    "user %s does not have permission %s.%s for URL %s",
                    current_user.id, major, minor, request.url
                )
                abort(403)

            return view_func(*args, **kwargs)

        return _wrapped_view

    return decorator


def reject_unauthenticated_datastar(view_func):
    """Returns 401 instead of the login-page redirect when an unauthenticated Datastar
    request arrives: fetch() follows redirects transparently, so a Datastar poller would
    otherwise receive the login page and try to morph it into the open page. On a 401
    Datastar patches nothing and the poll degrades harmlessly. Place above the
    @require_permission decorator so it runs first."""
    @wraps(view_func)
    def _wrapped_view(*args, **kwargs):
        if request.headers.get("Datastar-Request") and not current_user.is_authenticated:
            return "", 401
        return view_func(*args, **kwargs)
    return _wrapped_view


