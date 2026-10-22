import logging
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from saq.constants import QUEUE_DEFAULT
from saq.database.model import AuthApiKey, AuthApiKeyPermission, User
from saq.database.pool import get_db
from saq.util import is_uuid, sha256_str


def add_user(username: str, email: str, display_name: str, password: str, queue: Optional[str]=QUEUE_DEFAULT, timezone: Optional[str]="UTC") -> User:
    """
    Adds a new user to the database.
    """
    db = get_db()
    user = User(username=username, email=email, display_name=display_name, queue=queue, timezone=timezone, password=password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def delete_user(username: str) -> bool:
    """
    Deletes a user from the database by username.
    Returns True if the user was deleted, False if the user does not exist.
    """
    db = get_db()
    result = db.execute(User.__table__.delete().where(User.username == username)).rowcount
    db.commit()
    return result > 0

def create_api_key(
    user_id: int,
    name: str,
    *,
    inherit: bool = False,
    scope: Optional[list[tuple[str, str]]] = None,
    created_by: Optional[int] = None,
    api_key: Optional[str] = None,
) -> str:
    """Create a new API key for the given user and return the plaintext key exactly once.

    Exactly one of `inherit` (the key gets the owner's full permissions) or a non-empty `scope`
    (a list of (major, minor) ALLOW patterns) must be given -- there is no silent full-scope
    default. Only the sha256 is stored; the plaintext is never recoverable after this call.

    The scope is stored as given: the pattern rules of the API (aceapi_v2/users/service.py) are
    deliberately not applied to this operator path (docs/USER_PREFERENCES.md).
    """
    if inherit == bool(scope):
        raise ValueError("exactly one of inherit or a non-empty scope must be provided")

    if api_key is None:
        api_key = str(uuid.uuid4())
    elif not is_uuid(api_key):
        raise ValueError("api_key appears to not be a uuid value")

    session = get_db()
    key = AuthApiKey(
        user_id=user_id,
        name=name,
        key_hash=sha256_str(api_key),
        inherit_user_scope=inherit,
        created_by=created_by,
    )
    if not inherit:
        for (major, minor) in scope:
            key.scope.append(AuthApiKeyPermission(major=major, minor=minor, effect="ALLOW"))

    session.add(key)
    session.commit()
    logging.info("created api key '%s' for user %s (inherit=%s)", name, user_id, inherit)
    return api_key

def list_api_keys(user_id: int) -> list[AuthApiKey]:
    """Return a user's API keys (metadata only; no secret is recoverable)."""
    session = get_db()
    return list(session.execute(
        select(AuthApiKey)
        .options(selectinload(AuthApiKey.scope))
        .where(AuthApiKey.user_id == user_id)
        .order_by(AuthApiKey.created_at)
    ).scalars())

def revoke_api_key(key_id: int) -> bool:
    """Delete an API key by id. Returns False if no such key existed. Not reversible."""
    session = get_db()
    key = session.get(AuthApiKey, key_id)
    if key is None:
        return False

    session.delete(key)
    session.commit()
    logging.info("revoked api key id %s", key_id)
    return True
