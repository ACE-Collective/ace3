from dataclasses import dataclass
from functools import wraps
from typing import Optional

import logging
import uuid

from saq.configuration import get_config
from saq.constants import CONFIG_APIKEYS
from saq.crypto import encrypt_chunk, decrypt_chunk
from saq.database import get_db_connection
from saq.permissions.logic import user_has_permission
from saq.util import sha256_str, is_uuid

@dataclass
class ApiAuthResult:
    auth_type: Optional[str] = None
    auth_name: Optional[str] = None
    auth_user_id: Optional[int] = None

KEY_API_AUTH_TYPE = "type"
KEY_API_AUTH_NAME = "name"

API_AUTH_TYPE_CONFIG = "config"
API_AUTH_TYPE_USER = "user"

API_HEADER_NAME = "x-ice-auth"

def _get_config_api_key_match(auth_sha256: str) -> ApiAuthResult:
    """Returns an ApiAuthResult object if the given auth token is stored as a configuration value under [apikeys], None otherwise."""
    for valid_key_name, valid_key_value in get_config()[CONFIG_APIKEYS].items():
        if valid_key_value is not None and auth_sha256.lower() == valid_key_value.strip().lower():
            return ApiAuthResult(auth_type=API_AUTH_TYPE_CONFIG, auth_name=valid_key_name)

    return None

def _get_user_api_key_match(auth_sha256: str) -> ApiAuthResult:
    """Returns an ApiAuthResult object if the given auth token is valid for a user, None otherwise."""
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""SELECT username, id FROM users WHERE apikey_hash = %s""", (auth_sha256.lower(),))
        result = c.fetchone()
        if not result:
            return None

        return ApiAuthResult(auth_type=API_AUTH_TYPE_USER, auth_name=result[0], auth_user_id=result[1])

def verify_api_key(auth: str) -> ApiAuthResult:
    """Returns an ApiAuthResult object if the given auth token is valid, None otherwise."""
    if not auth:
        return None

    auth_sha256 = sha256_str(auth)
    return _get_config_api_key_match(auth_sha256) or _get_user_api_key_match(auth_sha256)

def set_user_api_key(user_id: int, api_key: Optional[str]=None) -> str:
    """Sets the api key for the given user. If one is not provided a new one is created.
    Returns the api_key, or None if the user_id does not exist."""
    if api_key is None:
        api_key = str(uuid.uuid4())
    else:
        if not is_uuid(api_key):
            raise ValueError("api_key appears to not be a uuid value")

    auth_sha256 = sha256_str(api_key)
    encrypted_api_key = encrypt_chunk(api_key.encode(errors="ignore"))

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""UPDATE users SET apikey_hash = %s, apikey_encrypted = %s WHERE id = %s""", (auth_sha256, encrypted_api_key, user_id))
        db.commit()
        if c.rowcount == 0:
            return None
        else:
            logging.info("api key created or modified for user %s", user_id)
            return api_key

def get_user_api_key(user_id: int) -> str:
    """Returns the api key for the given user, or None if the user does not exist."""
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""SELECT apikey_encrypted FROM users WHERE id = %s""", (user_id,))
        row = c.fetchone()
        if row and row[0] is not None:
            return decrypt_chunk(row[0]).decode()
        else:
            return None

def clear_user_api_key(user_id: int) -> bool:
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""UPDATE users SET apikey_hash = NULL, apikey_encrypted = NULL WHERE id = %s""", (user_id,))
        db.commit()
        if c.rowcount == 1:
            logging.info("cleared api access for user %s", user_id)
            return True
        else:
            return False

def api_auth_check(major: str, minor: str):
    def decorator(func):
        @wraps(func)
        def _api_auth_check(*args, **kwargs):
            from flask import request, abort
            api_auth_result = verify_api_key(request.headers.get(API_HEADER_NAME, None))
            if not api_auth_result:
                abort(403)

            if api_auth_result.auth_type == API_AUTH_TYPE_USER:
                if not user_has_permission(api_auth_result.auth_user_id, major, minor):
                    logging.error(
                        "user %s does not have permission %s.%s for URL %s",
                        api_auth_result.auth_user_id, major, minor, request.url
                    )
                    abort(403)

            logging.info("api access granted from %s type %s name %s", request.remote_addr, api_auth_result.auth_type, api_auth_result.auth_name)
            return func(*args, **kwargs)

        return _api_auth_check

    return decorator