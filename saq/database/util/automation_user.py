import logging

from sqlalchemy import select

from saq.database.model import User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user
from saq.environment import get_global_runtime_settings
import secrets


def initialize_automation_user():
    # get the id of the ace automation account
    try:
        get_global_runtime_settings().automation_user_id = get_db().query(User).filter(User.username == 'ace').one().id
        get_db().remove()
    except Exception:
        # if the account is missing go ahead and create it
        random_password = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+') for _ in range(16))
        user = add_user(
            username='ace',
            email='ace@localhost',
            display_name='automation',
            password=random_password,
            queue='default',
            timezone='UTC'
        )

        try:
            get_global_runtime_settings().automation_user_id = user.id
        except Exception as e:
            logging.error(f"missing automation account and unable to create it: {e}")
            raise e
        finally:
            get_db().remove()

    logging.debug(f"got id {get_global_runtime_settings().automation_user_id} for automation user account")

_automation_user_id_cache: dict[str, int] = {}


def lookup_automation_user_id() -> int | None:
    """The automation user's id, without touching the get_db() session.

    initialize_automation_user() is not run by every process (the CLI skips it, so
    automation_user_id is None in an engine started with `ace service start`), and it calls
    get_db().remove(), which would detach whatever the caller holds. This reads the id on a
    connection of its own, once per process, and never creates the user.
    """
    if get_global_runtime_settings().automation_user_id is not None:
        return get_global_runtime_settings().automation_user_id

    if "ace" not in _automation_user_id_cache:
        # a connection of its own from the session's engine: the session itself is left alone
        with get_db().get_bind().connect() as connection:
            user_id = connection.execute(select(User.id).where(User.username == "ace")).scalar()
        if user_id is None:
            return None
        _automation_user_id_cache["ace"] = user_id

    return _automation_user_id_cache["ace"]
