import logging
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