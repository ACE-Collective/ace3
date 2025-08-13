from typing import Optional
from saq.constants import QUEUE_DEFAULT
from saq.database.model import User
from saq.database.pool import get_db


def add_user(username: str, email: str, display_name: str, password: str, queue: Optional[str]=QUEUE_DEFAULT, timezone: Optional[str]="Etc/UTC") -> User:
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