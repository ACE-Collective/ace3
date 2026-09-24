# vim: sw=4:ts=4:et

from app.application import login_manager
from saq.database import User, get_db

@login_manager.user_loader
def load_user(user_id):
    return get_db().get(User, int(user_id))
