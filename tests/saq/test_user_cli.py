import pytest

from saq.cli.commands.user import modify_user, modify_user_parser
from saq.database.pool import get_db_connection
from saq.database.util.user_management import add_user


def _enabled(user_id: int) -> bool:
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT enabled FROM users WHERE id = %s", (user_id,))
        return bool(c.fetchone()[0])


@pytest.mark.integration
def test_modify_disables_and_enables_a_user():
    user = add_user("cli-user", "cli-user@localhost", "CLI User", "password")
    assert _enabled(user.id)

    modify_user(modify_user_parser.parse_args(["cli-user", "--disable"]))
    assert not _enabled(user.id)

    modify_user(modify_user_parser.parse_args(["cli-user", "--enable"]))
    assert _enabled(user.id)
