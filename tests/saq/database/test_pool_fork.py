"""Fork safety for the SQLAlchemy side of the connection pool.

ACE forks constantly -- the engine controller, every worker, the collectors -- and
ACE_MP_CONTEXT is the ``fork`` context, so a child starts life holding the parent's
open MySQL sockets. Two processes reading and writing one TLS-wrapped socket
desynchronises the record layer, and the *parent* is usually the one that notices, with
``[SSL: RECORD_LAYER_FAILURE] ... Lost connection to MySQL server during query``.
"""

import pytest

from sqlalchemy import text

from saq.database.pool import get_db
from saq.environment import ACE_MP_CONTEXT


def _child_uses_the_database():
    """Runs in the forked child. Does exactly what any ACE child process does first."""
    get_db().execute(text("SELECT 1")).scalar()
    get_db().commit()


@pytest.mark.integration
def test_orm_connection_survives_fork():
    # leave the transaction open so the parent's session is holding a checked out
    # connection at the moment of the fork. this is the state Engine.start_nonblocking()
    # forks in, and the one the checkout pid guard cannot see: no checkout event fires in
    # the child because the connection is already checked out.
    assert get_db().execute(text("SELECT 1")).scalar() == 1

    process = ACE_MP_CONTEXT.Process(target=_child_uses_the_database)
    process.start()
    process.join(30)

    assert not process.is_alive()
    assert process.exitcode == 0

    # the child must not have disturbed the connection the parent still holds
    assert get_db().execute(text("SELECT 1")).scalar() == 1
    get_db().commit()
