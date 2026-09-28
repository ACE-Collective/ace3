import pytest
from sqlalchemy import select, text

from saq.cas import Hold, index
from saq.database.model import CASHold, CASObject
from saq.database.pool import get_db
from saq.permissions.catalog import sync_permission_catalog

DIGEST = "e" * 64


@pytest.mark.integration
def test_deleting_the_object_row_cascades_to_holds():
    with index.transaction() as session:
        index.insert_object_if_absent(session, "test_plain", DIGEST, 1, 1, None)
        index.upsert_hold(session, "test_plain", DIGEST, Hold("k", "1"), None)
        index.upsert_hold(session, "test_plain", DIGEST, Hold("k", "2"), None)

    with index.transaction() as session:
        assert index.count_holds(session, "test_plain", DIGEST) == 2
        index.delete_object_row(session, "test_plain", DIGEST)

    with index.transaction() as session:
        assert index.count_holds(session, "test_plain", DIGEST) == 0
        assert index.get_object(session, "test_plain", DIGEST) is None


@pytest.mark.integration
def test_repeating_a_hold_is_idempotent():
    with index.transaction() as session:
        index.insert_object_if_absent(session, "test_plain", DIGEST, 1, 1, None)
        index.upsert_hold(session, "test_plain", DIGEST, Hold("k", "1"), "alice")
        index.upsert_hold(session, "test_plain", DIGEST, Hold("k", "1"), "bob")

    with index.transaction() as session:
        holds = index.list_holds(session, "test_plain", DIGEST)
        assert len(holds) == 1
        assert holds[0].created_by == "bob"


@pytest.mark.integration
def test_catalog_has_the_cas_permissions():
    session = get_db()
    sync_permission_catalog(session, prune=False)
    session.commit()
    rows = session.execute(text("SELECT minor FROM auth_permission_catalog WHERE major = 'cas' ORDER BY minor")).scalars().all()
    assert rows == ["hold", "purge"]
