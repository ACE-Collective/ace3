import os
from datetime import datetime, timedelta

import pytest

from saq.cas import Hold, get_cas, index
from saq.cas.health import _disk, node_stats, pool_health

from tests.saq.cas.conftest import age_object

pytestmark = pytest.mark.integration

GRACE = 3600            # etc/saq.unittest.default.yaml cas.default_grace_seconds
GC_OVERDUE = 7200       # cas.gc_overdue_seconds default


def _by_pool() -> dict[str, dict]:
    return {record["pool"]: record for record in pool_health()}


def test_empty_pools_are_still_reported():
    records = _by_pool()
    assert set(records) == {"test_plain", "test_encrypted", "test_permanent"}
    plain = records["test_plain"]
    assert plain["configured"] is True
    assert (plain["backend"], plain["encryption"], plain["retention"]) == ("local", "none", "held")
    assert (plain["objects_present"], plain["holds_live"], plain["purges_last_24h"], plain["gc_overdue"]) == (0, 0, 0, 0)
    assert records["test_permanent"]["gc_overdue"] is None     # nothing is ever collected
    assert "node" not in plain                                  # the index describes the cluster


def test_pool_health_counts(plain_pool, enc_pool, perm_pool):
    expired = datetime.now() - timedelta(days=1)

    held = plain_pool.put(b"held", hold=Hold("k", "1"))
    plain_pool.hold(held, Hold.legal("case-1"))
    plain_pool.hold(held, Hold("k", "expired", expires_at=expired))
    released = plain_pool.put(b"released", hold=Hold("k", "2", expires_at=expired))
    overdue = plain_pool.put(b"overdue")
    age_object(plain_pool, overdue, GRACE + GC_OVERDUE + 60)
    within = plain_pool.put(b"past grace, not yet overdue")
    age_object(plain_pool, within, GRACE + 60)
    deleting = plain_pool.put(b"deleting")
    with index.transaction() as session:
        index.set_deleting_forced(session, plain_pool.name, deleting)
        index.set_verified(session, plain_pool.name, held)

    purged = enc_pool.put(b"purged")
    enc_pool.purge(purged, reason="test", actor="tester")
    enc_pool.put(b"kept")
    perm_pool.put(b"forever")

    records = _by_pool()
    plain = records["test_plain"]
    sizes = [len(b"held"), len(b"released"), len(b"overdue"), len(b"past grace, not yet overdue")]
    assert (plain["objects_present"], plain["objects_deleting"]) == (4, 1)
    assert plain["size_bytes"] == sum(sizes) + len(b"deleting")
    assert plain["stored_bytes"] == plain["size_bytes"]          # plaintext pool
    assert (plain["never_verified"], plain["verified_last_7d"]) == (4, 1)
    assert (plain["holds_live"], plain["holds_expired"], plain["legal_holds"], plain["objects_held"]) == (2, 2, 1, 1)
    # released has an expired hold and a fresh last_held_at; within is past grace but GC has not had two
    # runs to get to it; only overdue counts
    assert plain["gc_overdue"] == 1
    assert plain["purges_last_24h"] == 0

    encrypted = records["test_encrypted"]
    assert (encrypted["objects_present"], encrypted["purges_last_24h"]) == (1, 1)
    assert encrypted["stored_bytes"] > encrypted["size_bytes"]  # header and tag
    assert records["test_permanent"]["objects_present"] == 1


def test_an_unconfigured_pool_with_rows_is_reported():
    with index.transaction() as session:
        index.insert_object_if_absent(session, "renamed_pool", "f" * 64, 7, 7, None)

    record = _by_pool()["renamed_pool"]
    assert record["configured"] is False
    assert (record["backend"], record["retention"], record["gc_overdue"]) == (None, None, None)
    assert (record["objects_present"], record["size_bytes"]) == (1, 7)


def test_node_stats(enc_pool, tmp_path):
    payload = b"cached " * 100
    digest = enc_pool.put(payload)
    enc_pool.materialize(digest, str(tmp_path / "out"))      # fills the read cache

    records = node_stats()
    [cache] = [record for record in records if record["kind"] == "read_cache"]
    assert (cache["entries"], cache["bytes"]) == (1, len(payload))
    assert cache["max_bytes"] == get_cas().config.read_cache.max_bytes
    assert cache["fs_free_bytes"] > 0 and cache["fs_total_bytes"] >= cache["fs_free_bytes"]
    assert "node" in cache

    pools = {record["pool"]: record for record in records if record["kind"] == "pool"}
    assert set(pools) == {"test_plain", "test_encrypted", "test_permanent"}
    assert pools["test_encrypted"]["path"] == enc_pool.backend.root
    assert all(record["fs_total_bytes"] > 0 for record in pools.values())


def test_disk_measures_the_nearest_existing_directory(tmp_path):
    missing = tmp_path / "not" / "there" / "yet"
    # free space moves with everything else on the box; the filesystem's size does not
    assert _disk(str(missing))[1] == _disk(str(tmp_path))[1]
    assert not os.path.exists(missing)
