import os

import fakeredis
import pytest

from saq.configuration.config import get_config
from saq.constants import F_TEST, REDIS_DB_FOR_DETECTION_A, REDIS_DB_FOR_DETECTION_B
from saq.database.model import ObservableDetection
from saq.database.pool import get_db
from saq.database.util.observable_detection import create_observable_detection
from saq.observables.export.manager import run_exports
from saq.observables.export.redis_cache import FINGERPRINT_KEY, RedisObservableExport
from tests.saq.helpers import search_log


@pytest.fixture
def fake_redis(monkeypatch):
    """Backs the redis export with fakeredis, keyed by database on one shared server.

    One server is the point: swapdb is a server-level command, so both databases have to live on the
    same one for the cutover to be observable.
    """
    server = fakeredis.FakeServer()
    connections = {}

    def _get_connection(database, config_name=None):
        if database not in connections:
            connections[database] = fakeredis.FakeStrictRedis(
                server=server, db=database, decode_responses=True)

        return connections[database]

    monkeypatch.setattr(
        "saq.observables.export.redis_cache.get_redis_connection", _get_connection)
    return _get_connection


@pytest.fixture
def live_db(fake_redis):
    """The database the analysis engine reads."""
    return fake_redis(REDIS_DB_FOR_DETECTION_A)


@pytest.fixture
def scratch_db(fake_redis):
    """The database the rebuild builds into before swapping it in."""
    return fake_redis(REDIS_DB_FOR_DETECTION_B)


@pytest.fixture
def no_detections():
    """Starts each test from an empty detection table."""
    get_db().query(ObservableDetection).delete()
    get_db().commit()


def redis_export() -> RedisObservableExport:
    return RedisObservableExport(get_config().get_observable_export_config("redis"))


@pytest.mark.unit
def test_build_export_list_does_not_filter():
    # the analyzer runs on every observable type, so the cache has to carry all of them -- including
    # values far below the yara export's minimum length
    export_list = redis_export().build_export_list({
        "fqdn": [{"id": 1, "value": "evil.example.com"}],
        "ip": [{"id": 2, "value": "::1"}],
        "some_type_no_other_target_exports": [{"id": 3, "value": "x"}],
    })

    assert {(entry.type, entry.id) for entry in export_list} == {
        ("fqdn", 1), ("ip", 2), ("some_type_no_other_target_exports", 3)}


@pytest.mark.unit
def test_record_fingerprint_is_a_noop(fake_redis, live_db):
    # publish() records it atomically with the data, so this must not write a second copy
    redis_export().record_fingerprint("abc123")
    assert live_db.get(FINGERPRINT_KEY) is None


@pytest.mark.integration
def test_export_populates_the_live_database(no_detections, live_db, scratch_db):
    detection = create_observable_detection(F_TEST, "evil_value", None)

    assert run_exports(["redis"]) == os.EX_OK

    assert live_db.get(f"{F_TEST}:evil_value") == str(detection.id)
    assert live_db.get(FINGERPRINT_KEY) is not None
    # the swap happened: what the rebuild wrote is now live, and the scratch database holds the
    # previous (empty) generation
    assert scratch_db.get(f"{F_TEST}:evil_value") is None


@pytest.mark.integration
def test_export_replaces_the_previous_generation(no_detections, live_db):
    stale = create_observable_detection(F_TEST, "stale_value", None)
    assert run_exports(["redis"]) == os.EX_OK
    assert live_db.get(f"{F_TEST}:stale_value") is not None

    from saq.database.util.observable_detection import delete_observable_detection
    delete_observable_detection(stale.id)
    create_observable_detection(F_TEST, "fresh_value", None)

    assert run_exports(["redis"]) == os.EX_OK
    assert live_db.get(f"{F_TEST}:stale_value") is None
    assert live_db.get(f"{F_TEST}:fresh_value") is not None


@pytest.mark.integration
def test_export_skips_when_nothing_changed(no_detections, live_db):
    create_observable_detection(F_TEST, "evil_value", None)
    assert run_exports(["redis"]) == os.EX_OK

    # a marker written straight into the live database survives only if no rebuild happened
    live_db.set("marker", "1")
    assert run_exports(["redis"]) == os.EX_OK

    assert search_log("no updates needed for observable export redis")
    assert live_db.get("marker") == "1"


@pytest.mark.integration
def test_export_rebuilds_after_the_cache_is_lost(no_detections, live_db):
    """A flushed redis must rebuild even though the detection set never changed.

    This is the whole reason the fingerprint lives in redis rather than in the state file: a file
    would still claim this list was published and the cache would stay empty.
    """
    create_observable_detection(F_TEST, "evil_value", None)
    assert run_exports(["redis"]) == os.EX_OK

    live_db.flushdb()
    assert run_exports(["redis"]) == os.EX_OK

    assert live_db.get(f"{F_TEST}:evil_value") is not None


@pytest.mark.integration
def test_expired_detections_are_excluded(no_detections, live_db):
    from datetime import datetime, timedelta

    create_observable_detection(F_TEST, "live_value", None)
    create_observable_detection(
        F_TEST, "expired_value", None, expires_on=datetime.now() - timedelta(days=1))
    create_observable_detection(
        F_TEST, "future_value", None, expires_on=datetime.now() + timedelta(days=1))

    assert run_exports(["redis"]) == os.EX_OK

    assert live_db.get(f"{F_TEST}:live_value") is not None
    assert live_db.get(f"{F_TEST}:future_value") is not None
    assert live_db.get(f"{F_TEST}:expired_value") is None


@pytest.mark.integration
def test_get_last_fingerprint_reads_what_publish_wrote(no_detections, live_db):
    create_observable_detection(F_TEST, "evil_value", None)
    export = redis_export()

    assert export.get_last_fingerprint() is None
    assert run_exports(["redis"]) == os.EX_OK

    assert export.get_last_fingerprint() == live_db.get(FINGERPRINT_KEY)
    # the recorded fingerprint is the one the published detection set produces
    detection_id = int(live_db.get(f"{F_TEST}:evil_value"))
    assert export.get_last_fingerprint() == export.build_export_list(
        {F_TEST: [{"id": detection_id, "value": "evil_value"}]}).fingerprint()
