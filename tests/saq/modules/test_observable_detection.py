from datetime import datetime, timedelta

import fakeredis
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_OBSERVABLE_DETECTION, F_TEST, REDIS_DB_FOR_DETECTION_A
from saq.database.model import Observable as DBObservable, ObservableDetection
from saq.database.pool import get_db
from saq.database.util.observable_detection import create_observable_detection, get_active_detections_by_type
from saq.modules.observable_detection import ObservableDetectionAnalyzer
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
def test_for_detection_observable(test_context):
    # Create a fake Redis connection
    redis_server = fakeredis.FakeServer()
    redis_connection = fakeredis.FakeStrictRedis(server=redis_server, db=REDIS_DB_FOR_DETECTION_A)

    # Cache a test observable as being for detection
    # type = test
    # value = test_value
    # id = 1
    redis_connection.set("test:test_value", "1")

    # Create a new root analysis and initialize the analysis module
    root = create_root_analysis(analysis_mode="test_single")
    analyzer = ObservableDetectionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_DETECTION))
    analyzer.root = root

    # Test an observable that is not enabled for detection
    not_enabled_observable = root.add_observable_by_spec(F_TEST, "something_else")
    analyzer.execute_analysis(not_enabled_observable, redis_connection=redis_connection)
    assert not_enabled_observable.has_detection_points() is False

    # Test an observable that is enabled for detection
    enabled_observable = root.add_observable_by_spec(F_TEST, "test_value")
    analyzer.execute_analysis(enabled_observable, redis_connection=redis_connection)
    assert enabled_observable.has_detection_points() is True

def _build_detection_cache(redis_connection):
    """The cache-rebuild half of `ace update-for-detection-observable-cache`.

    The CLI itself is a script, not an importable module, but its query is not: it delegates to
    get_active_detections_by_type(). This reproduces only the trivial redis-write loop around it.
    """
    count = 0
    for observable_type, detections in get_active_detections_by_type().items():
        for detection in detections:
            redis_connection.set(f"{observable_type}:{detection['value']}", detection["id"])
            count += 1
    return count


@pytest.mark.integration
def test_detection_for_a_never_seen_observable_fires(test_context):
    """End to end: a detection added before the value was ever seen still produces a detection point.

    This is the capability the old design could not express at all -- the flag lived on a row in the
    observables index, which only existed once an alert had contained the value.
    """
    get_db().query(ObservableDetection).delete()
    get_db().commit()

    detection = create_observable_detection(F_TEST, "never_seen_value", None, detection_context="ahead of time")

    # nothing in the observables index refers to this value
    assert get_db().query(DBObservable).filter(
        DBObservable.sha256 == detection.value_sha256).one_or_none() is None

    redis_server = fakeredis.FakeServer()
    redis_connection = fakeredis.FakeStrictRedis(server=redis_server, db=REDIS_DB_FOR_DETECTION_A)
    assert _build_detection_cache(redis_connection) == 1

    root = create_root_analysis(analysis_mode="test_single")
    analyzer = ObservableDetectionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_DETECTION))
    analyzer.root = root

    observable = root.add_observable_by_spec(F_TEST, "never_seen_value")
    analyzer.execute_analysis(observable, redis_connection=redis_connection)

    assert observable.has_detection_points() is True
    assert f"detect_{F_TEST}" in [str(t) for t in observable.tags]


@pytest.mark.integration
def test_expired_detection_is_excluded_from_the_cache():
    """expires_on now governs only the detection, and only an analyst sets it."""
    get_db().query(ObservableDetection).delete()
    get_db().commit()

    create_observable_detection(F_TEST, "live_value", None)
    create_observable_detection(
        F_TEST, "expired_value", None, expires_on=datetime.now() - timedelta(days=1))
    create_observable_detection(
        F_TEST, "future_value", None, expires_on=datetime.now() + timedelta(days=1))

    redis_server = fakeredis.FakeServer()
    redis_connection = fakeredis.FakeStrictRedis(server=redis_server, db=REDIS_DB_FOR_DETECTION_A)
    _build_detection_cache(redis_connection)

    assert redis_connection.get(f"{F_TEST}:live_value") is not None
    assert redis_connection.get(f"{F_TEST}:future_value") is not None
    assert redis_connection.get(f"{F_TEST}:expired_value") is None
