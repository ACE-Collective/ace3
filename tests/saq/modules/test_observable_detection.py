import fakeredis
import pytest

from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import ANALYSIS_MODULE_OBSERVABLE_DETECTION, F_TEST, REDIS_DB_FOR_DETECTION_A
from saq.database.model import Observable as DBObservable, ObservableDetection
from saq.database.pool import get_db
from saq.database.util.observable_detection import create_observable_detection, get_active_detections_by_type
from saq.modules.observable_detection import ObservableDetectionAnalyzer
from saq.observables.export.redis_cache import REDIS_CONFIG_NAME, RedisObservableExport
from tests.saq.helpers import create_root_analysis


@pytest.fixture
def build_detection_cache(monkeypatch):
    """Yields a function that builds the detection cache and returns the database the engine reads.

    This drives the real saq.observables.export.redis_cache against fakeredis rather than
    reimplementing its write loop, so what the analyzer reads here is what `ace observables export`
    would actually have written.
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

    def _build():
        export = RedisObservableExport(get_config().get_observable_export_config("redis"))
        export.publish(export.build_export_list(get_active_detections_by_type()))
        return _get_connection(REDIS_DB_FOR_DETECTION_A)

    return _build


def build_analyzer(test_context, root) -> ObservableDetectionAnalyzer:
    analyzer = ObservableDetectionAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_DETECTION))
    analyzer.root = root
    return analyzer


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
    analyzer = build_analyzer(test_context, root)

    # Test an observable that is not enabled for detection
    not_enabled_observable = root.add_observable_by_spec(F_TEST, "something_else")
    analyzer.execute_analysis(not_enabled_observable, redis_connection=redis_connection)
    assert not_enabled_observable.has_detection_points() is False

    # Test an observable that is enabled for detection
    enabled_observable = root.add_observable_by_spec(F_TEST, "test_value")
    analyzer.execute_analysis(enabled_observable, redis_connection=redis_connection)
    assert enabled_observable.has_detection_points() is True


@pytest.mark.integration
def test_detection_for_a_never_seen_observable_fires(test_context, build_detection_cache):
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

    redis_connection = build_detection_cache()

    root = create_root_analysis(analysis_mode="test_single")
    analyzer = build_analyzer(test_context, root)

    observable = root.add_observable_by_spec(F_TEST, "never_seen_value")
    analyzer.execute_analysis(observable, redis_connection=redis_connection)

    assert observable.has_detection_points() is True
    assert f"detect_{F_TEST}" in [str(t) for t in observable.tags]


@pytest.mark.integration
def test_analyzer_reads_the_exported_cache_without_the_escape_hatch(
        test_context, build_detection_cache, monkeypatch):
    """The analyzer's own connection points at the database the export publishes to.

    Every other test here injects a connection through the `redis_connection` kwarg, which bypasses
    exactly the wiring that has to line up between writer and reader: config section and database
    number. So this one resolves the connection the way production does.
    """
    get_db().query(ObservableDetection).delete()
    get_db().commit()

    create_observable_detection(F_TEST, "evil_value", None)
    live_db = build_detection_cache()

    calls = []

    def _get_connection(database, config_name=None):
        calls.append((database, config_name))
        return live_db

    monkeypatch.setattr(
        "saq.modules.observable_detection.get_redis_connection", _get_connection)

    root = create_root_analysis(analysis_mode="test_single")
    analyzer = build_analyzer(test_context, root)

    observable = root.add_observable_by_spec(F_TEST, "evil_value")
    analyzer.execute_analysis(observable)
    assert observable.has_detection_points() is True

    # the live database, on the same config section the export writes through
    assert calls == [(REDIS_DB_FOR_DETECTION_A, REDIS_CONFIG_NAME)]

    # and the connection is built once per module instance, not once per observable
    analyzer.execute_analysis(root.add_observable_by_spec(F_TEST, "another_value"))
    assert len(calls) == 1
