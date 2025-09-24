import fakeredis
import pytest

from saq.constants import F_TEST, REDIS_DB_FOR_DETECTION_A
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
    analyzer = ObservableDetectionAnalyzer(context=test_context)
    analyzer.root = root

    # Test an observable that is not enabled for detection
    not_enabled_observable = root.add_observable_by_spec(F_TEST, "something_else")
    analyzer.execute_analysis(not_enabled_observable, redis_connection=redis_connection)
    assert not_enabled_observable.has_detection_points() is False

    # Test an observable that is enabled for detection
    enabled_observable = root.add_observable_by_spec(F_TEST, "test_value")
    analyzer.execute_analysis(enabled_observable, redis_connection=redis_connection)
    assert enabled_observable.has_detection_points() is True