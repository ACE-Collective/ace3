from typing import Generator, override

import pytest

from saq.analysis.root import Submission
from saq.collectors.base_collector import CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.configuration import get_config
from saq.collectors.base_collector import Collector

import pymysql.err

class TestCollector(Collector):
    __test__ = False
    
    @override
    def collect(self) -> Generator[Submission, None, None]:
        if False:
            yield  # This is a stub to satisfy the type checker and linter.

    @override
    def update(self) -> None:
        pass

    @override
    def cleanup(self) -> None:
        pass

@pytest.mark.unit
def test_schedule_submission_interface_error_no_recovery(root_analysis, monkeypatch):
    get_config().add_service_config('service_generic_collector', CollectorServiceConfiguration(
        name="service_generic_collector",
        python_module="placeholder",
        python_class="placeholder",
        description="Generic Collector Service",
        enabled=True,
        workload_type="generic",
        delete_files=True,
    ))

    collector = CollectorService(
        collector=TestCollector(), 
        config=get_config().get_service_config('service_generic_collector'))

    assert collector.submission_scheduler is not None

    import saq.collectors.workload_repository
    def mock_execute_with_retry(*args, **kwargs):
        raise pymysql.err.InterfaceError(0, "")

    monkeypatch.setattr(saq.collectors.workload_repository, "execute_with_retry", mock_execute_with_retry)
    with pytest.raises(pymysql.err.InterfaceError):
        collector.submission_scheduler.schedule_submission(Submission(root_analysis), collector.remote_node_groups)
