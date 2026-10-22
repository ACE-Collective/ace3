"""Tests for ``Worker.delay_analysis`` (see docs/ENGINE.md §19.4).

Delaying analysis has two halves: a row in ``delayed_analysis`` that will bring
the analysis back, and ``analysis.delayed = True`` on the tree so the engine
knows to wait for it. ``Worker.delay_analysis`` returned ``True``
unconditionally, so a failed insert produced the second half without the first:
the analysis was marked delayed with nothing behind it to ever resume it, and
``root.delayed`` (computed from the tree) stayed true forever -- final analysis
and post analysis never ran for that root again.

``TestDelayRefusalReachesTheModule`` is the one that shows the consequence: a
real ``AnalysisModule`` on the other side of ``DelayedAnalysisAdapter`` must
close the analysis out instead of leaving it delayed.
"""
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest

from saq.analysis.adapter import RootAnalysisAdapter
from saq.analysis.root import RootAnalysis
from saq.constants import AnalysisExecutionResult, F_FQDN
from saq.database.pool import get_db_connection
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis_adapter import DelayedAnalysisAdapter
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineType
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.modules.interfaces import AnalysisModuleInterface
from saq.modules.rdap import RdapAnalysis
from saq.util.time import local_time


def make_worker(engine_type: EngineType) -> Worker:
    return Worker(
        name="test_worker",
        configuration_manager=ConfigurationManager(EngineConfiguration(engine_type=engine_type, single_threaded_mode=True)),
        node_manager=Mock(spec=NodeManagerInterface),
    )


@pytest.fixture
def worker() -> Worker:
    """A real Worker with its in-memory workload manager."""
    return make_worker(EngineType.LOCAL)


@pytest.fixture
def target(tmp_path):
    """The (root, observable, analysis) triple being delayed."""
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")
    analysis = observable.add_analysis(RdapAnalysis())
    return root, observable, analysis


def make_analysis_module(name: str = "test_module") -> AnalysisModuleInterface:
    module = Mock(spec=AnalysisModuleInterface)
    module.name = name
    return module


@pytest.mark.unit
def test_delay_accepted_marks_the_analysis_delayed(worker, target):
    """The request was recorded, so the analysis is waiting on it."""
    root, observable, analysis = target

    result = worker.delay_analysis(
        root, observable, analysis, make_analysis_module(), hours=0, minutes=0, seconds=10, timeout_seconds=60
    )

    assert result is True
    assert analysis.delayed is True
    assert worker.workload_manager.delayed_analysis_queue_size == 1


@pytest.mark.integration
def test_delay_accepted_records_the_delayed_analysis_row(target):
    """The same against the database workload manager: the row that brings the analysis back exists."""
    root, observable, analysis = target
    worker = make_worker(EngineType.DISTRIBUTED)

    result = worker.delay_analysis(
        root, observable, analysis, make_analysis_module(), hours=0, minutes=0, seconds=10, timeout_seconds=60
    )

    assert result is True
    assert analysis.delayed is True
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT analysis_module, storage_dir, delayed_until > NOW() FROM delayed_analysis WHERE uuid = %s AND observable_uuid = %s",
            (root.uuid, observable.uuid),
        )
        assert cursor.fetchall() == (("test_module", root.storage_dir, 1),)


@pytest.mark.unit
def test_delay_refused_when_request_is_not_recorded(worker, target):
    """Nothing recorded the request, so nothing will ever resume the analysis:
    the delay has to be refused rather than reported as scheduled."""
    root, observable, analysis = target

    with patch.object(worker.workload_manager, "add_delayed_analysis_request", return_value=False):
        result = worker.delay_analysis(
            root, observable, analysis, make_analysis_module(), hours=0, minutes=0, seconds=10, timeout_seconds=60
        )

    assert result is False
    assert analysis.delayed is False


@pytest.mark.unit
def test_delay_refused_when_deadline_expired(worker, target):
    """The pre-existing refusal path: once the timeout passes no request is
    inserted at all."""
    root, observable, analysis = target
    analysis_module = make_analysis_module()

    # backdate the start of the delay past the timeout below
    key = root.get_delayed_analysis_start_time_key(observable, analysis_module)
    root.delayed_analysis_tracking[key] = local_time() - timedelta(seconds=60)

    result = worker.delay_analysis(
        root, observable, analysis, analysis_module, hours=0, minutes=0, seconds=10, timeout_seconds=1
    )

    assert result is False
    assert analysis.delayed is False
    assert worker.workload_manager.delayed_analysis_queue_is_empty


class TestDelayRefusalReachesTheModule:
    """The consequence of the return value: a module asking for a delay the
    engine cannot record must end up with a closed-out analysis, not a root
    that is delayed forever."""

    def make_module(self, worker: Worker, root: RootAnalysis) -> AnalysisModule:
        context = AnalysisModuleContext(
            delayed_analysis_interface=DelayedAnalysisAdapter(worker),
            root=RootAnalysisAdapter(root),
        )
        config = AnalysisModuleConfig(
            name="test_module",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True,
        )
        return AnalysisModule(config, context=context)

    @pytest.mark.unit
    def test_failed_insert_does_not_leave_the_analysis_delayed(self, worker, target):
        root, observable, analysis = target
        module = self.make_module(worker, root)

        with patch.object(worker.workload_manager, "add_delayed_analysis_request", return_value=False):
            result = module.delay_analysis(observable, analysis, seconds=10, timeout_seconds=60)

        assert result == AnalysisExecutionResult.COMPLETED
        assert analysis.delayed is False
        assert analysis.completed is True
        assert not root.delayed

    @pytest.mark.unit
    def test_successful_insert_delays_the_analysis(self, worker, target):
        """Control: the delay is recorded, so the module reports INCOMPLETE and
        the root is waiting."""
        root, observable, analysis = target
        module = self.make_module(worker, root)

        result = module.delay_analysis(observable, analysis, seconds=10, timeout_seconds=60)

        assert result == AnalysisExecutionResult.INCOMPLETE
        assert analysis.delayed is True
        assert root.delayed
        assert worker.workload_manager.delayed_analysis_queue_size == 1
