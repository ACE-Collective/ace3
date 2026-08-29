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
from unittest.mock import MagicMock, Mock

import pytest

from saq.analysis.adapter import RootAnalysisAdapter
from saq.analysis.root import RootAnalysis
from saq.constants import AnalysisExecutionResult, F_FQDN, LockManagerType, WorkloadManagerType
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis_adapter import DelayedAnalysisAdapter
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.modules.interfaces import AnalysisModuleInterface
from saq.modules.rdap import RdapAnalysis
from saq.util.time import local_time


@pytest.fixture
def worker() -> Worker:
    """A real Worker with its collaborators replaced.

    ``Worker`` builds its lock manager, workload manager and orchestrator in
    ``__init__`` with no injection point, so they are reassigned afterwards.
    """
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = True
    configuration_manager.config.auto_refresh_frequency = 0

    worker = Worker(
        name="test_worker",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )

    worker.lock_manager = MagicMock()
    worker.workload_manager = MagicMock()
    worker.workload_manager.add_delayed_analysis_request.return_value = True
    return worker


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
        root, observable, analysis, make_analysis_module(), seconds=10, timeout_seconds=60
    )

    assert result is True
    assert analysis.delayed is True
    worker.workload_manager.add_delayed_analysis_request.assert_called_once()


@pytest.mark.unit
def test_delay_refused_when_request_is_not_recorded(worker, target):
    """Nothing recorded the request, so nothing will ever resume the analysis:
    the delay has to be refused rather than reported as scheduled."""
    root, observable, analysis = target
    worker.workload_manager.add_delayed_analysis_request.return_value = False

    result = worker.delay_analysis(
        root, observable, analysis, make_analysis_module(), seconds=10, timeout_seconds=60
    )

    assert result is False
    assert analysis.delayed is False


@pytest.mark.unit
def test_delay_refused_when_request_returns_none(worker, target):
    """Same for a workload manager that reports nothing at all -- only a
    positive answer counts as recorded."""
    root, observable, analysis = target
    worker.workload_manager.add_delayed_analysis_request.return_value = None

    result = worker.delay_analysis(
        root, observable, analysis, make_analysis_module(), seconds=10, timeout_seconds=60
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
        root, observable, analysis, analysis_module, seconds=10, timeout_seconds=1
    )

    assert result is False
    assert analysis.delayed is False
    worker.workload_manager.add_delayed_analysis_request.assert_not_called()


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
        worker.workload_manager.add_delayed_analysis_request.return_value = False
        module = self.make_module(worker, root)

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
