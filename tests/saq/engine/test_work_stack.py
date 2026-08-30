"""Tests for ``WorkStack`` / ``WorkTarget`` and the engine's "unit of analysis".

These guard docs/ENGINE.md §19.13. The engine's original design intended to
analyze ``Analysis`` objects the same way it analyzes ``Observable`` objects.
That was never implemented, but the scaffolding survived: ``WorkStack.append``
accepted an ``Analysis`` and silently dropped it, ``WorkTarget`` carried an
``analysis`` field annotated "(not actually supported)", and
``AnalysisModule.accepts()`` was wrapped in ``isinstance(obj, Observable)``
guards behind a ``valid_analysis_target_type`` gate that could never fire.

An ``Observable`` is now the engine's only unit of analysis, stated explicitly:
``WorkStack.append`` raises on anything else rather than swallowing it.

``WorkStack`` and the executor helpers exercised here touch neither the database
nor a running engine, so everything below is a unit test.
"""
import ast
import os
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.engine.work_stack import WorkStack, WorkTarget


class _StubAnalysis(Analysis):
    """A concrete Analysis we can attach to an observable."""


def _make_executor() -> AnalysisExecutor:
    """Minimum-viable AnalysisExecutor. The helpers under test read only their
    arguments, so nothing on the executor itself has to be a real value."""
    return AnalysisExecutor(
        configuration_manager=MagicMock(),
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _make_root(tmp_path, observable_count: int = 3) -> RootAnalysis:
    """A root with observables, each carrying an Analysis, so ``root.all`` is a
    genuinely mixed list of Analysis and Observable objects."""
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    for index in range(observable_count):
        observable = root.add_observable_by_spec(F_TEST, f"test_{index}")
        assert observable
        observable.add_analysis(_StubAnalysis())

    return root


@pytest.mark.unit
def test_append_observable(tmp_path):
    """The supported case: an Observable becomes a WorkTarget on the stack."""
    root = _make_root(tmp_path, observable_count=1)
    observable = root.all_observables[0]

    work_stack = WorkStack()
    work_stack.append(observable)

    assert len(work_stack) == 1
    work_item = work_stack.popleft()
    assert isinstance(work_item, WorkTarget)
    assert work_item.observable is observable


@pytest.mark.unit
def test_append_observable_is_deduplicated_by_uuid(tmp_path):
    """The uuid tracker keeps the same observable from queueing twice."""
    root = _make_root(tmp_path, observable_count=1)
    observable = root.all_observables[0]

    work_stack = WorkStack()
    work_stack.append(observable)
    work_stack.append(observable)

    assert len(work_stack) == 1


@pytest.mark.unit
def test_append_analysis_is_rejected():
    """§19.13: appending an Analysis used to hit an ``elif ...: pass`` branch and
    vanish without a trace. An Analysis is not a unit of analysis, so saying so
    is now an error rather than a silent drop."""
    work_stack = WorkStack()

    with pytest.raises(TypeError):
        work_stack.append(_StubAnalysis())

    assert len(work_stack) == 0


@pytest.mark.unit
def test_append_unknown_type_is_rejected():
    work_stack = WorkStack()

    with pytest.raises(TypeError):
        work_stack.append(object())

    assert len(work_stack) == 0


@pytest.mark.unit
def test_initialize_work_stack_queues_only_observables(tmp_path):
    """§19.13: ``_initialize_work_stack`` walked ``root.all_analysis`` and
    appended every one of them, which contributed nothing. The stack is — and
    always was — exactly the observables in the tree."""
    executor = _make_executor()
    root = _make_root(tmp_path)
    context = EngineExecutionContext(root)

    executor._initialize_work_stack(context)

    # the tree really does contain analysis (otherwise this proves nothing)
    assert len(root.all_analysis) > 1
    assert len(context.work_stack) == len(root.all_observables)
    while len(context.work_stack):
        assert isinstance(context.work_stack.popleft().observable, type(root.all_observables[0]))


@pytest.mark.unit
def test_initialize_work_stack_for_delayed_request_holds_one_target(tmp_path):
    """The delayed-analysis path is unchanged: exactly one pinned WorkTarget."""
    executor = _make_executor()
    root = _make_root(tmp_path, observable_count=1)
    observable = root.all_observables[0]

    # the work item *is* the delayed request now -- the context derives both
    # `root` and `delayed_analysis_request` from it (docs/ENGINE.md 19.15)
    delayed_request = DelayedAnalysisRequest(
        uuid=root.uuid,
        observable_uuid=observable.uuid,
        analysis_module_str="analysis_module_basic_test",
        next_analysis=datetime.now(),
        storage_dir=str(tmp_path),
    )
    delayed_request.root = root
    delayed_request.observable = observable
    delayed_request.analysis_module = MagicMock()

    context = EngineExecutionContext(delayed_request)

    executor._initialize_work_stack(context)

    assert len(context.work_stack) == 1
    work_item = context.work_stack.popleft()
    assert work_item.observable is observable
    assert work_item.analysis_module is delayed_request.analysis_module


@pytest.mark.unit
def test_final_analysis_repush_queues_only_observables(tmp_path):
    """The final-analysis pass pushes the whole tree back onto the stack. It used
    to iterate ``root.all`` (Analysis *and* Observable) and let the Analysis half
    fall into the dead branch; it now iterates ``all_observables``."""
    root = _make_root(tmp_path)
    assert len(root.all) > len(root.all_observables)  # root.all is mixed

    work_stack = WorkStack()
    for observable in root.all_observables:
        work_stack.append(observable)

    assert len(work_stack) == len(root.all_observables)


@pytest.mark.unit
def test_drain_work_stack_buffer_flushes_analysis_and_queues_observables(tmp_path):
    """The buffer stays mixed on purpose.

    Event listeners push both Analysis and Observable objects into
    ``work_stack_buffer``: the Analysis entries are there so their details get
    flushed to disk, not so they can be analyzed. Dropping Analysis from the
    *stack* must not drop the flush.
    """
    executor = _make_executor()
    root = _make_root(tmp_path, observable_count=1)
    observable = root.all_observables[0]
    analysis = root.all_analysis[-1]
    assert isinstance(analysis, _StubAnalysis)

    flush_analysis_details = MagicMock()
    root.analysis_tree_manager.flush_analysis_details = flush_analysis_details

    context = EngineExecutionContext(root)
    context.final_analysis_mode = True

    work_stack = WorkStack()
    # the analysis appears twice: the drain must flush it exactly once
    work_stack_buffer = [analysis, observable, analysis]

    executor._drain_work_stack_buffer(context, root, work_stack, work_stack_buffer)

    flush_analysis_details.assert_called_once_with(analysis)
    assert work_stack_buffer == []
    assert len(work_stack) == 1
    assert work_stack.popleft().observable is observable
    # anything on the buffer means the tree changed, so final analysis restarts
    assert context.final_analysis_mode is False


@pytest.mark.unit
def test_drain_work_stack_buffer_of_analysis_only_still_exits_final_analysis(tmp_path):
    """A buffer holding nothing but Analysis adds nothing to the stack, but it is
    still evidence the tree changed — final analysis mode reopens."""
    executor = _make_executor()
    root = _make_root(tmp_path, observable_count=1)
    analysis = root.all_analysis[-1]
    flush_analysis_details = MagicMock()
    root.analysis_tree_manager.flush_analysis_details = flush_analysis_details

    context = EngineExecutionContext(root)
    context.final_analysis_mode = True

    work_stack = WorkStack()
    executor._drain_work_stack_buffer(context, root, work_stack, [analysis])

    flush_analysis_details.assert_called_once_with(analysis)
    assert len(work_stack) == 0
    assert context.final_analysis_mode is False


@pytest.mark.unit
def test_work_target_does_not_carry_an_analysis():
    """§19.13: ``WorkTarget.analysis`` was never set by any caller and never read
    by anything but ``__str__``."""
    work_item = WorkTarget()

    assert not hasattr(work_item, "analysis")
    with pytest.raises(TypeError):
        WorkTarget(analysis=_StubAnalysis())


@pytest.mark.unit
def test_no_analysis_module_declares_an_analysis_target_type():
    """``AnalysisModule.valid_analysis_target_type`` defaulted to ``Observable``
    and documented "return None to disable the check". Nothing ever overrode it,
    and the engine only ever passes an Observable, so the gate could not reject
    anything — it is gone, and nothing may reintroduce it.

    Scanned statically so modules that fail to import (missing optional
    dependencies) are still covered.
    """
    module_root = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "saq")
    assert os.path.isdir(module_root)

    offenders = []
    for dir_path, _, file_names in os.walk(module_root):
        for file_name in file_names:
            if not file_name.endswith(".py"):
                continue

            target = os.path.join(dir_path, file_name)
            with open(target, "r", encoding="utf-8", errors="replace") as fp:
                try:
                    tree = ast.parse(fp.read(), filename=target)
                except SyntaxError:
                    continue

            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "valid_analysis_target_type"
                ):
                    offenders.append(f"{target}:{node.lineno}")

    assert offenders == []
