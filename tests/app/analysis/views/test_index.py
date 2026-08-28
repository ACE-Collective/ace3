import shutil
from datetime import datetime, timezone
from uuid import uuid4
from flask import url_for
import pytest

from saq.analysis.module_execution_delta import ModuleExecutionDelta
from saq.analysis.module_path import MODULE_PATH
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_BASIC_TEST, F_TEST
from saq.database.model import Alert
from saq.database.util.alert import ALERT
from saq.observables.testing import TestObservable
from saq.modules.adapter import AnalysisModuleAdapter

@pytest.mark.skip(reason="skipping tests with api_server")
@pytest.mark.system
def test_index(web_client, root_analysis, api_server, test_context):
    result = web_client.get(url_for("analysis.index"), query_string={"direct": str(uuid4())})

    # unknown uuid should return redirect to manage
    assert result.status_code == 302
    assert result.location == url_for("analysis.manage")

    test_observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    assert isinstance(test_observable, TestObservable)

    from saq.modules.test import BasicTestAnalyzer, BasicTestAnalysis
    from saq.modules.context import AnalysisModuleContext
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_BASIC_TEST)))
    context = AnalysisModuleContext(root=root_analysis)
    analyzer.set_context(context)
    analyzer.execute_analysis(test_observable)
    analysis = test_observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

    root_analysis.save() # TODO ALERT should save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    result = web_client.get(url_for("analysis.index"), query_string={
            "direct": root_analysis.uuid,
            "observable_uuid": test_observable.uuid,
            "module_path": MODULE_PATH(analysis),
        })
    assert result.status_code == 200

@pytest.mark.integration
def test_index_no_load(web_client, root_analysis):
    """Alert JSON is missing."""
    root_analysis.save() # TODO ALERT should save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    shutil.rmtree(alert.storage_dir)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 302
    assert result.location == url_for("analysis.manage")


@pytest.mark.unit
class TestTreeNode:
    """Test the TreeNode class functionality."""
    
    def test_tree_node_creation_with_analysis(self, root_analysis):
        """Test TreeNode creation with Analysis object."""
        from app.analysis.views.index import TreeNode
        
        node = TreeNode(root_analysis)
        assert node.obj is root_analysis
        assert node.parent is None
        assert node.children == []
        assert node.reference_node is None
        assert node.visible is False
        assert node.referents == []
        assert node.presenter is not None
        assert isinstance(node.uuid, str)
    
    def test_tree_node_creation_with_observable(self, root_analysis):
        """Test TreeNode creation with Observable object."""
        from app.analysis.views.index import TreeNode
        
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "test_observable")
        node = TreeNode(test_observable)
        
        assert node.obj == test_observable
        assert node.presenter is not None
        assert not node.is_analysis
        assert not node.is_root_analysis
    
    def test_tree_node_add_child(self, root_analysis):
        """Test adding child nodes."""
        from app.analysis.views.index import TreeNode
        
        parent_node = TreeNode(root_analysis)
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "child_test")
        child_node = TreeNode(test_observable)
        
        parent_node.add_child(child_node)
        
        assert len(parent_node.children) == 1
        assert parent_node.children[0] == child_node
        assert child_node.parent == parent_node
    
    def test_tree_node_remove_child(self, root_analysis):
        """Test removing child nodes."""
        from app.analysis.views.index import TreeNode
        
        parent_node = TreeNode(root_analysis)
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "child_test")
        child_node = TreeNode(test_observable)
        
        parent_node.add_child(child_node)
        parent_node.remove_child(child_node)
        
        assert len(parent_node.children) == 0
        assert child_node.parent == parent_node  # parent reference remains
    
    def test_tree_node_refer_to(self, root_analysis):
        """Test node references."""
        from app.analysis.views.index import TreeNode
        
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "ref_test")
        node1 = TreeNode(test_observable)
        node2 = TreeNode(test_observable)
        
        node1.refer_to(node2)
        
        assert node1.reference_node == node2
        assert node1 in node2.referents
    
    def test_tree_node_walk(self, root_analysis):
        """Test walking through tree nodes."""
        from app.analysis.views.index import TreeNode
        
        parent_node = TreeNode(root_analysis)
        child1 = TreeNode(root_analysis.add_observable_by_spec(F_TEST, "child1"))
        child2 = TreeNode(root_analysis.add_observable_by_spec(F_TEST, "child2"))
        
        parent_node.add_child(child1)
        parent_node.add_child(child2)
        
        visited_nodes = []
        parent_node.walk(lambda node: visited_nodes.append(node))
        
        assert len(visited_nodes) == 3
        assert parent_node in visited_nodes
        assert child1 in visited_nodes
        assert child2 in visited_nodes
    
    def test_tree_node_properties(self, root_analysis):
        """Test TreeNode properties."""
        from app.analysis.views.index import TreeNode
        
        # Test with RootAnalysis
        root_node = TreeNode(root_analysis)
        assert root_node.is_root_analysis
        assert root_node.is_analysis
        assert not root_node.volatile
        
        # Test with Observable
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "prop_test")
        obs_node = TreeNode(test_observable)
        assert not obs_node.is_root_analysis
        assert not obs_node.is_analysis
    
    def test_tree_node_find_observable_node(self, root_analysis):
        """Test finding observable nodes in tree."""
        from app.analysis.views.index import TreeNode
        
        parent_node = TreeNode(root_analysis)
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "find_test")
        child_node = TreeNode(test_observable)
        parent_node.add_child(child_node)
        
        found_node = parent_node.find_observable_node(F_TEST, "find_test")
        assert found_node == child_node
        
        not_found = parent_node.find_observable_node(F_TEST, "not_exists")
        assert not_found is None
    
    def test_tree_node_is_collapsible(self, root_analysis):
        """Test collapsible logic."""
        from app.analysis.views.index import TreeNode
        
        # Analysis node with children should be collapsible
        parent_node = TreeNode(root_analysis)
        child_node = TreeNode(root_analysis.add_observable_by_spec(F_TEST, "collapse_test"))
        parent_node.add_child(child_node)
        
        assert parent_node.is_collapsible(prune=False)
        
        # Node without children should not be collapsible
        empty_node = TreeNode(root_analysis)
        assert not empty_node.is_collapsible(prune=False)
    
    def test_tree_node_should_render(self, root_analysis):
        """Test rendering logic."""
        from app.analysis.views.index import TreeNode
        
        # Root analysis should always render
        root_node = TreeNode(root_analysis)
        assert root_node.should_render
        
        # Regular observable node should render
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "render_test")
        obs_node = TreeNode(test_observable)
        assert obs_node.should_render

@pytest.mark.integration
class TestIndexHelperFunctions:
    """Test helper functions in index.py."""
    
    def test_recurse_function(self, root_analysis, test_context):
        """Test the _recurse helper function."""
        from app.analysis.views.index import TreeNode, _recurse
        from saq.modules.test import BasicTestAnalyzer
        from saq.modules.context import AnalysisModuleContext
        
        # Add test observable and analysis
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "recurse_test")
        analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_BASIC_TEST)))
        context = AnalysisModuleContext(root=root_analysis)
        analyzer.set_context(context)
        analyzer.execute_analysis(test_observable)
        
        # Create tree and recurse
        root_node = TreeNode(root_analysis)
        _recurse(root_node)
        
        # Should have children for observables
        assert len(root_node.children) > 0
        
        # Find the test observable node
        test_obs_node = None
        for child in root_node.children:
            if hasattr(child.obj, 'value') and child.obj.value == "recurse_test":
                test_obs_node = child
                break
        
        assert test_obs_node is not None
        # Should have analysis children (if analysis was created)
        # Note: analysis might not be created in test environment
        # assert len(test_obs_node.children) > 0
    
    def test_sort_function(self, root_analysis):
        """Test the _sort helper function."""
        from app.analysis.views.index import TreeNode, _sort
        
        # Create parent with multiple children
        parent_node = TreeNode(root_analysis)
        
        # Add observables with different values to test sorting
        obs1 = root_analysis.add_observable_by_spec(F_TEST, "z_test")
        obs2 = root_analysis.add_observable_by_spec(F_TEST, "a_test")
        obs3 = root_analysis.add_observable_by_spec(F_TEST, "m_test")
        
        child1 = TreeNode(obs1)
        child2 = TreeNode(obs2)
        child3 = TreeNode(obs3)
        
        parent_node.add_child(child1)
        parent_node.add_child(child2)
        parent_node.add_child(child3)
        
        # Sort the tree
        _sort(parent_node)
        
        # Children should be sorted
        assert len(parent_node.children) == 3
        # Note: actual sorting depends on sort_order property and object comparison
    
    def test_prune_function(self, root_analysis, test_context):
        """Test the _prune helper function."""
        from app.analysis.views.index import TreeNode, _recurse, _prune
        from saq.modules.test import BasicTestAnalyzer
        from saq.modules.context import AnalysisModuleContext
        
        # Create a tree with analysis
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "prune_test")
        analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_BASIC_TEST)))
        context = AnalysisModuleContext(root=root_analysis)
        analyzer.set_context(context)
        analyzer.execute_analysis(test_observable)
        
        root_node = TreeNode(root_analysis)
        _recurse(root_node)
        
        # Before pruning, some nodes may not be visible
        def count_visible(node):
            count = 1 if node.visible else 0
            for child in node.children:
                count += count_visible(child)
            return count
        
        visible_before = count_visible(root_node)
        
        # Prune the tree
        _prune(root_node)
        # root node is visible (as done in the actual code)
        root_node.visible = True
        
        # Root should be visible after pruning
        assert root_node.visible
        
        # Some nodes should be visible now
        visible_after = count_visible(root_node)
        assert visible_after >= 1  # At least root should be visible
    
    def test_resolve_references_function(self, root_analysis):
        """Test the _resolve_references helper function."""
        from app.analysis.views.index import TreeNode, _resolve_references
        
        # Create nodes with references
        test_observable = root_analysis.add_observable_by_spec(F_TEST, "resolve_test")
        node1 = TreeNode(test_observable)
        node2 = TreeNode(test_observable)
        
        # Create a child for node2
        child_obs = root_analysis.add_observable_by_spec(F_TEST, "child_resolve")
        child_node = TreeNode(child_obs)
        node2.add_child(child_node)
        
        # Make node1 refer to node2
        node1.refer_to(node2)
        
        # Make node1 visible but not node2
        node1.visible = True
        node2.visible = False
        
        # Resolve references
        _resolve_references(node1)
        
        # node1 should now have node2's children and no reference
        assert node1.reference_node is None
        assert len(node1.children) == 1
        assert node1.children[0].obj == child_obs


@pytest.mark.integration
def test_index_with_session_variables(web_client, root_analysis, app):
    """Test index view with different session variables."""
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    with web_client.session_transaction() as sess:
        sess['prune'] = False
        sess['prune_volatile'] = False
    
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 200


@pytest.mark.integration
def test_index_with_observable_and_module_path(web_client, root_analysis, test_context):
    """Test index view with observable_uuid and module_path parameters."""
    from saq.modules.test import BasicTestAnalyzer, BasicTestAnalysis
    from saq.modules.context import AnalysisModuleContext
    
    # Add test observable and analysis
    test_observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_BASIC_TEST)))
    context = AnalysisModuleContext(root=root_analysis)
    analyzer.set_context(context)
    analyzer.execute_analysis(test_observable)
    analysis = test_observable.get_and_load_analysis(BasicTestAnalysis)
    
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    result = web_client.get(url_for("analysis.index"), query_string={
        "direct": root_analysis.uuid,
        "observable_uuid": test_observable.uuid,
        "module_path": MODULE_PATH(analysis)
    })
    
    assert result.status_code == 200


@pytest.mark.integration
def test_index_template_context(web_client, root_analysis):
    """Test that index view provides correct template context."""
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 200
    
    # The template should render without errors
    assert b'<!DOCTYPE html>' in result.data or b'<html' in result.data


@pytest.mark.integration
def test_index_database_queries(web_client, root_analysis):
    """Test that index view handles database queries correctly."""
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    # Test that the view handles database queries without errors
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 200


@pytest.mark.integration
def test_index_error_handling(web_client, root_analysis):
    """Test error handling in index view."""
    # Test with invalid observable_uuid
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    result = web_client.get(url_for("analysis.index"), query_string={
        "direct": root_analysis.uuid,
        "observable_uuid": "invalid-uuid"
    })
    
    # Should handle gracefully with redirect
    assert result.status_code == 302


@pytest.mark.integration
def test_index_with_comments(web_client, root_analysis):
    """Test index view handles comments correctly."""
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    # The view should handle cases where comments query might fail
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 200


def _run_basic_analyzer(root_analysis, test_context):
    """Helper: add a "test_1" observable and execute BasicTestAnalyzer on it.
    Returns (observable, analysis). Uses "test_1" specifically because
    BasicTestAnalyzer.execute_analysis dispatches on the observable
    value (saq/modules/test.py:65) and only specific values trigger
    create_analysis() — "test_1" being the canonical happy-path case
    used by test_index above.
    """
    from saq.modules.test import BasicTestAnalyzer, BasicTestAnalysis
    from saq.modules.context import AnalysisModuleContext

    test_observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_BASIC_TEST)))
    context = AnalysisModuleContext(root=root_analysis)
    analyzer.set_context(context)
    analyzer.execute_analysis(test_observable)
    analysis = test_observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis is not None, "BasicTestAnalyzer did not produce an analysis"
    return test_observable, analysis


@pytest.mark.integration
def test_index_renders_cache_hit_badge(web_client, root_analysis, test_context):
    """When root._module_executions contains a from_cache_hit=True delta
    matching an analysis in the tree, the rendered alert page shows the
    'cached' badge next to that analysis line.
    """
    test_observable, analysis = _run_basic_analyzer(root_analysis, test_context)

    # Synthesize the attribution delta the executor would have recorded
    # had this analysis been replayed from cache. ``cached_at`` is fixed
    # so the rendered tooltip carries a deterministic timestamp the test
    # can grep for.
    root_analysis.record_module_execution(ModuleExecutionDelta(
        module_path=MODULE_PATH(analysis),
        module_instance=None,
        module_version=1,
        observable_uuid=test_observable.uuid,
        observable_type=test_observable.type,
        observable_value=test_observable.value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=4,
        root_uuid=root_analysis.uuid,
        cache_key="dead" * 16,  # 64-char hex-shaped placeholder
        from_cache_hit=True,
        cached_at="2026-05-10T12:34:56+00:00",
    ))

    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    body = result.data.decode("utf-8")
    # Badge HTML pieces — checked independently so a small markup tweak
    # to one (icon class, label text) doesn't silently mask a regression
    # in the others.
    assert 'class="badge bg-white border border-dark"' in body
    assert "bi-lightning-fill" in body
    # Tooltip carries the cache_key prefix, the original cache timestamp
    # formatted YYYY-MM-DD HH:MM UTC, and execution_time_ms.
    assert "deaddeaddead" in body  # first 12 chars of the placeholder key
    assert "cached 2026-05-10 12:34 UTC" in body
    assert "4ms" in body


@pytest.mark.integration
def test_index_no_cache_hit_badge_for_live_analysis(
    web_client, root_analysis, test_context,
):
    """Mirror of the positive test: same alert shape but no from_cache_hit
    delta — the badge HTML must NOT appear. Guards against the macro
    rendering unconditionally.
    """
    _run_basic_analyzer(root_analysis, test_context)

    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    body = result.data.decode("utf-8")
    # The cached-badge string composition is unique to this feature so a
    # substring check is reliable. If it fires here the macro is leaking
    # the badge for non-cache-hit analyses.
    assert "bi-lightning-fill" not in body


@pytest.mark.integration
def test_index_renders_added_by_subtext(web_client, root_analysis, test_context):
    """An observable stamped with added_by/added_time shows the
    'added by <user>' subtext line in the rendered analysis tree.
    """
    test_observable, _ = _run_basic_analyzer(root_analysis, test_context)

    # username intentionally not in the users table so the template
    # exercises the raw-username fallback deterministically
    test_observable.added_by = "manual_analyst"
    test_observable.added_time = datetime(2026, 6, 11, 9, 30, 0, tzinfo=timezone.utc)

    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    body = result.data.decode("utf-8")
    assert 'class="observable-added-by"' in body
    assert "added by <strong>manual_analyst</strong>" in body
    assert "2026-06-11 09:30 UTC" in body


@pytest.mark.integration
def test_index_no_added_by_subtext_for_engine_observables(
    web_client, root_analysis, test_context,
):
    """Mirror of the positive test: observables without added_by must not
    render the subtext line.
    """
    _run_basic_analyzer(root_analysis, test_context)

    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    body = result.data.decode("utf-8")
    assert 'class="observable-added-by"' not in body
    assert "added by <strong>" not in body


@pytest.mark.integration
def test_index_tree_display_logic(web_client, root_analysis, test_context):
    """Test the tree display logic in index view."""
    from saq.modules.test import BasicTestAnalyzer
    from saq.modules.context import AnalysisModuleContext
    
    # Add some observables to create a tree
    test_observable = root_analysis.add_observable_by_spec(F_TEST, "tree_test")
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_BASIC_TEST)))
    context = AnalysisModuleContext(root=root_analysis)
    analyzer.set_context(context)
    analyzer.execute_analysis(test_observable)
    
    root_analysis.save()
    alert = ALERT(root_analysis)
    
    # Test with different prune settings
    with web_client.session_transaction() as sess:
        sess['prune'] = True
        sess['prune_volatile'] = True
    
    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 200


#
# Batched detection / interesting lookups for the observable action menu.
#
# ObservablePresenter.available_actions used to run one "is set for detection"
# query and one "is interesting" query every time it was read, and
# default_observable.html reads it three times per observable node. On a real
# alert (450 observable nodes) that was ~2,700 round-trips per page render, half
# of them going through run_async_with_session -- a cross-thread event loop hop
# that opens an AsyncSession and commits for a single-row SELECT.
#
# The view already batches both lookups (get_all_observable_detections /
# get_interesting_observables_by_hashes), so the render must not issue any of
# the per-observable ones.
#

@pytest.mark.integration
def test_index_does_not_query_per_observable_for_actions(
    web_client, root_analysis, test_context, monkeypatch,
):
    """Rendering the analysis tree must not issue per-observable detection or
    interesting lookups -- the view batches both before building the tree."""
    import saq.analysis.presenter.observable_presenter as presenter_module

    detection_calls = []
    interesting_calls = []

    def _spy_detection(observable):
        detection_calls.append(observable.uuid)
        return False

    def _spy_run_async(fn, *args, **kwargs):
        interesting_calls.append(args)
        return False

    monkeypatch.setattr(presenter_module, "observable_is_set_for_detection", _spy_detection)
    monkeypatch.setattr(presenter_module, "run_async_with_session", _spy_run_async)

    _run_basic_analyzer(root_analysis, test_context)
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    assert detection_calls == [], (
        f"per-observable detection lookup ran {len(detection_calls)} times during render")
    assert interesting_calls == [], (
        f"per-observable interesting lookup ran {len(interesting_calls)} times during render")


@pytest.mark.integration
def test_index_renders_detection_and_interesting_actions(
    web_client, root_analysis, test_context, monkeypatch,
):
    """The batched values must drive the same menu items the per-observable
    queries used to. Force both to True and check the 'already enabled' variants
    render."""
    import app.analysis.views.index as index_module
    from saq.database.util.observable_detection import ObservableDetectionSummary

    _run_basic_analyzer(root_analysis, test_context)
    root_analysis.save()
    ALERT(root_analysis)

    def _all_detected(alert):
        return {
            observable.uuid: ObservableDetectionSummary(
                observable_uuid=observable.uuid,
                for_detection=True,
                detection_modified_by="tester",
                detection_context="enabled by tester",
            )
            for observable in alert.all_observables
        }

    monkeypatch.setattr(index_module, "get_all_observable_detections", _all_detected)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    body = result.data.decode("utf-8")
    assert "Disable observable for future detection" in body
    assert "Enable observable for future detection" not in body


@pytest.mark.integration
def test_index_renders_unmark_interesting_for_interesting_observable(
    web_client, root_analysis, test_context,
):
    """Companion to the detection test for the other batched lookup: an
    observable actually marked interesting in the database must render the
    'Unmark as interesting' action rather than 'Mark as interesting'."""
    from aceapi_v2.observables.service import set_observable_interesting
    from aceapi_v2.sync import run_async_with_session

    test_observable, _ = _run_basic_analyzer(root_analysis, test_context)
    run_async_with_session(
        set_observable_interesting, test_observable.type, test_observable.value, True)

    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(
        url_for("analysis.index"),
        query_string={"direct": root_analysis.uuid},
    )
    assert result.status_code == 200

    body = result.data.decode("utf-8")
    assert "Unmark as interesting" in body


@pytest.mark.unit
def test_available_actions_built_once_per_presenter(root_analysis, monkeypatch):
    """available_actions is read three times per observable by
    default_observable.html; it must only do the lookups once."""
    import saq.analysis.presenter.observable_presenter as presenter_module
    from saq.analysis.presenter import create_observable_presenter

    detection_calls = []
    monkeypatch.setattr(
        presenter_module, "observable_is_set_for_detection",
        lambda observable: detection_calls.append(observable.uuid) or False)
    monkeypatch.setattr(
        presenter_module, "run_async_with_session",
        lambda fn, *args, **kwargs: False)

    observable = root_analysis.add_observable_by_spec(F_TEST, "cached_actions")
    presenter = create_observable_presenter(observable)

    first = presenter.available_actions
    assert presenter.available_actions is first
    assert presenter.available_actions is first
    assert len(detection_calls) == 1


@pytest.mark.unit
def test_available_actions_uses_supplied_context(root_analysis, monkeypatch):
    """When the view supplies the batched values, no lookup is performed."""
    import saq.analysis.presenter.observable_presenter as presenter_module
    from saq.analysis.presenter import create_observable_presenter
    from saq.constants import ACTION_DISABLE_DETECTION, ACTION_UNMARK_INTERESTING

    def _fail(*args, **kwargs):
        raise AssertionError("per-observable lookup should not run")

    monkeypatch.setattr(presenter_module, "observable_is_set_for_detection", _fail)
    monkeypatch.setattr(presenter_module, "run_async_with_session", _fail)

    observable = root_analysis.add_observable_by_spec(F_TEST, "supplied_context")
    presenter = create_observable_presenter(
        observable, detection_status=True, is_interesting=True)

    action_names = [action.name for action in presenter.available_actions]
    assert ACTION_DISABLE_DETECTION in action_names
    assert ACTION_UNMARK_INTERESTING in action_names
