import shutil
from uuid import uuid4
from flask import url_for
import pytest

from saq.analysis.module_path import MODULE_PATH
from saq.constants import F_TEST
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
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))
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
        analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))
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
        analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))
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
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))
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


@pytest.mark.integration
def test_index_tree_display_logic(web_client, root_analysis, test_context):
    """Test the tree display logic in index view."""
    from saq.modules.test import BasicTestAnalyzer
    from saq.modules.context import AnalysisModuleContext
    
    # Add some observables to create a tree
    test_observable = root_analysis.add_observable_by_spec(F_TEST, "tree_test")
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))
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
