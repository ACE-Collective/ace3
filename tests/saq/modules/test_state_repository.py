"""
Tests for the state repository implementation.
"""

import pytest

from saq.analysis.root import RootAnalysis
from saq.analysis.adapter import RootAnalysisAdapter
from saq.modules.state_repository import (
    InMemoryStateRepository,
    RootAnalysisStateRepository,
    StateRepositoryFactory
)


@pytest.mark.unit
class TestInMemoryStateRepository:
    """Test cases for the in-memory state repository."""
    
    def setup_method(self):
        """Set up a fresh repository for each test."""
        self.repository = InMemoryStateRepository()
    
    def test_get_state_non_existent(self):
        """Test getting state for a module that doesn't exist."""
        result = self.repository.get_state("non_existent_module")
        assert result is None
    
    def test_set_and_get_state(self):
        """Test setting and getting state for a module."""
        module_name = "test_module"
        test_state = {"key1": "value1", "key2": 42}
        
        self.repository.set_state(module_name, test_state)
        result = self.repository.get_state(module_name)
        
        assert result == test_state
    
    def test_has_state(self):
        """Test checking if state exists for a module."""
        module_name = "test_module"
        
        # Initially no state
        assert not self.repository.has_state(module_name)
        
        # After setting state
        self.repository.set_state(module_name, {"test": "data"})
        assert self.repository.has_state(module_name)
    
    def test_initialize_state_new_module(self):
        """Test initializing state for a new module."""
        module_name = "new_module"
        initial_state = {"initialized": True}
        
        self.repository.initialize_state(module_name, initial_state)
        result = self.repository.get_state(module_name)
        
        assert result == initial_state
    
    def test_initialize_state_existing_module(self):
        """Test that initializing state doesn't overwrite existing state."""
        module_name = "existing_module"
        existing_state = {"existing": "data"}
        initial_state = {"new": "data"}
        
        # Set existing state first
        self.repository.set_state(module_name, existing_state)
        
        # Try to initialize (should not overwrite)
        self.repository.initialize_state(module_name, initial_state)
        result = self.repository.get_state(module_name)
        
        assert result == existing_state
    
    def test_initialize_state_default_empty_dict(self):
        """Test that initialize_state defaults to empty dict when no initial state provided."""
        module_name = "empty_module"
        
        self.repository.initialize_state(module_name)
        result = self.repository.get_state(module_name)
        
        assert result == {}
    
    def test_delete_state_existing(self):
        """Test deleting state for an existing module."""
        module_name = "delete_me"
        
        self.repository.set_state(module_name, {"data": "value"})
        assert self.repository.has_state(module_name)
        
        result = self.repository.delete_state(module_name)
        
        assert result is True
        assert not self.repository.has_state(module_name)
        assert self.repository.get_state(module_name) is None
    
    def test_delete_state_non_existent(self):
        """Test deleting state for a non-existent module."""
        result = self.repository.delete_state("non_existent")
        assert result is False


@pytest.mark.unit
class TestRootAnalysisStateRepository:
    """Test cases for the root analysis state repository."""
    
    def setup_method(self):
        """Set up a fresh repository for each test."""
        self.root_analysis = RootAnalysis()
        self.root_adapter = RootAnalysisAdapter(self.root_analysis)
        self.repository = RootAnalysisStateRepository(self.root_adapter)
    
    def test_get_state_non_existent(self):
        """Test getting state for a module that doesn't exist."""
        result = self.repository.get_state("non_existent_module")
        assert result is None
    
    def test_set_and_get_state(self):
        """Test setting and getting state for a module."""
        module_name = "test_module"
        test_state = {"key1": "value1", "key2": 42}
        
        self.repository.set_state(module_name, test_state)
        result = self.repository.get_state(module_name)
        
        assert result == test_state
        # Verify it's also stored in the underlying root analysis
        assert self.root_adapter.state[module_name] == test_state
    
    def test_has_state(self):
        """Test checking if state exists for a module."""
        module_name = "test_module"
        
        # Initially no state
        assert not self.repository.has_state(module_name)
        
        # After setting state
        self.repository.set_state(module_name, {"test": "data"})
        assert self.repository.has_state(module_name)
    
    def test_initialize_state_new_module(self):
        """Test initializing state for a new module."""
        module_name = "new_module"
        initial_state = {"initialized": True}
        
        self.repository.initialize_state(module_name, initial_state)
        result = self.repository.get_state(module_name)
        
        assert result == initial_state
    
    def test_initialize_state_existing_module(self):
        """Test that initializing state doesn't overwrite existing state."""
        module_name = "existing_module"
        existing_state = {"existing": "data"}
        initial_state = {"new": "data"}
        
        # Set existing state first
        self.repository.set_state(module_name, existing_state)
        
        # Try to initialize (should not overwrite)
        self.repository.initialize_state(module_name, initial_state)
        result = self.repository.get_state(module_name)
        
        assert result == existing_state
    
    def test_delete_state_existing(self):
        """Test deleting state for an existing module."""
        module_name = "delete_me"
        
        self.repository.set_state(module_name, {"data": "value"})
        assert self.repository.has_state(module_name)
        
        result = self.repository.delete_state(module_name)
        
        assert result is True
        assert not self.repository.has_state(module_name)
        assert self.repository.get_state(module_name) is None
        # Verify it's also deleted from the underlying root analysis
        assert module_name not in self.root_adapter.state
    
    def test_delete_state_non_existent(self):
        """Test deleting state for a non-existent module."""
        result = self.repository.delete_state("non_existent")
        assert result is False
    
    def test_backward_compatibility(self):
        """Test that the repository works with existing root analysis state."""
        module_name = "legacy_module"
        legacy_state = {"legacy": "data"}
        
        # Set state directly on root analysis (simulating legacy behavior)
        self.root_adapter.state[module_name] = legacy_state
        
        # Repository should be able to read it
        result = self.repository.get_state(module_name)
        assert result == legacy_state
        
        # Repository should be able to modify it
        new_state = {"updated": "data"}
        self.repository.set_state(module_name, new_state)
        
        # Verify both through repository and direct access
        assert self.repository.get_state(module_name) == new_state
        assert self.root_adapter.state[module_name] == new_state


@pytest.mark.unit
class TestStateRepositoryFactory:
    """Test cases for the state repository factory."""
    
    def test_create_root_analysis_repository(self):
        """Test creating a root analysis repository."""
        root_analysis = RootAnalysis()
        root_adapter = RootAnalysisAdapter(root_analysis)
        
        repository = StateRepositoryFactory.create_root_analysis_repository(root_adapter)
        
        assert isinstance(repository, RootAnalysisStateRepository)
        assert repository._root_analysis is root_adapter
    
    def test_create_in_memory_repository(self):
        """Test creating an in-memory repository."""
        repository = StateRepositoryFactory.create_in_memory_repository()
        
        assert isinstance(repository, InMemoryStateRepository)
        assert repository._state_storage == {}


@pytest.mark.unit
class TestStateRepositoryIntegration:
    """Integration tests to verify the repository works with analysis modules."""
    
    def test_multiple_modules_separate_state(self):
        """Test that multiple modules maintain separate state."""
        repository = InMemoryStateRepository()
        
        module1_state = {"module": "one", "data": [1, 2, 3]}
        module2_state = {"module": "two", "data": {"key": "value"}}
        
        repository.set_state("module1", module1_state)
        repository.set_state("module2", module2_state)
        
        assert repository.get_state("module1") == module1_state
        assert repository.get_state("module2") == module2_state
        
        # Modifying one shouldn't affect the other
        repository.set_state("module1", {"modified": True})
        assert repository.get_state("module2") == module2_state
    
    def test_state_persistence_across_repository_instances(self):
        """Test that state persists when using the same root analysis."""
        root_analysis = RootAnalysis()
        root_adapter = RootAnalysisAdapter(root_analysis)
        
        # Create first repository instance and set state
        repo1 = RootAnalysisStateRepository(root_adapter)
        test_state = {"persistent": "data"}
        repo1.set_state("test_module", test_state)
        
        # Create second repository instance with same root analysis
        repo2 = RootAnalysisStateRepository(root_adapter)
        
        # State should be accessible from the new repository
        result = repo2.get_state("test_module")
        assert result == test_state 