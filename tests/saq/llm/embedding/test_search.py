import pytest
from unittest.mock import Mock
from qdrant_client.models import ScoredPoint

import saq.llm.embedding.search as search_module

pytestmark = pytest.mark.unit


@pytest.fixture
def mock_qdrant_client(monkeypatch):
    """Mock QdrantClient to avoid external dependencies."""
    mock_client = Mock()
    
    # Mock query_points to return a result with points
    mock_scored_point1 = ScoredPoint(
        id="point_1",
        version=1,
        score=0.95,
        payload={"text": "sample document 1", "root_uuid": "uuid1"},
        vector=None
    )
    mock_scored_point2 = ScoredPoint(
        id="point_2", 
        version=1,
        score=0.87,
        payload={"text": "sample document 2", "root_uuid": "uuid2"},
        vector=None
    )
    
    mock_result = Mock()
    mock_result.points = [mock_scored_point1, mock_scored_point2]
    mock_client.query_points.return_value = mock_result
    
    mock_client_class = Mock(return_value=mock_client)
    # Patch where the import happens (inside the function)
    monkeypatch.setattr("qdrant_client.QdrantClient", mock_client_class)
    return mock_client_class, mock_client


@pytest.fixture
def mock_load_model(monkeypatch):
    """Mock load_model to avoid loading heavy ML dependencies."""
    mock_model = Mock()
    
    # Mock encode to return a consistent vector representation
    def mock_encode(text, **kwargs):
        # Return a mock numpy array-like object that has tolist method
        mock_array = Mock()
        mock_array.tolist.return_value = [0.1, 0.2, 0.3, 0.4, 0.5]
        return mock_array
    
    mock_model.encode.side_effect = mock_encode
    
    mock_load_model_func = Mock(return_value=mock_model)
    monkeypatch.setattr("saq.llm.embedding.search.load_model", mock_load_model_func)
    return mock_load_model_func, mock_model


@pytest.fixture
def mock_get_embedding_model(monkeypatch):
    """Mock get_embedding_model to return a test model name."""
    mock_func = Mock(return_value="test-embedding-model")
    monkeypatch.setattr("saq.llm.embedding.search.get_embedding_model", mock_func)
    return mock_func


@pytest.fixture
def mock_get_config_value(monkeypatch):
    """Mock get_config_value for Qdrant configuration."""
    def mock_config(section, key):
        config_values = {
            ("qdrant", "url"): "http://localhost:6333"
        }
        return config_values.get((section, key), "default_value")
    
    mock_func = Mock(side_effect=mock_config)
    monkeypatch.setattr("saq.llm.embedding.search.get_config_value", mock_func)
    return mock_func


@pytest.fixture
def mock_get_alert_collection_name(monkeypatch):
    """Mock get_alert_collection_name to return test collection name."""
    mock_func = Mock(return_value="test-alerts-collection")
    monkeypatch.setattr("saq.llm.embedding.search.get_alert_collection_name", mock_func)
    return mock_func


class TestSearch:
    def test_search_basic_functionality(self, mock_qdrant_client, mock_load_model, 
                                       mock_get_embedding_model, mock_get_config_value,
                                       mock_get_alert_collection_name):
        """test that search function performs basic search correctly."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = "test search query"
        results = search_module.search(search_term)
        
        # Verify model loading with correct model name
        mock_get_embedding_model.assert_called_once()
        mock_load_model_func.assert_called_once_with("test-embedding-model")
        
        # Verify text encoding
        mock_model.encode.assert_called_once_with(search_term)
        
        # Verify Qdrant client instantiation with correct URL
        mock_get_config_value.assert_called_once_with("qdrant", "url")
        mock_client_class.assert_called_once_with(url="http://localhost:6333")
        
        # Verify query_points call with correct parameters
        mock_get_alert_collection_name.assert_called_once()
        mock_client.query_points.assert_called_once_with(
            collection_name="test-alerts-collection",
            query=[0.1, 0.2, 0.3, 0.4, 0.5],
            query_filter=None,
            limit=30
        )
        
        # Verify results
        assert isinstance(results, list)
        assert len(results) == 2
        assert all(isinstance(point, ScoredPoint) for point in results)
        assert results[0].id == "point_1"
        assert results[1].id == "point_2"

    def test_search_empty_string(self, mock_qdrant_client, mock_load_model,
                                mock_get_embedding_model, mock_get_config_value,
                                mock_get_alert_collection_name):
        """test search with empty string."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = ""
        results = search_module.search(search_term)
        
        # Should still call encode with empty string
        mock_model.encode.assert_called_once_with("")
        
        # Should still perform query
        mock_client.query_points.assert_called_once()
        
        assert isinstance(results, list)

    def test_search_special_characters(self, mock_qdrant_client, mock_load_model,
                                     mock_get_embedding_model, mock_get_config_value,
                                     mock_get_alert_collection_name):
        """test search with special characters in search term."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = "test@example.com & special/chars $100"
        results = search_module.search(search_term)
        
        # Should handle special characters correctly
        mock_model.encode.assert_called_once_with(search_term)
        mock_client.query_points.assert_called_once()
        
        assert isinstance(results, list)

    def test_search_unicode_characters(self, mock_qdrant_client, mock_load_model,
                                     mock_get_embedding_model, mock_get_config_value,
                                     mock_get_alert_collection_name):
        """test search with unicode characters."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = "тест 测试 🔍 café"
        results = search_module.search(search_term)
        
        # Should handle unicode correctly
        mock_model.encode.assert_called_once_with(search_term)
        mock_client.query_points.assert_called_once()
        
        assert isinstance(results, list)

    def test_search_no_results(self, mock_qdrant_client, mock_load_model,
                             mock_get_embedding_model, mock_get_config_value,
                             mock_get_alert_collection_name):
        """test search when no results are found."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        # Mock empty results
        mock_result = Mock()
        mock_result.points = []
        mock_client.query_points.return_value = mock_result
        
        search_term = "no results query"
        results = search_module.search(search_term)
        
        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_single_result(self, mock_qdrant_client, mock_load_model,
                                 mock_get_embedding_model, mock_get_config_value,
                                 mock_get_alert_collection_name):
        """test search with single result."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        # Mock single result
        mock_scored_point = ScoredPoint(
            id="single_point",
            version=1,
            score=0.99,
            payload={"text": "single result", "root_uuid": "single_uuid"},
            vector=None
        )
        mock_result = Mock()
        mock_result.points = [mock_scored_point]
        mock_client.query_points.return_value = mock_result
        
        search_term = "single result query"
        results = search_module.search(search_term)
        
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0].id == "single_point"
        assert results[0].score == 0.99

    def test_search_vector_encoding_called_correctly(self, mock_qdrant_client, mock_load_model,
                                                   mock_get_embedding_model, mock_get_config_value,
                                                   mock_get_alert_collection_name):
        """test that vector encoding is called with correct parameters and converted to list."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = "vector encoding test"
        search_module.search(search_term)
        
        # Verify encode was called
        mock_model.encode.assert_called_once_with(search_term)
        
        # Since we're using side_effect, the tolist is called on the returned mock array
        # We can't directly assert on it since it's inside the side_effect function
        # Instead, verify the final result was used correctly
        mock_client.query_points.assert_called_once()
        call_args = mock_client.query_points.call_args
        assert call_args.kwargs['query'] == [0.1, 0.2, 0.3, 0.4, 0.5]

    def test_search_query_parameters(self, mock_qdrant_client, mock_load_model,
                                   mock_get_embedding_model, mock_get_config_value,
                                   mock_get_alert_collection_name):
        """test that query_points is called with correct parameters."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = "parameter test"
        search_module.search(search_term)
        
        # Verify query_points call parameters
        mock_client.query_points.assert_called_once_with(
            collection_name="test-alerts-collection",
            query=[0.1, 0.2, 0.3, 0.4, 0.5],
            query_filter=None,
            limit=30
        )

    def test_search_configuration_values_used(self, mock_qdrant_client, mock_load_model,
                                            mock_get_embedding_model, mock_get_config_value,
                                            mock_get_alert_collection_name):
        """test that configuration values are properly used."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        # Change mock return values
        mock_get_embedding_model.return_value = "custom-model"
        mock_get_alert_collection_name.return_value = "custom-collection"
        mock_get_config_value.side_effect = lambda section, key: "http://custom:1234"
        
        search_term = "config test"
        search_module.search(search_term)
        
        # Verify custom values are used
        mock_load_model_func.assert_called_once_with("custom-model")
        mock_client_class.assert_called_once_with(url="http://custom:1234")
        
        call_args = mock_client.query_points.call_args
        assert call_args.kwargs['collection_name'] == "custom-collection"

    def test_search_returns_scored_points(self, mock_qdrant_client, mock_load_model,
                                        mock_get_embedding_model, mock_get_config_value,
                                        mock_get_alert_collection_name):
        """test that search returns actual ScoredPoint objects."""
        mock_client_class, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        
        search_term = "scored points test"
        results = search_module.search(search_term)
        
        # Verify return type and content
        assert isinstance(results, list)
        for point in results:
            assert isinstance(point, ScoredPoint)
            assert hasattr(point, 'id')
            assert hasattr(point, 'score')
            assert hasattr(point, 'payload')
