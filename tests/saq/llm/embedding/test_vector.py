import numpy as np
import pytest
import uuid
from unittest.mock import Mock, patch

from qdrant_client.models import UpdateStatus, VectorParams, Distance, PointStruct

from saq.constants import ANALYSIS_MODE_ANALYSIS
from saq.database.util.alert import ALERT
from tests.saq.helpers import create_root_analysis
import saq.llm.embedding.vector as vector_module

@pytest.fixture
def mock_qdrant_client(monkeypatch):
    """Mock get_qdrant_client to avoid external dependencies."""
    mock_client = Mock()
    mock_client.collection_exists.return_value = True
    mock_client.delete_collection = Mock()
    mock_client.create_collection = Mock()
    mock_client.delete.return_value = Mock(status=UpdateStatus.COMPLETED)
    mock_client.count.return_value = Mock(count=0)
    mock_client.upload_points = Mock()

    mock_get_client_func = Mock(return_value=mock_client)
    monkeypatch.setattr("saq.llm.embedding.vector.get_qdrant_client", mock_get_client_func)
    return mock_get_client_func, mock_client


@pytest.fixture
def mock_load_model(monkeypatch):
    """Mock load_model to avoid loading heavy ML dependencies."""
    mock_model = Mock()
    
    def mock_encode(context_records, **kwargs):
        # Return vectors with shape matching the number of context records
        num_records = len(context_records)
        return np.random.rand(num_records, 3)  # 3D vectors for each context record
    
    mock_model.encode.side_effect = mock_encode
    mock_model.get_sentence_embedding_dimension.return_value = 3
    
    mock_load_model_func = Mock(return_value=mock_model)
    monkeypatch.setattr("saq.llm.embedding.vector.load_model", mock_load_model_func)
    return mock_load_model_func, mock_model


@pytest.fixture
def mock_config(monkeypatch):
    """Mock configuration values."""
    config_values = {
        ("llm", "embedding_model"): "test-model",
        ("qdrant", "collection_alerts"): "test-collection",
        ("qdrant", "url"): "http://localhost:6333"
    }

    def mock_get_config_value(section, key):
        return config_values.get((section, key), "default_value")

    monkeypatch.setattr("saq.llm.embedding.vector.get_config_value", mock_get_config_value)
    return config_values


@pytest.fixture
def mock_get_db(monkeypatch):
    """Mock get_db for database queries."""
    mock_db = Mock()
    mock_query = Mock()
    mock_db.query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.order_by.return_value = []
    
    monkeypatch.setattr("saq.llm.embedding.vector.get_db", Mock(return_value=mock_db))
    return mock_db




@pytest.fixture
def sample_root_analysis(tmpdir):
    """Create a real RootAnalysis object for testing."""
    root = create_root_analysis(
        uuid=str(uuid.uuid4()),
        storage_dir=str(tmpdir / "test_analysis")
    )
    root.initialize_storage()
    root.description = "Test root analysis for vectorization"
    root.tool = "test_tool"
    root.tool_instance = "test_instance"
    root.analysis_mode = ANALYSIS_MODE_ANALYSIS
    return root


@pytest.fixture
def sample_alert(sample_root_analysis):
    """Create a real Alert object for testing."""
    sample_root_analysis.save()
    alert = ALERT(sample_root_analysis)
    alert.description = "Test alert for vectorization"
    alert.tool = "test_alert_tool"
    alert.tool_instance = "test_alert_instance"
    alert.alert_type = "test_alert_type"
    alert.disposition = None
    alert.owner = None
    return alert


@pytest.mark.unit
class TestGeneratePointId:
    def test_generate_point_id_consistent(self, sample_root_analysis):
        """test that _generate_point_id produces consistent results."""
        context_doc = "test document"
        
        point_id1 = vector_module._generate_point_id(sample_root_analysis, context_doc)
        point_id2 = vector_module._generate_point_id(sample_root_analysis, context_doc)
        
        assert point_id1 == point_id2
        assert isinstance(point_id1, str)
        # Should be a valid UUID
        uuid.UUID(point_id1)

    def test_generate_point_id_different_contexts(self, sample_root_analysis):
        """test that _generate_point_id produces different IDs for different contexts."""
        context_doc1 = "test document 1"
        context_doc2 = "test document 2"
        
        point_id1 = vector_module._generate_point_id(sample_root_analysis, context_doc1)
        point_id2 = vector_module._generate_point_id(sample_root_analysis, context_doc2)
        
        assert point_id1 != point_id2

    def test_generate_point_id_different_roots(self, tmpdir):
        """test that _generate_point_id produces different IDs for different roots."""
        root1 = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=str(tmpdir / "root1"))
        root2 = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=str(tmpdir / "root2"))
        context_doc = "same document"
        
        point_id1 = vector_module._generate_point_id(root1, context_doc)
        point_id2 = vector_module._generate_point_id(root2, context_doc)
        
        assert point_id1 != point_id2


@pytest.mark.unit
class TestGetEmbeddingModel:
    def test_get_embedding_model(self, mock_config):
        """test that get_embedding_model returns configured model name."""
        result = vector_module.get_embedding_model()
        assert result == "test-model"


@pytest.mark.unit
class TestGetAlertCollectionName:
    def test_get_alert_collection_name(self, mock_config):
        """test that get_alert_collection_name returns configured collection name."""
        result = vector_module.get_alert_collection_name()
        assert result == "test-collection"


@pytest.mark.unit
class TestClearVectors:
    def test_clear_vectors_collection_exists(self, mock_config, mock_qdrant_client):
        """test that clear_vectors deletes collection when it exists."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_client.collection_exists.return_value = True

        vector_module.clear_vectors()

        mock_get_client_func.assert_called_once()
        mock_client.collection_exists.assert_called_once_with(collection_name="test-collection")
        mock_client.delete_collection.assert_called_once_with(collection_name="test-collection")

    def test_clear_vectors_collection_does_not_exist(self, mock_config, mock_qdrant_client):
        """test that clear_vectors does nothing when collection doesn't exist."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_client.collection_exists.return_value = False

        vector_module.clear_vectors()

        mock_client.delete_collection.assert_not_called()


class TestGetContextRecords:
    @pytest.mark.unit
    def test_get_context_records_root_analysis_only(self, sample_root_analysis, mock_get_db):
        """test get_context_records with only root analysis (no alert)."""
        context_records = vector_module.get_context_records(sample_root_analysis)
        
        assert len(context_records) >= 1
        # Should contain root analysis summary
        root_summary_found = any("ROOT ANALYSIS SUMMARY" in record for record in context_records)
        assert root_summary_found

    @pytest.mark.integration
    def test_get_context_records_with_alert(self, sample_alert, mock_get_db):
        """test get_context_records with alert."""
        context_records = vector_module.get_context_records(sample_alert)
        
        assert len(context_records) >= 2
        # Should contain both alert and root analysis summaries
        alert_summary_found = any("ALERT SUMMARY" in record for record in context_records)
        root_summary_found = any("ROOT ANALYSIS SUMMARY" in record for record in context_records)
        assert alert_summary_found
        assert root_summary_found

    @pytest.mark.integration
    def test_get_context_records_alert_with_disposition(self, sample_alert, mock_get_db):
        """test get_context_records with alert that has disposition."""
        sample_alert.disposition = "FALSE_POSITIVE"
        
        context_records = vector_module.get_context_records(sample_alert)
        
        alert_record = next((record for record in context_records if "ALERT SUMMARY" in record), None)
        assert alert_record is not None
        assert "disposition: FALSE_POSITIVE" in alert_record

class TestVectorize:
    @pytest.mark.unit
    def test_vectorize_root_analysis(self, sample_root_analysis, mock_config, mock_qdrant_client,
                                    mock_load_model, mock_get_db):
        """test vectorize with root analysis."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        mock_client.collection_exists.return_value = False
        
        with patch('saq.llm.embedding.vector.time') as mock_time:
            mock_time.time.side_effect = [1000.0, 1002.5]  # Mock timing
            context_records = vector_module.vectorize(sample_root_analysis)
        
        # Verify model loading
        mock_load_model_func.assert_called_once_with("test-model")
        
        # Verify encoding
        mock_model.encode.assert_called_once()
        encoded_args = mock_model.encode.call_args[0][0]
        assert isinstance(encoded_args, list)
        assert len(encoded_args) > 0
        
        # Verify Qdrant client function called
        mock_get_client_func.assert_called_once()
        
        # Verify collection creation (since it doesn't exist)
        mock_client.create_collection.assert_called_once_with(
            collection_name="test-collection",
            vectors_config=VectorParams(size=3, distance=Distance.COSINE)
        )
        
        # Verify point deletion
        mock_client.delete.assert_called_once()
        delete_call_args = mock_client.delete.call_args
        assert delete_call_args.kwargs['collection_name'] == "test-collection"
        assert delete_call_args.kwargs['wait'] is True
        
        # Verify count check
        mock_client.count.assert_called_once()
        
        # Verify point upload
        mock_client.upload_points.assert_called_once()
        upload_call_args = mock_client.upload_points.call_args
        assert upload_call_args.kwargs['collection_name'] == "test-collection"
        points = upload_call_args.kwargs['points']
        assert len(points) >= 1  # Should have at least 1 point for the root analysis summary
        
        # Verify point structure
        for point in points:
            assert isinstance(point, PointStruct)
            assert point.payload['root_uuid'] == sample_root_analysis.uuid
            assert 'text' in point.payload

    @pytest.mark.integration
    def test_vectorize_alert(self, sample_alert, mock_config, mock_qdrant_client,
                            mock_load_model, mock_get_db):
        """test vectorize with alert."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_load_model_func, mock_model = mock_load_model
        mock_client.collection_exists.return_value = True
        
        with patch('saq.llm.embedding.vector.time') as mock_time:
            mock_time.time.side_effect = [1000.0, 1002.5]
            context_records = vector_module.vectorize(sample_alert)
        
        # Verify the target UUID used is the alert's UUID
        delete_call_args = mock_client.delete.call_args
        filter_condition = delete_call_args.kwargs['points_selector'].filter.must[0]
        assert filter_condition.match.value == sample_alert.uuid
        
        # Verify points have correct UUID in payload
        upload_call_args = mock_client.upload_points.call_args
        points = upload_call_args.kwargs['points']
        for point in points:
            assert point.payload['root_uuid'] == sample_alert.uuid

    @pytest.mark.unit
    def test_vectorize_existing_collection(self, sample_root_analysis, mock_config, mock_qdrant_client,
                                          mock_load_model, mock_get_db):
        """test vectorize when collection already exists."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_client.collection_exists.return_value = True
        
        vector_module.vectorize(sample_root_analysis)
        
        # Should not create collection
        mock_client.create_collection.assert_not_called()

    @pytest.mark.unit
    def test_vectorize_count_assertion_failure(self, sample_root_analysis, mock_config, mock_qdrant_client,
                                              mock_load_model, mock_get_db):
        """test vectorize fails when count check fails."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_client.count.return_value = Mock(count=5)  # Non-zero count
        
        with pytest.raises(AssertionError, match="count_result is 5"):
            vector_module.vectorize(sample_root_analysis)

    @pytest.mark.unit
    def test_vectorize_delete_status_assertion_failure(self, sample_root_analysis, mock_config, mock_qdrant_client,
                                                       mock_load_model, mock_get_db):
        """test vectorize fails when delete operation doesn't complete."""
        mock_get_client_func, mock_client = mock_qdrant_client
        mock_client.delete.return_value = Mock(status="FAILED")
        
        with pytest.raises(AssertionError):
            vector_module.vectorize(sample_root_analysis)

    @pytest.mark.unit
    def test_vectorize_returns_context_records(self, sample_root_analysis, mock_config, mock_qdrant_client,
                                              mock_load_model, mock_get_db):
        """test vectorize returns context records."""
        context_records = vector_module.vectorize(sample_root_analysis)
        
        assert isinstance(context_records, list)
        assert len(context_records) > 0
        for record in context_records:
            assert isinstance(record, str)