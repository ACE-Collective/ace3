import os
import pytest
from unittest.mock import Mock

import saq.llm.embedding.model as model_module

pytestmark = pytest.mark.unit


@pytest.fixture
def mock_sentence_transformer(monkeypatch):
    """Mock SentenceTransformer to avoid loading heavy dependencies."""
    mock_transformer = Mock()
    mock_transformer.save = Mock()
    mock_class = Mock(return_value=mock_transformer)
    
    def mock_import(*args, **kwargs):
        if args[0] == "sentence_transformers":
            mock_module = Mock()
            mock_module.SentenceTransformer = mock_class
            return mock_module
        return __import__(*args, **kwargs)
    
    monkeypatch.setattr("builtins.__import__", mock_import)
    return mock_class, mock_transformer


@pytest.fixture
def mock_data_dir(monkeypatch, tmpdir):
    """Mock get_data_dir to use temporary directory."""
    monkeypatch.setattr("saq.llm.embedding.model.get_data_dir", lambda: str(tmpdir))
    return str(tmpdir)


@pytest.fixture(autouse=True)
def clear_model_cache():
    """Clear the global model cache before each test."""
    model_module._loaded_models.clear()
    yield
    model_module._loaded_models.clear()


class TestGetModelCacheFolder:
    def test_get_model_cache_folder(self, mock_data_dir):
        """test that get_model_cache_folder returns correct path."""
        result = model_module.get_model_cache_folder()
        expected = os.path.join(mock_data_dir, "llm", "cache")
        assert result == expected


class TestGetModelCachePath:
    def test_get_model_cache_path(self, mock_data_dir):
        """test that get_model_cache_path returns correct model path."""
        model_name = "test-model"
        result = model_module.get_model_cache_path(model_name)
        expected = os.path.join(mock_data_dir, "llm", "cache", model_name)
        assert result == expected


class TestIsModelDownloaded:
    def test_is_model_downloaded_true(self, mock_data_dir):
        """test that is_model_downloaded returns true when model exists."""
        model_name = "test-model"
        cache_path = os.path.join(mock_data_dir, "llm", "cache", model_name)
        os.makedirs(cache_path, exist_ok=True)
        
        assert model_module.is_model_downloaded(model_name) is True

    def test_is_model_downloaded_false(self, mock_data_dir):
        """test that is_model_downloaded returns false when model does not exist."""
        model_name = "nonexistent-model"
        
        assert model_module.is_model_downloaded(model_name) is False


class TestDownloadModel:
    def test_download_model_creates_cache_folder(self, mock_data_dir, mock_sentence_transformer):
        """test that download_model creates cache folder if it doesn't exist."""
        mock_class, mock_transformer = mock_sentence_transformer
        model_name = "test-model"
        
        model_module.download_model(model_name)
        
        cache_folder = os.path.join(mock_data_dir, "llm", "cache")
        assert os.path.exists(cache_folder)

    def test_download_model_calls_sentence_transformer(self, mock_data_dir, mock_sentence_transformer):
        """test that download_model instantiates SentenceTransformer with correct parameters."""
        mock_class, mock_transformer = mock_sentence_transformer
        model_name = "test-model"
        
        result = model_module.download_model(model_name)
        
        mock_class.assert_called_once_with(model_name, device="cpu")
        assert result == mock_transformer

    def test_download_model_saves_to_correct_path(self, mock_data_dir, mock_sentence_transformer):
        """test that download_model saves model to correct cache path."""
        mock_class, mock_transformer = mock_sentence_transformer
        model_name = "test-model"
        
        model_module.download_model(model_name)
        
        expected_path = os.path.join(mock_data_dir, "llm", "cache", model_name)
        mock_transformer.save.assert_called_once_with(expected_path)

    def test_download_model_with_existing_cache_folder(self, mock_data_dir, mock_sentence_transformer):
        """test that download_model works when cache folder already exists."""
        mock_class, mock_transformer = mock_sentence_transformer
        cache_folder = os.path.join(mock_data_dir, "llm", "cache")
        os.makedirs(cache_folder, exist_ok=True)
        model_name = "test-model"
        
        result = model_module.download_model(model_name)
        
        mock_class.assert_called_once_with(model_name, device="cpu")
        assert result == mock_transformer


class TestLoadModel:
    def test_load_model_downloads_if_not_cached(self, mock_data_dir, mock_sentence_transformer):
        """test that load_model downloads model if not already cached."""
        mock_class, mock_transformer = mock_sentence_transformer
        model_name = "test-model"
        
        result = model_module.load_model(model_name)
        
        mock_class.assert_called_once_with(model_name, device="cpu")
        mock_transformer.save.assert_called_once()
        assert result == mock_transformer
        assert model_module._loaded_models[model_name] == mock_transformer

    def test_load_model_from_cache_if_downloaded(self, mock_data_dir, mock_sentence_transformer):
        """test that load_model loads from cache if model already downloaded."""
        mock_class, mock_transformer = mock_sentence_transformer
        model_name = "test-model"
        
        # Create cache directory to simulate downloaded model
        cache_path = os.path.join(mock_data_dir, "llm", "cache", model_name)
        os.makedirs(cache_path, exist_ok=True)
        
        result = model_module.load_model(model_name)
        
        mock_class.assert_called_once_with(cache_path, device="cpu")
        mock_transformer.save.assert_not_called()
        assert result == mock_transformer
        assert model_module._loaded_models[model_name] == mock_transformer

    def test_load_model_returns_cached_instance(self, mock_data_dir, mock_sentence_transformer):
        """test that load_model returns cached instance on subsequent calls."""
        mock_class, mock_transformer = mock_sentence_transformer
        model_name = "test-model"
        
        # First call
        result1 = model_module.load_model(model_name)
        
        # Second call
        result2 = model_module.load_model(model_name)
        
        # Should only instantiate SentenceTransformer once
        assert mock_class.call_count == 1
        assert result1 == result2 == mock_transformer
        assert model_module._loaded_models[model_name] == mock_transformer

    def test_load_model_different_models(self, mock_data_dir, mock_sentence_transformer):
        """test that load_model handles different models separately."""
        mock_class, mock_transformer = mock_sentence_transformer
        model1 = "test-model-1"
        model2 = "test-model-2"
        
        result1 = model_module.load_model(model1)
        result2 = model_module.load_model(model2)
        
        assert mock_class.call_count == 2
        assert model_module._loaded_models[model1] == mock_transformer
        assert model_module._loaded_models[model2] == mock_transformer
        assert result1 == result2 == mock_transformer