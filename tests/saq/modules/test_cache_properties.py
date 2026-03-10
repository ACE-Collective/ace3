from unittest.mock import patch

import pytest

from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig

pytestmark = pytest.mark.unit


def _make_config(**kwargs):
    defaults = {
        "name": "test_module",
        "python_module": "test",
        "python_class": "TestModule",
        "enabled": True,
    }
    defaults.update(kwargs)
    return AnalysisModuleConfig(**defaults)


class TestGetCacheProperties:
    def test_returns_extended_version(self):
        config = _make_config(extended_version={"key": "value"})
        module = AnalysisModule(config=config)
        props = module.get_cache_properties()
        assert props == {"key": "value"}

    def test_empty_by_default(self):
        config = _make_config()
        module = AnalysisModule(config=config)
        props = module.get_cache_properties()
        assert props == {}

    @patch("saq.git.get_repo_commit_hash")
    def test_includes_git_repo_commit_hash(self, mock_get_hash):
        mock_get_hash.return_value = "abc123def456"
        config = _make_config(cache_version_git_repos=["analyst-data"])
        module = AnalysisModule(config=config)
        props = module.get_cache_properties()
        assert props == {"git_repo:analyst-data": "abc123def456"}
        mock_get_hash.assert_called_once_with("analyst-data")

    @patch("saq.git.get_repo_commit_hash")
    def test_skips_unknown_git_repo(self, mock_get_hash):
        mock_get_hash.return_value = None
        config = _make_config(cache_version_git_repos=["unknown-repo"])
        module = AnalysisModule(config=config)
        props = module.get_cache_properties()
        assert props == {}

    @patch("saq.git.get_repo_commit_hash")
    def test_combines_extended_version_and_git_repos(self, mock_get_hash):
        mock_get_hash.return_value = "abc123"
        config = _make_config(
            extended_version={"static_key": "static_val"},
            cache_version_git_repos=["analyst-data"],
        )
        module = AnalysisModule(config=config)
        props = module.get_cache_properties()
        assert props == {
            "static_key": "static_val",
            "git_repo:analyst-data": "abc123",
        }

    @patch("saq.git.get_repo_commit_hash")
    def test_multiple_git_repos(self, mock_get_hash):
        mock_get_hash.side_effect = lambda name: {
            "repo-a": "hash_a",
            "repo-b": "hash_b",
        }.get(name)

        config = _make_config(cache_version_git_repos=["repo-a", "repo-b"])
        module = AnalysisModule(config=config)
        props = module.get_cache_properties()
        assert props == {
            "git_repo:repo-a": "hash_a",
            "git_repo:repo-b": "hash_b",
        }
