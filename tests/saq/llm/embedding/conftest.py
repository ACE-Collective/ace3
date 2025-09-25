import pytest
from unittest.mock import patch
from saq.constants import CONFIG_SERVICE_LLM_EMBEDDING, CONFIG_SERVICE_LLM_EMBEDDING_ENABLED

#
# when we run *these* tests, we *do* want to be vectorizing the root analysis objects
#

@pytest.fixture(autouse=True)
def mock_get_config_value_as_boolean():
    def mock_func(service, key):
        if service == CONFIG_SERVICE_LLM_EMBEDDING and key == CONFIG_SERVICE_LLM_EMBEDDING_ENABLED:
            return True

        from saq.configuration.config import get_config_value_as_boolean
        return get_config_value_as_boolean(service, key)
    
    with patch("saq.llm.embedding.service.get_config_value_as_boolean", side_effect=mock_func) as mock_patch:
        yield mock_patch
