import pytest
from pydantic import ValidationError

from saq.configuration import get_config
from saq.configuration.schema import RedisConfig
from saq.redis_client import get_redis_connection

pytestmark = pytest.mark.unit

REQUIRED = {"name": "default", "host": "redis", "port": 6379, "username": "u", "password": "p", "use_ssl": False}


@pytest.mark.parametrize("config_name, attribute", [(None, "redis"), ("local", "redis_local")])
def test_timeouts_come_from_config(monkeypatch, config_name, attribute):
    """Without both timeouts redis-py waits forever on a stalled server."""
    redis_config = getattr(get_config(), attribute)
    monkeypatch.setattr(redis_config, "socket_connect_timeout", 3)
    monkeypatch.setattr(redis_config, "socket_timeout", 7)

    kwargs = get_redis_connection(0, config_name=config_name).connection_pool.connection_kwargs

    assert kwargs["socket_connect_timeout"] == 3
    assert kwargs["socket_timeout"] == 7


def test_timeouts_default_when_not_configured():
    redis_config = RedisConfig.model_validate(REQUIRED)

    assert redis_config.socket_connect_timeout == 5
    assert redis_config.socket_timeout == 10


@pytest.mark.parametrize("socket_timeout", [0, 1])
def test_socket_timeout_must_outlast_the_indexer_blpop(socket_timeout):
    with pytest.raises(ValidationError):
        RedisConfig.model_validate({**REQUIRED, "socket_timeout": socket_timeout})
