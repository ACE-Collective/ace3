from typing import Optional
from saq.configuration.config import (
    get_config,
)


import redis


def get_redis_connection(database: int, config_name: Optional[str] = None) -> redis.Redis:

    # right now there are only two redis configurations
    if config_name is None:
        config_name = "default"

    assert config_name in ["default", "local"]

    if config_name == "default":
        redis_config = get_config().redis
    else:
        redis_config = get_config().redis_local

    kwargs = {
        "host": redis_config.host,
        "port": redis_config.port,
        "username": redis_config.username,
        "password": redis_config.password,
        "db": database,
        "decode_responses": True,
        "encoding": "utf-8",
        "health_check_interval": 30,
        # redis-py waits forever by default; a stall raises redis.TimeoutError instead
        "socket_connect_timeout": redis_config.socket_connect_timeout,
        "socket_timeout": redis_config.socket_timeout,
    }

    if redis_config.use_ssl:
        kwargs["ssl"] = True

    if redis_config.ssl_ca_path:
        kwargs["ssl_ca_path"] = redis_config.ssl_ca_path

    return redis.Redis(**kwargs)
