from saq.configuration.config import (
    get_config_value,
    get_config_value_as_boolean,
    get_config_value_as_int,
)

from saq.constants import (
    CONFIG_REDIS,
    CONFIG_REDIS_HOST,
    CONFIG_REDIS_PASSWORD,
    CONFIG_REDIS_PORT,
    CONFIG_REDIS_SSL_CA_PATH,
    CONFIG_REDIS_USE_SSL,
    CONFIG_REDIS_USERNAME,
)

import redis


def get_redis_connection(database: int, config_section: str = CONFIG_REDIS) -> redis.Redis:

    kwargs = {
        "host": get_config_value(config_section, CONFIG_REDIS_HOST),
        "port": get_config_value_as_int(config_section, CONFIG_REDIS_PORT),
        "username": get_config_value(config_section, CONFIG_REDIS_USERNAME),
        "password": get_config_value(config_section, CONFIG_REDIS_PASSWORD),
        "db": database,
        "decode_responses": True,
        "encoding": "utf-8",
        "health_check_interval": 30,
    }

    if get_config_value_as_boolean(config_section, CONFIG_REDIS_USE_SSL, False):
        kwargs["ssl"] = True

    if get_config_value(config_section, CONFIG_REDIS_SSL_CA_PATH):
        kwargs["ssl_ca_path"] = get_config_value(
            config_section, CONFIG_REDIS_SSL_CA_PATH
        )

    return redis.Redis(**kwargs)
