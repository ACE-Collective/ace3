# vim: sw=4:ts=4:et
#
# ACE proxy settings

from typing import Optional
import urllib
from saq.configuration.config import get_config, get_proxy_config

def proxies(proxy_name: Optional[str] = None) -> dict[str, str]:
    """Returns the current proxy settings pulled from the configuration.
       Parameters:
       key - a key to select a proxy other than the default globally configured one
       Returns a dict in the following format. ::

    {
        'http': 'url',
        'https': 'url'
    }
"""
    result = {}
    if proxy_name is None:
        proxy_name = get_config().global_settings.default_proxy

    if proxy_name is None:
        return result

    config = get_proxy_config(proxy_name)

    if config is not None:
        for proxy_key in [ 'http', 'https' ]:
            if config.host and config.port and config.transport:
                if config.user and config.password:
                    result[proxy_key] = '{}://{}:{}@{}:{}'.format(
                        config.transport, 
                        urllib.parse.quote_plus(config.user), 
                        urllib.parse.quote_plus(config.password), 
                        config.host, 
                        config.port)
                else:
                    result[proxy_key] = '{}://{}:{}'.format(config.transport,
                                                            config.host,
                                                            config.port)

    return result


def proxy_string_for_seleniumbase(proxy_name: Optional[str] = None) -> Optional[str]:
    """Returns a SeleniumBase-compatible proxy string for the named proxy config.

    HTTP proxies: host:port or user:pass@host:port
    SOCKS proxies: socks5://host:port or socks5://user:pass@host:port

    Returns None if proxy_name is None or no proxy is configured.
    """
    if proxy_name is None:
        return None

    config = get_proxy_config(proxy_name)
    if config is None:
        return None

    if config.user and config.password:
        auth = f"{config.user}:{config.password}@"
    else:
        auth = ""

    if config.transport and config.transport.startswith("socks"):
        return f"{config.transport}://{auth}{config.host}:{config.port}"
    else:
        return f"{auth}{config.host}:{config.port}"
