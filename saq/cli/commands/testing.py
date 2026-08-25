import logging
import sys
import time
import traceback

import requests

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration import get_config


# ============================================================================
# test utilities
#

def test_proxy(args):
    try:
        from saq import proxy
        default_proxy = get_config().get_proxy_config()
        requests.get(args.url, proxies=proxy.proxies(), verify=default_proxy.verify if default_proxy.verify else False)
        sys.exit(0)
    except Exception:
        traceback.print_exc()
        sys.exit(1)

test_parser = get_cli_subparsers().add_parser('test',
    help="Test commands.")
test_sp = test_parser.add_subparsers(dest='test_cmd')

test_proxy_parser = test_sp.add_parser('proxy',
    help="Text proxy access")
test_proxy_parser.add_argument('url',
    help="Test the proxy by accessing the given URL. Any content downloaded is discarded.")
test_proxy_parser.set_defaults(func=test_proxy)

def test_database_connections(args):
    from saq.database import get_db_connection

    for database_config in get_config().databases:
        db_name = database_config.name
        hostname = database_config.hostname
        print("trying {} @ hostname {} ...".format(db_name, hostname), end='', flush=True)
        try:
            with get_db_connection(db_name) as db:
                c = db.cursor()
                c.execute("SELECT 1")
                c.fetchone()
                print("OK")
        except Exception as e:
            print("FAILED: {}".format(e))
            sys.exit(1)

    sys.exit(0)

test_database_connections_parser = get_cli_subparsers().add_parser('test-database-connections',
    help="Test the connections to all configured databases.")
test_database_connections_parser.set_defaults(func=test_database_connections)

def test_network_semaphore(args):
    from saq.network_semaphore import NetworkSemaphoreClient

    client = NetworkSemaphoreClient()
    if client.acquire(args.semaphore_name):
        time.sleep(args.timeout)
        client.release()
    else:
        logging.error("test failed")

network_semaphore_test = get_cli_subparsers().add_parser('test-network-semaphore',
    help="Test the Network Semaphore Server by requesting a semaphore.")
network_semaphore_test.add_argument('semaphore_name', help="The name of the semaphore to acquire.")
network_semaphore_test.add_argument('-t', '--timeout', required=False, default=60, type=int, dest='timeout',
    help="The number of seconds to wait until the semaphore is released.  Defaults to 60.")
network_semaphore_test.set_defaults(func=test_network_semaphore)

def test_proxies(args):
    from saq.proxy import proxies
    for proxy_config in get_config().proxies:
        print("testing proxy {} ({})".format(proxy_config.name, proxy_config))
        session = requests.session()
        session.proxies = proxies(proxy_config.name)
        response = session.request('GET', args.url,
                                   timeout=20,
                                   allow_redirects=True,
                                   verify=False)

        print("result: ({}) - {}".format(response.status_code, response.reason))

    sys.exit(0)

test_proxies_parser = get_cli_subparsers().add_parser('test-proxies',
    help="Test the configured proxies to make sure ACE can use them.")
test_proxies_parser.add_argument('url', help="A sample URL to attempt to download through each proxy.")
test_proxies_parser.set_defaults(func=test_proxies)

# XXX replace this with calls to the engine code
def verify_modules(args):
    """Executes verify_environment() on all modules that are enabled."""
    from saq.modules.adapter import load_module_from_config

    for analysis_module_config in get_config().analysis_modules:
        # is this module disabled globally?
        # modules that are disable globally are not used anywhere
        if not analysis_module_config.enabled:
            logging.debug("analysis module {} disabled (globally)".format(analysis_module_config.name))
            continue

        logging.debug("verifying analysis module from {}".format(analysis_module_config.name))
        analysis_module = load_module_from_config(analysis_module_config.name)
        if analysis_module is None:
            logging.error("analysis module {} not found".format(analysis_module_config.name))
            continue

        # make sure the module has everything it needs
        try:
            analysis_module.verify_environment()
        except Exception as e:
            logging.error("analysis module {} failed environment verification: {}".format(analysis_module, e))
            traceback.print_exc()
            continue

        logging.info("analysis module {} verification OK".format(analysis_module_config.name))
    
verify_modules_parsers = get_cli_subparsers().add_parser('verify-modules',
    help="Executes verify_environment() on all modules that are enabled.")
verify_modules_parsers.set_defaults(func=verify_modules)
