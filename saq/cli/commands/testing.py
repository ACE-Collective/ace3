import logging
import sys
import time

import requests

from saq.cli.cli_main import EXIT_DATABASE_UNAVAILABLE, get_cli_subparsers
from saq.configuration import get_config
from saq.database.retry import is_connection_lost


# ============================================================================
# test utilities
#

def test_proxy(args):
    from saq import proxy
    try:
        # proxies have no tls verification setting, and test_proxies does not verify either
        requests.get(args.url, proxies=proxy.proxies(), verify=False, timeout=20)
    except Exception as e:
        logging.exception(f"unable to download {args.url} through the default proxy: {e}")
        sys.exit(1)

    sys.exit(0)

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
            sys.exit(EXIT_DATABASE_UNAVAILABLE if is_connection_lost(e) else 1)

    sys.exit(0)

test_database_connections_parser = test_sp.add_parser('database-connections',
    help="Test the connections to all configured databases.")
test_database_connections_parser.set_defaults(func=test_database_connections)

def test_network_semaphore(args):
    from saq.network_semaphore import NetworkSemaphoreClient

    client = NetworkSemaphoreClient()
    if not client.acquire(args.semaphore_name):
        logging.error(f"unable to acquire network semaphore {args.semaphore_name}")
        sys.exit(1)

    try:
        time.sleep(args.timeout)
    finally:
        client.release()

    sys.exit(0)

network_semaphore_test = test_sp.add_parser('network-semaphore',
    help="Test the Network Semaphore Server by requesting a semaphore.")
network_semaphore_test.add_argument('semaphore_name', help="The name of the semaphore to acquire.")
network_semaphore_test.add_argument('-t', '--timeout', required=False, default=60, type=int, dest='timeout',
    help="The number of seconds to wait until the semaphore is released.  Defaults to 60.")
network_semaphore_test.set_defaults(func=test_network_semaphore)

def test_proxies(args):
    from saq.proxy import proxies
    exit_code = 0
    for proxy_config in get_config().proxies:
        print("testing proxy {} ({})".format(proxy_config.name, proxy_config))
        session = requests.session()
        session.proxies = proxies(proxy_config.name)
        try:
            response = session.request('GET', args.url,
                                       timeout=20,
                                       allow_redirects=True,
                                       verify=False)
        except Exception as e:
            # one unreachable proxy must not stop the others from being tested
            print("result: FAILED - {}".format(e))
            exit_code = 1
            continue

        print("result: ({}) - {}".format(response.status_code, response.reason))

    sys.exit(exit_code)

test_proxies_parser = test_sp.add_parser('proxies',
    help="Test the configured proxies to make sure ACE can use them.")
test_proxies_parser.add_argument('url', help="A sample URL to attempt to download through each proxy.")
test_proxies_parser.set_defaults(func=test_proxies)

# XXX replace this with calls to the engine code
def verify_modules(args):
    """Executes verify_environment() on all modules that are enabled."""
    from saq.modules.adapter import load_module_from_config

    exit_code = 0
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
            exit_code = 1
            continue

        # make sure the module has everything it needs
        try:
            analysis_module.verify_environment()
        except Exception as e:
            logging.exception("analysis module {} failed environment verification: {}".format(analysis_module_config.name, e))
            exit_code = 1
            continue

        logging.info("analysis module {} verification OK".format(analysis_module_config.name))

    sys.exit(exit_code)

verify_modules_parsers = test_sp.add_parser('modules',
    help="Executes verify_environment() on all modules that are enabled.")
verify_modules_parsers.set_defaults(func=verify_modules)
