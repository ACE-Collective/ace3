import logging
import signal
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.error.reporting import report_exception


service_parser = get_cli_subparsers().add_parser('service',
    help="Service management commands. See ace service --help for details.")
service_sp = service_parser.add_subparsers(dest='service_cmd')

def start_service(args):
    from saq.service import load_service_by_name

    service = load_service_by_name(args.service)

    signal.signal(signal.SIGTERM, lambda signum, frame: service.stop())

    try:
        if args.single_threaded:
            service.start_single_threaded()
        else:
            service.start()

        service.wait()

    except KeyboardInterrupt:
        logging.info(f"caught keyboard interrupt, stopping service {args.service}")
        service.stop()
        service.wait()
        sys.exit(0)
    except Exception as e:
        logging.error(f"error starting service {args.service}: {e}")
        report_exception()
        sys.exit(1)

    logging.info(f"service {args.service} exited")
    sys.exit(0)

start_service_parser = service_sp.add_parser('start', help="Start an ACE service.")
start_service_parser.add_argument('service', help="The name of the service to start. This is referenced in the configuration as [service_<name>]")
start_service_parser.add_argument('--single-threaded', action='store_true', default=False, help="Start the service in single threaded mode.")
start_service_parser.set_defaults(func=start_service)
