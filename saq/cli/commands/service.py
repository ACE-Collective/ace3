import logging
import os
import threading

from saq.cli.cli_main import get_cli_subparsers
from saq.error.reporting import report_exception
from saq.shutdown import get_shutdown_coordinator, run_bounded


service_parser = get_cli_subparsers().add_parser('service',
    help="Service management commands. See ace service --help for details.")
service_sp = service_parser.add_subparsers(dest='service_cmd')

# how the shutdown budget is split between stop() and wait(). stop() signals the service
# to quit and wait() collects its threads and processes, so stop() gets the larger share:
# a wait() that overruns is survivable (the threads are abandoned and the process exits
# anyway), while a stop() that never gets to run leaves work locked and unreleased.
STOP_BUDGET_FRACTION = 0.6

# how often the run loop rechecks whether the service finished on its own
SERVICE_POLL_INTERVAL = 0.5


def start_service(args):
    from saq.configuration.config import get_service_config
    from saq.service import load_service_by_name

    service = load_service_by_name(args.service)

    # the deadline must stay below this container's stop_grace_period in
    # docker-compose.yml, so that we always exit before docker escalates to SIGKILL
    deadline = get_service_config(args.service).shutdown_deadline_seconds
    coordinator = get_shutdown_coordinator(deadline_seconds=deadline)

    # installed exactly once, here. the handler only sets a flag -- shutdown work happens
    # on the main path below, never inside a signal handler
    coordinator.install_signal_handlers()

    try:
        if args.single_threaded:
            service.start_single_threaded()
        else:
            service.start()

        # services come in two shapes and this handles both. a blocking service (the
        # engine, cron) does all its work inside start() and only returns when it is
        # finished, so the wait below falls straight through. a threaded service (the
        # collectors, most others) returns from start() immediately and does its waiting
        # in wait(); we sit here until either a signal arrives or the service finishes on
        # its own.
        _run_until_finished(service, coordinator, args.service)

    except KeyboardInterrupt:
        # only reachable if a service installed its own SIGINT handling over ours
        coordinator.request_shutdown("keyboard interrupt")
    except Exception as e:
        logging.error(f"error starting service {args.service}: {e}")
        report_exception()
        # exit non-zero so the container's restart policy and whoever is watching it can
        # tell a service that fell over from one that was asked to stop
        _shutdown(service, coordinator, args.service, exit_code=1)

    _shutdown(service, coordinator, args.service)


def _run_until_finished(service, coordinator, service_name: str):
    """Block until shutdown is requested or the service finishes by itself."""
    finished = threading.Event()

    def _wait():
        try:
            service.wait()
        except Exception as e:
            logging.warning(f"error waiting for service {service_name}: {e}")
        finally:
            finished.set()

    threading.Thread(target=_wait, name=f"service-wait-{service_name}", daemon=True).start()

    while True:
        if coordinator.wait_for_shutdown(SERVICE_POLL_INTERVAL):
            return

        if finished.is_set():
            logging.info(f"service {service_name} finished on its own")
            return


def _shutdown(service, coordinator, service_name: str, exit_code: int = 0):
    """Stop the service within the deadline, then exit the process. Does not return.

    Every step is bounded. The point is not that each one succeeds, but that the process
    exits on time regardless of which one wedges -- a service blocked on a database that
    has already gone away must not be the reason docker has to SIGKILL us.
    """
    # arm the watchdog if a signal did not already do it. without this a service that
    # returned from start() on its own could hang in stop() with nothing to catch it
    coordinator.request_shutdown(f"service {service_name} shutting down")

    logging.info(f"stopping service {service_name}")

    budget = coordinator.deadline_remaining()
    run_bounded(service.stop, budget * STOP_BUDGET_FRACTION, f"{service_name}.stop")
    run_bounded(service.wait, coordinator.deadline_remaining(), f"{service_name}.wait")

    coordinator.run_hooks()

    # stand the watchdog down: everything that needed stopping has stopped, so it must
    # not force-exit anything from here on
    coordinator.mark_complete()

    logging.info(f"service {service_name} exited with code {exit_code}")

    # os._exit rather than sys.exit, deliberately. by this point the only threads left
    # are daemon threads blocked on peers that are already gone -- lock keepalives,
    # semaphore failsafes, the asyncio loop in aceapi_v2.sync. Letting the interpreter
    # unwind them produces a burst of connection errors on the way out, which is exactly
    # the noise this change exists to remove. Everything ACE owns has been released above.
    logging.shutdown()
    os._exit(exit_code)


start_service_parser = service_sp.add_parser('start', help="Start an ACE service.")
start_service_parser.add_argument('service', help="The name of the service to start. This is referenced in the configuration as [service_<name>]")
start_service_parser.add_argument('--single-threaded', action='store_true', default=False, help="Start the service in single threaded mode.")
start_service_parser.set_defaults(func=start_service)
