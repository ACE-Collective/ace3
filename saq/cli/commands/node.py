"""Node lifecycle commands: inspect a node, drain it, resume it.

Draining a node is what makes a shutdown orderly across a cluster. It pauses the node's
collectors, lets them flush whatever they have already accepted, moves outstanding
delayed analysis to a node that can still run it, and marks the node as expected to be
offline so monitoring does not alert on a machine that was taken down on purpose.

The drain state machine itself already existed and is driven by the engine; these
commands are the operator's handle on it from the node itself, alongside the existing
HTTP API (POST /api/v2/nodes/{id}/drain) used from the GUI. Both apply the same
transitions, defined once in saq.constants.
"""

import logging
import sys
import time

from saq.cli.cli_main import get_cli_subparsers
from saq.constants import NODE_DRAIN_COMPLETE_STATUSES
from saq.database.util.node import (
    drain_node,
    get_collector_statuses,
    get_node_expected_state,
    get_node_status,
    get_node_workload_counts,
    resume_node,
)
from saq.environment import get_global_runtime_settings

node_parser = get_cli_subparsers().add_parser('node',
    help="Node lifecycle commands. See ace node --help for details.")
node_sp = node_parser.add_subparsers(dest='node_cmd')

# how often to re-check the node status while waiting for a drain to finish
DRAIN_POLL_INTERVAL = 2.0


def _require_node_id() -> int:
    node_id = get_global_runtime_settings().saq_node_id
    if node_id is None:
        logging.error("this node is not initialized in the database")
        sys.exit(1)

    return node_id


def node_status(args):
    node_id = _require_node_id()
    status = get_node_status(node_id)
    workload_count, delayed_count = get_node_workload_counts(node_id)

    print(f"node:     {get_global_runtime_settings().saq_node} (id {node_id})")
    print(f"status:   {status}")
    # what an operator said this node SHOULD be, as opposed to what it is. a drained node
    # that was deliberately stopped reads offline here; one that crashed reads online.
    print(f"expected: {get_node_expected_state(node_id)}")
    print(f"workload: {workload_count}")
    print(f"delayed:  {delayed_count}")

    collectors = get_collector_statuses(node_id)
    if collectors:
        print("collectors:")
        for name, collector_status, backlog_count, last_update in collectors:
            print(f"  {name}: {collector_status} (backlog {backlog_count}, last update {last_update})")

    sys.exit(0)


def node_drain(args):
    """Start a drain, optionally waiting for it to finish."""
    node_id = _require_node_id()

    if not drain_node(node_id):
        # not an error: a node that is already draining, drained or stopped is in the
        # state the caller wanted, and a shutdown script must be able to run twice
        current = get_node_status(node_id)
        logging.info("node %s not transitioned to draining (current status %s)", node_id, current)
        if current in NODE_DRAIN_COMPLETE_STATUSES:
            sys.exit(0)
    else:
        logging.info("node %s draining", node_id)

    if not args.wait:
        sys.exit(0)

    sys.exit(0 if _wait_for_drain(node_id, args.timeout) else 1)


def _wait_for_drain(node_id: int, timeout: float) -> bool:
    """Poll until the node reports drained, or the timeout expires.

    Returns True if it drained. A timeout is reported but is not necessarily fatal to a
    shutdown: the caller can still stop the node, and any work left behind is recovered
    by the primary node once this node's locks expire.
    """
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        status = get_node_status(node_id)
        if status in NODE_DRAIN_COMPLETE_STATUSES:
            logging.info("node %s drained", node_id)
            return True

        workload_count, delayed_count = get_node_workload_counts(node_id)
        logging.info("waiting for drain: status %s, workload %d, delayed %d",
                     status, workload_count, delayed_count)
        time.sleep(DRAIN_POLL_INTERVAL)

    logging.warning("node %s did not finish draining within %.0fs (status %s)",
                    node_id, timeout, get_node_status(node_id))
    return False


def node_resume(args):
    node_id = _require_node_id()

    if resume_node(node_id):
        logging.info("node %s resumed", node_id)
        sys.exit(0)

    logging.warning("node %s not resumed (current status %s)", node_id, get_node_status(node_id))
    sys.exit(1)


status_parser = node_sp.add_parser('status', help="Show this node's status, workload and collectors.")
status_parser.set_defaults(func=node_status)

drain_parser = node_sp.add_parser('drain',
    help="Stop this node accepting new work and let it finish what it has accepted.")
drain_parser.add_argument('--wait', action='store_true', default=False,
    help="Block until the node has finished draining.")
drain_parser.add_argument('--timeout', type=float, default=300.0,
    help="With --wait, how long to wait for the drain to finish before giving up (default 300s).")
drain_parser.set_defaults(func=node_drain)

resume_parser = node_sp.add_parser('resume', help="Cancel a drain and return this node to service.")
resume_parser.set_defaults(func=node_resume)
