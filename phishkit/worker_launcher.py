#!/usr/bin/env python3

#
# NOTE this is external to ACE so it doesn't use the saq namespace
#

"""Entry point of the phishkit manager container: runs the scan worker and the control worker.

The scan worker consumes the default "celery" queue (scan_url, scan_file, maintain_files) with the
full pool. The control worker consumes CONTROL_QUEUE (ping, scanner_image_id) with a solo pool of
its own, so those answer in milliseconds even while every scan slot is busy.

Both run until one of them exits; then the other is stopped and the container exits with the
first one's status, so the restart policy brings the pair back together. SIGTERM and SIGINT are
forwarded to both, which gives the scan worker celery's warm shutdown within the container's
stop_grace_period.

This deliberately does not import phishkit.phishkit: it would build the celery app and read the
config in the launcher process for nothing.
"""

import os
import signal
import subprocess
import sys
import time

# must match phishkit.phishkit.CONTROL_QUEUE
CONTROL_QUEUE = "phishkit_control"

CELERY = ["/opt/venv/bin/celery", "-A", "phishkit.phishkit", "worker", "--loglevel", "INFO"]

WORKERS = {
    "scan": CELERY + ["-Q", "celery", "-n", "scan@%h"],
    "control": CELERY + ["-Q", CONTROL_QUEUE, "-n", "control@%h", "--pool", "solo"],
}


def main() -> int:
    processes = {
        role: subprocess.Popen(argv, env={**os.environ, "PHISHKIT_WORKER_ROLE": role})
        for role, argv in WORKERS.items()
    }

    def forward(signum, _frame):
        for process in processes.values():
            if process.poll() is None:
                process.send_signal(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    # wait for the first worker to exit, for whatever reason
    while all(process.poll() is None for process in processes.values()):
        time.sleep(1)

    first_role, first = next((role, p) for role, p in processes.items() if p.returncode is not None)
    print(f"phishkit {first_role} worker exited with {first.returncode}, stopping the others", flush=True)
    forward(signal.SIGTERM, None)
    for process in processes.values():
        process.wait()

    # a worker killed by a signal has a negative returncode; report it the way a shell would
    return first.returncode if first.returncode >= 0 else 128 - first.returncode


if __name__ == "__main__":
    sys.exit(main())
