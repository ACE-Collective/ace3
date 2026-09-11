#!/usr/bin/env python3

#
# NOTE this module runs inside the js_deobfuscator manager container and is
# external to ACE — it must not import from the saq namespace.
#
# It exposes a single Celery task `deobfuscate` that takes an input file
# path (inside the shared js-deobfuscator volume) and runs the sandbox
# harness inside a throwaway scanner container. The scanner container is
# built from Dockerfile.js_deobfuscator in this same directory.
#

import argparse
import json
import logging
import os
import uuid
from subprocess import PIPE, Popen, TimeoutExpired

from celery import Celery
from yaml import load, SafeLoader

logger = logging.getLogger(__name__)

# The name of the volume shared with the scanner containers this manager spawns. Compose
# prefixes named volumes with the project name, so it varies per ACE instance and is passed in
# as ACE_JS_DEOBFUSCATOR_VOLUME. The default is the pre-multi-instance name.
JS_DEOBFUSCATOR_VOLUME = os.environ.get("ACE_JS_DEOBFUSCATOR_VOLUME", "ace-js-deobfuscator")


def _run_scanner(input_path: str, output_dir: str, job_id: str, timeout: int) -> tuple:
    """Spawn the throwaway scanner container to deobfuscate a single file.

    `input_path` and `output_dir` both live under /js-deobfuscator, which is
    bind-mounted via the JS_DEOBFUSCATOR_VOLUME named volume into both this
    manager container and the scanner container. Returns (stdout, stderr,
    returncode, output_file_path).
    """
    output_file = os.path.join(output_dir, "deobfuscated.js")
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network", "none",
        "-v", f"{JS_DEOBFUSCATOR_VOLUME}:/js-deobfuscator",
        os.environ.get("ACE3_JS_DEOBFUSCATOR_IMAGE_URL", "js-deobfuscator"),
        "node",
        "/opt/app/harness.js",
        input_path,
        output_file,
    ]

    logger.info("running scanner for job %s: %s", job_id, " ".join(cmd))
    process = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except TimeoutExpired:
        process.kill()
        process.wait()
        stdout, stderr = "", f"scanner container timed out after {timeout}s"
        returncode = -1
    else:
        returncode = process.returncode

    # persist stdout/stderr/exit.code next to the output file so the client
    # can surface them in the ACE analysis details
    with open(os.path.join(output_dir, "std.out"), "w") as fp:
        fp.write(stdout or "")
    with open(os.path.join(output_dir, "std.err"), "w") as fp:
        fp.write(stderr or "")
    with open(os.path.join(output_dir, "exit.code"), "w") as fp:
        fp.write(str(returncode))

    return stdout, stderr, returncode, output_file


if os.path.exists("/auth/passwords/redis"):
    with open("/auth/passwords/redis", "r") as fp:
        redis_password = fp.read().strip()
else:
    redis_password = ""

if os.path.exists("/auth/passwords/rabbitmq"):
    with open("/auth/passwords/rabbitmq", "r") as fp:
        rabbitmq_password = fp.read().strip()
else:
    rabbitmq_password = ""

app = Celery(
    "js_deobfuscator",
    backend=f"redis://ace3:{redis_password}@redis:6379/8",
    broker=f"pyamqp://ace3:{rabbitmq_password}@rabbitmq//",
)

app.conf.broker_transport_options = {"global_keyprefix": "js_deobfuscator"}

# isolate this app's queue from phishkit — both managers share the same
# rabbitmq broker, and if both listen on the default "celery" queue each
# worker ends up pulling the other's tasks and raising NotRegistered.
app.conf.task_default_queue = "js_deobfuscator"
app.conf.task_default_exchange = "js_deobfuscator"
app.conf.task_default_routing_key = "js_deobfuscator"


@app.task
def ping() -> str:
    return "pong"


@app.task
def deobfuscate(file_path: str, timeout: int = 30) -> str:
    """Run the sandbox harness against `file_path` and return the path to
    the result directory. `file_path` must already live under the shared
    js-deobfuscator volume (the client wrapper in saq/js_deobfuscator.py
    is responsible for copying it there first)."""
    job_id = str(uuid.uuid4())
    output_dir = f"/js-deobfuscator/output/{job_id}"
    os.makedirs(output_dir, exist_ok=True)

    logger.info("started deobfuscation job %s for %s", job_id, file_path)

    stdout, stderr, returncode, output_file = _run_scanner(
        input_path=file_path,
        output_dir=output_dir,
        job_id=job_id,
        timeout=timeout,
    )

    if returncode != 0:
        logger.warning(
            "deobfuscation job %s exited with %s; stderr=%s",
            job_id, returncode, stderr,
        )

    # harness prints a JSON status line on stdout — persist it so the client
    # can surface event_count / error in the analysis summary
    try:
        report = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        report = {"status": "parse_error", "raw_stdout": stdout}
    with open(os.path.join(output_dir, "report.json"), "w") as fp:
        json.dump(report, fp)

    return output_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="Load celery configuration from this file.")
    args = parser.parse_args()

    if args.config:
        with open(args.config, "r") as f:
            config = load(f, Loader=SafeLoader)
            if config:
                app.conf.update(config)

    app.worker_main(["worker", "--loglevel=INFO"])
