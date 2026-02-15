#!/usr/bin/env python3

#
# NOTE this is external to ACE so it doesn't use the saq namespace
#

import argparse
import logging
import mimetypes
import os
from subprocess import PIPE, Popen
import uuid
from celery import Celery
import shutil
from yaml import load, SafeLoader
import magic

logger = logging.getLogger(__name__)

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
    "phishkit",
    backend=f"redis://ace3:{redis_password}@redis:6379/7",
    broker=f"pyamqp://ace3:{rabbitmq_password}@rabbitmq//")

app.conf.broker_transport_options = {"global_keyprefix": "phishkit"}

@app.task
def ping() -> str:
    return "pong"

def _process_output(job_id: str, output_dir: str) -> str:
    """Returns the output directory path for the completed scan job."""
    return output_dir

def _correct_file_extension(file_path: str) -> str:
    """Attempts to correct the file extension of the given file based on the mime type.
    If the file extension needs to change, the file is renamed and the new file path is returned.
    If the guess on the mime type or file extension fails, the original file path is returned.
    Otherwise, the original file path is returned."""

    mime_type = magic.from_file(file_path, mime=True)
    if not mime_type:
        return file_path

    logging.info(f"mime type: {mime_type} for {file_path}")

    file_extension = mimetypes.guess_extension(mime_type)
    if not file_extension:
        return file_path

    # NOTE file_extension already has a leading dot
    logging.info(f"file extension: {file_extension} for {file_path}")

    if file_path.lower().endswith(f"{file_extension.lower()}"):
        return file_path

    # create a new file path with the correct extension
    dir_path = os.path.dirname(file_path)
    file_name, _ = os.path.splitext(os.path.basename(file_path))
    new_file_path = f"{dir_path}/{file_name}{file_extension}"
    logging.info(f"correcting file extension from {file_path} to {new_file_path}")
    os.rename(file_path, new_file_path)
    return new_file_path

@app.task
def scan_file(file_path: str) -> str:
    # create a place to put the file we're going to render in the browser
    job_id = str(uuid.uuid4())
    input_dir = f"/phishkit/input/{job_id}"
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(input_dir)
    os.makedirs(output_dir)

    logger.info("started file job %s for %s", job_id, file_path)

    # copy the file into the job input directory
    target_file_path = f"{input_dir}/{os.path.basename(file_path)}"
    shutil.copy2(file_path, target_file_path)

    # correct the file extension
    target_file_path = _correct_file_extension(target_file_path)

    # launch the scan job and wait for it to complete
    process = Popen(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "ace-phishkit:/phishkit",
            os.environ.get("ACE3_PHISHKIT_IMAGE_URL", "phishkit"),
            "/opt/venv/bin/python",
            "/opt/app/scanner.py",
            "--file",
            target_file_path,
            "--output-dir",
            output_dir,
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
    )
    _stdout, _stderr = process.communicate(timeout=15)

    for line in _stdout.splitlines():
        logging.info(f"stdout> {line}")

    if process.returncode != 0:
        for line in _stderr.splitlines():
            logging.info(f"stderr> {line}")

    with open(os.path.join(output_dir, "std.out"), "w") as fp:
        fp.write(_stdout)

    with open(os.path.join(output_dir, "std.err"), "w") as fp:
        fp.write(_stderr)

    with open(os.path.join(output_dir, "exit.code"), "w") as fp:
        fp.write(str(process.returncode))

    return _process_output(job_id, output_dir)

@app.task
def scan_url(url: str) -> str:
    # create an output directory for the scan
    job_id = str(uuid.uuid4())
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(output_dir)

    logger.info(f"started url job {job_id} for {url}")

    # launch the scan job and wait for it to complete
    process = Popen(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "ace-phishkit:/phishkit",
            os.environ.get("ACE3_PHISHKIT_IMAGE_URL", "phishkit"),
            "/opt/venv/bin/python",
            "/opt/app/scanner.py",
            url,
            "--output-dir",
            output_dir,
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
    )
    _stdout, _stderr = process.communicate(timeout=15)
    if process.returncode != 0:
        raise Exception(f"scan failed: {_stderr}")

    for line in _stdout.splitlines():
        logging.info(f"stdout> {line}")

    if process.returncode != 0:
        for line in _stderr.splitlines():
            logging.info(f"stderr> {line}")

    with open(os.path.join(output_dir, "std.out"), "w") as fp:
        fp.write(_stdout)

    with open(os.path.join(output_dir, "std.err"), "w") as fp:
        fp.write(_stderr)

    with open(os.path.join(output_dir, "exit.code"), "w") as fp:
        fp.write(str(process.returncode))

    return _process_output(job_id, output_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="Load celery configuration from this file.")
    args = parser.parse_args()

    if args.config:
        with open(args.config, "r") as f:
            config = load(f, Loader=SafeLoader)
            if config:
                app.conf.update(config)

    app.worker_main(
        [
            "worker",
            "--loglevel=INFO",
        ]
    )
