#!/usr/bin/env python3

#
# NOTE this is external to ACE so it doesn't use the saq namespace
#

import argparse
import logging
import os
from subprocess import PIPE, Popen
import uuid
from celery import Celery
from minio import Minio
from yaml import load, SafeLoader

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

if os.path.exists("/auth/passwords/minio"):
    with open("/auth/passwords/minio", "r") as fp:
        minio_password = fp.read().strip()
else:
    minio_password = ""

app = Celery(
    "phishkit",
    backend=f"redis://ace3:{redis_password}@redis:6379/7",
    broker=f"pyamqp://ace3:{rabbitmq_password}@rabbitmq//")

app.conf.broker_transport_options = {"global_keyprefix": "phishkit"}

@app.task
def ping() -> str:
    return "pong"

def _process_output(job_id: str, output_dir: str) -> str:
    # connect to minio
    minio = Minio(
        f"{os.getenv('MINIO_HOST')}:{os.getenv('MINIO_PORT')}",
        access_key=os.getenv("MINIO_ACCESS_KEY"),
        secret_key=minio_password,
        secure=False,  # HTTP, not HTTPS
    )

    # collect all the output files and put them in minio
    bucket_name = "ace3"
    file_prefix = f"phishkit/output/{job_id}"
    logging.info(f"looking for files in {output_dir}")
    for root, _, files in os.walk(output_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_file_path = os.path.relpath(file_path, output_dir)
            file_destination = f"{file_prefix}/{relative_file_path}"
            logger.info(f"uploading {file_path} to {bucket_name}/{file_destination}")
            minio.fput_object(bucket_name, file_destination, file_path)

    # return the object prefix
    return file_prefix


@app.task
def scan_file(bucket: str, file_path: str) -> str:
    # create a place to put the file we're going to render in the browser
    job_id = str(uuid.uuid4())
    input_dir = f"/phishkit/input/{job_id}"
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(input_dir)
    os.makedirs(output_dir)

    logger.info(f"started file job {job_id} for {bucket}/{file_path}")

    # create a place to put the rendered file
    target_file_path = f"{input_dir}/{os.path.basename(file_path)}"

    # download the file from minio
    minio = Minio(
        f"{os.getenv('MINIO_HOST')}:{os.getenv('MINIO_PORT')}",
        access_key=os.getenv("MINIO_ACCESS_KEY"),
        secret_key=minio_password,
        secure=False,  # HTTP, not HTTPS
    )
    minio.fget_object(bucket, file_path, target_file_path)

    # launch the scan job and wait for it to complete
    process = Popen(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "ace-phishkit:/phishkit",
            "phishkit",
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
            "phishkit",
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
