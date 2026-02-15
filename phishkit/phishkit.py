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
import boto3
from botocore.config import Config as BotoConfig
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

if os.path.exists("/auth/passwords/garage-secret-key"):
    with open("/auth/passwords/garage-secret-key", "r") as fp:
        s3_password = fp.read().strip()
else:
    s3_password = ""

app = Celery(
    "phishkit",
    backend=f"redis://ace3:{redis_password}@redis:6379/7",
    broker=f"pyamqp://ace3:{rabbitmq_password}@rabbitmq//")

app.conf.broker_transport_options = {"global_keyprefix": "phishkit"}

@app.task
def ping() -> str:
    return "pong"

def _get_s3_client():
    """Create a boto3 S3 client configured for the local S3-compatible storage."""
    endpoint_url = f"http://{os.getenv('S3_HOST')}:{os.getenv('S3_PORT')}"
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=os.getenv("S3_ACCESS_KEY"),
        aws_secret_access_key=s3_password,
        region_name="garage",
        config=BotoConfig(signature_version="s3v4"),
    )

def _process_output(job_id: str, output_dir: str) -> str:
    # connect to s3-compatible storage
    s3 = _get_s3_client()

    # collect all the output files and put them in s3
    bucket_name = "ace3"
    file_prefix = f"phishkit/output/{job_id}"
    logging.info(f"looking for files in {output_dir}")
    for root, _, files in os.walk(output_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_file_path = os.path.relpath(file_path, output_dir)
            file_destination = f"{file_prefix}/{relative_file_path}"
            logger.info(f"uploading {file_path} to {bucket_name}/{file_destination}")
            s3.upload_file(file_path, bucket_name, file_destination)

    # return the object prefix
    return file_prefix

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

    # download the file from s3-compatible storage
    s3 = _get_s3_client()
    s3.download_file(bucket, file_path, target_file_path)

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
