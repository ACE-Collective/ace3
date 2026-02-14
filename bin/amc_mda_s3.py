#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
import logging
import logging.handlers
import os
import shutil
import sys
from tempfile import NamedTemporaryFile
from typing import Optional
import uuid

import boto3
from botocore.config import Config as BotoConfig
import requests
import yara

# yara tags that control the filtering
ALLOW = "allow"
BLOCK = "block"

# by default we allow all content
DEFAULT_MODE = ALLOW

@dataclass
class S3Credentials:
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None

def get_ec2_metadata() -> S3Credentials:
    """Get the EC2 metadata for the current instance."""
    metadata_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    response = requests.get(metadata_url)
    response.raise_for_status()
    role_name = response.text

    metadata_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    response = requests.get(metadata_url)
    response.raise_for_status()
    credentials = response.json()

    # get the region from the EC2 metadata
    region_url = "http://169.254.169.254/latest/meta-data/placement/region"
    region_response = requests.get(region_url)
    region_response.raise_for_status()
    region = region_response.text.strip()

    return S3Credentials(
        access_key=credentials["AccessKeyId"],
        secret_key=credentials["SecretAccessKey"],
        session_token=credentials["Token"],
        region=region)

def get_s3_credentials_from_args(args) -> S3Credentials:
    """Get the S3 credentials from the arguments."""
    return S3Credentials(
        access_key=args.access_key,
        secret_key=args.secret_key,
        region=args.region)

def get_compiled_yara_rule_path(yara_rule_path: str) -> str:
    return f"{yara_rule_path}c"

def load_yara_rule(yara_rule_path: str) -> yara.Rules:
    compiled_rule_path = get_compiled_yara_rule_path(yara_rule_path)
    if os.path.exists(compiled_rule_path):
        return yara.load(compiled_rule_path)
    else:
        logger.warning(f"compiled yara rule {compiled_rule_path} does not exist, compiling on-the-fly")
        return yara.compile(filepath=yara_rule_path)

def compile_yara_rule(yara_rule_path: str) -> yara.Rules:
    compiled_rule_path = get_compiled_yara_rule_path(yara_rule_path)
    # if the compiled rule doesn't exist or the source rule is newer, we need to compile it
    if not os.path.exists(compiled_rule_path) or os.path.getmtime(yara_rule_path) > os.path.getmtime(compiled_rule_path):
        logger.info(f"compiling yara rule {yara_rule_path}")
        result = yara.compile(filepath=yara_rule_path)
        result.save(compiled_rule_path)
        return result
    else:
        # otherwise we just load the compiled rules
        return yara.load(compiled_rule_path)

def main(args) -> int:
    decision = ALLOW
    if args.default_block:
        decision = BLOCK

    # read standard input a temporary file
    with NamedTemporaryFile() as fp:
        shutil.copyfileobj(sys.stdin.buffer, fp)
        fp.flush()

        # did we specify a yara rule?
        if args.yara_rule_path:
            yara_rules = load_yara_rule(args.yara_rule_path)
            matches = yara_rules.match(fp.name)
            for match in matches:
                for tag in match.tags:
                    if tag == BLOCK:
                        logger.info(f"file {fp.name} matched block rule {match.rule}")
                        decision = BLOCK
                        continue

                    if tag == ALLOW:
                        logger.info(f"file {fp.name} matched allow rule {match.rule}")
                        decision = ALLOW
                        continue

            if decision is None and args.default_block:
                decision = BLOCK
            elif decision is None and not args.default_block:
                decision = ALLOW

            if decision is BLOCK:
                logger.info(f"final decision is to block {fp.name}")
                return os.EX_OK

        # generate a unique key for this upload
        unique_key = str(uuid.uuid4())

        if not args.bucket:
            logger.warning("no bucket specified, skipping upload")
            print(unique_key)
            return os.EX_OK

        if args.use_ec2_metadata:
            s3_credentials = get_ec2_metadata()
        else:
            s3_credentials = get_s3_credentials_from_args(args)

        protocol = "https" if args.secure else "http"
        endpoint_url = f"{protocol}://{args.endpoint}"
        s3_client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=s3_credentials.access_key,
            aws_secret_access_key=s3_credentials.secret_key,
            aws_session_token=s3_credentials.session_token,
            region_name=s3_credentials.region,
            config=BotoConfig(signature_version="s3v4"),
        )

        if args.create_bucket:
            s3_client.create_bucket(Bucket=args.bucket)

        fp.seek(0, os.SEEK_END)
        length = fp.tell()
        fp.seek(0)

        # upload the file to s3
        s3_client.put_object(Bucket=args.bucket, Key=unique_key, Body=fp, ContentLength=length)

        # print the unique key to standard output
        logger.info(f"uploaded file to {unique_key}")

        return os.EX_OK


if __name__ == "__main__":
    global logger

    parser = argparse.ArgumentParser()
    # bucket parameters
    parser.add_argument("--bucket", help="The bucket to upload the file to.")
    parser.add_argument("--create-bucket", action="store_true", default=False, help="Whether to create the bucket if it does not exist.")

    parser.add_argument("--spool-size-mb", type=int, default=1, help="The size of the spooled buffer to use.")
    parser.add_argument("--endpoint", default="garagehq:3900", help="The endpoint of the s3-compatible server. For AWS use s3.amazonaws.com")
    parser.add_argument("--access-key", help="The access key for the s3-compatible server.")
    parser.add_argument("--secret-key", help="The secret key for the s3-compatible server.")
    parser.add_argument("--secure", action="store_true", default=False, help="Whether to use SSL.")
    parser.add_argument("--use-ec2-metadata", action="store_true", default=False, help="Whether to use EC2 metadata to get the access key and secret key.")
    parser.add_argument("--region", help="Optional region to use. If not provided, the region will be inferred.")
    parser.add_argument("--syslog", action="store_true", default=False, help="Whether to use syslog.")
    parser.add_argument("--yara-rule-path", help="The path to a yara rule to use for filtering. By default all content is allowed.")
    parser.add_argument("--compile-only", action="store_true", default=False, help="Only compile the yara rule, do not run it.")
    parser.add_argument("--default-block", action="store_true", default=False, help="Block everything by default, only allow content matching yara rules with 'allow' tags.")
    args = parser.parse_args()

    # Configure logging to syslog
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    if args.syslog and os.path.exists("/dev/log"):
        # Create syslog handler
        handler = logging.handlers.SysLogHandler(address="/dev/log")
        handler.setLevel(logging.INFO)
    else:
        # just log to stdout
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    # are we only compiling the yara rule?
    if args.yara_rule_path and args.compile_only:
        compile_yara_rule(args.yara_rule_path)
        sys.exit(os.EX_OK)

    try:
        sys.exit(main(args))
    except Exception as e:
        logger.error(f"s3 upload failed: {e}")
        sys.exit(1)
