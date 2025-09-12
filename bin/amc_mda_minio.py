#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
import os
import shutil
import sys
from tempfile import SpooledTemporaryFile
from typing import Optional
import uuid

from minio import Minio
import requests

@dataclass
class S3Credentials:
    access_key: str
    secret_key: str
    session_token: Optional[str] = None

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

    return S3Credentials(
        access_key=credentials["AccessKeyId"],
        secret_key=credentials["SecretAccessKey"],
        session_token=credentials["Token"])

def get_s3_credentials_from_args(args) -> S3Credentials:
    """Get the S3 credentials from the arguments."""
    return S3Credentials(
        access_key=args.access_key,
        secret_key=args.secret_key)

def main(args) -> int:
    if args.use_ec2_metadata:
        s3_credentials = get_ec2_metadata()
    else:
        s3_credentials = get_s3_credentials_from_args(args)

    minio_client = Minio(
        endpoint=args.endpoint,
        access_key=s3_credentials.access_key,
        secret_key=s3_credentials.secret_key,
        session_token=s3_credentials.session_token,
        secure=args.secure,
        region=args.region
    )

    if args.create_bucket:
        minio_client.make_bucket(args.bucket)

    # generate a unique key for this upload
    unique_key = str(uuid.uuid4())

    # read standard input into a spooled buffer
    with SpooledTemporaryFile(max_size=args.spool_size_mb * 1024 * 1024) as fp:
        shutil.copyfileobj(sys.stdin.buffer, fp)
        length = fp.tell()
        fp.seek(0)

        # upload the file to minio
        minio_client.put_object(args.bucket, unique_key, fp, length=length)

        # print the unique key to standard output
        print(unique_key)

    return os.EX_OK


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # bucket parameters
    parser.add_argument("--bucket", required=True, help="The bucket to upload the file to.")
    parser.add_argument("--create-bucket", action="store_true", default=False, help="Whether to create the bucket if it does not exist.")

    #parser.add_argument("--key", required=True, help='The key to upload the file to.')
    parser.add_argument("--spool-size-mb", type=int, default=1, help="The size of the spooled buffer to use.")
    parser.add_argument("--endpoint", default="minio:9000", help="The endpoint of the minio server. For AWS use s3.amazonaws.com")
    parser.add_argument("--access-key", help="The access key of the minio server.")
    parser.add_argument("--secret-key", help="The secret key of the minio server.")
    parser.add_argument("--secure", action="store_true", default=False, help="Whether to use SSL.")
    parser.add_argument("--use-ec2-metadata", action="store_true", default=False, help="Whether to use EC2 metadata to get the access key and secret key.")
    parser.add_argument("--region", help="Optional region to use. If not provided, the region will be inferred.")
    args = parser.parse_args()

    sys.exit(main(args))