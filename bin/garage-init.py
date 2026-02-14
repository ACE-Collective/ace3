#!/usr/bin/env python3
#
# initializes the garage s3-compatible storage service
# uses the garage admin HTTP API v2 (port 3903) to configure layout, keys, buckets, and permissions
#

import json
import os
import sys
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# constants
GARAGE_ADMIN_URL = "http://garagehq:3903"
CAPACITY_100GB = 100 * 1024 * 1024 * 1024  # 107374182400
AUTH_DIR = "/auth/passwords"
INIT_MARKER = "/data/.init_done"
BUCKETS = ["ace3", "ace3test", "journal-emails", "ace-email-archive", "ace-email-archive-test"]
TEST_BUCKETS = {"ace3test", "ace-email-archive-test"}


def load_admin_token() -> str:
    """load admin token from environment variable or file"""
    token = os.environ.get("GARAGE_ADMIN_TOKEN")
    if token:
        return token

    token_path = os.path.join(AUTH_DIR, "garagehq-admin-token")
    if os.path.exists(token_path):
        with open(token_path, "r") as fp:
            return fp.read().strip()

    sys.stderr.write("ERROR: unable to load GARAGE_ADMIN_TOKEN from environment or file\n")
    sys.exit(1)


def create_session(admin_token: str) -> requests.Session:
    """create HTTP session with auth and retry logic"""
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    })

    # configure retry logic
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def wait_for_garage_api(session: requests.Session, max_attempts: int = 30, interval: int = 2):
    """wait for garage API to be ready"""
    print("waiting for garage API to be ready...")

    for attempt in range(1, max_attempts + 1):
        try:
            response = session.get(f"{GARAGE_ADMIN_URL}/v2/GetClusterStatus", timeout=5)
            if response.status_code == 200:
                print("garage API is ready")
                return
        except requests.exceptions.RequestException:
            pass

        if attempt == max_attempts:
            sys.stderr.write("ERROR: garage API did not become ready in time\n")
            sys.exit(1)

        print(f"  attempt {attempt}/{max_attempts}...")
        time.sleep(interval)


def configure_cluster_layout(session: requests.Session):
    """configure cluster layout with single node"""
    print("configuring cluster layout...")

    # get node ID
    response = session.get(f"{GARAGE_ADMIN_URL}/v2/GetClusterStatus")
    response.raise_for_status()
    status = response.json()

    if "nodes" not in status or not status["nodes"]:
        sys.stderr.write("ERROR: could not determine node ID from garage status\n")
        sys.stderr.write(f"Full status output:\n{json.dumps(status, indent=2)}\n")
        sys.exit(1)

    node_id = status["nodes"][0]["id"]
    print(f"  node ID: {node_id}")

    # update layout
    layout_update = {
        "roles": [
            {
                "id": node_id,
                "zone": "dc1",
                "capacity": CAPACITY_100GB,
                "tags": []
            }
        ]
    }
    print(f"  layout update JSON: {json.dumps(layout_update)}")

    response = session.post(
        f"{GARAGE_ADMIN_URL}/v2/UpdateClusterLayout",
        json=layout_update
    )
    response.raise_for_status()
    print(f"  update result:\n{json.dumps(response.json(), indent=2)}\n")

    # get layout version
    response = session.get(f"{GARAGE_ADMIN_URL}/v2/GetClusterLayout")
    response.raise_for_status()
    layout = response.json()
    print(f"  layout after update:\n{json.dumps(layout, indent=2)}")

    if "version" not in layout:
        sys.stderr.write("ERROR: could not determine layout version\n")
        sys.exit(1)

    layout_version = layout["version"]
    next_version = layout_version + 1
    print(f"\n  applying layout version {next_version}...")

    response = session.post(
        f"{GARAGE_ADMIN_URL}/v2/ApplyClusterLayout",
        json={"version": next_version}
    )
    response.raise_for_status()
    print(f"{json.dumps(response.json(), indent=2)}\n")


def create_api_key(session: requests.Session, name: str) -> dict:
    """create API key and return access/secret key pair"""
    response = session.post(
        f"{GARAGE_ADMIN_URL}/v2/CreateKey",
        json={"name": name}
    )
    response.raise_for_status()
    result = response.json()

    if "accessKeyId" not in result or "secretAccessKey" not in result:
        sys.stderr.write(f"ERROR: failed to create {name} key\n")
        sys.exit(1)

    return {
        "access_key": result["accessKeyId"],
        "secret_key": result["secretAccessKey"]
    }


def save_credentials(access_key: str, secret_key: str, prefix: str):
    """save credentials to auth directory"""
    os.makedirs(AUTH_DIR, exist_ok=True)

    access_key_path = os.path.join(AUTH_DIR, f"{prefix}-access-key")
    with open(access_key_path, "w") as fp:
        fp.write(access_key)

    secret_key_path = os.path.join(AUTH_DIR, f"{prefix}-secret-key")
    with open(secret_key_path, "w") as fp:
        fp.write(secret_key)


def create_bucket(session: requests.Session, name: str) -> Optional[str]:
    """create bucket and return bucket ID, or None if already exists"""
    try:
        response = session.post(
            f"{GARAGE_ADMIN_URL}/v2/CreateBucket",
            json={"globalAlias": name}
        )
        response.raise_for_status()
        result = response.json()

        if "id" not in result:
            print(f"  WARNING: could not extract bucket ID for {name} -- it may already exist")
            return None

        return result["id"]
    except requests.exceptions.RequestException as e:
        print(f"  WARNING: could not create bucket {name} -- it may already exist: {e}")
        return None


def grant_bucket_permission(session: requests.Session, bucket_id: str, access_key_id: str):
    """grant read/write/owner permissions to bucket"""
    response = session.post(
        f"{GARAGE_ADMIN_URL}/v2/AllowBucketKey",
        json={
            "bucketId": bucket_id,
            "accessKeyId": access_key_id,
            "permissions": {
                "read": True,
                "write": True,
                "owner": True
            }
        }
    )
    response.raise_for_status()


def main():
    """main initialization routine"""
    # check for marker file
    if os.path.exists(INIT_MARKER):
        print("garage already initialized -- skipping initialization")
        return 0

    # load admin token
    admin_token = load_admin_token()

    # create session
    session = create_session(admin_token)

    # wait for API readiness
    wait_for_garage_api(session)

    # configure cluster layout
    configure_cluster_layout(session)

    # create API keys
    print("creating API keys...")
    ace3api_creds = create_api_key(session, "ace3api")
    print(f"  ace3api access key: {ace3api_creds['access_key']}")

    ace3apitest_creds = create_api_key(session, "ace3apitest")
    print(f"  ace3apitest access key: {ace3apitest_creds['access_key']}")

    # save credentials
    save_credentials(ace3api_creds["access_key"], ace3api_creds["secret_key"], "garage")
    save_credentials(ace3apitest_creds["access_key"], ace3apitest_creds["secret_key"], "garage-test")

    # create buckets and grant permissions
    print("creating buckets...")
    for bucket_name in BUCKETS:
        print(f"  creating bucket: {bucket_name}")
        bucket_id = create_bucket(session, bucket_name)

        if bucket_id is None:
            continue

        # grant ace3api access to all buckets
        print(f"    granting ace3api access...")
        grant_bucket_permission(session, bucket_id, ace3api_creds["access_key"])

        # grant ace3apitest access only to test buckets
        if bucket_name in TEST_BUCKETS:
            print(f"    granting ace3apitest access...")
            grant_bucket_permission(session, bucket_id, ace3apitest_creds["access_key"])

    # touch marker file
    print("garage initialization complete")
    with open(INIT_MARKER, "w") as fp:
        fp.write("")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"ERROR: HTTP request failed: {e}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)
