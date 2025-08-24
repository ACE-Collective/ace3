import os
from typing import Optional, Union
import uuid

from celery.result import AsyncResult
from celery.exceptions import TimeoutError

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration.config import get_config_value
from saq.constants import BUCKET_ACE3, CONFIG_RABBITMQ, CONFIG_RABBITMQ_USER, CONFIG_RABBITMQ_PASSWORD, CONFIG_RABBITMQ_HOST
from saq.storage.factory import get_storage_system

def initialize_phishkit():
    from phishkit.phishkit import app
    rabbitmq_user = get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_USER)
    rabbitmq_password = get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_PASSWORD)
    rabbitmq_host = get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_HOST)
    app.conf.update({
        "broker_url": f"pyamqp://{rabbitmq_user}:{rabbitmq_password}@{rabbitmq_host}//"
    })

def ping_phishkit() -> str:
    from phishkit.phishkit import ping as pk_ping
    result = pk_ping.delay()
    return result.get(timeout=5)

def _download_files(bucket_name: str, prefix: str, output_dir: str) -> list[str]:
    # make sure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # list all the files and download them
    files = []
    for remote_path in get_storage_system().list_objects(BUCKET_ACE3, recursive=True, prefix=prefix):
        local_file_path = os.path.join(output_dir, os.path.relpath(remote_path, start=prefix))
        get_storage_system().download_file(BUCKET_ACE3, remote_path, local_file_path)
        files.append(local_file_path)

    return files

def scan_file(file_path: str, output_dir: str, is_async: bool = False, timeout: float = 15) -> Union[str, list[str]]:
    from phishkit.phishkit import scan_file as pk_scan_file

    # upload the file to storage first
    upload_prefix = f"phishkit/uploads/{uuid.uuid4()}"
    remote_file_path = f"{upload_prefix}/{os.path.basename(file_path)}"
    get_storage_system().upload_file(file_path, BUCKET_ACE3, remote_file_path)

    # scan the file
    result = pk_scan_file.delay(BUCKET_ACE3, remote_file_path)

    if is_async:
        return result.id
    else:
        # download the files
        download_prefix = result.get(timeout=timeout)
        return _download_files(BUCKET_ACE3, download_prefix, output_dir)

def scan_url(url: str, output_dir: str, is_async: bool = False, timeout: float = 15) -> Union[str, list[str]]:
    from phishkit.phishkit import scan_url as pk_scan_url
    result = pk_scan_url.delay(url)

    if is_async:
        return result.id
    else:
        # download the files
        prefix = result.get(timeout=timeout)
        return _download_files(BUCKET_ACE3, prefix, output_dir)

def get_async_scan_result(result_id: str, output_dir: str, timeout: float = 1) -> Optional[list[str]]:
    """Gets the result of a scan asynchronously. Returns the list of files if the scan is complete, otherwise None."""
    result = AsyncResult(result_id)
    try:
        prefix = result.get(timeout=5)
        return _download_files(BUCKET_ACE3, prefix, output_dir)
    except TimeoutError:
        return None


#
# cli
#


phishkit_parser = get_cli_subparsers().add_parser("phishkit", help="Submit URLs to phishkit for analysis.")
phishkit_sp = phishkit_parser.add_subparsers(dest="phishkit_cmd")

def cli_ping_phishkit(args) -> int:
    print(ping_phishkit())
    return os.EX_OK

phishkit_ping_parser = phishkit_sp.add_parser("ping", help="Ping the phishkit service.")
phishkit_ping_parser.set_defaults(func=cli_ping_phishkit)

def cli_scan(args) -> int:
    from urllib.parse import urlparse

    try:
        parsed_url = urlparse(args.target)
        # if the URL has a scheme, use the URL scanner, otherwise use the file scanner
        target_function = scan_file if not parsed_url.scheme else scan_url
    except ValueError:
        # if we can't parse the URL, assume it's a file
        target_function = scan_file

    if args.use_async:
        # are we asking for the results of a previous request?
        if args.id:
            scan_results = get_async_scan_result(args.id, args.output_dir, timeout=args.timeout)
            if scan_results is None:
                print("result not ready yet")
                return os.EX_OK
        else:
            # otherwse we start a new request and return the ID to the user
            result_id = target_function(args.target, args.output_dir, is_async=True)
            print(f"Scan started. ID: {result_id}")
            return os.EX_OK
    else:
        # if we're not using async, then we just run the scan and return the results
        scan_results = target_function(args.target, args.output_dir)

    # if we get this far then we have the results
    for file_path in scan_results:
        print(file_path)

    return os.EX_OK

phishkit_scan_parser = phishkit_sp.add_parser("scan", help="Scan a URL or file with phishkit.")
phishkit_scan_parser.add_argument("target", help="The thing to scan. By default, thing is interpreted as a URL.")
phishkit_scan_parser.add_argument("output_dir", help="The directory to save the output.")
phishkit_scan_parser.add_argument("--timeout", type=float, default=15, help="The timeout for the scan.")
phishkit_scan_parser.add_argument("--async", dest="use_async", action="store_true", help="Scan asynchronously. Returns the request ID instead of the list of files.")
phishkit_scan_parser.add_argument("--id", help="The ID of the scan to get the result of.")
phishkit_scan_parser.set_defaults(func=cli_scan)

