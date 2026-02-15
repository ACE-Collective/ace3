import os
import shutil
from typing import Optional, Union
import uuid

from celery.result import AsyncResult
from celery.exceptions import TimeoutError

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration.config import get_config

def initialize_phishkit():
    from phishkit.phishkit import app
    rabbitmq_user = get_config().rabbitmq.username
    rabbitmq_password = get_config().rabbitmq.password
    rabbitmq_host = get_config().rabbitmq.host
    app.conf.update({
        "broker_url": f"pyamqp://{rabbitmq_user}:{rabbitmq_password}@{rabbitmq_host}//"
    })

def ping_phishkit() -> str:
    from phishkit.phishkit import ping as pk_ping
    result = pk_ping.delay()
    return result.get(timeout=5)

def _copy_files(source_dir: str, output_dir: str) -> list[str]:
    """Copy all files from source_dir into output_dir, preserving relative paths."""
    os.makedirs(output_dir, exist_ok=True)

    files = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            src_path = os.path.join(root, filename)
            relative_path = os.path.relpath(src_path, start=source_dir)
            dest_path = os.path.join(output_dir, relative_path)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy2(src_path, dest_path)
            files.append(dest_path)

    return files

def scan_file(file_path: str, output_dir: str, is_async: bool = False, timeout: float = 15) -> Union[str, list[str]]:
    from phishkit.phishkit import scan_file as pk_scan_file

    # copy the file to the shared volume so the celery worker can access it
    shared_dir = f"/phishkit/input/{uuid.uuid4()}"
    os.makedirs(shared_dir, exist_ok=True)
    shared_file_path = os.path.join(shared_dir, os.path.basename(file_path))
    shutil.copy2(file_path, shared_file_path)

    # scan the file
    result = pk_scan_file.delay(shared_file_path)

    if is_async:
        return result.id
    else:
        # copy the results from the shared volume
        result_dir = result.get(timeout=timeout)
        return _copy_files(result_dir, output_dir)

def scan_url(url: str, output_dir: str, is_async: bool = False, timeout: float = 15) -> Union[str, list[str]]:
    from phishkit.phishkit import scan_url as pk_scan_url
    result = pk_scan_url.delay(url)

    if is_async:
        return result.id
    else:
        # copy the results from the shared volume
        result_dir = result.get(timeout=timeout)
        return _copy_files(result_dir, output_dir)

def get_async_scan_result(result_id: str, output_dir: str, timeout: float = 1) -> Optional[list[str]]:
    """Gets the result of a scan asynchronously. Returns the list of files if the scan is complete, otherwise None."""
    result = AsyncResult(result_id)
    try:
        result_dir = result.get(timeout=5)
        return _copy_files(result_dir, output_dir)
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

