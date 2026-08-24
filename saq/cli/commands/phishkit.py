import os

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration.config import get_config
from saq.phishkit import get_async_scan_result, maintain_files, ping_phishkit, scan_file, scan_url


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

    proxy = getattr(args, 'proxy', None)

    if args.use_async:
        # are we asking for the results of a previous request?
        if args.id:
            scan_results = get_async_scan_result(args.id, args.output_dir, timeout=args.timeout)
            if scan_results is None:
                print("result not ready yet")
                return os.EX_OK
        else:
            # otherwse we start a new request and return the ID to the user
            result_id = target_function(args.target, args.output_dir, is_async=True, proxy=proxy)
            print(f"Scan started. ID: {result_id}")
            return os.EX_OK
    else:
        # if we're not using async, then we just run the scan and return the results
        scan_results = target_function(args.target, args.output_dir, proxy=proxy)

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
phishkit_scan_parser.add_argument("--proxy", default=None, help="Proxy string to pass to phishkit scanner (e.g. host:port or user:pass@host:port).")
phishkit_scan_parser.set_defaults(func=cli_scan)

def cli_maintain_files(args) -> int:
    max_file_age_days = args.max_file_age_days
    if max_file_age_days is None:
        max_file_age_days = get_config().phishkit.max_file_age_days
    result = maintain_files(max_file_age_days)
    print(result)
    return os.EX_OK

phishkit_maintain_parser = phishkit_sp.add_parser("maintain-files", help="Delete phishkit input/output files older than the configured age.")
phishkit_maintain_parser.add_argument("--max-file-age-days", type=int, default=None,
    help="Delete phishkit input/output directories older than this many days (default: phishkit.max_file_age_days from config).")
phishkit_maintain_parser.set_defaults(func=cli_maintain_files)
