"""``ace yara`` -- talk to the running yara scanner service (docs/YARA_SCANNER.md).

``scan`` sends each file's path to the service the way the engine does, and the worker reads
the file there, which makes it the quickest way to check that the service is up and serving
the rules you expect. To test rules without the service,
use the ``scan`` command of the yara_scanner library instead.
"""

import json
import sys

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.yara_scanning imports below are inside their command functions on purpose, matching
# the convention in this package (see yara_qa.py): this module is imported on every `ace`
# invocation just to register its parsers.

yara_parser = get_cli_subparsers().add_parser("yara", help="The yara scanner service (docs/YARA_SCANNER.md).")
yara_sp = yara_parser.add_subparsers(dest="yara_cmd")


def cli_scan(args):
    """Scan files with the running yara scanner service."""
    from saq.yara_scanning import client
    from saq.yara_scanning.protocol import encode_matches

    paths = list(args.files)
    if args.from_stdin:
        paths.extend(line.strip() for line in sys.stdin if line.strip())

    exit_code = 0
    for path in paths:
        try:
            matches = client.scan_file(path, meta_tags=args.meta_tags)
        except Exception as e:
            print(f"{path}: {type(e).__name__}: {e}", file=sys.stderr)
            exit_code = 1
            continue

        if args.json:
            # matched string data is binary, so it is printed base64 encoded
            print(json.dumps({"path": path, "matches": encode_matches(matches)}, indent=2, sort_keys=True))
            continue

        if not matches:
            print(f"{path}: no matches")
            continue

        print(f"{path}: {len(matches)} rule matches")
        for match in matches:
            print(f"\t{match['rule']} ({match['commit']})" if match.get("commit") else f"\t{match['rule']}")

    return exit_code


scan_parser = yara_sp.add_parser("scan", help="Scan files with the running yara scanner service.")
scan_parser.add_argument("files", nargs="*", help="The files to scan.")
scan_parser.add_argument("--from-stdin", action="store_true", default=False, help="Also read the paths to scan from stdin, one per line.")
scan_parser.add_argument("--meta-tags", nargs="+", default=None, help="Tags describing the scan target, for rules that filter on meta_tags.")
scan_parser.add_argument("-j", "--json", action="store_true", default=False, help="Print the full matches as JSON.")
scan_parser.set_defaults(func=cli_scan)
