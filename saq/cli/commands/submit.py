import logging
import os
import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.constants import F_FILE
from saq.util.hashing import sha256_file


def submit(args) -> int:
    from ace_api import submit
    observables = []
    files = []

    if len(args.targets) % 2 != 0:
        print("Error: targets must be pairs of indicator types and values.")
        return os.EX_USAGE

    for i in range(0, len(args.targets), 2):
        observable = { 'type': args.targets[i], 'value': args.targets[i + 1] }
        if args.targets[i] == F_FILE:
            files.append((os.path.basename(args.targets[i + 1]), open(args.targets[i + 1], 'rb')))
            observable['file_path'] = os.path.basename(args.targets[i + 1])
            observable['value'] = sha256_file(args.targets[i + 1])

        observables.append(observable)

    description = args.description or "ACE Manual Correlation"
    analysis_mode = args.analysis_mode or "analysis"
    queue = args.queue or "default"

    submit(description=description, analysis_mode=analysis_mode, queue=queue, observables=observables, files=files, remote_host=args.remote_host)
    return os.EX_OK

submit_parser = get_cli_subparsers().add_parser('submit',
    help="Submit a request to ACE for analysis and/or correlation.")
submit_parser.add_argument('-d', '--description', help="The description (title) of the analysis.")
submit_parser.add_argument('-m', '--mode', '--analysis_mode', dest='analysis_mode',
    help='The mode of analysis. Default to "analysis". Set it to "correlation" to automatically become an alert.')
submit_parser.add_argument('--queue', dest='queue',
    help="The queue to assign the alert to (if it becomes an alert.) Defaults to the default queue.")
submit_parser.add_argument("--remote-host", default="ace-http", help="The remote host to submit the analysis to.")
submit_parser.add_argument('targets', nargs="*",
    help="One or more pairs of indicator types and values.")
submit_parser.set_defaults(func=submit)
