#!/usr/bin/python3
# vim: sw=4:ts=4:et

import argparse
import csv
import datetime
import json
import logging
import os.path
import re
import sys
from getpass import getpass

sys.path.append(".")

from splunklib.results import Message

from saq.configuration import initialize_configuration
from saq.splunk import SplunkClient, create_timedelta

parser = argparse.ArgumentParser()
parser.add_argument("search", nargs=argparse.REMAINDER)
parser.add_argument(
    "-v",
    "--verbose",
    required=False,
    action="store_true",
    default=False,
    dest="verbose",
    help="Log verbose messages.  Helps when debugging searches.",
)
parser.add_argument(
    "-q",
    "--quiet",
    required=False,
    action="store_true",
    default=False,
    dest="quiet",
    help="Only log error messages.",
)

parser.add_argument(
    "-U",
    "--uri",
    required=False,
    default=None,
    dest="uri",
    help="The splunk URI to connect to.",
)
parser.add_argument(
    "-u",
    "--user",
    required=False,
    default=None,
    dest="username",
    help="Your splunk username.",
)
parser.add_argument(
    "-p",
    "--password",
    required=False,
    default=False,
    action="store_true",
    dest="password",
    help="Prompt for a password (will not echo.)",
)
parser.add_argument(
    "-m",
    "--max-result-count",
    required=False,
    default=1000,
    type=int,
    dest="max_result_count",
    help="Maximum number of results to return.  Defaults to 1000",
)
parser.add_argument(
    "--proxy", required=False, default=None, dest="proxy", help="Set proxy"
)
parser.add_argument(
    "--user_context",
    required=False,
    default=None,
    dest="user_context",
    help="Set user context",
)
parser.add_argument(
    "--app", required=False, default=None, dest="app", help="Set app context"
)

parser.add_argument(
    "-s",
    "--start-time",
    required=False,
    default=None,
    dest="start_time",
    help="Starting time in YYYY-MM-DD HH:MM:SS format.  Defaults to 24 hours before now.",
)
parser.add_argument(
    "-e",
    "--end-time",
    required=False,
    default=None,
    dest="end_time",
    help="Ending time in YYYY-MM-DD HH:MM:SS format.  Defaults to now.",
)

parser.add_argument(
    "-S",
    "--relative-start-time",
    required=False,
    default=None,
    dest="relative_start_time",
    help="Specify the starting time as a time relative to now in DD:HH:MM:SS format.",
)
parser.add_argument(
    "-E",
    "--relative-end-time",
    required=False,
    default=None,
    dest="relative_end_time",
    help="Specify the ending time as a time relative to now in DD:HH:MM:SS format.",
)
parser.add_argument(
    "--enviro",
    action="store",
    required=False,
    default="default",
    dest="enviro",
    help="Specify which splunk config to use (default=default). Maps to splunk_config_<name> sections in saq.yaml.",
)

# the options only apply in the default csv mode
parser.add_argument(
    "--headers",
    required=False,
    default=False,
    action="store_true",
    dest="headers",
    help="Display headers in CSV output mode.",
)

# json display option
parser.add_argument(
    "--json",
    required=False,
    default=False,
    action="store_true",
    dest="json",
    help="Output in JSON instead of CSV",
)

# redirect to a file
parser.add_argument(
    "-o",
    "--output",
    required=False,
    default=None,
    dest="output",
    help="Send output to a file.  Default is stdout.",
)


parser.add_argument(
    "--search-file",
    required=False,
    default=False,
    action="store",
    dest="search_file",
    help="File containing the search query.",
)

# adding this for use with url_click cloudphish hunt
parser.add_argument(
    "-i",
    "--use-index-time",
    required=False,
    default=None,
    action="store_true",
    dest="use_index_time",
    help="Use __index time specs instead.",
)

parser.add_argument(
    "--query-timeout",
    required=False,
    default=None,
    dest="query_timeout",
    help="Amount of time (in HH:MM:SS format) until a query times out.  Defaults to 30 minutes.",
)

args = parser.parse_args()

logging_level = logging.WARNING
if args.quiet:
    logging_level = logging.ERROR
if args.verbose:
    logging_level = logging.DEBUG
logging.basicConfig(
    format="[%(asctime)s] [%(filename)s:%(lineno)d] [%(threadName)s] [%(levelname)s] - %(message)s",
    level=logging_level,
)

# Initialize ACE configuration
initialize_configuration()

# Build kwargs for command-line overrides
client_kwargs = {}

# Handle URI override (parse host:port)
if args.uri is not None:
    if ":" in args.uri:
        host, port = args.uri.rsplit(":", 1)
        client_kwargs["host"] = host
        client_kwargs["port"] = int(port)
    else:
        client_kwargs["host"] = args.uri

# Handle username/password override
if args.username is not None:
    client_kwargs["username"] = args.username
    if args.password:
        client_kwargs["password"] = getpass("Enter password: ")
    else:
        logging.fatal("--user requires --password")
        sys.exit(1)

# Handle proxy override
if args.proxy is not None:
    client_kwargs["proxies"] = {"http": args.proxy, "https": args.proxy}

# Handle context overrides
if args.user_context is not None:
    client_kwargs["user_context"] = args.user_context
if args.app is not None:
    client_kwargs["app"] = args.app

max_result_count = args.max_result_count

# make sure we have what we need
fatal = False
search_text = None
if args.search_file:
    if os.path.isfile(args.search_file):
        with open(args.search_file, "r") as fp:
            search_text = fp.read()
            # comments in the search files are lines that start with #
            search_text = re.sub(
                r"^\s*#.*$", "", search_text, count=0, flags=re.MULTILINE
            )
            # put it all on one line for splunk
            # we don't *need* to do this except for keeping the logs clean
            search_text = re.sub(r"\n", " ", search_text, count=0)
        args.search = search_text
    else:
        logging.fatal("search file does not exist")
if len(args.search) < 1:
    logging.fatal("missing search")
    fatal = True

if fatal:
    sys.exit(1)

query = None
if args.search_file:
    query = search_text
else:
    query = " ".join(args.search)

# figure out the time range given the options
start_time = None
end_time = None
datetime_format = "%Y-%m-%d %H:%M:%S"

if args.start_time is not None:
    start_time = datetime.datetime.strptime(args.start_time, datetime_format)

if args.end_time is not None:
    end_time = datetime.datetime.strptime(args.end_time, datetime_format)

if args.relative_start_time is not None:
    start_time = datetime.datetime.now() - create_timedelta(args.relative_start_time)
if args.relative_end_time is not None:
    end_time = datetime.datetime.now() - create_timedelta(args.relative_end_time)

if start_time is not None and end_time is None:
    end_time = datetime.datetime.now()

if start_time is None and "earliest" not in query.lower():
    logging.debug("defaulting to past 24 hours")
    start_time = datetime.datetime.now() - create_timedelta("00:24:00:00")
    end_time = datetime.datetime.now()

# Create Splunk client using ACE config with any command-line overrides
try:
    searcher = SplunkClient(args.enviro, **client_kwargs)
except ValueError as e:
    logging.fatal(f"Failed to load Splunk config '{args.enviro}': {e}")
    logging.fatal("Make sure splunk_config_%s is defined in saq.yaml", args.enviro)
    sys.exit(1)

search_result = searcher.query(
    query,
    start=start_time,
    end=end_time,
    limit=max_result_count,
    timeout=args.query_timeout if args.query_timeout else "00:30:00",
    use_index_time=args.use_index_time,
)

output_fp = sys.stdout
if args.output:
    output_fp = open(args.output, "w", encoding="utf-8")

# Print any Splunk messages to stderr
for item in search_result:
    if isinstance(item, Message):
        sys.stderr.write(f"[Splunk {item.type}] {item.message}\n")

# Filter to just the result dictionaries
results = [r for r in search_result if isinstance(r, dict)]

# JSON output
if args.json:
    data = {
        "search": query,
        "enviro": args.enviro,
        "max_result_count": max_result_count,
        "result": results,
    }
    json.dump(data, output_fp)

# CSV output
else:
    writer = csv.writer(output_fp)
    for i, result in enumerate(results):
        if i == 0 and args.headers:
            writer.writerow(list(result.keys()))
        writer.writerow(list(result.values()))
