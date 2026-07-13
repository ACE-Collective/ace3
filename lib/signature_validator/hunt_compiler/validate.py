#!/usr/bin/env python3

import argparse
from datetime import datetime, timedelta, timezone, tzinfo
import getpass
import glob
import json
import os
import re
import sys
import traceback
from typing import Optional
import urllib3
import warnings
from zoneinfo import ZoneInfo

import requests
import yaml

try:
    from requests_pkcs12 import post as pkcs12_post
    PKCS12_AVAILABLE = True
except ImportError:
    PKCS12_AVAILABLE = False

from hunt_compiler import compile_hunt

warnings.simplefilter("ignore", urllib3.exceptions.SecurityWarning)

# Matches DD:HH:MM:SS, HH:MM:SS, MM:SS, or S — same shape used by saq/util/time.py
# and accepted by the hunt config's `time_range`/`time_ranges.*.duration_before` fields.
_RE_DURATION = re.compile(r'^(\d+:)?(\d+:)?(\d+:)?\d+$')


def _parse_duration(timespec: str) -> timedelta:
    """Parse [D:][H:][M:]S into a timedelta. Mirrors saq.util.time.create_timedelta."""
    if not _RE_DURATION.match(timespec):
        raise ValueError(
            f"invalid duration {timespec!r}; expected [D:][H:][M:]S (e.g. 00:10:00 or 30)"
        )
    parts = timespec.split(':')
    seconds = int(parts[-1])
    minutes = int(parts[-2]) if len(parts) > 1 else 0
    hours = int(parts[-3]) if len(parts) > 2 else 0
    days = int(parts[-4]) if len(parts) > 3 else 0
    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def _parse_time_range_override(value: str) -> tuple[str, str]:
    """Parse a `--time-range NAME=DURATION` argument into (name, duration_str)."""
    if '=' not in value:
        raise argparse.ArgumentTypeError(
            f"--time-range must be NAME=DURATION (got {value!r})"
        )
    name, _, duration = value.partition('=')
    name = name.strip()
    duration = duration.strip()
    if not name or not duration:
        raise argparse.ArgumentTypeError(
            f"--time-range must be NAME=DURATION (got {value!r})"
        )
    try:
        _parse_duration(duration)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e
    return name, duration


def _read_hunt_durations(file_path: str) -> dict[str, str]:
    """Read `rule.time_ranges` (and the legacy `rule.time_range`) from a hunt YAML.

    Returns a dict of {token_name: duration_str}. The single `time_range` is mapped
    to the TIMESPEC token. Returns an empty dict if neither field is present.
    """
    with open(file_path, 'r') as fp:
        parsed = yaml.safe_load(fp)
    if not isinstance(parsed, dict):
        return {}
    rule = parsed.get('rule')
    if not isinstance(rule, dict):
        return {}

    durations: dict[str, str] = {}
    time_ranges = rule.get('time_ranges')
    if isinstance(time_ranges, dict):
        for name, value in time_ranges.items():
            if isinstance(value, str):
                durations[name] = value
            elif isinstance(value, dict) and isinstance(value.get('duration_before'), str):
                durations[name] = value['duration_before']

    legacy = rule.get('time_range')
    if isinstance(legacy, str) and 'TIMESPEC' not in durations:
        durations['TIMESPEC'] = legacy

    return durations


def _synthesize_start_time(
    file_path: str,
    end_time_str: str,
    overrides: dict[str, str],
    tz: tzinfo,
) -> str:
    """Compute a `--start-time` from the hunt's time ranges + CLI overrides.

    The synthesized start_time spans the widest configured/overridden duration so the
    server's existing required-fields check passes. Per-token windows are still
    derived from time_ranges/overrides at execution time.
    """
    yaml_durations = _read_hunt_durations(file_path)
    merged = {**yaml_durations, **overrides}
    if not merged:
        raise ValueError(
            f"hunt {file_path} has no `time_range` or `time_ranges` and no --time-range "
            "overrides were provided; cannot synthesize a start_time. Pass -s explicitly."
        )
    widest = max(_parse_duration(d) for d in merged.values())
    end_dt = datetime.strptime(end_time_str, "%m/%d/%Y:%H:%M:%S").replace(tzinfo=tz)
    start_dt = end_dt - widest
    return start_dt.strftime("%m/%d/%Y:%H:%M:%S")


def parse_args():
    parser = argparse.ArgumentParser(description="Validate a hunt")
    parser.add_argument(
        "file_paths", type=str, nargs="*",
        help="the hunt YAML file(s) to validate (required unless --signature-dir is used)"
    )
    parser.add_argument(
        "--signature-dir",
        type=str,
        default=None,
        help="Directory to scan for *.yaml hunt files (excluding template.yaml). "
             "Mutually exclusive with positional file paths.",
    )
    parser.add_argument(
        "-r",
        "--remote-host",
        type=str,
        help="The remote host to connect to",
        default=os.environ.get("ACE_API_HOST", "aceatu.com:443"),
    )
    parser.add_argument(
        "-u",
        "--ui-host",
        type=str,
        help="The UI host to link to",
        default=os.environ.get("ACE_UI_HOST", "aceatu.com:443"),
    )
    parser.add_argument(
        "-k",
        "--api-key",
        type=str,
        help="The api key to use",
        default=os.environ.get("ACE_API_KEY", None),
    )
    parser.add_argument(
        "-V",
        "--disable-ssl-verification",
        action="store_true",
        help="Whether to disable the ssl certificate verification",
        default=False,
    )
    parser.add_argument(
        "--ca-bundle",
        type=str,
        help="Path to a custom root CA bundle file for SSL certificate verification",
        default=os.environ.get("ACE_CA_BUNDLE", None),
    )
    parser.add_argument(
        "--client-cert",
        type=str,
        help="Path to a client SSL certificate file (can be combined cert+key or specify --client-key separately)",
        default=os.environ.get("ACE_CLIENT_CERT", None),
    )
    parser.add_argument(
        "--client-key",
        type=str,
        help="Path to a client SSL certificate key file (required if --client-cert is not a combined file)",
        default=os.environ.get("ACE_CLIENT_KEY", None),
    )
    parser.add_argument(
        "--client-p12",
        type=str,
        help="Path to a PKCS#12 (.p12/.pfx) client certificate file (alternative to --client-cert)",
        default=os.environ.get("ACE_CLIENT_P12", None),
    )
    parser.add_argument(
        "--client-p12-password",
        type=str,
        help="Password for the PKCS#12 file (can also be set via ACE_CLIENT_P12_PASSWORD env var)",
        default=os.environ.get("ACE_CLIENT_P12_PASSWORD", None),
    )

    parser.add_argument(
        "-s",
        "--start-time",
        type=str,
        help="The start time to use for the hunt in MM/DD/YYYY:HH:MM:SS format",
    )
    parser.add_argument(
        "-e",
        "--end-time",
        type=str,
        help="The end time to use for the hunt in MM/DD/YYYY:HH:MM:SS format",
    )
    parser.add_argument(
        "-z",
        "--timezone",
        type=str,
        help="The timezone to use for the hunt specified by tz database (IANA) time zone identifier. If not specified, UTC is assumed.",
    )
    parser.add_argument(
        "--time-range",
        dest="time_range_overrides",
        action="append",
        type=_parse_time_range_override,
        metavar="NAME=DURATION",
        help="Override a hunt's TIMESPEC duration_before for one token. Repeatable. "
             "DURATION uses [D:][H:][M:]S format (e.g. --time-range TIMESPEC=00:10:00). "
             "When -s/--start-time is omitted, it is synthesized from the widest of the "
             "merged YAML defaults and these overrides.",
    )
    parser.add_argument(
        "--analyze-results",
        action="store_true",
        help="Submit any results to the ACE instance for analysis. This is implied if -a is specified.",
    )
    parser.add_argument(
        "-a",
        "--alert",
        action="store_true",
        help="Submit any results to the ACE instance as alerts.",
    )
    parser.add_argument(
        "-q",
        "--queue",
        type=str,
        help="The queue to use for the hunt. If not specified, defaults to the current user name.",
        default=getpass.getuser(),
    )
    parser.add_argument(
        "--print-results", action="store_true", help="Print the raw query results."
    )
    parser.add_argument(
        "--print-logs", action="store_true", help="Print the execution logs."
    )
    parser.add_argument(
        "--print-trace",
        action="store_true",
        help="Print the correlation trace data when present in results.",
    )
    parser.add_argument(
        "--print-original-results",
        action="store_true",
        help="Print the original (pre-correlation) query results returned in the response.",
    )
    parser.add_argument(
        "-sq",
        "--save-original-results",
        type=str,
        metavar="FILE",
        help="Save the original (pre-correlation) query results from the response to the given JSON file.",
    )
    parser.add_argument(
        "-lq",
        "--query-results-file",
        type=str,
        metavar="FILE",
        help="Path to a JSON file containing a list of event dicts. When set, the API skips "
             "the data-source query and feeds these events directly into the hunt's correlation logic. "
             "Use this to iterate on correlate: YAML against a previously captured event list.",
    )
    parser.add_argument(
        "-sc",
        "--save-correlate-results",
        type=str,
        metavar="FILE",
        help="Save the correlate (follow-up) query results from the response to the given JSON file.",
    )
    parser.add_argument(
        "-lc",
        "--correlate-results-file",
        type=str,
        metavar="FILE",
        help="Path to a JSON file of saved correlate query results (from --save-correlate-results). "
             "When set, the correlation engine replays matching follow-up queries instead of re-running "
             "them; queries not present are run live. Use this to iterate on summary_details / correlate "
             "logic without re-querying the data source.",
    )
    parser.add_argument(
        "-o", "--output-file", help="Save the raw JSON to the given file."
    )
    parser.add_argument(
        "--package-root",
        type=str,
        help="The directory that anchors all embedded hunt file paths. When omitted, "
             "the compiler walks upward from the hunt file looking for a .hunt-root marker.",
        default=os.environ.get("ACE_HUNT_PACKAGE_ROOT", None),
    )
    rel_group = parser.add_argument_group(
        "Relative time window (mutually exclusive with -s/-e)"
    )
    rel_group.add_argument(
        "-H",
        "--hours",
        type=int,
        default=0,
        help="Look back N hours (e.g., -H 12 or --hours 12)",
    )
    rel_group.add_argument(
        "-D",
        "--days",
        type=int,
        default=0,
        help="Look back N days (e.g., -D 3 or --days 3)",
    )
    rel_group.add_argument(
        "-S",
        "--seconds",
        type=int,
        default=0,
        help="Look back N seconds (e.g., -S 30 or --seconds 30)",
    )
    rel_group.add_argument(
        "-M",
        "--minutes",
        type=int,
        default=0,
        help="Look back N minutes (e.g., -M 5 or --minutes 5)",
    )

    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.signature_dir and args.file_paths:
        raise ValueError(
            "Cannot specify both positional hunt files and --signature-dir. Use one or the other."
        )

    if not args.signature_dir and not args.file_paths:
        raise ValueError(
            "At least one hunt YAML file is required, or use --signature-dir to scan a directory."
        )

    if args.signature_dir and not os.path.isdir(args.signature_dir):
        raise ValueError(f"--signature-dir path is not a directory: {args.signature_dir}")

    if args.api_key is None:
        raise ValueError(
            "The API key is not set! Please set the ACE_API_KEY environment variable."
        )

    # Validate that PEM and p12 options are not both specified
    if args.client_cert and args.client_p12:
        raise ValueError(
            "Cannot specify both --client-cert and --client-p12. Use one or the other."
        )

    if args.client_p12 and not PKCS12_AVAILABLE:
        raise ValueError(
            "requests-pkcs12 library is not installed. Install it with: pip install requests-pkcs12"
        )

    # When using --query-results-file the API skips the data-source query, so time
    # arguments are not needed (and relative-time flags would be misleading).
    if args.query_results_file:
        if not os.path.isfile(args.query_results_file):
            raise ValueError(f"--query-results-file path does not exist: {args.query_results_file}")
        try:
            with open(args.query_results_file, "r") as fp:
                loaded = json.load(fp)
        except json.JSONDecodeError as e:
            raise ValueError(f"--query-results-file is not valid JSON: {e}") from e
        if not isinstance(loaded, list):
            raise ValueError(
                f"--query-results-file must contain a JSON list of event objects, got {type(loaded).__name__}"
            )

    # --correlate-results-file replays saved follow-up queries; validate it up front.
    if args.correlate_results_file:
        if not os.path.isfile(args.correlate_results_file):
            raise ValueError(f"--correlate-results-file path does not exist: {args.correlate_results_file}")
        try:
            with open(args.correlate_results_file, "r") as fp:
                loaded = json.load(fp)
        except json.JSONDecodeError as e:
            raise ValueError(f"--correlate-results-file is not valid JSON: {e}") from e
        if not isinstance(loaded, dict) or not isinstance(loaded.get("queries"), list):
            raise ValueError(
                "--correlate-results-file must be a JSON object with a 'queries' list "
                "(as produced by --save-correlate-results)"
            )

    # `-s` is optional now, but `-e` without `-s` is only valid for query hunts where we can
    # synthesize start_time from time_ranges. `-s` without `-e` is never useful — reject it.
    if args.start_time and not args.end_time:
        raise ValueError("--start-time requires --end-time (or use --hours/--days).")

    rel_any = (
        (args.seconds and args.seconds > 0)
        or (args.minutes and args.minutes > 0)
        or (args.hours and args.hours > 0)
        or (args.days and args.days > 0)
    )

    # Disallow mixing absolute and relative
    if rel_any and (args.start_time or args.end_time):
        raise ValueError(
            "Specify either absolute times (-s/-e) OR relative (-S/--seconds, -M/--minutes, -H/--hours, -D/--days), not both."
        )

    # Non-negative relative inputs
    if args.seconds is not None and args.seconds < 0:
        raise ValueError("--seconds must be >= 0")
    if args.minutes is not None and args.minutes < 0:
        raise ValueError("--minutes must be >= 0")
    if args.hours is not None and args.hours < 0:
        raise ValueError("--hours must be >= 0")
    if args.days is not None and args.days < 0:
        raise ValueError("--days must be >= 0")

    # Validate timezone (if provided)
    if args.timezone:
        try:
            ZoneInfo(args.timezone)  # ensure it's a valid IANA TZ
        except Exception as e:
            raise ValueError(
                f"Invalid timezone '{args.timezone}'. Use an IANA zone like 'UTC' or 'America/Chicago'."
            ) from e

    date_fmt = "%m/%d/%Y:%H:%M:%S"
    if args.end_time is not None:
        try:
            end_dt = datetime.strptime(args.end_time, date_fmt)
        except ValueError as e:
            raise ValueError(
                "End time must be in MM/DD/YYYY:HH:MM:SS format. %s" % e
            ) from e
        if args.start_time is not None:
            try:
                start_dt = datetime.strptime(args.start_time, date_fmt)
            except ValueError as e:
                raise ValueError(
                    "Start time must be in MM/DD/YYYY:HH:MM:SS format. %s" % e
                ) from e
            if end_dt <= start_dt:
                raise ValueError(
                    "End time must be after start time (got start=%s, end=%s)"
                    % (args.start_time, args.end_time)
                )


def validate_hunt(
    file_path: str,
    remote_host: str,
    api_key: str,
    disable_ssl_verification: bool = False,
    ca_bundle: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    client_p12: Optional[str] = None,
    client_p12_password: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    timezone: Optional[str] = None,
    analyze_results: bool = False,
    create_alerts: bool = False,
    queue: Optional[str] = None,
    query_results: Optional[list] = None,
    package_root: Optional[str] = None,
    time_range_overrides: Optional[dict[str, str]] = None,
    correlate_results: Optional[dict] = None,
) -> bool:
    compiled = compile_hunt(file_path, package_root=package_root)

    json_data = {
        "compiled_hunt": compiled.model_dump(),
    }

    if (start_time is not None and end_time is not None) or query_results is not None:
        execution_arguments = {
            "analyze_results": analyze_results,
            "create_alerts": create_alerts,
            "queue": queue,
        }
        if start_time is not None and end_time is not None:
            execution_arguments["start_time"] = start_time
            execution_arguments["end_time"] = end_time
            execution_arguments["timezone"] = timezone
        if query_results is not None:
            execution_arguments["query_results"] = query_results
        if time_range_overrides:
            execution_arguments["time_range_overrides"] = time_range_overrides
        if correlate_results is not None:
            execution_arguments["correlate_results"] = correlate_results
        json_data["execution_arguments"] = execution_arguments

    # Configure SSL verification
    if disable_ssl_verification:
        verify_setting = False
    elif ca_bundle:
        verify_setting = ca_bundle
    else:
        verify_setting = True

    # Make the request - use requests_pkcs12 if p12 file is provided, otherwise use regular requests
    if client_p12:
        # Use requests_pkcs12 for PKCS#12 files
        response = pkcs12_post(
            "https://{}/api/hunt/validate".format(remote_host),
            json=json_data,
            headers={"x-ace-auth": api_key},
            verify=verify_setting,
            pkcs12_filename=client_p12,
            pkcs12_password=client_p12_password,
        )
    else:
        # Use regular requests for PEM certificates
        cert_setting = None
        if client_cert:
            if client_key:
                cert_setting = (client_cert, client_key)
            else:
                cert_setting = client_cert

        response = requests.post(
            "https://{}/api/hunt/validate".format(remote_host),
            json=json_data,
            headers={"x-ace-auth": api_key},
            verify=verify_setting,
            cert=cert_setting,
        )

    try:
        response.raise_for_status()
    except requests.exceptions.RequestException:
        if response.status_code == 400:
            return response.json()

        raise

    return response.json()


def _format_expression(expr: dict, lines: list, indent: int = 6):
    """Recursively format an expression trace for display."""
    prefix = " " * indent
    etype = expr["expression_type"]
    result = expr["result"]
    result_color = "\033[92m" if result else "\033[91m"

    if etype in ("and", "or", "not"):
        lines.append(f"{prefix}{etype.upper()} -> {result_color}{result}\033[0m")
        for sub in expr.get("sub_expressions") or []:
            _format_expression(sub, lines, indent + 2)
    elif etype == "jinja":
        rendered = expr.get("rendered_value", "")
        lines.append(f"{prefix}jinja -> {result_color}{result}\033[0m (rendered: {rendered})")
    else:
        # equals, glob, regex
        prop_name = expr.get("property_name", "")
        prop_value = expr.get("property_value", "")
        compare_value = expr.get("compare_value", "")
        lines.append(
            f"{prefix}{etype}: {prop_name} = {prop_value} vs {compare_value} -> {result_color}{result}\033[0m"
        )

    if expr.get("error"):
        lines.append(f"{prefix}\033[91merror: {expr['error']}\033[0m")


def _format_step(step: dict, lines: list, indent: int = 4):
    """Format a single step trace for display."""
    prefix = " " * indent
    desc = step.get("description", "")
    desc_suffix = f"  # {desc}" if desc else ""
    inner = step["step"]
    trace_type = inner["trace_type"]

    if trace_type == "condition":
        result = inner["expression"]["result"]
        result_color = "\033[92m" if result else "\033[91m"
        branch = inner["branch_taken"]
        lines.append(f"{prefix}WHEN ({result_color}{result}\033[0m) -> {branch}{desc_suffix}")
        _format_expression(inner["expression"], lines, indent + 4)
        if inner.get("error"):
            lines.append(f"{prefix}  \033[91merror: {inner['error']}\033[0m")
        for sub_step in inner.get("branch_steps", []):
            _format_step(sub_step, lines, indent + 4)

    elif trace_type == "transform":
        method_info = f"{inner['transform_type']}.{inner['method']} ({inner['command_type']})"
        lines.append(f"{prefix}TRANSFORM {method_info}{desc_suffix}")
        if inner.get("rendered_command"):
            lines.append(f"{prefix}  cmd: {inner['rendered_command']}")
        if inner.get("property_name"):
            lines.append(f"{prefix}  -> {inner['property_name']} = {inner.get('property_value', '')}")
        if inner.get("result_count") is not None:
            lines.append(f"{prefix}  results: {inner['result_count']}")
        if inner.get("error"):
            lines.append(f"{prefix}  \033[91merror: {inner['error']}\033[0m")

    elif trace_type == "action":
        interrupt = " [INTERRUPT]" if inner.get("is_interrupt") else ""
        lines.append(f"{prefix}ACTION {inner['action_type']}{interrupt}{desc_suffix}")
        if inner.get("rendered_log_message"):
            lines.append(f"{prefix}  msg: {inner['rendered_log_message']}")
        if inner.get("error"):
            lines.append(f"{prefix}  \033[91merror: {inner['error']}\033[0m")


def format_correlation_trace(trace_data: dict) -> str:
    """Format a correlation trace dict for console display."""
    lines = []

    # Stream events
    stream_events = trace_data.get("stream_events", [])
    if stream_events:
        lines.append("  Stream Events:")
        for se in stream_events:
            detail = f" - {se['detail']}" if se.get("detail") else ""
            idx = f" (at event {se['at_event_index']})" if se.get("at_event_index") is not None else ""
            lines.append(f"    [{se['event_type']}]{idx}{detail}")
        lines.append("")

    # Event traces
    event_traces = trace_data.get("event_traces", [])
    for et in event_traces:
        outcome = et["outcome"]
        if outcome == "alert":
            outcome_color = "\033[92m"
        elif outcome == "error":
            outcome_color = "\033[91m"
        else:
            outcome_color = "\033[93m"
        lines.append(f"  Event {et['event_index']}: {outcome_color}{outcome}\033[0m")
        for step in et.get("steps", []):
            _format_step(step, lines, indent=4)
        lines.append("")

    return "\n".join(lines)


def main():
    args = parse_args()
    validate_args(args)

    # Collapse the repeatable --time-range list into a {token: duration_str} dict.
    # Later occurrences win — argparse appends in order.
    time_range_overrides: dict[str, str] = {}
    for name, duration in args.time_range_overrides or []:
        time_range_overrides[name] = duration

    # Translate relative (-S/-M/-H/-D) into absolute times expected by the API ---
    if (
        (args.seconds and args.seconds > 0)
        or (args.minutes and args.minutes > 0)
        or (args.hours and args.hours > 0)
        or (args.days and args.days > 0)
    ):
        tz = ZoneInfo(args.timezone) if args.timezone else timezone.utc
        now = datetime.now(tz)
        delta = timedelta(seconds=args.seconds or 0, minutes=args.minutes or 0, hours=args.hours or 0, days=args.days or 0)
        if delta <= timedelta(0):
            raise ValueError("Specify a positive relative window using --seconds, --minutes, --hours, and/or --days.")
        date_fmt = "%m/%d/%Y:%H:%M:%S"
        args.start_time = (now - delta).strftime(date_fmt)
        args.end_time = now.strftime(date_fmt)

    # resolve input files
    if args.signature_dir:
        pattern = os.path.join(args.signature_dir, "*.yaml")
        file_paths = sorted(
            f for f in glob.glob(pattern) if os.path.basename(f) != "template.yaml"
        )
        if not file_paths:
            print(f"\033[1;91mno YAML files found in {args.signature_dir}\033[0m")
            sys.exit(1)
    else:
        file_paths = args.file_paths

    multiple_files = len(file_paths) > 1
    has_failures = False

    # Load query results override once (validate_args has already verified it parses).
    query_results_override = None
    if args.query_results_file:
        with open(args.query_results_file, "r") as fp:
            query_results_override = json.load(fp)

    # Load saved correlate query results for replay (validated in validate_args).
    correlate_results_override = None
    if args.correlate_results_file:
        with open(args.correlate_results_file, "r") as fp:
            correlate_results_override = json.load(fp)

    for file_path in file_paths:
        try:
            # When -e is supplied without -s, synthesize a start_time spanning the widest
            # of the merged YAML defaults + CLI overrides, so the API's required-fields
            # check still passes. Per-token windows are derived server-side at execution.
            effective_start_time = args.start_time
            if args.end_time and not args.start_time and query_results_override is None:
                tz = ZoneInfo(args.timezone) if args.timezone else timezone.utc
                effective_start_time = _synthesize_start_time(
                    file_path, args.end_time, time_range_overrides, tz,
                )

            result = validate_hunt(
                file_path,
                args.remote_host,
                args.api_key,
                args.disable_ssl_verification,
                args.ca_bundle,
                args.client_cert,
                args.client_key,
                args.client_p12,
                args.client_p12_password,
                effective_start_time,
                args.end_time,
                args.timezone,
                args.analyze_results,
                args.alert,
                args.queue,
                query_results_override,
                args.package_root,
                time_range_overrides or None,
                correlate_results_override,
            )
        except Exception:
            has_failures = True
            if multiple_files:
                print(f"\033[1;91m{file_path}: ERROR\033[0m")
                for line in traceback.format_exc().splitlines():
                    print(f"  {line}")
            else:
                traceback.print_exc()
            continue

        if args.output_file:
            with open(args.output_file, "w") as fp:
                json.dump(result, fp, indent=4, sort_keys=True)

        if not result["valid"]:
            error_message = result.get("error", "Unknown error")
            has_failures = True
            if multiple_files:
                print(f"\033[1;91m{file_path}: ERROR\033[0m")
                for line in error_message.splitlines():
                    print(f"  \033[1;91m{line}\033[0m")
            else:
                print()
                print(f"\033[1;91m{error_message}\033[0m")
                print()
            continue

        executing_hunt = (
            (effective_start_time is not None and args.end_time is not None)
            or query_results_override is not None
        )

        # if we did not execute the hunt then we just checked validation
        if not executing_hunt:
            if multiple_files:
                print(f"\033[92m{file_path}: OK\033[0m")
            else:
                print("\033[92mOK: hunt is valid\033[0m")
            continue

        # Original query results: the server snapshots the raw query results before any
        # processing and exposes them at the top level for every hunt (correlate or not),
        # present even when correlation filters out every event.
        if args.save_original_results:
            original = result.get("original_events") or []
            if not original:
                print("\033[93mNo events in response to save\033[0m")
            else:
                with open(args.save_original_results, "w") as fp:
                    json.dump(original, fp, indent=4, sort_keys=True)
                print(
                    f"\033[92msaved {len(original)} original events to {args.save_original_results}\033[0m"
                )

        # Correlate (follow-up) query results ride the top level of the response so they
        # can be saved for offline replay even when correlation filtered out every event.
        if args.save_correlate_results:
            correlate = result.get("correlate_results")
            if not correlate or not correlate.get("queries"):
                print("\033[93mNo correlate results in response (hunt may not run correlate queries)\033[0m")
            else:
                with open(args.save_correlate_results, "w") as fp:
                    json.dump(correlate, fp, indent=4, sort_keys=True)
                print(
                    f"\033[92msaved {len(correlate['queries'])} correlate query results to {args.save_correlate_results}\033[0m"
                )

        if args.print_original_results:
            original = result.get("original_events") or []
            if not original:
                print("\033[93mNo events in response to print\033[0m")
            else:
                print()
                print("\033[1;96mOriginal Query Results:\033[0m")
                for event in original:
                    print(json.dumps(event, indent=4, sort_keys=True))
                print()

        # The correlation trace is returned at the top level of the response so it is
        # available even when every event was filtered out (i.e. roots is empty).
        if args.print_trace:
            correlation_trace = result.get("correlation_trace")
            if correlation_trace:
                print()
                print("\033[1;96mCorrelation Trace:\033[0m")
                print(format_correlation_trace(correlation_trace))
            else:
                print()
                print("\033[93mNo correlation trace data in results (hunt may not have a correlate block).\033[0m")

        # if we are executing the hunt then we need to print the results
        for root in result["roots"]:
            if args.alert:
                print(
                    f"{root['description']}: https://{args.ui_host}/ace/analysis?direct={root['uuid']}"
                )
            else:
                print()
                print(f"\033[1;94m{root['description']}\033[0m")
                print()
                for _, observable in root["observable_store"].items():
                    output_type = observable["type"]
                    if "display_type" in observable and observable["display_type"]:
                        output_type = f"{observable['display_type']} ({observable['type']})"

                    output_value = observable["value"]
                    if "display_value" in observable and observable["display_value"]:
                        output_value = observable["display_value"]

                    output = f"  (*) {output_type} - {output_value}"
                    if "time" in observable and observable["time"]:
                        output += " - {}".format(observable["time"])
                    if "tags" in observable:
                        output += " tags [{}]".format(",".join(observable["tags"]))
                    if "directives" in observable:
                        output += " direc [{}]".format(",".join(observable["directives"]))

                    print(f"\033[1m{output}\033[0m")

                for tag in root["tags"]:
                    print(f"\033[1;90m  (+) {tag}\033[0m")

                for pivot_link in root.get("pivot_links", []):
                    print(
                        f"\033[1;90m  🔗 ({pivot_link['url']})[{pivot_link['text']}]\033[0m"
                    )

                print()

                events = root["details"]["events"]
                query = root["details"]["query"]
                search_link = root["details"]["search_link"]
                print(f"\033[92m{search_link}\033[0m")
                print()
                print(f"\033[95m{query}\033[0m")  # Print query in purple

                if args.print_results:
                    for event in events:
                        print(json.dumps(event, indent=4, sort_keys=True))

                    print()

                if args.print_logs:
                    for log in result["logs"]:
                        print(log)

                    print()

                if not args.print_results and not args.print_logs:
                    print()
                    print(f"\033[92m{len(events)} events returned\033[0m")

    sys.exit(1 if has_failures else 0)


if __name__ == "__main__":
    main()
