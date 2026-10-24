"""Dissects pcap/pcapng captures with tshark and turns what they carried into observables
(docs/PCAP_ANALYSIS.md).

tshark's dissectors parse untrusted bytes and have a long CVE history, so tshark only ever runs in
the Landlock sandbox (saq/sandbox/runner.py): no network, nothing of ACE readable, bounded by a
timeout, rlimits and an output cap.
"""

import datetime
import ipaddress
import json
import logging
import os
import re
import shutil
import stat
import struct
from dataclasses import dataclass
from itertools import zip_longest
from typing import Callable, Literal, Optional, override
from urllib.parse import SplitResult, urlsplit

from cryptography.x509.oid import NameOID
from pydantic import Field

from saq import x509 as x509_util
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.configuration.config import get_config
from saq.configuration.schema import PcapConfig
from saq.constants import (
    F_FILE,
    F_FQDN,
    F_HOSTNAME,
    F_IP,
    F_JA4,
    F_MAC_ADDRESS,
    F_SHA256,
    F_URL,
    F_USER_AGENT,
    DIRECTIVE_NO_CRAWL,
    R_DOWNLOADED_FROM,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.environment import get_data_dir
from saq.error.reporting import log_loop_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import PCAPNG_BYTE_ORDER_MAGICS, PCAPNG_SECTION_HEADER, is_pcap_file
from saq.observables.file import FileObservable
from saq.observables.network.layer2 import normalize_mac_address
from saq.util.hashing import sha256_bytes, sha256_file
from saq.util.strings import format_item_list_for_summary
from saq.util.ui import human_readable_size
from saq.sandbox.launcher import EXIT_SANDBOX_FAILURE
from saq.sandbox.runner import (
    SandboxCancelled,
    build_sandbox_argv,
    create_workdir,
    landlock_available,
    run_sandboxed,
    sweep_stale_workdirs,
)

TAG_TLS_KEYLOG = "tls_keylog"
# on a pcapng that carries its own decryption secrets, one per kind: pcap_embedded_tls_keys, ...
TAG_EMBEDDED_SECRETS = "pcap_embedded_{}_keys"

CATEGORY_HOSTS = "hosts"
CATEGORY_DNS = "dns"
CATEGORY_TLS = "tls"
CATEGORY_HTTP = "http"
CATEGORY_FILES = "files"

CATEGORY_TITLES = {
    CATEGORY_HOSTS: "Hosts",
    CATEGORY_DNS: "DNS",
    CATEGORY_TLS: "TLS",
    CATEGORY_HTTP: "HTTP",
    CATEGORY_FILES: "Files",
}

# keeps the observables of one analysis grouped by type in the tree (children sort by sort_order)
SORT_ORDER = {
    F_FILE: 10,
    F_URL: 20,
    F_FQDN: 30,
    F_JA4: 40,
    F_USER_AGENT: 50,
    F_HOSTNAME: 60,
    F_IP: 70,
    F_MAC_ADDRESS: 80,
}

# only the packets that carry one of these reach the field output; hosts and flows come from the
# statistics run, which sees every packet
DISPLAY_FILTER = "dns || tls.handshake || http.request || http.response || http2.headers || dhcp || nbns"

TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "udp.stream", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.flags.response", "dns.qry.name", "dns.resp.name", "dns.resp.type", "dns.cname", "dns.a", "dns.aaaa",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja4",
    "tls.handshake.random", "tls.handshake.certificate",
    "http.request.method", "http.host", "http.request.full_uri", "http.user_agent",
    "http.response.code", "http.content_type", "http.request_in",
    "http2.headers.method", "http2.headers.scheme", "http2.headers.authority", "http2.headers.path",
    "http2.headers.user_agent",
    "dhcp.option.hostname", "dhcp.hw.mac_addr", "nbns.name",
)

EXPORT_OBJECT_PROTOCOLS = ("http", "smb", "ftp-data", "tftp", "imf")

# the owner of an SOA or NS record (usually from the authority section of a reply with no answer) is a zone
DNS_ZONE_RECORD_TYPES = {"2", "6"}
# the EDNS OPT pseudo-record, which every modern resolver adds; its owner is the root, not a name
DNS_OPT_RECORD_TYPE = "41"
# how tshark prints the root domain
DNS_ROOT_NAME = "<root>"

# capinfos only reads the record headers, so it never needs the time a full tshark pass does
CAPINFOS_TIMEOUT_SECONDS = 30
# copying the capture into the workdir, stopping the sandbox and parsing tshark's output, around one tshark run
RUN_MARGIN_SECONDS = 30
# the tool never ran: the launcher could not set the sandbox up (EXIT_SANDBOX_FAILURE), or prlimit or
# setpriv could not execute it (126, 127); tshark and capinfos never exit with these themselves
NODE_FAILURE_EXIT_CODES = (EXIT_SANDBOX_FAILURE, 126, 127)

# TLS handshake message types
TLS_CLIENT_HELLO = "1"
TLS_CERTIFICATE = "11"

# the NSS key log format (https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/)
KEYLOG_LABELS = (
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
    "RSA",
)
RE_KEYLOG_LINE = re.compile(r"^(" + "|".join(KEYLOG_LABELS) + r") ([0-9a-fA-F]+) ([0-9a-fA-F]+)$")
KEYLOG_SNIFF_BYTES = 4096
KEYLOG_SNIFF_LINES = 5

RE_NBNS_SUFFIX = re.compile(r"<[0-9a-fA-F]{2}>.*$")

RE_ENDPOINT = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s*$")
RE_CONVERSATION = re.compile(
    r"^(\S+)\s+<->\s+(\S+)\s+\d+\s+\S+ \S+\s+\d+\s+\S+ \S+\s+(\d+)\s+(\S+ \S+)\s+([\d.]+)\s+([\d.]+)\s*$")
RE_IO_STAT_TOTAL = re.compile(r"^\|\s*[\d.]+\s*<>\s*[\d.]+\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|")

KEY_ERROR = "error"
KEY_CLIENT_RANDOMS = "tls_client_randoms"
KEY_CARVED_SHA256 = "carved_sha256"
KEY_INDEX = "index"
KEY_ADDED = "added"
KEY_OMITTED = "omitted"


class PcapError(Exception):
    """tshark could not dissect the capture."""


class PcapNodeError(Exception):
    """This node cannot run tshark at all (no Landlock, a tool that does not start): an operator's
    problem, not the capture's."""


# ----------------------------------------------------------------------------------------------
# key logs
# ----------------------------------------------------------------------------------------------

@dataclass
class KeylogContents:
    label_counts: dict[str, int]
    client_randoms: set[str]
    lines: list[str]


def is_keylog_file(path: str) -> bool:
    """True if the first lines of the file (comments and blank lines aside) are all key log lines."""
    try:
        with open(path, "rb") as fp:
            head = fp.read(KEYLOG_SNIFF_BYTES)
    except OSError:
        # a file that cannot be read is not a key log anyone can use
        return False

    try:
        text = head.decode("ascii")
    except UnicodeDecodeError:
        return False

    lines = text.splitlines()
    # the last line of a full read may be cut in the middle
    if len(head) == KEYLOG_SNIFF_BYTES and lines:
        lines = lines[:-1]

    checked = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not RE_KEYLOG_LINE.match(line):
            return False
        checked += 1
        if checked >= KEYLOG_SNIFF_LINES:
            break

    return checked > 0


def parse_keylog_lines(text_lines) -> KeylogContents:
    """Every valid key log line. Anything else is dropped, so what reaches tshark is only key material."""
    label_counts: dict[str, int] = {}
    client_randoms: set[str] = set()
    lines: list[str] = []
    for line in text_lines:
        m = RE_KEYLOG_LINE.match(line.strip())
        if m is None:
            continue
        label = m.group(1)
        label_counts[label] = label_counts.get(label, 0) + 1
        # an RSA line is keyed by the encrypted pre-master secret, not the client random
        if label != "RSA":
            client_randoms.add(m.group(2).lower())
        lines.append(line.strip())

    return KeylogContents(label_counts, client_randoms, lines)


def read_keylog(path: str) -> KeylogContents:
    with open(path, "r", encoding="ascii", errors="ignore") as fp:
        return parse_keylog_lines(fp)


# pcapng blocks (https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/)
PCAPNG_DECRYPTION_SECRETS_BLOCK = 0x0000000A
PCAPNG_SECRETS_TYPES = {
    0x544C534B: "TLS",
    0x5353484B: "SSH",
    0x57474B4C: "WireGuard",
    0x5A4E574B: "ZigBee NWK",
    0x5A415053: "ZigBee APS",
    0x55414B4C: "OPC UA",
}


# each block header costs about a microsecond in python: a capture of tiny blocks must not hold
# the worker, so the scan stops after this many (Wireshark writes the secrets before the packets
# they decrypt, near the start of the file)
EMBEDDED_SECRETS_MAX_BLOCKS = 1_000_000
EMBEDDED_SECRETS_STOP_CHECK_BLOCKS = 10_000


def read_embedded_secrets(path: str, max_tls_bytes: int, stopping: Callable[[], bool] = lambda: False) -> Optional[dict]:
    """The Decryption Secrets Blocks of a pcapng, which tshark decrypts with on its own. Returns
    {"types": {name: blocks}, "label_counts": {...}, "client_randoms": set} or None when there are
    none. Only block headers are read (the rest is skipped by seeking), at most
    EMBEDDED_SECRETS_MAX_BLOCKS of them, and only up to max_tls_bytes of TLS secrets are parsed. The
    secrets themselves are not returned. Raises SandboxCancelled once stopping() says so."""
    types: dict[str, int] = {}
    tls_lines: list[str] = []
    tls_bytes = 0
    with open(path, "rb") as fp:
        if fp.read(4) != PCAPNG_SECTION_HEADER:
            return None
        fp.seek(0)
        endian = "<"
        blocks = 0
        while True:
            blocks += 1
            if blocks > EMBEDDED_SECRETS_MAX_BLOCKS:
                logging.info("stopped looking for decryption secrets in pcap %s after %s blocks", path,
                             EMBEDDED_SECRETS_MAX_BLOCKS, extra={"pcap_path": path})
                break
            if blocks % EMBEDDED_SECRETS_STOP_CHECK_BLOCKS == 0 and stopping():
                raise SandboxCancelled(f"stopped reading pcap {path}: the analysis was stopped")
            block_start = fp.tell()
            header = fp.read(12)
            if len(header) < 12:
                break
            if header[:4] == PCAPNG_SECTION_HEADER:
                # every section declares its own byte order
                if header[8:12] not in PCAPNG_BYTE_ORDER_MAGICS:
                    break
                endian = "<" if header[8:12] == PCAPNG_BYTE_ORDER_MAGICS[0] else ">"
            block_type, length, first_word = struct.unpack(endian + "III", header)
            # a damaged block ends the scan: tshark has already read what it could of the file
            if length < 12 or length % 4:
                break
            if block_type == PCAPNG_DECRYPTION_SECRETS_BLOCK and length >= 20:
                raw_length = fp.read(4)
                # the file ends inside the block
                if len(raw_length) < 4:
                    break
                secrets_length = struct.unpack(endian + "I", raw_length)[0]
                name = PCAPNG_SECRETS_TYPES.get(first_word, f"0x{first_word:08x}")
                types[name] = types.get(name, 0) + 1
                if name == "TLS" and secrets_length <= length - 20 and tls_bytes + secrets_length <= max_tls_bytes:
                    tls_lines.extend(fp.read(secrets_length).decode("ascii", errors="ignore").splitlines())
                    tls_bytes += secrets_length
            fp.seek(block_start + length)

    if not types:
        return None

    contents = parse_keylog_lines(tls_lines)
    return {"types": types, "label_counts": contents.label_counts, "client_randoms": contents.client_randoms}


def find_keylog_observables(root, max_size: int) -> list[FileObservable]:
    """Every file in the tree that is a TLS key log, whatever its name."""
    result = []
    for observable in root.get_observables_by_type(F_FILE):
        path = observable.full_path
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > max_size:
                continue
        except OSError:
            # gone or unreadable since it was added: not a key log anyone can use
            continue
        if is_keylog_file(path):
            result.append(observable)

    return sorted(result, key=lambda o: o.sha256_hash or "")


# ----------------------------------------------------------------------------------------------
# running tshark
# ----------------------------------------------------------------------------------------------

class PcapCategoryConfig(AnalysisModuleConfig):
    category: Literal["dns", "tls", "http", "files"] = Field(..., description="which part of the capture index this instance turns into observables")


class _StopWhen:
    """The cancel event run_sandboxed polls, set when stopping() says so: the engine shutting down
    (or the analysis being cancelled) stops a run in the middle, not only before the next one."""

    def __init__(self, stopping: Callable[[], bool]):
        self.is_set = stopping


def _run_tshark(config: PcapConfig, pcap_path: str, workdir: str, args: list[str],
                stopping: Callable[[], bool]) -> str:
    """Runs tshark on <workdir>/input (the copy of pcap_path) in the sandbox and returns its stdout."""
    return _run_tool(config, pcap_path, workdir, [config.tshark_path, "-n", "-r", "input", *args], config.tshark_timeout,
                     stopping)


def _run_tool(config: PcapConfig, pcap_path: str, workdir: str, command: list[str], timeout_seconds: int,
              stopping: Callable[[], bool]) -> str:
    """Runs a Wireshark tool on <workdir>/input (the copy of pcap_path) in the sandbox and returns its
    stdout. Raises SandboxCancelled once stopping() says so, killing the tool if it is running."""
    if not landlock_available():
        raise PcapNodeError("the Landlock sandbox is not available on this node; tshark is never run unsandboxed")

    tool = os.path.basename(command[0])
    timeout = datetime.timedelta(seconds=timeout_seconds)
    argv = build_sandbox_argv(command, workdir, config.sandbox, timeout)
    # never os.environ: Landlock does not filter the environment and ACE's carries secrets
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": workdir}
    try:
        result = run_sandboxed(argv, None, env, workdir, timeout, config.sandbox.max_output_bytes,
                               cancel=_StopWhen(stopping))
    except SandboxCancelled as e:
        # a RuntimeError too, but not the capture's failure: nothing is recorded, so it runs again
        raise SandboxCancelled(f"stopped {tool} on pcap {pcap_path}: the analysis was stopped") from e
    except RuntimeError as e:
        raise PcapError(f"{tool} failed: {e}") from e

    # a missing binary, a wrong tshark_path or a node the sandbox cannot be set up on; the launcher's
    # verdicts on a run that did start (EXIT_DEADLINE, EXIT_PROCESS_LIMIT) are the capture's problem
    if not result.stdout.strip() and result.returncode in NODE_FAILURE_EXIT_CODES:
        raise PcapNodeError(f"{tool} could not be run in the sandbox: {result.stderr.strip()[-500:]}")

    # a capture cut short mid-packet exits non-zero after printing everything before the cut
    if result.returncode != 0 and not result.stdout.strip():
        raise PcapError(f"{tool} exited with {result.returncode}: {result.stderr.strip()[-500:]}")

    if result.returncode != 0:
        logging.info("%s exited with %s on pcap %s but produced output: %s", tool, result.returncode, pcap_path,
                     result.stderr.strip()[-500:], extra={"pcap_path": pcap_path})

    return result.stdout


RE_CAPINFOS_FIELD = re.compile(r"^([A-Za-z][A-Za-z ]+):\s+(.*?)\s*$")
RE_CAPINFOS_ENCAPSULATION = re.compile(r"^\s+Encapsulation = (.+?) \(")


def parse_capinfos(output: str) -> dict:
    """The capture's metadata from `capinfos -M -S` (times as epoch seconds)."""
    fields: dict[str, str] = {}
    encapsulations: list[str] = []
    for line in output.splitlines():
        m = RE_CAPINFOS_ENCAPSULATION.match(line)
        if m:
            if m.group(1) not in encapsulations:
                encapsulations.append(m.group(1))
            continue
        m = RE_CAPINFOS_FIELD.match(line)
        if m:
            fields.setdefault(m.group(1).strip(), m.group(2))

    def _number(key: str, kind=int):
        try:
            return kind(fields[key].split()[0])
        except (KeyError, IndexError, ValueError):
            return None

    order = fields.get("Strict time order")
    return {
        "format": fields.get("File type"),
        "size": _number("File size"),
        "packets": _number("Number of packets"),
        "first": _number("Earliest packet time", float),
        "last": _number("Latest packet time", float),
        "duration": _number("Capture duration", float),
        "application": fields.get("Capture application"),
        "interfaces": _number("Number of interfaces in file"),
        "encapsulations": encapsulations,
        # True when packets are in time order, so capture order is chronological
        "strict_time_order": {"True": True, "False": False}.get(order),
    }


def _unique_path(path: str) -> str:
    """Returns path, or when something already exists there, the first free <name>_NNN<ext> next to it.
    A carve moves at most max_extracted_files files, so the linear search per file is bounded."""
    if not os.path.lexists(path):
        return path
    stem, ext = os.path.splitext(path)
    index = 0
    while os.path.lexists(f"{stem}_{index:03}{ext}"):
        index += 1
    return f"{stem}_{index:03}{ext}"


def _host_without_port(host: str) -> str:
    host = host.strip()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def _first(layers: dict, field: str) -> Optional[str]:
    values = layers.get(field)
    return values[0] if values else None


def _parse_statistics(output: str, max_rows: int) -> dict:
    """Packet count, endpoints and conversations from `-q -z io,stat,0 -z endpoints,... -z conv,...`."""
    stats = {"packets": 0, "bytes": 0, "mac": [], "ip": [], "flows": []}
    section = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Ethernet Endpoints"):
            section = "mac"
        elif stripped.startswith("IPv4 Endpoints") or stripped.startswith("IPv6 Endpoints"):
            section = "ip"
        elif stripped.startswith("TCP Conversations"):
            section = "tcp"
        elif stripped.startswith("UDP Conversations"):
            section = "udp"
        elif stripped.startswith("| IO Statistics"):
            section = "io"
        elif section == "io":
            m = RE_IO_STAT_TOTAL.match(stripped)
            if m:
                stats["packets"] = int(m.group(1))
                stats["bytes"] = int(m.group(2))
        elif section in ("mac", "ip"):
            m = RE_ENDPOINT.match(stripped)
            if m:
                stats[section].append({"address": m.group(1), "packets": int(m.group(2)), "bytes": int(m.group(3))})
        elif section in ("tcp", "udp"):
            m = RE_CONVERSATION.match(stripped)
            if m:
                stats["flows"].append({
                    "protocol": section,
                    "a": m.group(1),
                    "b": m.group(2),
                    "frames": int(m.group(3)),
                    "bytes": m.group(4),
                    "start": float(m.group(5)),
                    "duration": float(m.group(6)),
                })

    for key in ("mac", "ip", "flows"):
        rows = sorted(stats[key], key=lambda r: r.get("packets", r.get("frames", 0)), reverse=True)
        stats[f"{key}_total"] = len(rows)
        stats[key] = rows[:max_rows]

    return stats


def _parse_fields(output: str) -> list[dict]:
    try:
        packets = json.loads(output) if output.strip() else []
    except json.JSONDecodeError as e:
        raise PcapError(f"unable to parse tshark output: {e}") from e

    return [packet.get("_source", {}).get("layers", {}) for packet in packets if isinstance(packet, dict)]


def _epoch(layers: dict) -> Optional[float]:
    try:
        return float(_first(layers, "frame.time_epoch"))
    except (TypeError, ValueError):
        return None


def _flow_key(layers: dict) -> Optional[str]:
    if "tcp.stream" in layers:
        return f"tcp:{layers['tcp.stream'][0]}"
    if "udp.stream" in layers:
        return f"udp:{layers['udp.stream'][0]}"
    return None


def _endpoints(layers: dict) -> tuple[Optional[str], Optional[str]]:
    src = _first(layers, "ip.src") or _first(layers, "ipv6.src")
    dst = _first(layers, "ip.dst") or _first(layers, "ipv6.dst")
    sport = _first(layers, "tcp.srcport") or _first(layers, "udp.srcport")
    dport = _first(layers, "tcp.dstport") or _first(layers, "udp.dstport")
    return (f"{src}:{sport}" if src else None), (f"{dst}:{dport}" if dst else None)


def build_index(packets: list[dict], certificates: list[dict], objects: list[dict], max_rows: int) -> dict:
    """The parts of the capture that become observables, from tshark's per-packet fields."""
    dns: dict[str, dict] = {}
    tls: dict[str, dict] = {}
    http: dict[str, dict] = {}
    hostnames: dict[str, dict] = {}
    certificate_by_der: dict[str, str] = {c["der_hex"]: c["sha256"] for c in certificates}

    for layers in packets:
        frame = _first(layers, "frame.number") or ""

        # dns.resp.name and dns.resp.type are parallel: one entry per resource record
        record_names = [name for name, record_type in zip_longest(layers.get("dns.resp.name", []), layers.get("dns.resp.type", []))
                        if name is not None and record_type != DNS_OPT_RECORD_TYPE]
        # every name gets a row, also one never looked up (a CNAME target, a zone): it is an fqdn observable
        for name in layers.get("dns.qry.name", []) + record_names + layers.get("dns.cname", []):
            if name.lower() != DNS_ROOT_NAME:
                dns.setdefault(name.lower(), {"name": name.lower(), "answers": [], "queries": 0, "responses": 0,
                                              "seen_as": []})
        roles = [(name, "cname") for name in layers.get("dns.cname", [])]
        roles += [(name, "zone") for name, record_type in zip(layers.get("dns.resp.name", []), layers.get("dns.resp.type", []))
                  if record_type in DNS_ZONE_RECORD_TYPES]
        for name, role in roles:
            if name.lower() == DNS_ROOT_NAME:
                continue
            seen_as = dns[name.lower()]["seen_as"]
            if role not in seen_as:
                seen_as.append(role)
        if "dns.qry.name" in layers:
            is_response = _first(layers, "dns.flags.response") in ("True", "1", "true")
            answers = layers.get("dns.a", []) + layers.get("dns.aaaa", []) + layers.get("dns.cname", [])
            for name in layers["dns.qry.name"]:
                # a root query (". NS", a resolver priming itself) names nothing
                if name.lower() == DNS_ROOT_NAME:
                    continue
                entry = dns[name.lower()]
                entry["responses" if is_response else "queries"] += 1
                if is_response:
                    seen_at = _epoch(layers)
                    answer_times = entry.setdefault("answer_times", {})
                    for answer in answers:
                        if answer not in entry["answers"]:
                            entry["answers"].append(answer)
                        # when the answer was first returned: the time an answer IP observable carries
                        if seen_at is not None and (answer not in answer_times or seen_at < answer_times[answer]):
                            answer_times[answer] = seen_at

        handshake_types = layers.get("tls.handshake.type", [])
        flow = _flow_key(layers)
        if flow and TLS_CLIENT_HELLO in handshake_types:
            client, server = _endpoints(layers)
            session = tls.setdefault(flow, {"flow": flow, "certificates": []})
            session.update({
                "client": client,
                "server": server,
                "sni": _first(layers, "tls.handshake.extensions_server_name"),
                "ja4": _first(layers, "tls.handshake.ja4"),
                "client_random": (_first(layers, "tls.handshake.random") or "").lower() or None,
            })
        if flow and TLS_CERTIFICATE in handshake_types:
            session = tls.setdefault(flow, {"flow": flow, "certificates": []})
            for der_hex in layers.get("tls.handshake.certificate", []):
                sha256 = certificate_by_der.get(der_hex.replace(":", "").lower())
                if sha256 and sha256 not in session["certificates"]:
                    session["certificates"].append(sha256)

        if "http.request.method" in layers:
            http[frame] = {
                "method": _first(layers, "http.request.method"),
                "url": _first(layers, "http.request.full_uri"),
                "host": _first(layers, "http.host"),
                "user_agent": _first(layers, "http.user_agent"),
                "status": None,
                "content_type": None,
            }
        elif "http.response.code" in layers:
            request = http.get(_first(layers, "http.request_in") or "")
            if request is not None and request["status"] is None:
                request["status"] = _first(layers, "http.response.code")
                request["content_type"] = _first(layers, "http.content_type")

        methods = layers.get("http2.headers.method", [])
        schemes = layers.get("http2.headers.scheme", [])
        authorities = layers.get("http2.headers.authority", [])
        paths = layers.get("http2.headers.path", [])
        if methods and len(methods) == len(schemes) == len(authorities) == len(paths):
            agents = layers.get("http2.headers.user_agent", [])
            for index, method in enumerate(methods):
                http[f"{frame}:{index}"] = {
                    "method": method,
                    "url": f"{schemes[index]}://{authorities[index]}{paths[index]}",
                    "host": authorities[index],
                    "user_agent": agents[index] if index < len(agents) else None,
                    "status": None,
                    "content_type": None,
                }

        for name in layers.get("dhcp.option.hostname", []):
            hostnames.setdefault(name.lower(), {"name": name, "source": "dhcp", "mac": _first(layers, "dhcp.hw.mac_addr")})
        for name in layers.get("nbns.name", []):
            name = RE_NBNS_SUFFIX.sub("", name).strip()
            if name and not name.startswith("_"):
                hostnames.setdefault(name.lower(), {"name": name, "source": "nbns", "mac": None})

    index = {
        CATEGORY_DNS: list(dns.values()),
        CATEGORY_TLS: list(tls.values()),
        # key logs are matched against every session, not only the ones the table keeps
        KEY_CLIENT_RANDOMS: sorted({s["client_random"] for s in tls.values() if s.get("client_random")}),
        # and a later decryption knows every file this run carved or listed, not only the rows kept
        KEY_CARVED_SHA256: sorted({o["sha256"] for o in objects} | {c["sha256"] for c in certificates}),
        CATEGORY_HTTP: list(http.values()),
        "hostnames": list(hostnames.values()),
        "objects": objects,
        "certificates": [{k: v for k, v in c.items() if k != "der_hex"} for c in certificates],
    }
    for key in INDEX_ROW_KEYS:
        index[f"{key}_total"] = len(index[key])
        index[key] = index[key][:max_rows]

    return index


# what makes two rows of an index table the same row
INDEX_ROW_KEYS = {
    CATEGORY_DNS: lambda row: row["name"],
    CATEGORY_TLS: lambda row: row["flow"],
    CATEGORY_HTTP: lambda row: (row.get("method"), row.get("url")),
    "hostnames": lambda row: row["name"].lower(),
    "objects": lambda row: row["sha256"],
    "certificates": lambda row: row["sha256"],
}


def merge_index(previous: Optional[dict], new: dict, max_rows: int) -> dict:
    """new, with every row of previous kept as it was: a later decryption adds rows to the earlier
    one's tables and never replaces them (the files an earlier key log carved are not carved again,
    so they are only in previous)."""
    if not previous:
        return new

    merged = dict(new)
    merged[KEY_CARVED_SHA256] = sorted(set(previous.get(KEY_CARVED_SHA256, [])) | set(new.get(KEY_CARVED_SHA256, [])))
    for key, row_key in INDEX_ROW_KEYS.items():
        old_rows = previous.get(key, [])
        new_rows = new.get(key, [])
        old_keys = {row_key(row) for row in old_rows}
        added = [row for row in new_rows if row_key(row) not in old_keys]
        merged[key] = (old_rows + added)[:max_rows]
        old_total = previous.get(f"{key}_total", len(old_rows))
        new_total = new.get(f"{key}_total", len(new_rows))
        # a later run decrypts every earlier session again, so its tables already count the earlier
        # rows; only its objects leave out what was carved before (known_sha256)
        total = old_total + new_total if key == "objects" else max(old_total, new_total)
        merged[f"{key}_total"] = max(total, len(merged[key]))
    return merged


MAX_CERTIFICATE_SANS = 10


def _name_text(name) -> Optional[str]:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attributes = name.get_attributes_for_oid(oid)
        if attributes:
            return str(attributes[0].value)
    return name.rfc4514_string() or None


def certificate_names(der: bytes) -> dict:
    """Subject, other SAN DNS names (the first MAX_CERTIFICATE_SANS) and issuer of a DER certificate,
    for the analyst; empty when it does not parse."""
    try:
        cert = x509_util.load_cert_der(der)
        if cert is None:
            return {}
        subject = _name_text(cert.subject)
        sans = [name for name in x509_util.san_dns_names(cert) if name != subject]
        return {"subject": subject, "sans": sans[:MAX_CERTIFICATE_SANS], "san_total": len(sans),
                "issuer": _name_text(cert.issuer)}
    except Exception:
        # a certificate in a capture is whatever the peer sent; one that does not parse is shown by its hash
        return {}


def describe_certificate(entry: dict) -> str:
    """One line for a certificate: subject (SAN: a, b, c, +N more) - issued by X."""
    if not entry.get("subject"):
        return f"certificate {entry['sha256'][:16]}"
    text = entry["subject"]
    sans = entry.get("sans", [])[:3]
    if sans:
        more = entry.get("san_total", len(sans)) - len(sans)
        text += f" (SAN: {', '.join(sans)}{f', +{more} more' if more > 0 else ''})"
    if entry.get("issuer") and entry["issuer"] != entry["subject"]:
        text += f" \u2014 issued by {entry['issuer']}"
    elif entry.get("issuer"):
        text += " \u2014 self-signed"
    return text


def _real_directory(path: str) -> bool:
    """True if path is a directory itself, not a symlink to one. tshark may create symlinks in its
    workdir, and following one would let it point ACE, which is not sandboxed, anywhere."""
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        # tshark exported nothing there
        return False


def _collect_carved_files(workdir: str, target_dir: str, packets: list[dict], max_files: int,
                          known_sha256: set[str]) -> tuple[list[dict], list[dict]]:
    """Moves the objects tshark exported and the certificates seen in the handshakes out of the
    workdir into target_dir (beside the pcap in the root's storage, so they are stored in place).
    Content already in known_sha256 is skipped. Returns (objects, certificates), whose paths are
    relative to the pcap's directory so they survive the storage directory moving."""
    objects: list[dict] = []
    certificates: list[dict] = []
    remaining = max_files
    base_dir = os.path.dirname(target_dir)

    # what crossed the wire first: a payload matters more than the certificates of the handshakes
    # everything in the workdir is tshark's, so nothing is followed out of it: no symlinked directory
    # and no file that is a symlink or a hard link to one elsewhere. The launcher killed whatever
    # tshark started before run_sandboxed returned, so nothing can swap a path after it is checked.
    seen_sha256: set[str] = set()
    objects_dir = os.path.join(workdir, "objects")
    for protocol in EXPORT_OBJECT_PROTOCOLS:
        protocol_dir = os.path.join(objects_dir, protocol)
        if not _real_directory(objects_dir) or not _real_directory(protocol_dir):
            continue
        for file_name in sorted(os.listdir(protocol_dir)):
            source = os.path.join(protocol_dir, file_name)
            source_stat = os.lstat(source)
            if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
                continue
            sha256 = sha256_file(source)
            if sha256 in known_sha256 or sha256 in seen_sha256:
                continue
            seen_sha256.add(sha256)
            entry = {"protocol": protocol, "file_name": file_name, "sha256": sha256,
                     "size": source_stat.st_size, "path": None}
            if remaining > 0:
                target = _unique_path(os.path.join(target_dir, protocol, file_name))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.move(source, target)
                entry["path"] = os.path.relpath(target, base_dir)
                remaining -= 1
            objects.append(entry)

    seen_der: set[str] = set()
    for layers in packets:
        for der_hex in layers.get("tls.handshake.certificate", []):
            der_hex = der_hex.replace(":", "").lower()
            if der_hex in seen_der:
                continue
            seen_der.add(der_hex)
            try:
                der = bytes.fromhex(der_hex)
            except ValueError:
                # tshark printed something that is not a certificate's bytes; there is nothing to carve
                continue
            sha256 = sha256_bytes(der)
            entry = {"sha256": sha256, "der_hex": der_hex, "path": None, **certificate_names(der)}
            if sha256 not in known_sha256 and remaining > 0:
                path = os.path.join(target_dir, "certificates", f"{sha256}.der")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fp:
                    fp.write(der)
                entry["path"] = os.path.relpath(path, base_dir)
                remaining -= 1
            certificates.append(entry)

    return objects, certificates


def _split_url(url: str) -> Optional[SplitResult]:
    """urlsplit, or None for a URL that does not parse."""
    try:
        return urlsplit(url)
    except ValueError:
        # tshark builds the URL from the Host header the client sent, which can be anything ("[x")
        return None


def _link_http_objects(index: dict):
    """An exported HTTP object is named after the last segment of its URL path; link it to that URL
    when exactly one request in the capture matches."""
    by_name: dict[str, set[str]] = {}
    for request in index[CATEGORY_HTTP]:
        parts = _split_url(request["url"]) if request.get("url") else None
        if parts is None:
            continue
        name = os.path.basename(parts.path)
        if name:
            by_name.setdefault(name, set()).add(request["url"])

    for entry in index["objects"]:
        if entry["protocol"] != "http":
            continue
        urls = by_name.get(entry["file_name"], set())
        entry["url"] = next(iter(urls)) if len(urls) == 1 else None


def dissect(config: PcapConfig, pcap_path: str, target_dir: str, keylog_lines: Optional[list[str]] = None,
            known_sha256: Optional[set[str]] = None, statistics: bool = True,
            stopping: Callable[[], bool] = lambda: False) -> dict:
    """Runs tshark over the capture and returns its index. Carved files land in target_dir. Raises
    SandboxCancelled once stopping() says the engine is shutting down, stopping a run in progress."""

    def _check_stopping():
        if stopping():
            raise SandboxCancelled(f"stopped dissecting pcap {pcap_path}: the engine is shutting down")

    work_root = os.path.join(get_data_dir(), config.work_dir)
    sweep_stale_workdirs(work_root)
    with create_workdir(work_root) as workdir:
        # a copy, never a hard link: tshark may write anything in its workdir, and through a link
        # it could change the evidence itself
        shutil.copyfile(pcap_path, os.path.join(workdir, "input"))
        os.mkdir(os.path.join(workdir, "objects"))

        index_stats = {}
        statistics_error = None
        capture = None
        if statistics:
            capinfos = os.path.join(os.path.dirname(config.tshark_path), "capinfos")
            _check_stopping()
            try:
                capture = parse_capinfos(_run_tool(config, pcap_path, workdir, [capinfos, "-M", "-S", "input"],
                                                   CAPINFOS_TIMEOUT_SECONDS, stopping))
            except PcapError as e:
                # only the page header needs it; the dissection does not
                logging.info("no capture metadata for pcap %s: %s", pcap_path, e)
            _check_stopping()
            try:
                output = _run_tshark(config, pcap_path, workdir, ["-q", "-z", "io,stat,0", "-z", "endpoints,eth",
                                                                  "-z", "endpoints,ip", "-z", "endpoints,ipv6",
                                                                  "-z", "conv,tcp", "-z", "conv,udp"], stopping)
                index_stats = _parse_statistics(output, config.max_table_rows)
            except PcapError as e:
                # a line per conversation can outgrow the output cap (a scan, heavy DNS); only the
                # endpoint and flow tables need it, so the field pass still runs
                statistics_error = str(e)
                logging.info("no packet statistics for pcap %s: %s", pcap_path, e, extra={"pcap_path": pcap_path})
            if index_stats.get("packets", 0) > config.max_field_packets:
                logging.info("pcap %s has %s packets: DNS, TLS and HTTP are read from the first %s", pcap_path,
                             index_stats["packets"], config.max_field_packets, extra={"pcap_path": pcap_path})

        # tshark's JSON is about 1 kB a packet and must fit under the sandbox's output cap. The limit
        # is a display filter, not -c, so tshark still reads every packet and the object export
        # covers the whole capture.
        args = ["-T", "json", "-Y", f"frame.number <= {config.max_field_packets} && ({DISPLAY_FILTER})"]
        for field in TSHARK_FIELDS:
            args.extend(["-e", field])
        for protocol in EXPORT_OBJECT_PROTOCOLS:
            args.extend(["--export-objects", f"{protocol},objects/{protocol}"])
        if keylog_lines:
            with open(os.path.join(workdir, "keylog"), "w") as fp:
                fp.write("\n".join(keylog_lines) + "\n")
            args.extend(["-o", "tls.keylog_file:keylog"])

        _check_stopping()
        packets = _parse_fields(_run_tshark(config, pcap_path, workdir, args, stopping))
        objects, certificates = _collect_carved_files(workdir, target_dir, packets, config.max_extracted_files,
                                                      known_sha256 or set())

    index = build_index(packets, certificates, objects, config.max_table_rows)
    index["field_packet_limit"] = config.max_field_packets
    _link_http_objects(index)
    if statistics:
        index["statistics"] = index_stats
        index["statistics_error"] = statistics_error
        index["capture"] = capture
    return index


# ----------------------------------------------------------------------------------------------
# index -> observables
# ----------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PcapObservable:
    category: str
    o_type: str
    # the sha256 for a file, so a file is the same observable whatever its path
    value: str
    volatile: bool = False
    path: Optional[str] = None
    downloaded_from: Optional[str] = None
    # a certificate ACE only observed on the wire: x509_analyzer should not crawl its names
    no_crawl: bool = False
    # shown in the alert tree; one per observable, so it is only set when no module has set one
    display_type: Optional[str] = None
    # epoch seconds; a timed observable is distinct from the same value without a time
    time: Optional[float] = None

    @property
    def key(self) -> tuple[str, str]:
        return self.o_type, self.value


def _is_interesting_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_multicast or address.is_unspecified or address.is_link_local
                or address.is_loopback or address.is_reserved)


def _is_interesting_mac(value: str) -> bool:
    try:
        first_octet = int(value.split(":")[0], 16)
    except ValueError:
        return False
    # the group bit covers broadcast and multicast
    return not (first_octet & 1) and value != "00:00:00:00:00:00"


def _host_observable(category: str, host: str, excluded_suffixes: list[str], fqdn_display_type: Optional[str] = None,
                     ip_display_type: Optional[str] = None, ip_time: Optional[float] = None) -> Optional[PcapObservable]:
    host = _host_without_port(host).rstrip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        if not _is_interesting_ip(host):
            return None
        return PcapObservable(category, F_IP, host, volatile=True, display_type=ip_display_type, time=ip_time)
    except ValueError:
        pass
    if any(host.endswith(suffix) for suffix in excluded_suffixes):
        return None
    return PcapObservable(category, F_FQDN, host, display_type=fqdn_display_type)


MAX_JA4_DESTINATIONS = 3


def ja4_display_types(sessions: list[dict]) -> dict[str, str]:
    """For each JA4, where its sessions went: the SNI, or the server address when there is none."""
    destinations: dict[str, list[str]] = {}
    for session in sessions:
        if not session.get("ja4"):
            continue
        target = session.get("sni") or _host_without_port(session.get("server") or "") or None
        targets = destinations.setdefault(session["ja4"], [])
        if target and target not in targets:
            targets.append(target)

    # JA4 describes the client that sent the hello, not the server: one per client application is normal
    result = {}
    for ja4, targets in destinations.items():
        if not targets:
            result[ja4] = "JA4 client fingerprint (TLS ClientHello)"
            continue
        result[ja4] = ("JA4 client fingerprint (TLS ClientHello), seen to "
                       f"{format_item_list_for_summary(targets, MAX_JA4_DESTINATIONS)}")
    return result


def _dns_display_type(row: dict) -> str:
    """How the name was seen, the most direct way first."""
    if row.get("queries") or row.get("responses"):
        return "DNS Query Name"
    seen_as = row.get("seen_as", [])
    if "cname" in seen_as:
        return "DNS CNAME Target"
    if "zone" in seen_as:
        return "DNS Zone (SOA/NS)"
    return "DNS Record Name"


def collect_observables(index: dict, excluded_fqdn_suffixes: list[str]) -> list[PcapObservable]:
    """Every observable the index holds, each in the category whose analysis adds it."""
    result: list[PcapObservable] = []
    seen: set[tuple] = set()

    def _add(item: Optional[PcapObservable]):
        # the first one wins: it carries the most specific display type
        if item is not None and (item.category, *item.key) not in seen:
            seen.add((item.category, *item.key))
            result.append(item)

    statistics = index.get("statistics", {})
    for row in statistics.get("ip", []):
        if _is_interesting_ip(row["address"]):
            _add(PcapObservable(CATEGORY_HOSTS, F_IP, row["address"], volatile=True))
    for row in statistics.get("mac", []):
        mac = normalize_mac_address(row["address"])
        if mac and _is_interesting_mac(row["address"]):
            _add(PcapObservable(CATEGORY_HOSTS, F_MAC_ADDRESS, mac, volatile=True))
    for row in index.get("hostnames", []):
        _add(PcapObservable(CATEGORY_HOSTS, F_HOSTNAME, row["name"], volatile=True))

    for row in index.get(CATEGORY_DNS, []):
        _add(_host_observable(CATEGORY_DNS, row["name"], excluded_fqdn_suffixes, fqdn_display_type=_dns_display_type(row)))
    # one observable per answer IP, at the first time any response returned it
    first_answered: dict[str, float] = {}
    for row in index.get(CATEGORY_DNS, []):
        for answer, seen_at in row.get("answer_times", {}).items():
            if answer not in first_answered or seen_at < first_answered[answer]:
                first_answered[answer] = seen_at
    for row in index.get(CATEGORY_DNS, []):
        for answer in row["answers"]:
            _add(_host_observable(CATEGORY_DNS, answer, excluded_fqdn_suffixes, ip_display_type="DNS Answer IP",
                                  ip_time=first_answered.get(answer)))

    ja4_labels = ja4_display_types(index.get(CATEGORY_TLS, []))
    # a name DNS also saw keeps its DNS label, so the label never depends on which category ran first
    dns_names = {row["name"] for row in index.get(CATEGORY_DNS, [])}
    for row in index.get(CATEGORY_TLS, []):
        if row.get("sni"):
            sni_label = None if row["sni"].rstrip(".").lower() in dns_names else "TLS SNI"
            _add(_host_observable(CATEGORY_TLS, row["sni"], excluded_fqdn_suffixes, fqdn_display_type=sni_label))
        if row.get("ja4"):
            _add(PcapObservable(CATEGORY_TLS, F_JA4, row["ja4"], display_type=ja4_labels[row["ja4"]]))
    for row in index.get("certificates", []):
        if row.get("path"):
            _add(PcapObservable(CATEGORY_TLS, F_FILE, row["sha256"], path=row["path"], no_crawl=True))

    for row in index.get(CATEGORY_HTTP, []):
        if row.get("url") and getattr(_split_url(row["url"]), "scheme", None) in ("http", "https"):
            _add(PcapObservable(CATEGORY_HTTP, F_URL, row["url"]))
        if row.get("host"):
            _add(_host_observable(CATEGORY_HTTP, row["host"], excluded_fqdn_suffixes))
        if row.get("user_agent"):
            _add(PcapObservable(CATEGORY_HTTP, F_USER_AGENT, row["user_agent"]))

    for row in index.get("objects", []):
        if row.get("path"):
            _add(PcapObservable(CATEGORY_FILES, F_FILE, row["sha256"], path=row["path"],
                                downloaded_from=row.get("url")))

    return result


def _observable_key(observable: Observable) -> tuple[str, str]:
    if isinstance(observable, FileObservable):
        return F_FILE, observable.sha256_hash or ""
    return observable.type, observable.value


def add_pcap_observables(analysis: Analysis, pcap_file: FileObservable, items: list[PcapObservable],
                         max_per_type: int, reserved: list[PcapObservable] = ()) -> tuple[dict[str, int], dict[str, int]]:
    """Adds the observables to the analysis, at most max_per_type of each type for the whole capture:
    the ones every pcap node of pcap_file already has count, so one capture never puts more than
    max_per_type nodes of a type in the tree. reserved are observables another node adds later,
    whose room is kept for them. Returns (added, omitted) counts by type."""
    added: dict[str, int] = {}
    omitted: dict[str, int] = {}
    present = {_observable_key(o) for o in analysis.observables}
    per_type: dict[str, int] = {}
    in_capture: set[tuple[str, str]] = set()
    for node in pcap_file.all_analysis:
        if isinstance(node, PCAP_ANALYSIS_TYPES):
            for o in node.observables:
                per_type[o.type] = per_type.get(o.type, 0) + 1
                in_capture.add(_observable_key(o))
    for item in reserved:
        if item.key not in in_capture:
            per_type[item.o_type] = per_type.get(item.o_type, 0) + 1

    # a payload file before a certificate: the certificates seen in the handshakes never take the
    # room of what crossed the wire
    items = sorted(items, key=lambda item: item.no_crawl)

    for item in items:
        if item.key in present:
            continue
        if per_type.get(item.o_type, 0) >= max_per_type:
            omitted[item.o_type] = omitted.get(item.o_type, 0) + 1
            continue

        if item.o_type == F_FILE:
            observable = analysis.add_file_observable(os.path.join(os.path.dirname(pcap_file.full_path), item.path))
            if observable is not None:
                observable.add_relationship(R_EXTRACTED_FROM, pcap_file)
                if item.no_crawl:
                    observable.add_directive(DIRECTIVE_NO_CRAWL)
                if item.downloaded_from:
                    url = analysis.add_observable_by_spec(F_URL, item.downloaded_from)
                    if url is not None:
                        url.sort_order = SORT_ORDER[F_URL]
                        observable.add_relationship(R_DOWNLOADED_FROM, url)
        else:
            o_time = None if item.time is None else datetime.datetime.fromtimestamp(item.time, datetime.timezone.utc)
            observable = analysis.add_observable_by_spec(item.o_type, item.value, o_time=o_time, volatile=item.volatile)

        # None: an invalid value for its type, or the root's per-type limit was reached
        if observable is None:
            omitted[item.o_type] = omitted.get(item.o_type, 0) + 1
            continue

        # set here: Observable.__init__ does not pass its sort_order argument on
        observable.sort_order = SORT_ORDER.get(item.o_type, 100)
        # an observable has one display type wherever it appears: never replace another module's
        if item.display_type and observable._display_type is None:
            observable.display_type = item.display_type

        present.add(item.key)
        per_type[item.o_type] = per_type.get(item.o_type, 0) + 1
        added[item.o_type] = added.get(item.o_type, 0) + 1

    return added, omitted


def _merge_counts(details: dict, key: str, counts: dict[str, int]):
    merged = details.setdefault(key, {})
    for o_type, count in counts.items():
        merged[o_type] = merged.get(o_type, 0) + count


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{count} {o_type}" for o_type, count in sorted(counts.items()))


def _stopping(module: AnalysisModule) -> Callable[[], bool]:
    """When a pcap module's tshark run should stop: the engine is shutting down, or the analysis was cancelled."""
    return lambda: module.shutdown or module.is_canceled_analysis()


def _run_seconds(config: PcapConfig) -> int:
    """The most one tshark run can take, with the work around it."""
    return config.tshark_timeout + RUN_MARGIN_SECONDS


def _out_of_time(needed: float, left: float) -> str:
    return (f"skipped: dissecting this capture can take {needed:.0f} s and only {max(left, 0):.0f} s are left "
            "of this module's maximum_analysis_time or this alert's analysis time")


def _session_randoms(index: dict) -> set[str]:
    """The client randoms of every TLS session in the capture, which key log lines are keyed by."""
    return set(index.get(KEY_CLIENT_RANDOMS, []))


def _embedded_randoms(index: dict) -> set[str]:
    """The sessions the capture's own secrets already decrypted in the plaintext pass."""
    return set((index.get("embedded_secrets") or {}).get("keyed_client_randoms", []))


def _get_pcap_analysis(observable: FileObservable) -> Optional["PcapAnalysis"]:
    analysis = observable.get_and_load_analysis(PcapAnalysis)
    if not isinstance(analysis, PcapAnalysis) or analysis.error or analysis.index is None:
        return None
    return analysis


# ----------------------------------------------------------------------------------------------
# core analysis
# ----------------------------------------------------------------------------------------------

def embedded_secrets_tags(types: dict[str, int]) -> list[str]:
    """pcap_embedded_tls_keys, pcap_embedded_ssh_keys, ... for the kinds of secrets a capture carries."""
    tags = []
    for name in types:
        slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") if name in PCAPNG_SECRETS_TYPES.values() else "unknown"
        tags.append(TAG_EMBEDDED_SECRETS.format(slug))
    return sorted(set(tags))


def _describe_embedded(embedded: dict) -> str:
    parts = []
    for name in sorted(embedded["types"]):
        if name == "TLS":
            parts.append(f"TLS keys for {len(embedded.get('keyed_client_randoms', []))} sessions")
        else:
            parts.append(name)
    return ", ".join(parts)


class PcapAnalysis(Analysis):
    """The capture index, the flows and the hosts of a pcap."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {KEY_ERROR: None, KEY_INDEX: None, KEY_ADDED: {}, KEY_OMITTED: {}}

    @override
    @property
    def display_name(self) -> str:
        return "PCAP Analysis"

    @property
    def error(self) -> Optional[str]:
        return self.details.get(KEY_ERROR)

    @error.setter
    def error(self, value: Optional[str]):
        self.details[KEY_ERROR] = value

    @property
    def index(self) -> Optional[dict]:
        return self.details.get(KEY_INDEX)

    def generate_summary(self) -> Optional[str]:
        if not self.details:
            return None
        if self.error:
            return f"PCAP Analysis: failed: {self.error}"
        if self.index is None:
            return None

        statistics = self.index.get("statistics", {})
        if self.index.get("statistics_error"):
            summary = f"PCAP Analysis: no packet statistics ({self.index['statistics_error']}), "
        else:
            summary = f"PCAP Analysis: {statistics.get('packets', 0)} packets, {statistics.get('flows_total', 0)} flows, "
        summary += f"{self.index.get(f'{CATEGORY_TLS}_total', len(self.index.get(CATEGORY_TLS, [])))} TLS sessions"
        embedded = self.index.get("embedded_secrets")
        if embedded:
            summary += f", decryption keys embedded ({_describe_embedded(embedded)})"
        if self.details.get(KEY_ADDED):
            summary += f" ({_format_counts(self.details[KEY_ADDED])})"
        return summary


class PcapAnalyzer(AnalysisModule):
    """Dissects a pcap/pcapng file with sandboxed tshark."""

    @property
    def generated_analysis_type(self):
        return PcapAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        path = _file.full_path
        if not os.path.isfile(path) or not is_pcap_file(path):
            return AnalysisExecutionResult.COMPLETED

        config = get_config().pcap
        size = os.path.getsize(path)
        if size > config.max_file_size:
            self._failed(_file, f"{size} bytes exceeds max_file_size {config.max_file_size}")
            return AnalysisExecutionResult.COMPLETED

        needed = CAPINFOS_TIMEOUT_SECONDS + 2 * _run_seconds(config)
        left = self.time_left()
        if needed > left:
            self._failed(_file, _out_of_time(needed, left))
            logging.info("not dissecting pcap %s (sha256 %s) in %s: %s s needed, %.0f s left", path, _file.sha256_hash,
                         self.get_root().uuid, needed, left, extra={"pcap_sha256": _file.sha256_hash})
            return AnalysisExecutionResult.COMPLETED

        try:
            index = dissect(config, path, f"{path}.pcap_objects", stopping=_stopping(self))
            embedded = read_embedded_secrets(path, config.max_keylog_size, stopping=_stopping(self))
        except SandboxCancelled as e:
            # no analysis yet, so the capture is dissected again when the work item is picked up again
            logging.info("%s", e, extra={"pcap_sha256": _file.sha256_hash})
            return AnalysisExecutionResult.INCOMPLETE
        except PcapNodeError as e:
            self._failed(_file, str(e))
            log_loop_exception(e, f"unable to dissect pcap {path} (sha256 {_file.sha256_hash}) in {self.get_root().uuid}")
            return AnalysisExecutionResult.COMPLETED
        except PcapError as e:
            # a capture tshark cannot read is the analyst's to see, in the analysis, not an operator's
            self._failed(_file, str(e))
            logging.info("unable to dissect pcap %s (sha256 %s) in %s: %s", path, _file.sha256_hash, self.get_root().uuid, e,
                         extra={"pcap_sha256": _file.sha256_hash})
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapAnalysis)
        if embedded:
            # client randoms are sent in the clear; only the secrets keyed by them are sensitive
            embedded["keyed_client_randoms"] = sorted(_session_randoms(index) & embedded.pop("client_randoms"))
            index["embedded_secrets"] = embedded
            for tag in embedded_secrets_tags(embedded["types"]):
                _file.add_tag(tag)
            logging.info("pcap %s carries embedded decryption secrets: %s", path, _describe_embedded(embedded),
                         extra={"pcap_sha256": _file.sha256_hash})

        if index.get("capture"):
            index["capture"]["file_name"] = _file.file_name
        analysis.details[KEY_INDEX] = index
        hosts = [o for o in collect_observables(index, config.excluded_fqdn_suffixes) if o.category == CATEGORY_HOSTS]
        added, omitted = add_pcap_observables(analysis, _file, hosts, config.max_observables_per_type)
        analysis.details[KEY_ADDED] = added
        analysis.details[KEY_OMITTED] = omitted
        return AnalysisExecutionResult.COMPLETED

    def _failed(self, _file: FileObservable, error: str):
        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapAnalysis)
        analysis.error = error


# ----------------------------------------------------------------------------------------------
# category analyses
# ----------------------------------------------------------------------------------------------

class PcapCategoryAnalysis(Analysis):
    """One category (dns, tls, http, files) of a pcap's index; one per configured instance."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {"category": None, "rows": [], "total": 0, KEY_ADDED: {}, KEY_OMITTED: {}}

    @property
    def title(self) -> str:
        return f"PCAP {CATEGORY_TITLES.get(self.details.get('category') or self.instance or '', 'Category')}"

    @override
    @property
    def display_name(self) -> str:
        return self.title

    def generate_summary(self) -> Optional[str]:
        if not self.details or not self.details.get("category"):
            return None
        summary = f"{self.title}: {self.details.get('total', 0)} {'files' if self.details['category'] == CATEGORY_FILES else 'entries'}"
        if self.details.get(KEY_ADDED):
            summary += f" ({_format_counts(self.details[KEY_ADDED])})"
        if self.details.get(KEY_OMITTED):
            summary += f", {sum(self.details[KEY_OMITTED].values())} over the limit"
        return summary


def _rows_key(category: str) -> str:
    """Where the index keeps a category's rows."""
    return "objects" if category == CATEGORY_FILES else category


class PcapCategoryAnalyzer(AnalysisModule):
    """Adds one category of a pcap's index as observables."""

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return PcapCategoryConfig

    @property
    def generated_analysis_type(self):
        return PcapCategoryAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        if not os.path.isfile(_file.full_path) or not is_pcap_file(_file.full_path):
            return AnalysisExecutionResult.COMPLETED

        self.wait_for_analysis(_file, PcapAnalysis)
        return self._add_category(_file, final=False)

    def execute_final_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        # only reached when execute_analysis left the capture INCOMPLETE
        if not os.path.isfile(_file.full_path) or not is_pcap_file(_file.full_path):
            return AnalysisExecutionResult.COMPLETED
        return self._add_category(_file, final=True)

    def _add_category(self, _file: FileObservable, final: bool) -> AnalysisExecutionResult:
        if not _file.get_analysis(PcapAnalysis):
            # pcap_analyzer was stopped (the engine shutting down) or has not run in this pass yet,
            # e.g. after a dependency on it failed when it stopped. INCOMPLETE records nothing, so this
            # runs again in final analysis, or when the work item is picked up again, instead of
            # recording that the capture has nothing in this category.
            if not final or _stopping(self)():
                return AnalysisExecutionResult.INCOMPLETE
            return AnalysisExecutionResult.COMPLETED

        pcap_analysis = _get_pcap_analysis(_file)
        # the dissection failed: its error is on the PCAP Analysis node
        if pcap_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        config = get_config().pcap
        category = self.config.category
        index = pcap_analysis.index
        everything = collect_observables(index, config.excluded_fqdn_suffixes)
        items = [o for o in everything if o.category == category]
        # the files node may run after this one: its payload files keep their room
        reserved = [o for o in everything if o.category == CATEGORY_FILES] if category != CATEGORY_FILES else []
        rows = index.get(_rows_key(category), [])
        # nothing in the capture for this category: no node in the tree
        if not items and not rows:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapCategoryAnalysis)
        analysis.details["category"] = category
        analysis.details["capture"] = index.get("capture")
        analysis.details["field_packet_limit"] = index.get("field_packet_limit")
        analysis.details["rows"] = rows
        analysis.details["total"] = index.get(f"{_rows_key(category)}_total", len(rows))
        if category == CATEGORY_TLS:
            analysis.details["certificates"] = index.get("certificates", [])

        added, omitted = add_pcap_observables(analysis, _file, items, config.max_observables_per_type, reserved)
        analysis.details[KEY_ADDED] = added
        analysis.details[KEY_OMITTED] = omitted
        return AnalysisExecutionResult.COMPLETED


# ----------------------------------------------------------------------------------------------
# TLS decryption
# ----------------------------------------------------------------------------------------------

class PcapTlsDecryptionAnalysis(Analysis):
    """What the TLS sessions of a pcap carried, decrypted with the key logs found in the tree."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,
            "keylogs": [],
            "sessions": 0,
            "sessions_with_keys": 0,
            KEY_INDEX: None,
            KEY_ADDED: {},
            KEY_OMITTED: {},
        }

    @override
    @property
    def display_name(self) -> str:
        return "PCAP TLS Decryption"

    @property
    def error(self) -> Optional[str]:
        return self.details.get(KEY_ERROR)

    @property
    def applied_keylogs(self) -> set[str]:
        return {k["sha256"] for k in self.details.get("keylogs", [])}

    def generate_summary(self) -> Optional[str]:
        if not self.details:
            return None
        sessions = self.details.get("sessions", 0)
        if self.details.get(KEY_ERROR):
            return f"PCAP TLS Decryption: failed: {self.details[KEY_ERROR]}"
        sources = []
        if self.details.get("sessions_with_embedded_keys"):
            sources.append("embedded in the capture")
        if self.details.get("keylogs"):
            sources.append(f"{len(self.details['keylogs'])} key logs")
        if not sources:
            return f"PCAP TLS Decryption: no TLS key log found ({sessions} TLS sessions)"
        summary = (f"PCAP TLS Decryption: keys for {self.details.get('sessions_with_keys', 0)} of {sessions} TLS sessions "
                   f"({' and '.join(sources)})")
        if self.details.get(KEY_ADDED):
            summary += f", new: {_format_counts(self.details[KEY_ADDED])}"
        return summary


def apply_keylogs(config: PcapConfig, pcap_file: FileObservable, pcap_analysis: PcapAnalysis,
                  analysis: PcapTlsDecryptionAnalysis, keylog_observables: list[FileObservable],
                  stopping: Callable[[], bool] = lambda: False):
    """Decrypts the capture with every given key log and adds what the decrypted traffic shows
    beyond the plaintext index. Idempotent: calling it again with the same key logs adds nothing.
    Raises SandboxCancelled, having recorded nothing, when stopping() says the engine is shutting down."""
    keylogs = []
    # a dict keeps the first-seen order of the lines without a quadratic membership test
    lines: dict[str, None] = {}
    client_randoms: set[str] = set()
    for observable in keylog_observables:
        contents = read_keylog(observable.full_path)
        keylogs.append({"sha256": observable.sha256_hash, "file_name": observable.file_name,
                        "label_counts": contents.label_counts})
        client_randoms |= contents.client_randoms
        lines.update(dict.fromkeys(contents.lines))

    plaintext_index = pcap_analysis.index
    applied = {k["sha256"] for k in analysis.details.get("keylogs", [])}
    all_keylogs = analysis.details.get("keylogs", []) + [k for k in keylogs if k["sha256"] not in applied]
    analysis.details["capture"] = plaintext_index.get("capture")
    session_randoms = _session_randoms(plaintext_index)
    embedded_randoms = _embedded_randoms(plaintext_index)
    analysis.details["sessions"] = len(session_randoms)
    analysis.details["sessions_with_embedded_keys"] = len(embedded_randoms)
    analysis.details["sessions_with_keys"] = len(session_randoms & (client_randoms | embedded_randoms))
    has_rsa_keys = any("RSA" in k["label_counts"] for k in keylogs)
    if not lines or not ((session_randoms & client_randoms) - embedded_randoms or has_rsa_keys):
        analysis.details["keylogs"] = all_keylogs
        return

    # whatever the plaintext pass or an earlier decryption already found is not carved again
    known_sha256 = set(plaintext_index.get(KEY_CARVED_SHA256, []))
    known_sha256 |= set((analysis.details.get(KEY_INDEX) or {}).get(KEY_CARVED_SHA256, []))
    known_sha256 |= {o.sha256_hash for o in analysis.observables if isinstance(o, FileObservable)}
    # a SandboxCancelled passes through before the key logs are recorded as applied, so they are
    # applied again when the work item is picked up again
    try:
        index = dissect(config, pcap_file.full_path, f"{pcap_file.full_path}.pcap_decrypted", keylog_lines=list(lines),
                        known_sha256=known_sha256, statistics=False, stopping=stopping)
    except PcapNodeError as e:
        analysis.details["keylogs"] = all_keylogs
        analysis.details[KEY_ERROR] = str(e)
        log_loop_exception(e, f"unable to decrypt pcap {pcap_file.full_path} (sha256 {pcap_file.sha256_hash})")
        return
    except PcapError as e:
        # like a capture that cannot be dissected: the analyst sees it in the analysis
        analysis.details["keylogs"] = all_keylogs
        analysis.details[KEY_ERROR] = str(e)
        logging.info("unable to decrypt pcap %s (sha256 %s): %s", pcap_file.full_path, pcap_file.sha256_hash, e,
                     extra={"pcap_sha256": pcap_file.sha256_hash})
        return

    analysis.details["keylogs"] = all_keylogs
    index.pop(KEY_CLIENT_RANDOMS, None)
    analysis.details[KEY_ERROR] = None
    analysis.details[KEY_INDEX] = merge_index(analysis.details.get(KEY_INDEX), index, config.max_table_rows)
    plaintext_keys = {o.key for o in collect_observables(plaintext_index, config.excluded_fqdn_suffixes)}
    items = [o for o in collect_observables(index, config.excluded_fqdn_suffixes)
             if o.category != CATEGORY_HOSTS and o.key not in plaintext_keys]
    added, omitted = add_pcap_observables(analysis, pcap_file, items, config.max_observables_per_type)
    _merge_counts(analysis.details, KEY_ADDED, added)
    _merge_counts(analysis.details, KEY_OMITTED, omitted)
    logging.info("decrypted TLS in pcap %s with %s key logs: keys for %s of %s sessions, added %s",
                 pcap_file.full_path, len(keylogs), analysis.details["sessions_with_keys"],
                 analysis.details["sessions"], added,
                 extra={"pcap_sha256": pcap_file.sha256_hash, "keylog_sha256": [k["sha256"] for k in keylogs]})


class PcapTlsDecryptor(AnalysisModule):
    """Decrypts the TLS in a pcap with the key logs in the tree, once everything else is analyzed."""

    @property
    def generated_analysis_type(self):
        return PcapTlsDecryptionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        # INCOMPLETE leaves a pcap to execute_final_analysis, when every key log is in the tree
        if os.path.isfile(_file.full_path) and is_pcap_file(_file.full_path):
            return AnalysisExecutionResult.INCOMPLETE
        return AnalysisExecutionResult.COMPLETED

    def execute_final_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        if not os.path.isfile(_file.full_path) or not is_pcap_file(_file.full_path):
            return AnalysisExecutionResult.COMPLETED

        pcap_analysis = _get_pcap_analysis(_file)
        if pcap_analysis is None or not pcap_analysis.index.get(CATEGORY_TLS):
            return AnalysisExecutionResult.COMPLETED

        config = get_config().pcap
        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapTlsDecryptionAnalysis)
        left = self.time_left()
        if _run_seconds(config) > left:
            analysis.details[KEY_ERROR] = _out_of_time(_run_seconds(config), left)
            logging.info("not decrypting pcap %s (sha256 %s): %s s needed, %.0f s left", _file.full_path,
                         _file.sha256_hash, _run_seconds(config), left, extra={"pcap_sha256": _file.sha256_hash})
            return AnalysisExecutionResult.COMPLETED

        keylogs = find_keylog_observables(self.get_root(), config.max_keylog_size)
        try:
            apply_keylogs(config, _file, pcap_analysis, analysis, keylogs, stopping=_stopping(self))
        except SandboxCancelled as e:
            # without the analysis this runs again when the work item is picked up again
            _file.delete_analysis(analysis)
            logging.info("%s", e, extra={"pcap_sha256": _file.sha256_hash})
            return AnalysisExecutionResult.INCOMPLETE
        return AnalysisExecutionResult.COMPLETED


# ----------------------------------------------------------------------------------------------
# key log analysis
# ----------------------------------------------------------------------------------------------

class TlsKeylogAnalysis(Analysis):
    """A TLS key log (SSLKEYLOGFILE format). The secrets themselves are never stored here."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {"label_counts": {}, "client_randoms": 0, "applied_to": [], "skipped": []}

    @override
    @property
    def display_name(self) -> str:
        return "TLS Key Log"

    def generate_summary(self) -> Optional[str]:
        if not self.details:
            return None
        counts = self.details.get("label_counts", {})
        summary = (f"TLS Key Log: {sum(counts.values())} secrets for {self.details.get('client_randoms', 0)} "
                   f"TLS sessions ({_format_counts(counts)})")
        if self.details.get("applied_to"):
            summary += f", applied to {len(self.details['applied_to'])} pcaps"
        if self.details.get("skipped"):
            summary += f", not applied to {len(self.details['skipped'])} pcaps (out of time)"
        return summary


class TlsKeylogAnalyzer(AnalysisModule):
    """Recognizes a TLS key log by its content. When the key log arrives after a pcap's decryption
    analysis completed (an analyst adds it to the alert), decrypts that pcap with it."""

    @property
    def generated_analysis_type(self):
        return TlsKeylogAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        config = get_config().pcap
        path = _file.full_path
        if not os.path.isfile(path) or os.path.getsize(path) > config.max_keylog_size or not is_keylog_file(path):
            return AnalysisExecutionResult.COMPLETED

        contents = read_keylog(path)
        analysis = self.create_analysis(_file)
        assert isinstance(analysis, TlsKeylogAnalysis)
        analysis.details["label_counts"] = contents.label_counts
        analysis.details["client_randoms"] = len(contents.client_randoms)
        _file.add_tag(TAG_TLS_KEYLOG)

        root = self.get_root()
        for pcap_file in root.get_observables_by_type(F_FILE):
            decryption = pcap_file.get_and_load_analysis(PcapTlsDecryptionAnalysis)
            # not decrypted yet: its final analysis finds this key log by itself
            if not isinstance(decryption, PcapTlsDecryptionAnalysis) or not decryption.completed:
                continue
            if _file.sha256_hash in decryption.applied_keylogs:
                continue
            pcap_analysis = _get_pcap_analysis(pcap_file)
            if pcap_analysis is None:
                continue
            # the key logs applied before already decrypted what they could: only sessions this one
            # has keys for are worth another tshark run
            new_sessions = (_session_randoms(pcap_analysis.index) & contents.client_randoms) - _embedded_randoms(pcap_analysis.index)
            if not new_sessions and "RSA" not in contents.label_counts:
                continue
            # one tshark run per pcap: the pcaps left over once a run no longer fits in the time left
            # are skipped and said so
            if _run_seconds(config) > self.time_left():
                analysis.details["skipped"].append(pcap_file.sha256_hash)
                continue

            logging.info("applying late TLS key log %s to pcap %s", path, pcap_file.full_path,
                         extra={"keylog_sha256": _file.sha256_hash, "pcap_sha256": pcap_file.sha256_hash})
            try:
                apply_keylogs(config, pcap_file, pcap_analysis, decryption, find_keylog_observables(root, config.max_keylog_size),
                              stopping=_stopping(self))
            except SandboxCancelled as e:
                # without this analysis the key log is applied again, to the pcaps it was not applied
                # to yet, when the work item is picked up again
                _file.delete_analysis(analysis)
                logging.info("%s", e, extra={"keylog_sha256": _file.sha256_hash, "pcap_sha256": pcap_file.sha256_hash})
                return AnalysisExecutionResult.INCOMPLETE
            decryption.set_details_modified()
            analysis.details["applied_to"].append(pcap_file.sha256_hash)

        if analysis.details["skipped"]:
            logging.info("out of time to apply TLS key log %s to %s more pcaps", path, len(analysis.details["skipped"]),
                         extra={"keylog_sha256": _file.sha256_hash, "pcap_sha256": analysis.details["skipped"]})
        return AnalysisExecutionResult.COMPLETED


# ----------------------------------------------------------------------------------------------
# presentation
# ----------------------------------------------------------------------------------------------

# columns whose values (addresses, fingerprints) must never be split across lines
NOWRAP_COLUMNS = {"Server", "JA4", "A", "B", "Address"}


def _pivot(o_type: str, value: Optional[str], text: Optional[str] = None) -> Optional[dict]:
    """A cell the GUI renders as a link to the alerts that have this observable, like a click on an
    observable in the alert tree."""
    if not value:
        return None
    return {"text": text or value, "pivot_type": o_type, "pivot_value": value}


def _ip_pivot(address: Optional[str], text: Optional[str] = None):
    """A link for an address the hosts analysis adds as an observable; plain text for one it never adds."""
    if address and _is_interesting_ip(address):
        return _pivot(F_IP, address, text)
    return text or address


def _mac_pivot(address: Optional[str]):
    if not address:
        return address
    mac = normalize_mac_address(address)
    if mac is None:
        return address
    return _pivot(F_MAC_ADDRESS, mac) if _is_interesting_mac(address) else mac


def _flow_endpoint(endpoint: str):
    # conversations print address:port with no brackets around an IPv6 address
    return _ip_pivot(endpoint.rsplit(":", 1)[0], endpoint)


def _table(title: str, columns: list[str], rows: list[list], total: Optional[int] = None,
           order: Optional[str] = None, note: Optional[str] = None) -> dict:
    return {"title": title, "columns": columns, "rows": rows, "total": total if total is not None else len(rows),
            "nowrap": [column in NOWRAP_COLUMNS for column in columns], "order": order, "note": note}


JA4_NOTE = ("JA4 fingerprints the client that started the session (its TLS ClientHello), not the server. "
            "Every session from the same browser or application has the same JA4, whatever site it went to, "
            "so one JA4 across many sites is normal. An unexpected JA4 points at an unusual client.")


def _capture_order(what: str, capture: Optional[dict]) -> str:
    """How a table kept in the order things appear in the capture reads in time."""
    time_order = (capture or {}).get("strict_time_order")
    if time_order is True:
        return f"{what}, which is chronological."
    if time_order is False:
        return (f"{what}. The packets in this capture are not in time order, so this is not strictly "
                "chronological.")
    return f"{what}."


def _packet_limit_note(limit: Optional[int], capture: Optional[dict]) -> Optional[str]:
    """Says a table was read from the start of the capture only, when it was."""
    packets = (capture or {}).get("packets")
    if not limit or packets is None or packets <= limit:
        return None
    return f"Read from the first {limit:,} of the capture's {packets:,} packets only."


def _notes(*notes: Optional[str]) -> Optional[str]:
    return " ".join(note for note in notes if note) or None


def _format_time_range(capture: dict) -> Optional[str]:
    if capture.get("first") is None or capture.get("last") is None:
        return None
    first = datetime.datetime.fromtimestamp(capture["first"], datetime.timezone.utc)
    last = datetime.datetime.fromtimestamp(capture["last"], datetime.timezone.utc)
    end = last.strftime("%H:%M:%S") if last.date() == first.date() else last.strftime("%Y-%m-%d %H:%M:%S")
    duration = capture.get("duration")
    if duration is None:
        length = ""
    elif duration < 60:
        length = f" ({duration:.1f} s)"
    else:
        length = f" ({datetime.timedelta(seconds=round(duration))})"
    return f"{first.strftime('%Y-%m-%d %H:%M:%S')} to {end} UTC{length}"


def capture_summary(capture: Optional[dict]) -> list[str]:
    """The parts of the line that says which capture a table page came from."""
    if not capture:
        return []
    parts = [capture.get("file_name"), capture.get("format")]
    if capture.get("size") is not None:
        parts.append(human_readable_size(capture["size"]))
    if capture.get("encapsulations"):
        interfaces = capture.get("interfaces") or 0
        parts.append(f"{', '.join(capture['encapsulations'])}, {interfaces} interface{'' if interfaces == 1 else 's'}")
    if capture.get("packets") is not None:
        parts.append(f"{capture['packets']:,} packets")
    parts.append(_format_time_range(capture))
    if capture.get("application"):
        # "Dumpcap (Wireshark) 4.4.19 (Git v4.4.19 packaged as ...)": the build details add nothing
        parts.append(f"written by {re.sub(r' [(]Git [^)]*[)]$', '', capture['application'])}")
    return [part for part in parts if part]


def index_tables(index: Optional[dict], category: Optional[str] = None, capture: Optional[dict] = None) -> list[dict]:
    """The tables shown for one category of an index (or all of them when category is None)."""
    if not index:
        return []

    tables = []
    limit_note = _packet_limit_note(index.get("field_packet_limit"), capture)
    if category in (None, CATEGORY_DNS) and index.get(CATEGORY_DNS):
        tables.append(_table("DNS", ["Name", "Answers", "Queries", "Responses"],
                             [[r["name"], ", ".join(r["answers"]), r.get("queries"), r.get("responses")]
                              for r in index[CATEGORY_DNS]],
                             index.get(f"{CATEGORY_DNS}_total"),
                             _capture_order("Names in the order they first appear in the capture", capture), limit_note))
    if category in (None, CATEGORY_TLS) and index.get(CATEGORY_TLS):
        certificates = {c["sha256"]: c for c in index.get("certificates", [])}
        tables.append(_table("TLS Sessions", ["Server", "SNI", "JA4", "Certificates"],
                             [[r.get("server"), r.get("sni"), _pivot(F_JA4, r.get("ja4")),
                               [describe_certificate(certificates.get(h, {"sha256": h})) for h in r.get("certificates", [])]]
                              for r in index[CATEGORY_TLS]], index.get(f"{CATEGORY_TLS}_total"),
                             _capture_order("Sessions in the order their handshakes start", capture),
                             _notes(JA4_NOTE, limit_note)))
    if category in (None, CATEGORY_HTTP) and index.get(CATEGORY_HTTP):
        tables.append(_table("HTTP Requests", ["Method", "URL", "Status", "Content Type", "User Agent"],
                             [[r.get("method"), _pivot(F_URL, r.get("url")), r.get("status"), r.get("content_type"),
                               r.get("user_agent")]
                              for r in index[CATEGORY_HTTP]], index.get(f"{CATEGORY_HTTP}_total"),
                             _capture_order("Requests in the order they were sent", capture), limit_note))
    if category in (None, CATEGORY_FILES) and index.get("objects"):
        tables.append(_table("Carved Files", ["Protocol", "File Name", "Size", "SHA256", "URL"],
                             # a file observable's value is its sha256, so the file name pivots on the content
                             [[r["protocol"], _pivot(F_FILE, r["sha256"], text=r["file_name"]), r["size"],
                               _pivot(F_SHA256, r["sha256"]), _pivot(F_URL, r.get("url"))] for r in index["objects"]],
                             index.get("objects_total"),
                             # tshark's object export does not say when each object crossed the wire
                             order="By protocol, then file name. Not chronological."))
    return tables


class PcapAnalysisPresenter(AnalysisPresenter):

    @property
    def template_path(self) -> str:
        return "analysis/pcap_analysis.html"

    @property
    def capture(self) -> Optional[dict]:
        details = self._analysis.details or {}
        if isinstance(self._analysis, PcapAnalysis):
            return (details.get(KEY_INDEX) or {}).get("capture")
        return details.get("capture")

    @property
    def capture_summary(self) -> list[str]:
        return capture_summary(self.capture)

    @property
    def notice(self) -> Optional[str]:
        """What the page is missing although the analysis did not fail."""
        if isinstance(self._analysis, PcapAnalysis) and (self._analysis.index or {}).get("statistics_error"):
            return (f"No endpoint or flow tables: the packet statistics pass failed "
                    f"({self._analysis.index['statistics_error']}).")
        return None

    @property
    def tables(self) -> list[dict]:
        details = self._analysis.details or {}
        analysis = self._analysis
        capture = self.capture
        if isinstance(analysis, PcapAnalysis):
            index = details.get(KEY_INDEX) or {}
            statistics = index.get("statistics", {})
            tables = []
            embedded = index.get("embedded_secrets")
            if embedded:
                rows = [[f"{name} secrets blocks", count] for name, count in sorted(embedded["types"].items())]
                rows += [[f"TLS {label}", count] for label, count in sorted(embedded.get("label_counts", {}).items())]
                rows.append(["TLS sessions with keys", len(embedded.get("keyed_client_randoms", []))])
                tables.append(_table("Embedded Decryption Secrets", ["Secret", "Count"], rows))
            if index.get("hostnames"):
                tables.append(_table("Hostnames", ["Name", "Source", "MAC"],
                                     [[_pivot(F_HOSTNAME, r["name"]), r["source"], _mac_pivot(r.get("mac"))]
                                      for r in index["hostnames"]], index.get("hostnames_total"),
                                     _capture_order("In the order they first appear in the capture", capture),
                                     _packet_limit_note(index.get("field_packet_limit"), capture)))
            if statistics.get("ip"):
                tables.append(_table("IP Endpoints", ["Address", "Packets", "Bytes"],
                                     [[_ip_pivot(r["address"]), r["packets"], r["bytes"]] for r in statistics["ip"]],
                                     statistics.get("ip_total"),
                                     order="Most packets first."))
            if statistics.get("mac"):
                tables.append(_table("Ethernet Endpoints", ["Address", "Packets", "Bytes"],
                                     [[_mac_pivot(r["address"]), r["packets"], r["bytes"]] for r in statistics["mac"]],
                                     statistics.get("mac_total"),
                                     order="Most packets first."))
            if statistics.get("flows"):
                tables.append(_table("Flows", ["Protocol", "A", "B", "Frames", "Bytes", "Start", "Duration"],
                                     [[r["protocol"], _flow_endpoint(r["a"]), _flow_endpoint(r["b"]), r["frames"], r["bytes"],
                                       r["start"], r["duration"]]
                                      for r in statistics["flows"]], statistics.get("flows_total"),
                                     order="Most frames first. Start is seconds after the first packet."))
            return tables
        if isinstance(analysis, PcapCategoryAnalysis):
            category = details.get("category")
            rows_key = _rows_key(category)
            index = {rows_key: details.get("rows", []), f"{rows_key}_total": details.get("total"),
                     "certificates": details.get("certificates", []),
                     "field_packet_limit": details.get("field_packet_limit")}
            return index_tables(index, category, capture)
        if isinstance(analysis, PcapTlsDecryptionAnalysis):
            rows = []
            if details.get("sessions_with_embedded_keys"):
                rows.append(["(embedded in the capture)", "", f"keys for {details['sessions_with_embedded_keys']} TLS sessions"])
            rows += [[k["file_name"], k["sha256"], _format_counts(k["label_counts"])] for k in details.get("keylogs", [])]
            tables = [_table("Key Sources", ["Source", "SHA256", "Secrets"], rows)] if rows else []
            return tables + index_tables(details.get(KEY_INDEX), capture=capture)
        if isinstance(analysis, TlsKeylogAnalysis):
            return [_table("Secrets", ["Label", "Count"], [[k, v] for k, v in sorted(details.get("label_counts", {}).items())])]
        return []


for _analysis_class in (PcapAnalysis, PcapCategoryAnalysis, PcapTlsDecryptionAnalysis, TlsKeylogAnalysis):
    register_analysis_presenter(_analysis_class, PcapAnalysisPresenter)

# the analyses whose observables share one capture's max_observables_per_type
PCAP_ANALYSIS_TYPES = (PcapAnalysis, PcapCategoryAnalysis, PcapTlsDecryptionAnalysis)
