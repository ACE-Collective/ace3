"""Dissects pcap/pcapng captures with tshark and turns what they carried into observables.

tshark's dissectors parse untrusted bytes and have a long CVE history, so tshark only ever runs in
the Landlock sandbox (saq/sandbox/runner.py): no network, nothing of ACE readable, bounded by a
timeout, rlimits and an output cap. See docs/PCAP_ANALYSIS.md for the analysis tree this builds.

One tshark run per capture builds an *index* (stored in PcapAnalysis.details); every other pcap
analysis reads that index instead of running tshark again:

- PcapAnalyzer: the index, the flows table and the hosts (IPs, MACs, hostnames)
- PcapCategoryAnalyzer: one configured instance per category (dns, tls, http, files)
- PcapTlsDecryptor: runs in final analysis, so every TLS key log in the tree (also one extracted
  late, from an archive) is known by then; adds only what the decrypted traffic shows beyond the
  plaintext index
- TlsKeylogAnalyzer: recognizes key logs by content and applies one added after the pcap's
  decryption analysis already completed
"""

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from typing import Literal, Optional, override
from urllib.parse import urlsplit

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.configuration.schema import SandboxConfig
from saq.constants import (
    F_FILE,
    F_FQDN,
    F_HOSTNAME,
    F_IP,
    F_JA4,
    F_MAC_ADDRESS,
    F_URL,
    F_USER_AGENT,
    R_DOWNLOADED_FROM,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.environment import get_data_dir
from saq.error.reporting import log_loop_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_pcap_file
from saq.observables.file import FileObservable
from saq.sandbox.runner import (
    build_sandbox_argv,
    create_workdir,
    landlock_available,
    run_sandboxed,
    sweep_stale_workdirs,
)

TAG_TLS_KEYLOG = "tls_keylog"

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
    "frame.number",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "udp.stream", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.flags.response", "dns.qry.name", "dns.resp.name", "dns.cname", "dns.a", "dns.aaaa",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja4",
    "tls.handshake.random", "tls.handshake.certificate",
    "http.request.method", "http.host", "http.request.full_uri", "http.user_agent",
    "http.response.code", "http.content_type", "http.request_in",
    "http2.headers.method", "http2.headers.scheme", "http2.headers.authority", "http2.headers.path",
    "http2.headers.user_agent",
    "dhcp.option.hostname", "dhcp.hw.mac_addr", "nbns.name",
)

EXPORT_OBJECT_PROTOCOLS = ("http", "smb", "ftp-data", "tftp", "imf")

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
KEY_WARNING = "warning"
KEY_INDEX = "index"
KEY_ADDED = "added"
KEY_OMITTED = "omitted"


class PcapError(Exception):
    """tshark could not dissect the capture."""


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


def read_keylog(path: str) -> KeylogContents:
    """Every valid key log line of the file. Anything else in it is dropped, so what reaches tshark
    is only key material."""
    label_counts: dict[str, int] = {}
    client_randoms: set[str] = set()
    lines: list[str] = []
    with open(path, "r", encoding="ascii", errors="ignore") as fp:
        for line in fp:
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


def find_keylog_observables(root, max_size: int) -> list[FileObservable]:
    """Every file in the tree that is a TLS key log, whatever its name."""
    result = []
    for observable in root.get_observables_by_type(F_FILE):
        path = observable.full_path
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > max_size:
                continue
        except OSError:
            continue
        if is_keylog_file(path):
            result.append(observable)

    return sorted(result, key=lambda o: o.sha256_hash or "")


# ----------------------------------------------------------------------------------------------
# running tshark
# ----------------------------------------------------------------------------------------------

class PcapModuleConfig(AnalysisModuleConfig):
    tshark_path: str = Field(default="/usr/bin/tshark", description="the tshark binary")
    tshark_timeout: int = Field(default=240, gt=0, description="seconds one tshark run may take")
    work_dir: str = Field(default="var/pcap_sandbox", description="where each tshark run gets its private working directory (relative to DATA_DIR)")
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig, description="limits for the sandboxed tshark process; allowed_tcp_ports stays empty (no network)")
    max_file_size: int = Field(default=1024 ** 3, gt=0, description="largest capture dissected, in bytes")
    max_keylog_size: int = Field(default=10 * 1024 ** 2, gt=0, description="largest file considered as a TLS key log, in bytes")
    max_table_rows: int = Field(default=500, gt=0, description="most rows kept in each table of the analysis details")
    max_extracted_files: int = Field(default=100, ge=0, description="most files carved out of one capture (objects and certificates)")
    max_observables_per_type: int = Field(default=100, ge=0, description="most observables of one type one pcap analysis adds")
    excluded_fqdn_suffixes: list[str] = Field(default_factory=lambda: [".arpa", ".local"], description="names ending in one of these are never added as fqdn observables")


class PcapCategoryConfig(PcapModuleConfig):
    category: Literal["dns", "tls", "http", "files"] = Field(..., description="which part of the capture index this instance turns into observables")


def _run_tshark(config: PcapModuleConfig, workdir: str, args: list[str]) -> str:
    """Runs tshark on <workdir>/input in the sandbox and returns its stdout."""
    if not landlock_available():
        raise PcapError("the Landlock sandbox is not available on this node; tshark is never run unsandboxed")

    timeout = datetime.timedelta(seconds=config.tshark_timeout)
    argv = build_sandbox_argv([config.tshark_path, "-n", "-r", "input", *args], workdir, config.sandbox, timeout)
    # never os.environ: Landlock does not filter the environment and ACE's carries secrets
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": workdir}
    try:
        result = run_sandboxed(argv, None, env, workdir, timeout, config.sandbox.max_output_bytes)
    except RuntimeError as e:
        raise PcapError(f"tshark failed: {e}") from e

    # a capture cut short mid-packet exits non-zero after printing everything before the cut
    if result.returncode != 0 and not result.stdout.strip():
        raise PcapError(f"tshark exited with {result.returncode}: {result.stderr.strip()[-500:]}")

    if result.returncode != 0:
        logging.info("tshark exited with %s but produced output: %s", result.returncode, result.stderr.strip()[-500:])

    return result.stdout


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _unique_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    index = 1
    while os.path.exists(f"{base}_{index}{ext}"):
        index += 1
    return f"{base}_{index}{ext}"


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

        for name in layers.get("dns.qry.name", []) + layers.get("dns.resp.name", []) + layers.get("dns.cname", []):
            entry = dns.setdefault(name.lower(), {"name": name.lower(), "answers": [], "count": 0})
            entry["count"] += 1
        if _first(layers, "dns.flags.response") in ("True", "1", "true"):
            answers = layers.get("dns.a", []) + layers.get("dns.aaaa", []) + layers.get("dns.cname", [])
            for name in layers.get("dns.qry.name", []):
                entry = dns[name.lower()]
                for answer in answers:
                    if answer not in entry["answers"]:
                        entry["answers"].append(answer)

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
        CATEGORY_HTTP: list(http.values()),
        "hostnames": list(hostnames.values()),
        "objects": objects,
        "certificates": [{"sha256": c["sha256"], "path": c["path"]} for c in certificates],
    }
    for key in (CATEGORY_DNS, CATEGORY_TLS, CATEGORY_HTTP, "hostnames"):
        index[f"{key}_total"] = len(index[key])
        index[key] = index[key][:max_rows]

    return index


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
                continue
            sha256 = hashlib.sha256(der).hexdigest()
            entry = {"sha256": sha256, "der_hex": der_hex, "path": None}
            if sha256 not in known_sha256 and remaining > 0:
                path = os.path.join(target_dir, "certificates", f"{sha256}.der")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fp:
                    fp.write(der)
                entry["path"] = os.path.relpath(path, base_dir)
                remaining -= 1
            certificates.append(entry)

    objects_dir = os.path.join(workdir, "objects")
    for protocol in EXPORT_OBJECT_PROTOCOLS:
        protocol_dir = os.path.join(objects_dir, protocol)
        if not os.path.isdir(protocol_dir):
            continue
        for file_name in sorted(os.listdir(protocol_dir)):
            source = os.path.join(protocol_dir, file_name)
            if not os.path.isfile(source) or os.path.islink(source):
                continue
            sha256 = _sha256_file(source)
            if sha256 in known_sha256 or any(o["sha256"] == sha256 for o in objects):
                continue
            entry = {"protocol": protocol, "file_name": file_name, "sha256": sha256,
                     "size": os.path.getsize(source), "path": None}
            if remaining > 0:
                target = _unique_path(os.path.join(target_dir, protocol, file_name))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.move(source, target)
                entry["path"] = os.path.relpath(target, base_dir)
                remaining -= 1
            objects.append(entry)

    return objects, certificates


def _link_http_objects(index: dict):
    """An exported HTTP object is named after the last segment of its URL path; link it to that URL
    when exactly one request in the capture matches."""
    by_name: dict[str, set[str]] = {}
    for request in index[CATEGORY_HTTP]:
        if not request.get("url"):
            continue
        name = os.path.basename(urlsplit(request["url"]).path)
        if name:
            by_name.setdefault(name, set()).add(request["url"])

    for entry in index["objects"]:
        if entry["protocol"] != "http":
            continue
        urls = by_name.get(entry["file_name"], set())
        entry["url"] = next(iter(urls)) if len(urls) == 1 else None


def dissect(config: PcapModuleConfig, pcap_path: str, target_dir: str, keylog_lines: Optional[list[str]] = None,
            known_sha256: Optional[set[str]] = None, statistics: bool = True) -> dict:
    """Runs tshark over the capture and returns its index. Carved files land in target_dir."""
    work_root = os.path.join(get_data_dir(), config.work_dir)
    sweep_stale_workdirs(work_root)
    with create_workdir(work_root) as workdir:
        # a copy, never a hard link: tshark may write anything in its workdir, and through a link
        # it could change the evidence itself
        shutil.copyfile(pcap_path, os.path.join(workdir, "input"))
        os.mkdir(os.path.join(workdir, "objects"))

        index_stats = {}
        if statistics:
            output = _run_tshark(config, workdir, ["-q", "-z", "io,stat,0", "-z", "endpoints,eth", "-z", "endpoints,ip",
                                                   "-z", "endpoints,ipv6", "-z", "conv,tcp", "-z", "conv,udp"])
            index_stats = _parse_statistics(output, config.max_table_rows)

        args = ["-T", "json", "-Y", DISPLAY_FILTER]
        for field in TSHARK_FIELDS:
            args.extend(["-e", field])
        for protocol in EXPORT_OBJECT_PROTOCOLS:
            args.extend(["--export-objects", f"{protocol},objects/{protocol}"])
        if keylog_lines:
            with open(os.path.join(workdir, "keylog"), "w") as fp:
                fp.write("\n".join(keylog_lines) + "\n")
            args.extend(["-o", "tls.keylog_file:keylog"])

        packets = _parse_fields(_run_tshark(config, workdir, args))
        objects, certificates = _collect_carved_files(workdir, target_dir, packets, config.max_extracted_files,
                                                      known_sha256 or set())

    index = build_index(packets, certificates, objects, config.max_table_rows)
    _link_http_objects(index)
    if statistics:
        index["statistics"] = index_stats
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


def _host_observable(category: str, host: str, excluded_suffixes: list[str]) -> Optional[PcapObservable]:
    host = _host_without_port(host).rstrip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return PcapObservable(category, F_IP, host, volatile=True) if _is_interesting_ip(host) else None
    except ValueError:
        pass
    if any(host.endswith(suffix) for suffix in excluded_suffixes):
        return None
    return PcapObservable(category, F_FQDN, host)


def collect_observables(index: dict, excluded_fqdn_suffixes: list[str]) -> list[PcapObservable]:
    """Every observable the index holds, each in the category whose analysis adds it."""
    result: list[PcapObservable] = []

    def _add(item: Optional[PcapObservable]):
        if item is not None and item not in result:
            result.append(item)

    statistics = index.get("statistics", {})
    for row in statistics.get("ip", []):
        if _is_interesting_ip(row["address"]):
            _add(PcapObservable(CATEGORY_HOSTS, F_IP, row["address"], volatile=True))
    for row in statistics.get("mac", []):
        if _is_interesting_mac(row["address"]):
            _add(PcapObservable(CATEGORY_HOSTS, F_MAC_ADDRESS, row["address"], volatile=True))
    for row in index.get("hostnames", []):
        _add(PcapObservable(CATEGORY_HOSTS, F_HOSTNAME, row["name"], volatile=True))

    for row in index.get(CATEGORY_DNS, []):
        _add(_host_observable(CATEGORY_DNS, row["name"], excluded_fqdn_suffixes))
        for answer in row["answers"]:
            _add(_host_observable(CATEGORY_DNS, answer, excluded_fqdn_suffixes))

    for row in index.get(CATEGORY_TLS, []):
        if row.get("sni"):
            _add(_host_observable(CATEGORY_TLS, row["sni"], excluded_fqdn_suffixes))
        if row.get("ja4"):
            _add(PcapObservable(CATEGORY_TLS, F_JA4, row["ja4"]))
    for row in index.get("certificates", []):
        if row.get("path"):
            _add(PcapObservable(CATEGORY_TLS, F_FILE, row["sha256"], path=row["path"]))

    for row in index.get(CATEGORY_HTTP, []):
        if row.get("url") and urlsplit(row["url"]).scheme in ("http", "https"):
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
                         max_per_type: int) -> tuple[dict[str, int], dict[str, int]]:
    """Adds the observables to the analysis, at most max_per_type of each type (counting the ones it
    already has). Returns (added, omitted) counts by type."""
    added: dict[str, int] = {}
    omitted: dict[str, int] = {}
    present = {_observable_key(o) for o in analysis.observables}
    per_type: dict[str, int] = {}
    for o in analysis.observables:
        per_type[o.type] = per_type.get(o.type, 0) + 1

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
                if item.downloaded_from:
                    url = analysis.add_observable_by_spec(F_URL, item.downloaded_from)
                    if url is not None:
                        url.sort_order = SORT_ORDER[F_URL]
                        observable.add_relationship(R_DOWNLOADED_FROM, url)
        else:
            observable = analysis.add_observable_by_spec(item.o_type, item.value, volatile=item.volatile)

        # None: an invalid value for its type, or the root's per-type limit was reached
        if observable is None:
            omitted[item.o_type] = omitted.get(item.o_type, 0) + 1
            continue

        # set here: Observable.__init__ does not pass its sort_order argument on
        observable.sort_order = SORT_ORDER.get(item.o_type, 100)

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


def _get_pcap_analysis(observable: FileObservable) -> Optional["PcapAnalysis"]:
    analysis = observable.get_and_load_analysis(PcapAnalysis)
    if not isinstance(analysis, PcapAnalysis) or analysis.error or analysis.index is None:
        return None
    return analysis


# ----------------------------------------------------------------------------------------------
# core analysis
# ----------------------------------------------------------------------------------------------

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
        summary = (f"PCAP Analysis: {statistics.get('packets', 0)} packets, {statistics.get('flows_total', 0)} flows, "
                   f"{len(self.index.get(CATEGORY_TLS, []))} TLS sessions")
        if self.details.get(KEY_ADDED):
            summary += f" ({_format_counts(self.details[KEY_ADDED])})"
        return summary


class PcapAnalyzer(AnalysisModule):
    """Dissects a pcap/pcapng file with sandboxed tshark."""

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return PcapModuleConfig

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

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapAnalysis)

        size = os.path.getsize(path)
        if size > self.config.max_file_size:
            analysis.error = f"{size} bytes exceeds max_file_size {self.config.max_file_size}"
            return AnalysisExecutionResult.COMPLETED

        try:
            index = dissect(self.config, path, f"{path}.pcap_objects")
        except Exception as e:
            analysis.error = str(e)
            log_loop_exception(e, f"unable to dissect pcap {path} (sha256 {_file.sha256_hash}) in {self.get_root().uuid}")
            return AnalysisExecutionResult.COMPLETED

        analysis.details[KEY_INDEX] = index
        hosts = [o for o in collect_observables(index, self.config.excluded_fqdn_suffixes) if o.category == CATEGORY_HOSTS]
        added, omitted = add_pcap_observables(analysis, _file, hosts, self.config.max_observables_per_type)
        analysis.details[KEY_ADDED] = added
        analysis.details[KEY_OMITTED] = omitted
        return AnalysisExecutionResult.COMPLETED


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
        pcap_analysis = _get_pcap_analysis(_file)
        if pcap_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        category = self.config.category
        index = pcap_analysis.index
        items = [o for o in collect_observables(index, self.config.excluded_fqdn_suffixes) if o.category == category]
        rows = index.get("objects", []) if category == CATEGORY_FILES else index.get(category, [])
        # nothing in the capture for this category: no node in the tree
        if not items and not rows:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapCategoryAnalysis)
        analysis.details["category"] = category
        analysis.details["rows"] = rows
        analysis.details["total"] = len(rows) if category == CATEGORY_FILES else index.get(f"{category}_total", len(rows))
        if category == CATEGORY_TLS:
            analysis.details["certificates"] = index.get("certificates", [])

        added, omitted = add_pcap_observables(analysis, _file, items, self.config.max_observables_per_type)
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
        if not self.details.get("keylogs"):
            return f"PCAP TLS Decryption: no TLS key log found ({sessions} TLS sessions)"
        summary = (f"PCAP TLS Decryption: keys for {self.details.get('sessions_with_keys', 0)} of {sessions} TLS sessions "
                   f"({len(self.details['keylogs'])} key logs)")
        if self.details.get(KEY_ADDED):
            summary += f", new: {_format_counts(self.details[KEY_ADDED])}"
        return summary


def apply_keylogs(config: PcapModuleConfig, pcap_file: FileObservable, pcap_analysis: PcapAnalysis,
                  analysis: PcapTlsDecryptionAnalysis, keylog_observables: list[FileObservable]):
    """Decrypts the capture with every given key log and adds what the decrypted traffic shows
    beyond the plaintext index. Idempotent: calling it again with the same key logs adds nothing."""
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
    analysis.details["keylogs"] = keylogs
    session_randoms = {s.get("client_random") for s in plaintext_index.get(CATEGORY_TLS, []) if s.get("client_random")}
    analysis.details["sessions"] = len(session_randoms)
    analysis.details["sessions_with_keys"] = len(session_randoms & client_randoms)
    has_rsa_keys = any("RSA" in k["label_counts"] for k in keylogs)
    if not lines or not (session_randoms & client_randoms or has_rsa_keys):
        return

    known_sha256 = {o["sha256"] for o in plaintext_index.get("objects", [])}
    known_sha256 |= {c["sha256"] for c in plaintext_index.get("certificates", [])}
    known_sha256 |= {o.sha256_hash for o in analysis.observables if isinstance(o, FileObservable)}
    try:
        index = dissect(config, pcap_file.full_path, f"{pcap_file.full_path}.pcap_decrypted", keylog_lines=list(lines),
                        known_sha256=known_sha256, statistics=False)
    except Exception as e:
        analysis.details[KEY_ERROR] = str(e)
        log_loop_exception(e, f"unable to decrypt pcap {pcap_file.full_path} (sha256 {pcap_file.sha256_hash})")
        return

    analysis.details[KEY_ERROR] = None
    analysis.details[KEY_INDEX] = index
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

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return PcapModuleConfig

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

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, PcapTlsDecryptionAnalysis)
        keylogs = find_keylog_observables(self.get_root(), self.config.max_keylog_size)
        apply_keylogs(self.config, _file, pcap_analysis, analysis, keylogs)
        return AnalysisExecutionResult.COMPLETED


# ----------------------------------------------------------------------------------------------
# key log analysis
# ----------------------------------------------------------------------------------------------

class TlsKeylogAnalysis(Analysis):
    """A TLS key log (SSLKEYLOGFILE format). The secrets themselves are never stored here."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {"label_counts": {}, "client_randoms": 0, "applied_to": []}

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
        return summary


class TlsKeylogAnalyzer(AnalysisModule):
    """Recognizes a TLS key log by its content. When the key log arrives after a pcap's decryption
    analysis completed (an analyst adds it to the alert), decrypts that pcap with it."""

    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return PcapModuleConfig

    @property
    def generated_analysis_type(self):
        return TlsKeylogAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        path = _file.full_path
        if not os.path.isfile(path) or os.path.getsize(path) > self.config.max_keylog_size or not is_keylog_file(path):
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

            logging.info("applying late TLS key log %s to pcap %s", path, pcap_file.full_path,
                         extra={"keylog_sha256": _file.sha256_hash, "pcap_sha256": pcap_file.sha256_hash})
            apply_keylogs(self.config, pcap_file, pcap_analysis, decryption,
                          find_keylog_observables(root, self.config.max_keylog_size))
            decryption.set_details_modified()
            analysis.details["applied_to"].append(pcap_file.sha256_hash)

        return AnalysisExecutionResult.COMPLETED


# ----------------------------------------------------------------------------------------------
# presentation
# ----------------------------------------------------------------------------------------------

def _table(title: str, columns: list[str], rows: list[list], total: Optional[int] = None) -> dict:
    return {"title": title, "columns": columns, "rows": rows, "total": total if total is not None else len(rows)}


def index_tables(index: Optional[dict], category: Optional[str] = None) -> list[dict]:
    """The tables shown for one category of an index (or all of them when category is None)."""
    if not index:
        return []

    tables = []
    if category in (None, CATEGORY_DNS) and index.get(CATEGORY_DNS):
        tables.append(_table("DNS", ["Name", "Answers", "Seen"],
                             [[r["name"], ", ".join(r["answers"]), r["count"]] for r in index[CATEGORY_DNS]],
                             index.get(f"{CATEGORY_DNS}_total")))
    if category in (None, CATEGORY_TLS) and index.get(CATEGORY_TLS):
        tables.append(_table("TLS Sessions", ["Client", "Server", "SNI", "JA4", "Certificates"],
                             [[r.get("client"), r.get("server"), r.get("sni"), r.get("ja4"), ", ".join(r.get("certificates", []))]
                              for r in index[CATEGORY_TLS]], index.get(f"{CATEGORY_TLS}_total")))
    if category in (None, CATEGORY_HTTP) and index.get(CATEGORY_HTTP):
        tables.append(_table("HTTP Requests", ["Method", "URL", "Status", "Content Type", "User Agent"],
                             [[r.get("method"), r.get("url"), r.get("status"), r.get("content_type"), r.get("user_agent")]
                              for r in index[CATEGORY_HTTP]], index.get(f"{CATEGORY_HTTP}_total")))
    if category in (None, CATEGORY_FILES) and index.get("objects"):
        tables.append(_table("Carved Files", ["Protocol", "File Name", "Size", "SHA256", "URL"],
                             [[r["protocol"], r["file_name"], r["size"], r["sha256"], r.get("url")] for r in index["objects"]]))
    return tables


class PcapAnalysisPresenter(AnalysisPresenter):

    @property
    def template_path(self) -> str:
        return "analysis/pcap_analysis.html"

    @property
    def tables(self) -> list[dict]:
        details = self._analysis.details or {}
        analysis = self._analysis
        if isinstance(analysis, PcapAnalysis):
            index = details.get(KEY_INDEX) or {}
            statistics = index.get("statistics", {})
            tables = []
            if index.get("hostnames"):
                tables.append(_table("Hostnames", ["Name", "Source", "MAC"],
                                     [[r["name"], r["source"], r.get("mac")] for r in index["hostnames"]]))
            if statistics.get("ip"):
                tables.append(_table("IP Endpoints", ["Address", "Packets", "Bytes"],
                                     [[r["address"], r["packets"], r["bytes"]] for r in statistics["ip"]], statistics.get("ip_total")))
            if statistics.get("mac"):
                tables.append(_table("Ethernet Endpoints", ["Address", "Packets", "Bytes"],
                                     [[r["address"], r["packets"], r["bytes"]] for r in statistics["mac"]], statistics.get("mac_total")))
            if statistics.get("flows"):
                tables.append(_table("Flows", ["Protocol", "A", "B", "Frames", "Bytes", "Start", "Duration"],
                                     [[r["protocol"], r["a"], r["b"], r["frames"], r["bytes"], r["start"], r["duration"]]
                                      for r in statistics["flows"]], statistics.get("flows_total")))
            return tables
        if isinstance(analysis, PcapCategoryAnalysis):
            category = details.get("category")
            rows_key = "objects" if category == CATEGORY_FILES else category
            index = {rows_key: details.get("rows", []), f"{category}_total": details.get("total")}
            return index_tables(index, category)
        if isinstance(analysis, PcapTlsDecryptionAnalysis):
            tables = []
            if details.get("keylogs"):
                tables.append(_table("Key Logs", ["File", "SHA256", "Secrets"],
                                     [[k["file_name"], k["sha256"], _format_counts(k["label_counts"])] for k in details["keylogs"]]))
            return tables + index_tables(details.get(KEY_INDEX))
        if isinstance(analysis, TlsKeylogAnalysis):
            return [_table("Secrets", ["Label", "Count"], [[k, v] for k, v in sorted(details.get("label_counts", {}).items())])]
        return []


for _analysis_class in (PcapAnalysis, PcapCategoryAnalysis, PcapTlsDecryptionAnalysis, TlsKeylogAnalysis):
    register_analysis_presenter(_analysis_class, PcapAnalysisPresenter)
