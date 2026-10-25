import datetime
import logging
import os
import shutil
import struct
import time
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import (
    ANALYSIS_MODULE_ARCHIVE,
    ANALYSIS_MODULE_FILE_TYPE,
    ANALYSIS_MODULE_HIDDEN_MIME,
    ANALYSIS_MODULE_PCAP_ANALYZER,
    ANALYSIS_MODULE_PCAP_DNS,
    ANALYSIS_MODULE_PCAP_FILES,
    ANALYSIS_MODULE_PCAP_HTTP,
    ANALYSIS_MODULE_PCAP_TLS,
    ANALYSIS_MODULE_PCAP_TLS_DECRYPTION,
    ANALYSIS_MODULE_TLS_KEYLOG,
    ANALYSIS_MODULE_X509_ANALYZER,
    DIRECTIVE_CRAWL,
    DIRECTIVE_NO_CRAWL,
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
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.adapter import AnalysisModuleAdapter
from saq.mime_extractor import parse_mime
from saq.modules.file_analysis.archive import ArchiveAnalysis
from saq.modules.file_analysis.mime import HiddenMIMEAnalysis, HiddenMIMEAnalyzer
from saq.modules.x509 import MAX_NO_CRAWL_SAN_FQDNS, X509Analysis
from saq.modules.file_analysis import pcap
from saq.modules.file_analysis.is_file_type import is_pcap_file
from saq.modules.file_analysis.pcap import (
    CATEGORY_DNS,
    CATEGORY_FILES,
    CATEGORY_HOSTS,
    CATEGORY_HTTP,
    CATEGORY_TLS,
    PcapAnalysis,
    PcapAnalysisPresenter,
    PcapAnalyzer,
    PcapCategoryAnalysis,
    PcapError,
    PcapObservable,
    PcapTlsDecryptionAnalysis,
    TlsKeylogAnalysis,
    TAG_TLS_KEYLOG,
    add_pcap_observables,
    build_index,
    collect_observables,
    is_keylog_file,
    read_keylog,
)
from saq.sandbox.launcher import EXIT_DEADLINE, EXIT_PROCESS_LIMIT, EXIT_SANDBOX_FAILURE
from saq.sandbox.runner import SandboxCancelled, SandboxResult
from saq.util.hashing import sha256_bytes
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context

FIXTURES = os.path.join(os.path.dirname(__file__), "test_pcap")
NETWORK_PCAP = os.path.join(FIXTURES, "network.pcap")
HTTP_TLS_PCAPNG = os.path.join(FIXTURES, "http_tls.pcapng")
HTTP_TLS_DSB_PCAPNG = os.path.join(FIXTURES, "http_tls_dsb.pcapng")
SSLKEYLOG = os.path.join(FIXTURES, "sslkeylog.txt")

PCAP_MODULES = (
    ANALYSIS_MODULE_PCAP_ANALYZER,
    ANALYSIS_MODULE_PCAP_DNS,
    ANALYSIS_MODULE_PCAP_TLS,
    ANALYSIS_MODULE_PCAP_HTTP,
    ANALYSIS_MODULE_PCAP_FILES,
    ANALYSIS_MODULE_PCAP_TLS_DECRYPTION,
    ANALYSIS_MODULE_TLS_KEYLOG,
)

CLIENT_RANDOM_12 = "be401d9c38e74ed55c59ecc279468bae1062bacd07759010cb2c9c80f7e0afaf"

STATISTICS_OUTPUT = """
===================================
| IO Statistics                   |
|---------------------------------|
| Interval       | Frames | Bytes |
|---------------------------------|
| 0.000 <> 4.000 |      5 |   859 |
===================================
================================================================================
UDP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.20.30.40:53001          <-> 10.20.30.1:53                    1 170 bytes       1 80 bytes        2 250 bytes     2.000000000         1.0000
0.0.0.0:68                 <-> 255.255.255.255:67               0 0 bytes         1 310 bytes       1 310 bytes     0.000000000         0.0000
================================================================================
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
127.0.0.1:36704            <-> 127.0.0.1:18443                  7 2 kB             8 1029 bytes      15 3 kB           0.018660592         0.0085
================================================================================
================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
10.20.30.40                    4           445          3             275           1             170
10.20.30.1                     3           335          1             170           2             165
================================================================================
================================================================================
Ethernet Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
02:00:00:aa:00:01              5           755          4             585           1             170
ff:ff:ff:ff:ff:ff              2           420          0               0           2             420
================================================================================
"""


def _config(name: str = ANALYSIS_MODULE_PCAP_ANALYZER, **overrides):
    config = get_analysis_module_config(name)
    return config.model_copy(update=overrides) if overrides else config


def _pcap_config(**overrides):
    config = get_config().pcap
    return config.model_copy(update=overrides) if overrides else config


def _never() -> bool:
    return False


def _new_root():
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    return root


def _adapter(module_class, root, name: str = ANALYSIS_MODULE_PCAP_ANALYZER, **overrides):
    analyzer = AnalysisModuleAdapter(module_class(context=create_test_context(root=root), config=_config(name, **overrides)))
    analyzer.root = root
    return analyzer


def _run_engine(root):
    engine = Engine()
    for module in PCAP_MODULES:
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    return load_root(get_storage_dir(root.uuid))


def _values(analysis, o_type: str) -> set[str]:
    return {o.value for o in analysis.get_observables_by_type(o_type)}


def _category(observable, category: str) -> PcapCategoryAnalysis:
    return observable.get_and_load_analysis(PcapCategoryAnalysis, instance=category)


# ----------------------------------------------------------------------------------------------
# unit
# ----------------------------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("header,expected", [
    (b"\xd4\xc3\xb2\xa1", True),
    (b"\xa1\xb2\xc3\xd4", True),
    (b"\x4d\x3c\xb2\xa1", True),
    (b"\xa1\xb2\x3c\x4d", True),
    (b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a", True),
    (b"\x0a\x0d\x0d\x0a\x00\x00\x00\x1c\x1a\x2b\x3c\x4d", True),
    # LF CR CR LF starts text as easily as a pcapng: the byte-order magic is what makes it one
    (b"\x0a\x0d\x0d\x0atext after a stray line ending", False),
    (b"GET / HTTP/1.1", False),
    (b"", False),
])
def test_is_pcap_file(tmp_path, header, expected):
    path = tmp_path / "capture.bin"
    path.write_bytes(header + b"\x00" * 20)
    assert is_pcap_file(str(path)) is expected


@pytest.mark.unit
def test_is_pcap_file_missing_file(tmp_path):
    assert not is_pcap_file(str(tmp_path / "missing"))
    assert not is_pcap_file(None)


@pytest.mark.unit
def test_is_keylog_file(tmp_path):
    keylog = tmp_path / "anything.dat"
    keylog.write_text("# SSL/TLS secrets log file, generated by NSS\n\n" + open(SSLKEYLOG).read())
    assert is_keylog_file(str(keylog))
    assert is_keylog_file(SSLKEYLOG)


@pytest.mark.unit
@pytest.mark.parametrize("content", [
    b"",
    b"# only a comment\n",
    b"CLIENT_RANDOM abc\n",
    b"hello world\n",
    b"CLIENT_RANDOM 00 11\nnot a key log line\n",
    b"\xff\xfe binary",
])
def test_is_keylog_file_rejects(tmp_path, content):
    path = tmp_path / "keys.txt"
    path.write_bytes(content)
    assert not is_keylog_file(str(path))


@pytest.mark.unit
def test_is_keylog_file_ignores_a_line_cut_by_the_sniff(tmp_path):
    line = "CLIENT_RANDOM " + "a" * 64 + " " + "b" * 96 + "\n"
    path = tmp_path / "keys.txt"
    # the sniff ends in the middle of a line
    path.write_text(line * (pcap.KEYLOG_SNIFF_BYTES // len(line) + 2))
    assert is_keylog_file(str(path))


@pytest.mark.unit
def test_read_keylog(tmp_path):
    path = tmp_path / "keys.txt"
    path.write_text(
        "# comment\n"
        f"CLIENT_RANDOM {CLIENT_RANDOM_12.upper()} 00ff\n"
        f"CLIENT_TRAFFIC_SECRET_0 {'c' * 64} 11\n"
        "RSA 0123456789abcdef 22\n"
        "garbage that never reaches tshark\n"
    )
    contents = read_keylog(str(path))
    assert contents.label_counts == {"CLIENT_RANDOM": 1, "CLIENT_TRAFFIC_SECRET_0": 1, "RSA": 1}
    # an RSA line is not keyed by a client random
    assert contents.client_randoms == {CLIENT_RANDOM_12, "c" * 64}
    assert len(contents.lines) == 3
    assert not any("garbage" in line for line in contents.lines)


@pytest.mark.unit
def test_parse_statistics():
    stats = pcap._parse_statistics(STATISTICS_OUTPUT, max_rows=500)
    assert stats["packets"] == 5
    assert stats["bytes"] == 859
    assert [r["address"] for r in stats["ip"]] == ["10.20.30.40", "10.20.30.1"]
    assert [r["address"] for r in stats["mac"]] == ["02:00:00:aa:00:01", "ff:ff:ff:ff:ff:ff"]
    assert stats["flows_total"] == 3
    # sorted by frames
    assert stats["flows"][0] == {"protocol": "tcp", "a": "127.0.0.1:36704", "b": "127.0.0.1:18443",
                                 "frames": 15, "bytes": "3 kB", "start": 0.018660592, "duration": 0.0085}


@pytest.mark.unit
def test_parse_statistics_caps_rows():
    stats = pcap._parse_statistics(STATISTICS_OUTPUT, max_rows=1)
    assert len(stats["flows"]) == 1
    assert stats["flows_total"] == 3
    assert stats["ip_total"] == 2


@pytest.mark.unit
def test_parse_fields_rejects_malformed_output():
    with pytest.raises(PcapError):
        pcap._parse_fields("[{not json")
    assert pcap._parse_fields("") == []


def _packets() -> list[dict]:
    return [
        {"frame.number": ["1"], "dhcp.option.hostname": ["Workstation-1"], "dhcp.hw.mac_addr": ["02:00:00:aa:00:01"]},
        {"frame.number": ["2"], "nbns.name": ["NBHOST<00>", "NBHOST<00> (Workstation/Redirector)", "__MSBROWSE__<01>"]},
        {"frame.number": ["3"], "dns.flags.response": ["False"], "dns.qry.name": ["WWW.Example.com"]},
        {"frame.number": ["4"], "dns.flags.response": ["True"], "dns.qry.name": ["www.example.com"],
         "dns.resp.name": ["www.example.com", "cdn.example.com"], "dns.cname": ["cdn.example.com"],
         "dns.a": ["198.51.100.7"]},
        {"frame.number": ["5"], "ip.src": ["10.0.0.1"], "ip.dst": ["198.51.100.7"], "tcp.stream": ["0"],
         "tcp.srcport": ["50000"], "tcp.dstport": ["443"], "tls.handshake.type": ["1"],
         "tls.handshake.extensions_server_name": ["tls.example.com"], "tls.handshake.ja4": ["t13d0312h1_aaa_bbb"],
         "tls.handshake.random": [CLIENT_RANDOM_12.upper()]},
        {"frame.number": ["6"], "tcp.stream": ["0"], "tls.handshake.type": ["2", "11"],
         "tls.handshake.certificate": ["30:82:01", "308202"]},
        {"frame.number": ["7"], "http.request.method": ["GET"], "http.request.full_uri": ["http://web.example.com:8080/a.exe"],
         "http.host": ["web.example.com:8080"], "http.user_agent": ["agent, with comma"]},
        {"frame.number": ["8"], "http.response.code": ["200"], "http.content_type": ["application/octet-stream"],
         "http.request_in": ["7"]},
        {"frame.number": ["9"], "http2.headers.method": ["GET", "POST"], "http2.headers.scheme": ["https", "https"],
         "http2.headers.authority": ["h2.example.com", "h2.example.com"], "http2.headers.path": ["/x", "/y"],
         "http2.headers.user_agent": ["h2-agent"]},
    ]


def _certificates() -> list[dict]:
    return [{"sha256": "11" * 32, "der_hex": "308201", "path": "c.pcap.pcap_objects/certificates/1.der"},
            {"sha256": "22" * 32, "der_hex": "308202", "path": None}]


@pytest.mark.unit
def test_build_index():
    objects = [{"protocol": "http", "file_name": "a.exe", "sha256": "33" * 32, "size": 3, "path": "x/a.exe"}]
    index = build_index(_packets(), _certificates(), objects, max_rows=500)

    dns = {r["name"]: r for r in index[CATEGORY_DNS]}
    assert set(dns) == {"www.example.com", "cdn.example.com"}
    assert dns["www.example.com"]["answers"] == ["198.51.100.7", "cdn.example.com"]
    # one lookup is one query and one response, however many records its answer carries
    assert (dns["www.example.com"]["queries"], dns["www.example.com"]["responses"]) == (1, 1)
    # a CNAME target nobody looked up has a row but no lookups of its own
    assert (dns["cdn.example.com"]["queries"], dns["cdn.example.com"]["responses"]) == (0, 0)
    assert dns["cdn.example.com"]["seen_as"] == ["cname"]
    assert dns["www.example.com"]["seen_as"] == []

    (session,) = index[CATEGORY_TLS]
    assert session["client"] == "10.0.0.1:50000"
    assert session["server"] == "198.51.100.7:443"
    assert session["sni"] == "tls.example.com"
    assert session["ja4"] == "t13d0312h1_aaa_bbb"
    assert session["client_random"] == CLIENT_RANDOM_12
    assert index[pcap.KEY_CLIENT_RANDOMS] == [CLIENT_RANDOM_12]
    assert session["certificates"] == ["11" * 32, "22" * 32]

    requests = {r["url"]: r for r in index[CATEGORY_HTTP]}
    assert requests["http://web.example.com:8080/a.exe"]["status"] == "200"
    assert requests["http://web.example.com:8080/a.exe"]["user_agent"] == "agent, with comma"
    assert requests["https://h2.example.com/x"]["user_agent"] == "h2-agent"
    assert requests["https://h2.example.com/y"]["method"] == "POST"

    assert {h["name"] for h in index["hostnames"]} == {"Workstation-1", "NBHOST"}
    assert index["certificates"] == [{"sha256": "11" * 32, "path": "c.pcap.pcap_objects/certificates/1.der"},
                                     {"sha256": "22" * 32, "path": None}]


@pytest.mark.unit
def test_dns_display_types():
    packets = [
        # an HTTPS record lookup with no answer: the SOA of the zone comes back in the authority section
        {"frame.number": ["1"], "dns.flags.response": ["True"], "dns.qry.name": ["fonts.example.com"],
         "dns.resp.name": ["example.com"], "dns.resp.type": ["6"]},
        # a CNAME chain
        {"frame.number": ["2"], "dns.flags.response": ["True"], "dns.qry.name": ["www.example.com"],
         "dns.resp.name": ["www.example.com", "cdn.example.net"], "dns.resp.type": ["5", "1"],
         "dns.cname": ["cdn.example.net"], "dns.a": ["198.51.100.7"]},
        # an additional record for a name that is neither
        {"frame.number": ["3"], "dns.flags.response": ["True"], "dns.qry.name": ["mx.example.com"],
         "dns.resp.name": ["mx.example.com", "relay.example.org"], "dns.resp.type": ["15", "1"]},
    ]
    index = build_index(packets, [], [], max_rows=500)
    labels = {i.value: i.display_type for i in collect_observables(index, []) if i.category == CATEGORY_DNS}
    assert labels == {
        "fonts.example.com": "DNS Query Name", "example.com": "DNS Zone (SOA/NS)",
        "www.example.com": "DNS Query Name", "cdn.example.net": "DNS CNAME Target",
        "mx.example.com": "DNS Query Name", "relay.example.org": "DNS Record Name",
        "198.51.100.7": "DNS Answer IP"}


@pytest.mark.unit
def test_build_index_caps_rows():
    objects = [{"protocol": "http", "file_name": f"{i}.bin", "sha256": f"{i:064x}", "size": 1, "path": None}
               for i in range(3)]
    index = build_index(_packets(), [], objects, max_rows=1)
    assert len(index[CATEGORY_HTTP]) == 1
    assert index[f"{CATEGORY_HTTP}_total"] == 3
    assert len(index["objects"]) == 1
    assert index["objects_total"] == 3

    # the files node and its table count every carved file, not only the rows kept
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = index
    core.completed = True
    observable.add_analysis(core)
    analyzer = _adapter(pcap.PcapCategoryAnalyzer, root, ANALYSIS_MODULE_PCAP_FILES)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    files = observable.get_analysis(PcapCategoryAnalysis, instance=CATEGORY_FILES)
    assert files.details["total"] == 3
    (table,) = PcapAnalysisPresenter(files).tables
    assert (len(table["rows"]), table["total"]) == (1, 3)


@pytest.mark.unit
def test_build_index_skips_edns_and_the_root():
    packets = [
        # a resolver priming itself: the query names the root
        {"frame.number": ["1"], "dns.flags.response": ["False"], "dns.qry.name": ["<Root>"]},
        {"frame.number": ["2"], "dns.flags.response": ["True"], "dns.qry.name": ["www.example.com"],
         "dns.resp.name": ["www.example.com", "<Root>"], "dns.resp.type": ["1", "41"], "dns.a": ["198.51.100.7"]},
        # a record the EDNS check must not drop just because its name came without a type
        {"frame.number": ["3"], "dns.flags.response": ["True"], "dns.qry.name": ["a.example.com"],
         "dns.resp.name": ["a.example.com", "b.example.com"], "dns.resp.type": ["1"]},
        # NXDOMAIN for a top-level domain that does not exist: the authority is the root zone's SOA
        {"frame.number": ["4"], "dns.flags.response": ["True"], "dns.qry.name": ["host.invalidtld"],
         "dns.resp.name": ["<Root>"], "dns.resp.type": ["6"]},
    ]
    index = build_index(packets, [], [], max_rows=500)
    assert [r["name"] for r in index[CATEGORY_DNS]] == ["www.example.com", "a.example.com", "b.example.com",
                                                        "host.invalidtld"]
    assert index[f"{CATEGORY_DNS}_total"] == 4
    assert all(r["seen_as"] == [] for r in index[CATEGORY_DNS])


@pytest.mark.unit
def test_collect_observables():
    index = build_index(_packets(), _certificates(), [
        {"protocol": "http", "file_name": "a.exe", "sha256": "33" * 32, "size": 3, "path": "x/a.exe",
         "url": "http://web.example.com:8080/a.exe"},
        {"protocol": "smb", "file_name": "b", "sha256": "44" * 32, "size": 3, "path": None},
    ], max_rows=500)
    index["statistics"] = {
        "ip": [{"address": a} for a in ("10.0.0.1", "224.0.0.251", "0.0.0.0", "255.255.255.255", "127.0.0.1",
                                        "169.254.1.1", "fe80::1", "2001:db8::1")],
        "mac": [{"address": a} for a in ("02:00:00:aa:00:01", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb",
                                         "00:00:00:00:00:00")],
    }
    index[CATEGORY_DNS].append({"name": "1.0.0.10.in-addr.arpa", "answers": ["printer.local"], "queries": 1, "responses": 1})

    items = collect_observables(index, [".arpa", ".local"])
    by_category: dict[str, set] = {}
    for item in items:
        by_category.setdefault(item.category, set()).add((item.o_type, item.value, item.volatile))

    assert by_category[CATEGORY_HOSTS] == {
        (F_IP, "10.0.0.1", True), (F_IP, "2001:db8::1", True), (F_MAC_ADDRESS, "02-00-00-aa-00-01", True),
        (F_HOSTNAME, "Workstation-1", True), (F_HOSTNAME, "NBHOST", True),
    }
    assert by_category[CATEGORY_DNS] == {
        (F_FQDN, "www.example.com", False), (F_FQDN, "cdn.example.com", False), (F_IP, "198.51.100.7", True),
    }
    assert by_category[CATEGORY_TLS] == {
        (F_FQDN, "tls.example.com", False), (F_JA4, "t13d0312h1_aaa_bbb", False), (F_FILE, "11" * 32, False),
    }
    assert by_category[CATEGORY_HTTP] == {
        (F_URL, "http://web.example.com:8080/a.exe", False), (F_URL, "https://h2.example.com/x", False),
        (F_URL, "https://h2.example.com/y", False), (F_FQDN, "web.example.com", False),
        (F_FQDN, "h2.example.com", False), (F_USER_AGENT, "agent, with comma", False),
        (F_USER_AGENT, "h2-agent", False),
    }
    # a file over the extraction limit has no path and so no observable
    (carved,) = [i for i in items if i.category == CATEGORY_FILES]
    assert carved.value == "33" * 32
    assert carved.downloaded_from == "http://web.example.com:8080/a.exe"


@pytest.mark.unit
@pytest.mark.parametrize("host,expected", [
    ("web.example.com:8080", (F_FQDN, "web.example.com")),
    ("WEB.example.com.", (F_FQDN, "web.example.com")),
    ("198.51.100.7:80", (F_IP, "198.51.100.7")),
    ("[2001:db8::1]:443", (F_IP, "2001:db8::1")),
    ("2001:db8::1", (F_IP, "2001:db8::1")),
    ("127.0.0.1:80", None),
    ("", None),
    ("printer.local", None),
])
def test_host_observable(host, expected):
    result = pcap._host_observable(CATEGORY_HTTP, host, [".local"])
    assert (None if result is None else (result.o_type, result.value)) == expected


@pytest.mark.unit
def test_link_http_objects_needs_a_unique_match():
    index = {
        CATEGORY_HTTP: [{"url": "http://a.example.com/x/file.bin"}, {"url": "http://b.example.com/y/file.bin"},
                        {"url": "http://a.example.com/once.js"}, {"url": None}],
        "objects": [{"protocol": "http", "file_name": "file.bin"}, {"protocol": "http", "file_name": "once.js"},
                    {"protocol": "smb", "file_name": "once.js"}],
    }
    pcap._link_http_objects(index)
    assert [o.get("url") for o in index["objects"]] == [None, "http://a.example.com/once.js", None]


@pytest.mark.unit
def test_add_pcap_observables_limits_and_dedupes():
    root = _new_root()
    pcap_file = root.add_file_observable(NETWORK_PCAP)
    analysis = PcapAnalysis()
    pcap_file.add_analysis(analysis)

    # first, so it is refused for being invalid, not for being over the limit
    items = [PcapObservable(CATEGORY_DNS, F_FQDN, "not a valid fqdn!")]
    items += [PcapObservable(CATEGORY_DNS, F_FQDN, f"host{i}.example.com") for i in range(3)]
    items.append(PcapObservable(CATEGORY_DNS, F_IP, "198.51.100.7", volatile=True))

    added, omitted = add_pcap_observables(analysis, pcap_file, items, max_per_type=2)
    assert added == {F_FQDN: 2, F_IP: 1}
    assert omitted == {F_FQDN: 2}
    assert _values(analysis, F_FQDN) == {"host0.example.com", "host1.example.com"}
    assert analysis.get_observables_by_type(F_IP)[0].volatile
    assert analysis.get_observables_by_type(F_FQDN)[0].sort_order == pcap.SORT_ORDER[F_FQDN]

    # a second call adds nothing it already has and still respects the limit
    added, omitted = add_pcap_observables(analysis, pcap_file, items, max_per_type=2)
    assert added == {}
    assert omitted == {F_FQDN: 2}


@pytest.mark.unit
def test_run_tshark_refuses_without_landlock(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "landlock_available", lambda: False)
    # not a PcapError: a node that cannot dissect anything is an operator's problem, logged at ERROR
    with pytest.raises(pcap.PcapNodeError, match="Landlock"):
        pcap._run_tshark(_pcap_config(), "capture.pcap", str(tmp_path), [], _never)


@pytest.mark.unit
def test_run_tshark_failure_without_output(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", lambda *args, **kwargs: SandboxResult(2, "", "file is damaged"))
    with pytest.raises(PcapError, match="file is damaged"):
        pcap._run_tshark(_pcap_config(), "capture.pcap", str(tmp_path), [], _never)


@pytest.mark.unit
def test_run_tshark_timeout(monkeypatch, tmp_path):
    def _timeout(*args, **kwargs):
        raise RuntimeError("command timed out after 0:04:00")

    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", _timeout)
    with pytest.raises(PcapError, match="timed out"):
        pcap._run_tshark(_pcap_config(), "capture.pcap", str(tmp_path), [], _never)


@pytest.mark.unit
def test_run_tshark_keeps_output_of_a_truncated_capture(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", lambda *args, **kwargs: SandboxResult(2, "[]", "cut short"))
    with caplog.at_level(logging.INFO):
        assert pcap._run_tshark(_pcap_config(), "/storage/capture.pcap", str(tmp_path), [], _never) == "[]"
    (record,) = [r for r in caplog.records if "cut short" in r.getMessage()]
    assert "/storage/capture.pcap" in record.getMessage()
    assert record.pcap_path == "/storage/capture.pcap"


@pytest.mark.unit
def test_pcap_analyzer_ignores_other_files(tmp_path):
    root = _new_root()
    path = tmp_path / "notes.txt"
    path.write_text("not a capture")
    observable = root.add_file_observable(str(path))
    analyzer = _adapter(PcapAnalyzer, root)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(PcapAnalysis) is None


@pytest.mark.unit
def test_pcap_analyzer_oversized(monkeypatch, tmp_path):
    monkeypatch.setattr(get_config().pcap, "max_file_size", 10)
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(PcapAnalyzer, root)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(PcapAnalysis)
    assert "exceeds max_file_size" in analysis.error
    assert analysis.generate_summary().startswith("PCAP Analysis: failed:")


@pytest.mark.unit
def test_pcap_analyzer_reports_dissection_failure(monkeypatch, caplog):
    def _fail(*args, **kwargs):
        raise PcapError("tshark exited with 2: damaged")

    monkeypatch.setattr(pcap, "dissect", _fail)
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(PcapAnalyzer, root)
    with caplog.at_level(logging.INFO):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    # the analyst sees it in the analysis; it is not an operator's problem
    assert observable.get_analysis(PcapAnalysis).error == "tshark exited with 2: damaged"
    (record,) = [r for r in caplog.records if "unable to dissect pcap" in r.getMessage()]
    assert record.levelno == logging.INFO
    assert "tshark exited with 2: damaged" in record.getMessage()
    assert record.pcap_sha256 == observable.sha256_hash


@pytest.mark.unit
def test_pcap_analyzer_reports_a_node_problem_at_error(monkeypatch, caplog):
    monkeypatch.setattr(pcap, "landlock_available", lambda: False)
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(PcapAnalyzer, root)
    with caplog.at_level(logging.INFO):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert "Landlock" in observable.get_analysis(PcapAnalysis).error
    assert any(r.levelno == logging.ERROR and "unable to dissect pcap" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_presenter_tables():
    category = PcapCategoryAnalysis()
    category.details = {"category": CATEGORY_DNS, "total": 7,
                        "rows": [{"name": "a.example.com", "answers": ["1.2.3.4"], "queries": 2, "responses": 1}]}
    (table,) = PcapAnalysisPresenter(category).tables
    assert table["title"] == "DNS"
    assert table["columns"] == ["Name", "Answers", "Queries", "Responses"]
    assert table["rows"] == [["a.example.com", "1.2.3.4", 2, 1]]
    assert table["total"] == 7

    files = PcapCategoryAnalysis()
    files.details = {"category": CATEGORY_FILES, "rows": [{"protocol": "http", "file_name": "a", "size": 1, "sha256": "x"}],
                     "total": 1}
    assert PcapAnalysisPresenter(files).tables[0]["title"] == "Carved Files"

    keylog = TlsKeylogAnalysis()
    keylog.details = {"label_counts": {"CLIENT_RANDOM": 2}, "client_randoms": 2, "applied_to": []}
    assert PcapAnalysisPresenter(keylog).tables[0]["rows"] == [["CLIENT_RANDOM", 2]]
    assert keylog.generate_summary() == "TLS Key Log: 2 secrets for 2 TLS sessions (2 CLIENT_RANDOM)"

    decryption = PcapTlsDecryptionAnalysis()
    decryption.details["sessions"] = 3
    assert decryption.generate_summary() == "PCAP TLS Decryption: no TLS key log found (3 TLS sessions)"
    assert PcapAnalysisPresenter(decryption).tables == []


# ----------------------------------------------------------------------------------------------
# integration: the engine with the real tshark
# ----------------------------------------------------------------------------------------------

@pytest.mark.integration
def test_pcap_tree(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    network = root_analysis.add_file_observable(NETWORK_PCAP)
    http_tls = root_analysis.add_file_observable(HTTP_TLS_PCAPNG)
    root_analysis.save()
    root_analysis.schedule()

    root = _run_engine(root_analysis)
    network = root.get_observable(network.uuid)
    http_tls = root.get_observable(http_tls.uuid)

    core = network.get_and_load_analysis(PcapAnalysis)
    assert core.error is None
    assert core.index["statistics"]["packets"] == 5
    assert _values(core, F_IP) == {"10.20.30.40", "10.20.30.1", "10.20.30.255"}
    assert _values(core, F_MAC_ADDRESS) == {"02-00-00-aa-00-01", "02-00-00-bb-00-02"}
    assert _values(core, F_HOSTNAME) == {"pcap-workstation", "PCAPNBNSHOST"}
    assert all(o.volatile for o in core.observables)

    dns = _category(network, CATEGORY_DNS)
    assert _values(dns, F_FQDN) == {"www.pcap-dns.example", "cdn.pcap-dns.example"}
    counts = {row[0]: (row[2], row[3]) for row in PcapAnalysisPresenter(dns).tables[0]["rows"]}
    # the response's EDNS OPT record (owner: the root) is no name
    assert counts == {"www.pcap-dns.example": (1, 1), "cdn.pcap-dns.example": (0, 0),
                      "7.100.51.198.in-addr.arpa": (1, 0)}
    assert dns.details[pcap.KEY_OMITTED] == {}
    # the answer IP carries the time of the response that returned it (frame 4, 00:00:03); names do not
    (answer_ip,) = dns.get_observables_by_type(F_IP)
    assert answer_ip.time == datetime.datetime(2026, 1, 1, 0, 0, 3, tzinfo=datetime.timezone.utc)
    assert all(o.time is None for o in dns.get_observables_by_type(F_FQDN))
    labels = {o.value: o.display_type for o in dns.observables}
    assert labels == {"www.pcap-dns.example": "DNS Query Name (fqdn)", "cdn.pcap-dns.example": "DNS CNAME Target (fqdn)",
                      "198.51.100.7": "DNS Answer IP (ip)"}
    # the page says which capture it came from, and that capture order is chronological here
    assert PcapAnalysisPresenter(dns).capture_summary == [
        "network.pcap", "pcap", "870 B", "Ethernet, 1 interface", "5 packets",
        "2026-01-01 00:00:00 to 00:00:04 UTC (4.0 s)"]
    assert PcapAnalysisPresenter(dns).tables[0]["order"] == (
        "Names in the order they first appear in the capture, which is chronological.")
    assert _values(dns, F_IP) == {"198.51.100.7"}
    assert "PCAP DNS" in dns.summary
    # nothing of these categories in the synthesized frames: no node in the tree
    assert not _category(network, CATEGORY_TLS)
    assert not network.get_and_load_analysis(PcapTlsDecryptionAnalysis)

    # loopback addresses and MACs are filtered out
    core = http_tls.get_and_load_analysis(PcapAnalysis)
    assert core.observables == []
    assert len(core.index[CATEGORY_TLS]) == 2

    assert not [tag for tag in http_tls.tags if str(tag).startswith("pcap_embedded_")]
    tls = _category(http_tls, CATEGORY_TLS)
    assert _values(tls, F_FQDN) == {"pcap-tls12.example", "pcap-tls13.example"}
    (table,) = PcapAnalysisPresenter(tls).tables
    assert table["columns"] == ["Server", "SNI", "JA4", "Certificates"]
    certificates = sorted(row[3] for row in table["rows"])
    assert certificates == [[], ["pcap-tls.example (SAN: pcap-tls12.example, pcap-tls13.example) \u2014 self-signed"]]
    assert sorted(o.display_type for o in tls.get_observables_by_type(F_JA4)) == [
        "JA4 client fingerprint (TLS ClientHello), seen to pcap-tls12.example (ja4)",
        "JA4 client fingerprint (TLS ClientHello), seen to pcap-tls13.example (ja4)"]
    # nothing in this capture resolved them, so they are labelled as TLS server names
    assert {o.display_type for o in tls.get_observables_by_type(F_FQDN)} == {"TLS SNI (fqdn)"}
    assert PcapAnalysisPresenter(tls).tables[0]["note"] == pcap.JA4_NOTE
    # only the TLS 1.2 certificate travels in the clear
    (certificate,) = tls.get_observables_by_type(F_FILE)
    assert certificate.has_relationship(R_EXTRACTED_FROM)

    http = _category(http_tls, CATEGORY_HTTP)
    assert _values(http, F_URL) == {"http://pcap-http.example:18080/payload.txt"}
    assert _values(http, F_USER_AGENT) == {"pcap-fixture-agent/1.0"}
    assert _values(http, F_FQDN) == {"pcap-http.example"}

    files = _category(http_tls, CATEGORY_FILES)
    (payload,) = files.get_observables_by_type(F_FILE)
    assert payload.file_name == "payload.txt"
    with open(payload.full_path) as fp:
        assert fp.read() == "plaintext payload carried over http\n"
    downloaded_from = [r.target.value for r in payload.relationships if r.r_type == R_DOWNLOADED_FROM]
    assert downloaded_from == ["http://pcap-http.example:18080/payload.txt"]

    decryption = http_tls.get_and_load_analysis(PcapTlsDecryptionAnalysis)
    assert decryption.summary == "PCAP TLS Decryption: no TLS key log found (2 TLS sessions)"
    assert decryption.observables == []


def _assert_decrypted(decryption: PcapTlsDecryptionAnalysis):
    assert decryption.details["sessions"] == 2
    assert decryption.details["sessions_with_keys"] == 2
    assert _values(decryption, F_URL) == {"https://pcap-tls12.example:18443/secret12.txt",
                                          "https://pcap-tls13.example:18444/secret13.txt"}
    assert {o.file_name for o in decryption.get_observables_by_type(F_FILE)} == {"secret12.txt", "secret13.txt"}
    # already in the plaintext analyses
    assert "pcap-tls12.example" not in _values(decryption, F_FQDN)
    assert "pcap-fixture-agent/1.0" not in _values(decryption, F_USER_AGENT)


@pytest.mark.integration
def test_pcap_decrypts_with_keylog_found_in_tree(root_analysis, tmp_path):
    # the key log is found by its content, whatever it is called
    keylog_path = tmp_path / "capture-keys.dat"
    shutil.copy(SSLKEYLOG, keylog_path)

    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(HTTP_TLS_PCAPNG)
    keylog = root_analysis.add_file_observable(str(keylog_path))
    root_analysis.save()
    root_analysis.schedule()

    root = _run_engine(root_analysis)
    capture = root.get_observable(capture.uuid)
    keylog = root.get_observable(keylog.uuid)

    decryption = capture.get_and_load_analysis(PcapTlsDecryptionAnalysis)
    _assert_decrypted(decryption)
    assert [k["file_name"] for k in decryption.details["keylogs"]] == ["capture-keys.dat"]
    assert "keys for 2 of 2 TLS sessions" in decryption.summary

    assert keylog.has_tag(TAG_TLS_KEYLOG)
    keylog_analysis = keylog.get_and_load_analysis(TlsKeylogAnalysis)
    assert keylog_analysis.details["client_randoms"] == 2
    # the secrets themselves are never stored in the analysis
    assert CLIENT_RANDOM_12 not in str(keylog_analysis.details)


@pytest.mark.integration
def test_pcap_decrypts_with_keylog_extracted_from_archive(root_analysis, tmp_path):
    archive_path = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(SSLKEYLOG, "sslkeylog.txt")

    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(HTTP_TLS_PCAPNG)
    root_analysis.add_file_observable(str(archive_path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in PCAP_MODULES + (ANALYSIS_MODULE_FILE_TYPE, ANALYSIS_MODULE_ARCHIVE):
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_analysis.uuid))
    _assert_decrypted(root.get_observable(capture.uuid).get_and_load_analysis(PcapTlsDecryptionAnalysis))


@pytest.mark.integration
def test_pcap_late_keylog(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(HTTP_TLS_PCAPNG)
    root_analysis.save()
    root_analysis.schedule()

    root = _run_engine(root_analysis)
    decryption = root.get_observable(capture.uuid).get_and_load_analysis(PcapTlsDecryptionAnalysis)
    assert decryption.completed
    assert decryption.details["keylogs"] == []

    # an analyst adds the key log to the alert after analysis finished
    keylog = root.add_file_observable(SSLKEYLOG)
    root.save()
    root.schedule()

    root = _run_engine(root)
    decryption = root.get_observable(capture.uuid).get_and_load_analysis(PcapTlsDecryptionAnalysis)
    _assert_decrypted(decryption)
    keylog_analysis = root.get_observable(keylog.uuid).get_and_load_analysis(TlsKeylogAnalysis)
    assert keylog_analysis.details["applied_to"] == [root.get_observable(capture.uuid).sha256_hash]


@pytest.mark.integration
def test_pcapng_with_embedded_secrets(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(HTTP_TLS_DSB_PCAPNG)
    root_analysis.save()
    root_analysis.schedule()

    root = _run_engine(root_analysis)
    capture = root.get_observable(capture.uuid)

    # called out for the analyst
    assert capture.has_tag("pcap_embedded_tls_keys")
    assert not capture.has_tag("pcap_embedded_ssh_keys")
    core = capture.get_and_load_analysis(PcapAnalysis)
    assert "decryption keys embedded (TLS keys for 2 sessions)" in core.summary
    assert "Embedded Decryption Secrets" in [t["title"] for t in PcapAnalysisPresenter(core).tables]
    decryption = capture.get_and_load_analysis(PcapTlsDecryptionAnalysis)
    assert decryption.summary == "PCAP TLS Decryption: keys for 2 of 2 TLS sessions (embedded in the capture)"
    assert decryption.observables == []

    # tshark uses the decryption secrets block on its own: the plaintext pass already sees inside TLS
    http = _category(capture, CATEGORY_HTTP)
    assert "https://pcap-tls13.example:18444/secret13.txt" in _values(http, F_URL)
    files = _category(capture, CATEGORY_FILES)
    assert {o.file_name for o in files.get_observables_by_type(F_FILE)} == {"payload.txt", "secret12.txt", "secret13.txt"}


@pytest.mark.integration
def test_corrupt_pcap(root_analysis, tmp_path, caplog):
    corrupt = tmp_path / "corrupt.pcap"
    corrupt.write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(64))

    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(str(corrupt))
    root_analysis.save()
    root_analysis.schedule()

    with caplog.at_level(logging.INFO):
        root = _run_engine(root_analysis)

    capture = root.get_observable(capture.uuid)
    core = capture.get_and_load_analysis(PcapAnalysis)
    assert core.error
    assert core.summary.startswith("PCAP Analysis: failed: ")
    records = [r for r in caplog.records if "unable to dissect pcap" in r.getMessage()]
    assert records and all(r.levelno == logging.INFO for r in records)
    # the category and decryption analyses have nothing to work from
    assert not _category(capture, CATEGORY_DNS)
    assert not capture.get_and_load_analysis(PcapTlsDecryptionAnalysis)


# ----------------------------------------------------------------------------------------------
# in-process module runs (the engine runs modules where coverage does not see them)
# ----------------------------------------------------------------------------------------------

@pytest.mark.integration
def test_modules_in_process():
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)

    core = _adapter(PcapAnalyzer, root)
    assert core.execute_analysis(capture) == AnalysisExecutionResult.COMPLETED
    core_analysis = capture.get_analysis(PcapAnalysis)
    core_analysis.completed = True
    assert core_analysis.generate_summary().startswith("PCAP Analysis: 41 packets, 3 flows, 2 TLS sessions")
    titles = [t["title"] for t in PcapAnalysisPresenter(core_analysis).tables]
    assert titles == ["IP Endpoints", "Ethernet Endpoints", "Flows"]

    for category, name in ((CATEGORY_TLS, ANALYSIS_MODULE_PCAP_TLS), (CATEGORY_HTTP, ANALYSIS_MODULE_PCAP_HTTP),
                           (CATEGORY_FILES, ANALYSIS_MODULE_PCAP_FILES), (CATEGORY_DNS, ANALYSIS_MODULE_PCAP_DNS)):
        analyzer = _adapter(pcap.PcapCategoryAnalyzer, root, name)
        assert analyzer.execute_analysis(capture) == AnalysisExecutionResult.COMPLETED

    tls = capture.get_analysis(PcapCategoryAnalysis, instance=CATEGORY_TLS)
    assert tls.display_name == "PCAP TLS"
    assert tls.generate_summary() == "PCAP TLS: 2 entries (1 file, 2 fqdn, 2 ja4)"
    assert [t["title"] for t in PcapAnalysisPresenter(tls).tables] == ["TLS Sessions"]
    assert capture.get_analysis(PcapCategoryAnalysis, instance=CATEGORY_FILES).generate_summary() == "PCAP Files: 1 files (1 file)"
    # nothing for dns in this capture
    assert capture.get_analysis(PcapCategoryAnalysis, instance=CATEGORY_DNS) is None

    decryptor = _adapter(pcap.PcapTlsDecryptor, root, ANALYSIS_MODULE_PCAP_TLS_DECRYPTION)
    assert decryptor.execute_analysis(capture) == AnalysisExecutionResult.INCOMPLETE
    assert decryptor.execute_final_analysis(capture) == AnalysisExecutionResult.COMPLETED
    decryption = capture.get_analysis(PcapTlsDecryptionAnalysis)
    assert decryption.details["keylogs"] == []
    decryption.completed = True

    # a key log arriving after the decryption completed is applied by the key log's own analysis
    keylog = root.add_file_observable(SSLKEYLOG)
    keylog_analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG)
    assert keylog_analyzer.execute_analysis(keylog) == AnalysisExecutionResult.COMPLETED
    _assert_decrypted(decryption)
    assert decryption.details_modified
    assert decryption.applied_keylogs == {keylog.sha256_hash}
    assert "new: 2 file, 2 url" in decryption.generate_summary()
    titles = [t["title"] for t in PcapAnalysisPresenter(decryption).tables]
    assert titles[0] == "Key Sources" and "HTTP Requests" in titles and "Carved Files" in titles

    keylog_analysis = keylog.get_analysis(TlsKeylogAnalysis)
    assert keylog_analysis.display_name == "TLS Key Log"
    assert keylog_analysis.generate_summary().endswith("applied to 1 pcaps")

    # applying it again adds nothing
    before = len(decryption.observables)
    second = root.add_file_observable(SSLKEYLOG)
    assert second is keylog
    pcap.apply_keylogs(_pcap_config(), capture, core_analysis, decryption, [keylog])
    assert len(decryption.observables) == before


@pytest.mark.unit
def test_keylog_analyzer_skips_pcaps_it_cannot_apply_to(monkeypatch):
    applied = []
    monkeypatch.setattr(pcap, "apply_keylogs", lambda *args, **kwargs: applied.append(args))

    root = _new_root()
    keylog = root.add_file_observable(SSLKEYLOG)
    not_decrypted = root.add_file_observable(NETWORK_PCAP)
    pending = root.add_file_observable(HTTP_TLS_PCAPNG)
    pending.add_analysis(PcapTlsDecryptionAnalysis())

    already = root.add_file_observable(HTTP_TLS_DSB_PCAPNG)
    done = PcapTlsDecryptionAnalysis()
    done.details["keylogs"] = [{"sha256": keylog.sha256_hash, "file_name": "k", "label_counts": {}}]
    done.completed = True
    already.add_analysis(done)

    analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG)
    assert analyzer.execute_analysis(keylog) == AnalysisExecutionResult.COMPLETED
    assert applied == []
    assert keylog.has_tag(TAG_TLS_KEYLOG)
    assert not_decrypted.get_analysis(PcapTlsDecryptionAnalysis) is None


@pytest.mark.unit
def test_keylog_analyzer_ignores_other_files(tmp_path):
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG)
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(TlsKeylogAnalysis) is None


@pytest.mark.unit
def test_find_keylog_observables_skips_oversized():
    root = _new_root()
    root.add_file_observable(SSLKEYLOG)
    root.add_file_observable(NETWORK_PCAP)
    assert len(pcap.find_keylog_observables(root, max_size=10 * 1024)) == 1
    assert pcap.find_keylog_observables(root, max_size=10) == []


@pytest.mark.unit
def test_apply_keylogs_reports_decryption_failure(monkeypatch, caplog):
    def _fail(*args, **kwargs):
        raise PcapError("tshark failed: command timed out after 0:04:00")

    monkeypatch.setattr(pcap, "dissect", _fail)
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    keylog = root.add_file_observable(SSLKEYLOG)
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}],
                                    pcap.KEY_CLIENT_RANDOMS: [CLIENT_RANDOM_12]}
    decryption = PcapTlsDecryptionAnalysis()
    capture.add_analysis(decryption)

    with caplog.at_level(logging.INFO):
        pcap.apply_keylogs(_pcap_config(), capture, core, decryption, [keylog])

    assert decryption.error == "tshark failed: command timed out after 0:04:00"
    assert decryption.generate_summary() == "PCAP TLS Decryption: failed: tshark failed: command timed out after 0:04:00"
    assert decryption.details["sessions_with_keys"] == 1
    (record,) = [r for r in caplog.records if "unable to decrypt pcap" in r.getMessage()]
    assert record.levelno == logging.INFO
    assert record.pcap_sha256 == capture.sha256_hash


@pytest.mark.unit
def test_apply_keylogs_skips_tshark_without_matching_keys(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "dissect", lambda *args, **kwargs: pytest.fail("tshark must not run"))
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    other = tmp_path / "other.keys"
    other.write_text(f"CLIENT_RANDOM {'0' * 64} {'1' * 96}\n")
    keylog = root.add_file_observable(str(other))
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}],
                                    pcap.KEY_CLIENT_RANDOMS: [CLIENT_RANDOM_12]}
    decryption = PcapTlsDecryptionAnalysis()
    capture.add_analysis(decryption)

    pcap.apply_keylogs(_pcap_config(), capture, core, decryption, [keylog])
    assert decryption.details["sessions"] == 1
    assert decryption.details["sessions_with_keys"] == 0
    assert "keys for 0 of 1 TLS sessions" in decryption.generate_summary()


@pytest.mark.unit
def test_collect_carved_files(tmp_path):
    workdir = tmp_path / "work"
    (workdir / "objects" / "http").mkdir(parents=True)
    (workdir / "objects" / "http" / "a.bin").write_bytes(b"first")
    (workdir / "objects" / "http" / "dup.bin").write_bytes(b"first")
    (workdir / "objects" / "http" / "known.bin").write_bytes(b"known")
    (workdir / "objects" / "http" / "late.bin").write_bytes(b"over the limit")
    (workdir / "objects" / "http" / "subdir").mkdir()
    (workdir / "objects" / "smb").mkdir()
    (workdir / "objects" / "smb" / "a.bin").write_bytes(b"second")
    target = tmp_path / "capture.pcap.pcap_objects"
    # an earlier run left a file of the same name
    (target / "http").mkdir(parents=True)
    (target / "http" / "a.bin").write_bytes(b"older")

    packets = [{"tls.handshake.certificate": ["30:82:01", "zz-not-hex", "308201"]}]
    known = {sha256_bytes(b"known")}
    objects, certificates = pcap._collect_carved_files(str(workdir), str(target), packets, max_files=3, known_sha256=known)

    # what crossed the wire is carved first; the certificate gets what is left, which is nothing
    assert [(o["protocol"], o["file_name"], o["path"]) for o in objects] == [
        ("http", "a.bin", "capture.pcap.pcap_objects/http/a_000.bin"),
        ("http", "late.bin", "capture.pcap.pcap_objects/http/late.bin"),
        ("smb", "a.bin", "capture.pcap.pcap_objects/smb/a.bin"),
    ]
    assert len(certificates) == 1
    assert certificates[0]["path"] is None
    assert (target / "http" / "a_000.bin").read_bytes() == b"first"

    # with room left, the certificate is carved too
    second = tmp_path / "second_work"
    (second / "objects" / "http").mkdir(parents=True)
    (second / "objects" / "http" / "more.bin").write_bytes(b"more")
    objects, certificates = pcap._collect_carved_files(str(second), str(tmp_path / "second"), packets, max_files=2,
                                                       known_sha256=set())
    assert [o["file_name"] for o in objects] == ["more.bin"]
    assert certificates[0]["path"] == f"second/certificates/{certificates[0]['sha256']}.der"


@pytest.mark.unit
def test_summaries():
    core = PcapAnalysis()
    assert core.display_name == "PCAP Analysis"
    assert core.generate_summary() is None
    core.details = {}
    assert core.generate_summary() is None

    category = PcapCategoryAnalysis()
    assert category.generate_summary() is None
    category.details.update({"category": CATEGORY_HTTP, "total": 4, pcap.KEY_ADDED: {F_URL: 3}, pcap.KEY_OMITTED: {F_URL: 1}})
    assert category.generate_summary() == "PCAP HTTP: 4 entries (3 url), 1 over the limit"

    decryption = PcapTlsDecryptionAnalysis()
    assert decryption.display_name == "PCAP TLS Decryption"
    decryption.details = {}
    assert decryption.generate_summary() is None

    keylog = TlsKeylogAnalysis()
    keylog.details = {}
    assert keylog.generate_summary() is None
    assert PcapAnalysisPresenter(keylog).tables == [{"title": "Secrets", "columns": ["Label", "Count"], "rows": [], "total": 0,
                                                     "nowrap": [False, False], "order": None, "note": None}]


@pytest.mark.unit
def test_dissect_gives_tshark_a_copy_of_the_evidence(monkeypatch, tmp_path):
    evidence = tmp_path / "capture.pcap"
    shutil.copy(NETWORK_PCAP, evidence)
    inodes = []
    timeouts = {}

    def _fake_tool(config, pcap_path, workdir, command, timeout_seconds, stopping):
        assert pcap_path == str(evidence)
        inodes.append(os.stat(os.path.join(workdir, "input")).st_ino)
        tool = os.path.basename(command[0])
        timeouts.setdefault(tool, set()).add(timeout_seconds)
        if tool == "capinfos":
            return CAPINFOS_OUTPUT
        if "-T" in command:
            assert command[command.index("-Y") + 1].startswith("frame.number <= 50000 && (")
            return ""
        return STATISTICS_OUTPUT

    monkeypatch.setattr(pcap, "_run_tool", _fake_tool)
    index = pcap.dissect(_pcap_config(), str(evidence), str(tmp_path / "capture.pcap.pcap_objects"))

    # capinfos and both tshark runs
    assert len(inodes) == 3 and all(inode != os.stat(evidence).st_ino for inode in inodes)
    # capinfos only reads record headers: its short timeout keeps the three runs inside maximum_analysis_time
    assert timeouts == {"capinfos": {pcap.CAPINFOS_TIMEOUT_SECONDS}, "tshark": {_pcap_config().tshark_timeout}}
    assert pcap.CAPINFOS_TIMEOUT_SECONDS + 2 * _pcap_config().tshark_timeout < _config().maximum_analysis_time
    assert index["field_packet_limit"] == 50000
    assert index["capture"]["packets"] == 1234
    assert index["statistics"]["packets"] == 5
    assert index[CATEGORY_TLS] == []


@pytest.mark.integration
def test_archive_leaves_captures_to_the_pcap_modules(root_analysis):
    # libmagic calls a pcapng application/octet-stream; 7z would "extract" junk from it into a
    # directory the archive module then reports in full
    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(HTTP_TLS_PCAPNG)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in PCAP_MODULES + (ANALYSIS_MODULE_FILE_TYPE, ANALYSIS_MODULE_ARCHIVE):
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_analysis.uuid))
    capture = root.get_observable(capture.uuid)
    assert not capture.get_and_load_analysis(ArchiveAnalysis)
    (payload,) = _category(capture, CATEGORY_FILES).get_observables_by_type(F_FILE)
    assert payload.file_path.endswith("http_tls.pcapng.pcap_objects/http/payload.txt")



def _certificate_der(subject: str, issuer: str, sans: list[str]) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
    # x509_analyzer reads a certificate with .strip(), which corrupts the ~2% of DER certificates whose
    # signature ends in a whitespace byte; sign again until this one does not, so the tests are stable
    while True:
        der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        if der == der.strip():
            return der


@pytest.mark.unit
def test_certificate_names_and_description():
    sans = ["*.leaf.example"] + [f"alt{i}.leaf.example" for i in range(14)]
    names = pcap.certificate_names(_certificate_der("*.leaf.example", "Example Issuing CA", sans))
    assert names["subject"] == "*.leaf.example"
    # the subject is not repeated among the SANs, and only the first few are kept
    assert names["sans"] == [f"alt{i}.leaf.example" for i in range(pcap.MAX_CERTIFICATE_SANS)]
    assert names["san_total"] == 14
    assert pcap.describe_certificate({"sha256": "ab" * 32, **names}) == (
        "*.leaf.example (SAN: alt0.leaf.example, alt1.leaf.example, alt2.leaf.example, +11 more)"
        " \u2014 issued by Example Issuing CA")

    root = pcap.certificate_names(_certificate_der("Example Root", "Example Root", []))
    assert pcap.describe_certificate({"sha256": "cd" * 32, **root}) == "Example Root \u2014 self-signed"

    # what a peer sends need not parse
    assert pcap.certificate_names(b"\x30\x82\x01") == {}
    assert pcap.describe_certificate({"sha256": "ef" * 32}) == f"certificate {'ef' * 8}"


@pytest.mark.unit
def test_tls_table_layout():
    index = {
        CATEGORY_TLS: [{"client": "10.0.0.1:50000", "server": "198.51.100.7:443", "sni": "a.example",
                        "ja4": "t13d0312h1_aaa_bbb", "certificates": ["11" * 32, "22" * 32]}],
        "certificates": [{"sha256": "11" * 32, "subject": "a.example", "sans": [], "san_total": 0, "issuer": "CA"}],
    }
    (table,) = pcap.index_tables(index, CATEGORY_TLS)
    assert table["columns"] == ["Server", "SNI", "JA4", "Certificates"]
    assert table["nowrap"] == [True, False, True, False]
    assert table["rows"] == [["198.51.100.7:443", "a.example",
                              {"text": "t13d0312h1_aaa_bbb", "pivot_type": F_JA4, "pivot_value": "t13d0312h1_aaa_bbb"},
                              ["a.example \u2014 issued by CA", f"certificate {'22' * 8}"]]]


@pytest.mark.unit
def test_pivot_cells():
    index = {
        CATEGORY_HTTP: [{"method": "GET", "url": "http://a.example/x", "status": "200"},
                        {"method": "CONNECT", "url": None}],
        "objects": [{"protocol": "http", "file_name": "x", "size": 3, "sha256": "ab" * 32, "url": None},
                    {"protocol": "http", "file_name": "y", "size": 3, "sha256": "cd" * 32, "url": "http://a.example/y"}],
    }
    http, files = pcap.index_tables(index)
    # a carved file's URL pivots like a request's; a file with no matched URL has an empty cell
    assert files["rows"][1][4] == {"text": "http://a.example/y", "pivot_type": F_URL, "pivot_value": "http://a.example/y"}
    assert files["rows"][0][4] is None
    assert http["rows"][0][1] == {"text": "http://a.example/x", "pivot_type": F_URL, "pivot_value": "http://a.example/x"}
    # nothing to pivot on: a plain empty cell
    assert http["rows"][1][1] is None
    # a file observable's value is its sha256: the name is shown, the content is what it pivots on
    assert files["rows"][0][1] == {"text": "x", "pivot_type": F_FILE, "pivot_value": "ab" * 32}
    assert files["rows"][0][3] == {"text": "ab" * 32, "pivot_type": "sha256", "pivot_value": "ab" * 32}


@pytest.mark.unit
def test_read_embedded_secrets_from_fixtures():
    embedded = pcap.read_embedded_secrets(HTTP_TLS_DSB_PCAPNG, max_tls_bytes=1024 * 1024)
    assert embedded["types"] == {"TLS": 1}
    assert embedded["label_counts"] == read_keylog(SSLKEYLOG).label_counts
    assert CLIENT_RANDOM_12 in embedded["client_randoms"]
    assert len(embedded["client_randoms"]) == 2

    assert pcap.read_embedded_secrets(HTTP_TLS_PCAPNG, max_tls_bytes=1024 * 1024) is None
    # a libpcap file has no blocks at all
    assert pcap.read_embedded_secrets(NETWORK_PCAP, max_tls_bytes=1024 * 1024) is None


def _block(endian: str, block_type: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def _pcapng(endian: str, *blocks: bytes) -> bytes:
    shb = _block(endian, 0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    return shb + b"".join(blocks)


def _dsb(endian: str, secrets_type: int, data: bytes) -> bytes:
    return _block(endian, 0x0000000A, struct.pack(endian + "II", secrets_type, len(data)) + data)


@pytest.mark.unit
@pytest.mark.parametrize("endian", ["<", ">"])
def test_read_embedded_secrets_byte_orders(tmp_path, endian):
    keylog = f"CLIENT_RANDOM {CLIENT_RANDOM_12} {'1' * 96}\n".encode()
    path = tmp_path / "capture.pcapng"
    path.write_bytes(_pcapng(endian,
                             _block(endian, 0x00000001, b"\x01\x00\x00\x00\xff\xff\x00\x00"),
                             _dsb(endian, 0x57474B4C, b"wireguard keys"),
                             _dsb(endian, 0x544C534B, keylog),
                             _dsb(endian, 0x12345678, b"x")))
    embedded = pcap.read_embedded_secrets(str(path), max_tls_bytes=1024)
    assert embedded["types"] == {"WireGuard": 1, "TLS": 1, "0x12345678": 1}
    assert embedded["label_counts"] == {"CLIENT_RANDOM": 1}
    assert embedded["client_randoms"] == {CLIENT_RANDOM_12}

    # past the TLS byte budget the block is still counted, but not parsed
    embedded = pcap.read_embedded_secrets(str(path), max_tls_bytes=10)
    assert embedded["types"]["TLS"] == 1
    assert embedded["client_randoms"] == set()


@pytest.mark.unit
def test_read_embedded_secrets_stops_at_a_damaged_block(tmp_path):
    path = tmp_path / "damaged.pcapng"
    path.write_bytes(_pcapng("<", struct.pack("<II", 0x0000000A, 7) + b"\x00" * 16,
                             _dsb("<", 0x544C534B, b"never reached")))
    assert pcap.read_embedded_secrets(str(path), max_tls_bytes=1024) is None

    # a section header with an unknown byte order
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00" + b"\xde\xad\xbe\xef" + b"\x00" * 16)
    assert pcap.read_embedded_secrets(str(path), max_tls_bytes=1024) is None


@pytest.mark.unit
def test_apply_keylogs_skips_sessions_the_capture_already_decrypted(monkeypatch):
    monkeypatch.setattr(pcap, "dissect", lambda *args, **kwargs: pytest.fail("tshark must not run"))
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_DSB_PCAPNG)
    keylog = root.add_file_observable(SSLKEYLOG)
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {
        CATEGORY_TLS: [{"client_random": r} for r in read_keylog(SSLKEYLOG).client_randoms],
        pcap.KEY_CLIENT_RANDOMS: sorted(read_keylog(SSLKEYLOG).client_randoms),
        "embedded_secrets": {"types": {"TLS": 1}, "keyed_client_randoms": sorted(read_keylog(SSLKEYLOG).client_randoms)},
    }
    decryption = PcapTlsDecryptionAnalysis()
    capture.add_analysis(decryption)

    pcap.apply_keylogs(_pcap_config(), capture, core, decryption, [keylog])
    assert decryption.details["sessions_with_keys"] == 2
    assert decryption.generate_summary() == (
        "PCAP TLS Decryption: keys for 2 of 2 TLS sessions (embedded in the capture and 1 key logs)")
    rows = PcapAnalysisPresenter(decryption).tables[0]["rows"]
    assert rows[0] == ["(embedded in the capture)", "", "keys for 2 TLS sessions"]


@pytest.mark.unit
def test_certificate_names_fallbacks(monkeypatch):
    # neither a CN nor an O: the whole name is shown
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Only Unit")])
    now = datetime.datetime.now(datetime.timezone.utc)
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
           .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    assert pcap.certificate_names(der)["subject"] == "OU=Only Unit"

    # a certificate whose extensions do not parse is shown by its hash
    def _broken(cert):
        raise x509.DuplicateExtension("duplicate", x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    monkeypatch.setattr(pcap.x509_util, "san_dns_names", _broken)
    assert pcap.certificate_names(der) == {}


@pytest.mark.unit
def test_carved_certificates_are_marked_no_crawl():
    root = _new_root()
    pcap_file = root.add_file_observable(HTTP_TLS_PCAPNG)
    analysis = PcapCategoryAnalysis()
    pcap_file.add_analysis(analysis)

    with open(os.path.join(root.file_dir, "c.der"), "wb") as fp:
        fp.write(_certificate_der("leaf.example", "CA", []))
    with open(os.path.join(root.file_dir, "a.bin"), "wb") as fp:
        fp.write(b"payload")
    cert = PcapObservable(CATEGORY_TLS, F_FILE, "ab" * 32, path="c.der", no_crawl=True)
    carved = PcapObservable(CATEGORY_FILES, F_FILE, "cd" * 32, path="a.bin")
    monkey_dir = os.path.dirname(pcap_file.full_path)

    def _rel(item):
        return PcapObservable(item.category, item.o_type, item.value,
                              path=os.path.relpath(os.path.join(root.file_dir, item.path), monkey_dir),
                              no_crawl=item.no_crawl)

    add_pcap_observables(analysis, pcap_file, [_rel(cert), _rel(carved)], max_per_type=10)
    cert_obs = next(o for o in analysis.get_observables_by_type(F_FILE) if o.file_name == "c.der")
    carved_obs = next(o for o in analysis.get_observables_by_type(F_FILE) if o.file_name == "a.bin")
    assert cert_obs.has_directive(DIRECTIVE_NO_CRAWL)
    assert not carved_obs.has_directive(DIRECTIVE_NO_CRAWL)


@pytest.mark.integration
@pytest.mark.parametrize("suppress", [False, True])
def test_x509_analyzer_honors_no_crawl(root_analysis, tmp_path, suppress):
    cert_path = tmp_path / "leaf.der"
    sans = [f"alt{i}.example.com" for i in range(15)]
    cert_path.write_bytes(_certificate_der("leaf.example.com", "Example CA", sans))

    root_analysis.analysis_mode = "test_groups"
    cert = root_analysis.add_file_observable(str(cert_path))
    if suppress:
        cert.add_directive(DIRECTIVE_NO_CRAWL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_FILE_TYPE, "test_groups")
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_X509_ANALYZER, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root.get_observable(cert.uuid).get_and_load_analysis(X509Analysis)
    assert analysis is not None
    # the names are always extracted; a certificate only observed adds the first few as observables
    assert "leaf.example.com" in _values(analysis, F_FQDN)
    assert analysis.san_dns_names == sans
    expected = sans[:MAX_NO_CRAWL_SAN_FQDNS] if suppress else sans
    assert _values(analysis, F_FQDN) - {"leaf.example.com"} == set(expected)
    crawl_urls = [o for o in analysis.get_observables_by_type(F_URL) if o.has_directive(DIRECTIVE_CRAWL)]
    assert (crawl_urls == []) is suppress


CAPINFOS_OUTPUT = """File name:           input
File type:           pcapng
File encapsulation:  ether
Number of packets:   1234
File size:           567890 bytes
Capture duration:    45.5 seconds
Earliest packet time: 1767225600.25
Latest packet time:   1767225645.75
Strict time order:   False
Capture application: Dumpcap (Wireshark) 4.4.19 (Git v4.4.19 packaged as 4.4.19-1)
Number of interfaces in file: 2
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65536
Interface #1 info:
                     Encapsulation = Raw IP (7 - rawip)
Number of decryption secrets in file: 1
"""


@pytest.mark.unit
def test_parse_capinfos():
    capture = pcap.parse_capinfos(CAPINFOS_OUTPUT)
    assert capture == {"format": "pcapng", "size": 567890, "packets": 1234, "first": 1767225600.25,
                       "last": 1767225645.75, "duration": 45.5,
                       "application": "Dumpcap (Wireshark) 4.4.19 (Git v4.4.19 packaged as 4.4.19-1)",
                       "interfaces": 2, "encapsulations": ["Ethernet", "Raw IP"], "strict_time_order": False}
    # whatever capinfos leaves out is simply unknown
    assert pcap.parse_capinfos("garbage") == {"format": None, "size": None, "packets": None, "first": None,
                                              "last": None, "duration": None, "application": None,
                                              "interfaces": None, "encapsulations": [], "strict_time_order": None}


@pytest.mark.unit
def test_capture_summary():
    capture = {**pcap.parse_capinfos(CAPINFOS_OUTPUT), "file_name": "capture.pcapng"}
    assert pcap.capture_summary(capture) == [
        "capture.pcapng", "pcapng", "554.6 KB", "Ethernet, Raw IP, 2 interfaces", "1,234 packets",
        "2026-01-01 00:00:00 to 00:00:45 UTC (45.5 s)", "written by Dumpcap (Wireshark) 4.4.19"]

    # across midnight, and longer than a minute
    capture.update({"first": 1767311990.0, "last": 1767312190.0, "duration": 200.0})
    assert pcap.capture_summary(capture)[5] == "2026-01-01 23:59:50 to 2026-01-02 00:03:10 UTC (0:03:20)"

    capture["duration"] = None
    assert pcap.capture_summary(capture)[5] == "2026-01-01 23:59:50 to 2026-01-02 00:03:10 UTC"

    assert pcap.capture_summary(None) == []
    assert pcap.capture_summary({"file_name": "x.pcap", "first": None}) == ["x.pcap"]


@pytest.mark.unit
def test_order_notes_follow_the_capture_time_order():
    index = {CATEGORY_HTTP: [{"method": "GET", "url": "http://a.example/"}],
             "objects": [{"protocol": "http", "file_name": "a", "size": 1, "sha256": "ab" * 32}]}
    http, files = pcap.index_tables(index, capture={"strict_time_order": True})
    assert http["order"] == "Requests in the order they were sent, which is chronological."
    assert files["order"] == "By protocol, then file name. Not chronological."

    (http,) = pcap.index_tables(index, CATEGORY_HTTP, capture={"strict_time_order": False})
    assert http["order"].endswith("not in time order, so this is not strictly chronological.")
    (http,) = pcap.index_tables(index, CATEGORY_HTTP)
    assert http["order"] == "Requests in the order they were sent."


@pytest.mark.unit
def test_ja4_display_types():
    sessions = [
        {"ja4": "t13_a", "sni": "one.example", "server": "198.51.100.1:443"},
        {"ja4": "t13_a", "sni": "one.example", "server": "198.51.100.1:443"},
        {"ja4": "t13_a", "sni": None, "server": "198.51.100.2:443"},
        {"ja4": "t13_a", "sni": "two.example"},
        {"ja4": "t13_a", "sni": "three.example"},
        {"ja4": "q13_b", "sni": None, "server": "[2001:db8::1]:443"},
        {"ja4": "t12_c"},
        {"ja4": None, "sni": "ignored.example"},
    ]
    assert pcap.ja4_display_types(sessions) == {
        "t13_a": "JA4 client fingerprint (TLS ClientHello), seen to one.example, 198.51.100.2, two.example + 1 more",
        "q13_b": "JA4 client fingerprint (TLS ClientHello), seen to 2001:db8::1",
        "t12_c": "JA4 client fingerprint (TLS ClientHello)",
    }


@pytest.mark.unit
def test_embedded_secrets_tags():
    assert pcap.embedded_secrets_tags({"TLS": 2, "WireGuard": 1, "OPC UA": 1, "0x12345678": 1}) == [
        "pcap_embedded_opc_ua_keys", "pcap_embedded_tls_keys", "pcap_embedded_unknown_keys",
        "pcap_embedded_wireguard_keys"]


@pytest.mark.unit
def test_display_type_never_replaces_another_modules():
    root = _new_root()
    pcap_file = root.add_file_observable(NETWORK_PCAP)
    analysis = PcapCategoryAnalysis()
    pcap_file.add_analysis(analysis)
    existing = root.add_observable_by_spec(F_FQDN, "shared.example")
    existing.display_type = "Certificate SAN DNS Name"

    add_pcap_observables(analysis, pcap_file, [
        PcapObservable(CATEGORY_DNS, F_FQDN, "shared.example", display_type="DNS Query Name"),
        PcapObservable(CATEGORY_DNS, F_FQDN, "own.example", display_type="DNS Query Name")], max_per_type=10)
    labels = {o.value: o.display_type for o in analysis.observables}
    assert labels == {"shared.example": "Certificate SAN DNS Name (fqdn)", "own.example": "DNS Query Name (fqdn)"}


@pytest.mark.unit
def test_capture_metadata_is_optional(monkeypatch, tmp_path, caplog):
    def _no_capinfos(config, pcap_path, workdir, command, timeout_seconds, stopping):
        if os.path.basename(command[0]) == "capinfos":
            raise PcapError("capinfos exited with 2: damaged")
        return "" if "-T" in command else STATISTICS_OUTPUT

    monkeypatch.setattr(pcap, "_run_tool", _no_capinfos)
    with caplog.at_level(logging.INFO):
        index = pcap.dissect(_pcap_config(), NETWORK_PCAP, str(tmp_path / "out"))
    assert index["capture"] is None
    assert index["statistics"]["packets"] == 5
    assert "no capture metadata for pcap" in caplog.text



@pytest.mark.unit
def test_sni_label_only_for_names_dns_did_not_see():
    index = {
        CATEGORY_DNS: [{"name": "seen.example", "answers": [], "queries": 1, "responses": 1, "seen_as": []}],
        CATEGORY_TLS: [{"sni": "Seen.Example.", "ja4": None}, {"sni": "unresolved.example", "ja4": None}],
    }
    labels = {(i.category, i.value): i.display_type for i in collect_observables(index, [])}
    assert labels[(CATEGORY_DNS, "seen.example")] == "DNS Query Name"
    # the same name under TLS adds no label of its own, whichever category module runs first
    assert labels[(CATEGORY_TLS, "seen.example")] is None
    assert labels[(CATEGORY_TLS, "unresolved.example")] == "TLS SNI"



@pytest.mark.unit
def test_dns_answer_ip_takes_its_first_response_time():
    packets = [
        {"frame.number": ["1"], "frame.time_epoch": ["1767225605.5"], "dns.flags.response": ["True"],
         "dns.qry.name": ["b.example"], "dns.a": ["198.51.100.7", "198.51.100.8"]},
        {"frame.number": ["2"], "frame.time_epoch": ["1767225601.25"], "dns.flags.response": ["True"],
         "dns.qry.name": ["a.example"], "dns.a": ["198.51.100.7"]},
        # no packet time: the answer stays untimed rather than guessing one
        {"frame.number": ["3"], "dns.flags.response": ["True"], "dns.qry.name": ["c.example"], "dns.a": ["198.51.100.9"]},
    ]
    index = build_index(packets, [], [], max_rows=500)
    times = {i.value: i.time for i in collect_observables(index, []) if i.o_type == F_IP}
    # one observable per IP, at the earliest response that returned it, whichever name it answered
    assert times == {"198.51.100.7": 1767225601.25, "198.51.100.8": 1767225605.5, "198.51.100.9": None}


@pytest.mark.unit
def test_unparseable_mac_is_left_alone():
    index = {"statistics": {"mac": [{"address": "02:00:00:aa"}]}}
    assert not [i for i in collect_observables(index, []) if i.o_type == F_MAC_ADDRESS]
    assert pcap._mac_pivot("02:00:00:aa") == "02:00:00:aa"
    assert pcap._mac_pivot(None) is None


@pytest.mark.unit
def test_hosts_tables_pivot_on_observables_only():
    analysis = PcapAnalysis()
    analysis.details[pcap.KEY_INDEX] = {
        "hostnames": [{"name": "WS-1", "source": "dhcp", "mac": "02:00:00:aa:00:01"},
                      {"name": "NB", "source": "nbns", "mac": None}],
        "statistics": {
            "ip": [{"address": "10.0.0.1", "packets": 2, "bytes": 3}, {"address": "224.0.0.251", "packets": 1, "bytes": 1}],
            "mac": [{"address": "02:00:00:aa:00:01", "packets": 2, "bytes": 3},
                    {"address": "ff:ff:ff:ff:ff:ff", "packets": 1, "bytes": 1}],
            "flows": [{"protocol": "tcp", "a": "10.0.0.1:50000", "b": "198.51.100.7:443", "frames": 3, "bytes": "1 kB",
                       "start": 0.5, "duration": 1.0},
                      {"protocol": "udp", "a": "fe80::1:5353", "b": "2001:db8::7:53", "frames": 1, "bytes": "90 bytes",
                       "start": 1.0, "duration": 0.0}],
        },
    }
    tables = {t["title"]: t["rows"] for t in PcapAnalysisPresenter(analysis).tables}

    def pivot(o_type, value, text=None):
        return {"text": text or value, "pivot_type": o_type, "pivot_value": value}

    assert tables["Hostnames"] == [[pivot(F_HOSTNAME, "WS-1"), "dhcp", pivot(F_MAC_ADDRESS, "02-00-00-aa-00-01")],
                                   [pivot(F_HOSTNAME, "NB"), "nbns", None]]
    # multicast and broadcast are never observables, so they are not links
    assert [r[0] for r in tables["IP Endpoints"]] == [pivot(F_IP, "10.0.0.1"), "224.0.0.251"]
    assert [r[0] for r in tables["Ethernet Endpoints"]] == [pivot(F_MAC_ADDRESS, "02-00-00-aa-00-01"), "ff-ff-ff-ff-ff-ff"]
    # a flow endpoint shows address:port and pivots on the address, IPv6 included
    assert tables["Flows"][0][1:3] == [pivot(F_IP, "10.0.0.1", "10.0.0.1:50000"),
                                       pivot(F_IP, "198.51.100.7", "198.51.100.7:443")]
    assert tables["Flows"][1][1:3] == ["fe80::1:5353", pivot(F_IP, "2001:db8::7", "2001:db8::7:53")]


@pytest.mark.unit
def test_merge_index_keeps_every_earlier_row():
    previous = {
        CATEGORY_DNS: [{"name": "a.example.com"}], f"{CATEGORY_DNS}_total": 1,
        CATEGORY_HTTP: [{"method": "GET", "url": "https://a.example.com/1"}], f"{CATEGORY_HTTP}_total": 1,
        "objects": [{"sha256": "11" * 32, "file_name": "first.txt", "path": "x/first.txt"}], "objects_total": 1,
        "certificates": [{"sha256": "33" * 32, "path": "x/c.der"}], "certificates_total": 1,
    }
    # the later run decrypts the earlier sessions again, but does not carve their files again
    new = {
        CATEGORY_DNS: [{"name": "a.example.com"}, {"name": "b.example.com"}], f"{CATEGORY_DNS}_total": 2,
        CATEGORY_HTTP: [{"method": "GET", "url": "https://a.example.com/1"}, {"method": "GET", "url": "https://b.example.com/2"}],
        f"{CATEGORY_HTTP}_total": 2,
        "objects": [{"sha256": "22" * 32, "file_name": "second.txt", "path": "x/second.txt"}], "objects_total": 1,
        "certificates": [{"sha256": "33" * 32, "path": None}], "certificates_total": 1,
        "field_packet_limit": 50000,
    }
    merged = pcap.merge_index(previous, new, max_rows=500)

    assert [r["name"] for r in merged[CATEGORY_DNS]] == ["a.example.com", "b.example.com"]
    assert merged[f"{CATEGORY_DNS}_total"] == 2
    assert [r["url"] for r in merged[CATEGORY_HTTP]] == ["https://a.example.com/1", "https://b.example.com/2"]
    assert [o["file_name"] for o in merged["objects"]] == ["first.txt", "second.txt"]
    assert merged["objects_total"] == 2
    # the earlier row wins: its certificate was written to disk, the later run's was not
    assert merged["certificates"] == [{"sha256": "33" * 32, "path": "x/c.der"}]
    assert merged["certificates_total"] == 1
    assert merged["field_packet_limit"] == 50000

    assert pcap.merge_index(None, new, max_rows=500) is new

    # appended rows are still capped, and still counted
    capped = pcap.merge_index(previous, new, max_rows=1)
    assert [o["file_name"] for o in capped["objects"]] == ["first.txt"]
    assert capped["objects_total"] == 2


@pytest.mark.unit
def test_merge_index_counts_a_table_once_past_the_row_limit():
    # a late key log decrypts the same 600 names again; both indexes keep 500 rows
    rows = [{"name": f"host{i}.example"} for i in range(500)]
    previous = {CATEGORY_DNS: rows, f"{CATEGORY_DNS}_total": 600, "objects": [], "objects_total": 0}
    new = {CATEGORY_DNS: list(rows), f"{CATEGORY_DNS}_total": 600, "objects": [], "objects_total": 0}
    merged = pcap.merge_index(previous, new, max_rows=500)
    assert (len(merged[CATEGORY_DNS]), merged[f"{CATEGORY_DNS}_total"]) == (500, 600)


def _write_keylog(tmp_path, name: str, keep) -> str:
    with open(SSLKEYLOG) as fp:
        lines = [line for line in fp if keep(line)]
    path = tmp_path / name
    path.write_text("".join(lines))
    return str(path)


@pytest.mark.integration
def test_late_keylog_adds_to_the_earlier_decryption(root_analysis, tmp_path):
    # one key log per session: the TLS 1.2 session is keyed by CLIENT_RANDOM, the TLS 1.3 one by the rest
    tls12 = _write_keylog(tmp_path, "tls12.keys", lambda line: line.startswith("CLIENT_RANDOM "))
    tls13 = _write_keylog(tmp_path, "tls13.keys", lambda line: not line.startswith("CLIENT_RANDOM "))

    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(HTTP_TLS_PCAPNG)
    root_analysis.add_file_observable(tls12)
    root_analysis.save()
    root_analysis.schedule()

    root = _run_engine(root_analysis)
    decryption = root.get_observable(capture.uuid).get_and_load_analysis(PcapTlsDecryptionAnalysis)
    assert [o["file_name"] for o in decryption.details[pcap.KEY_INDEX]["objects"]] == ["secret12.txt"]

    root.add_file_observable(tls13)
    root.save()
    root.schedule()

    root = _run_engine(root)
    decryption = root.get_observable(capture.uuid).get_and_load_analysis(PcapTlsDecryptionAnalysis)
    _assert_decrypted(decryption)
    # the file the first key log carved is still listed after the second key log's run
    assert [o["file_name"] for o in decryption.details[pcap.KEY_INDEX]["objects"]] == ["secret12.txt", "secret13.txt"]
    assert [k["file_name"] for k in decryption.details["keylogs"]] == ["tls12.keys", "tls13.keys"]
    (table,) = [t for t in PcapAnalysisPresenter(decryption).tables if t["title"] == "Carved Files"]
    assert [row[1]["text"] for row in table["rows"]] == ["secret12.txt", "secret13.txt"]


def _decrypted_capture(root):
    """A pcap whose decryption analysis completed with no key log, ready for a late one."""
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}],
                                    pcap.KEY_CLIENT_RANDOMS: [CLIENT_RANDOM_12]}
    capture.add_analysis(core)
    decryption = PcapTlsDecryptionAnalysis()
    decryption.completed = True
    capture.add_analysis(decryption)
    return capture, decryption


@pytest.mark.unit
def test_keylog_analyzer_skips_pcaps_it_has_no_new_keys_for(tmp_path):
    root = _new_root()
    capture, decryption = _decrypted_capture(root)
    other = tmp_path / "other.keys"
    other.write_text(f"CLIENT_RANDOM {'0' * 64} {'1' * 96}\n")
    keylog = root.add_file_observable(str(other))

    analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG)
    assert analyzer.execute_analysis(keylog) == AnalysisExecutionResult.COMPLETED
    analysis = keylog.get_analysis(TlsKeylogAnalysis)
    # no tshark run: the decryption analysis is untouched
    assert analysis.details["applied_to"] == []
    assert analysis.details["skipped"] == []
    assert decryption.details["keylogs"] == []


@pytest.mark.unit
def test_keylog_analyzer_skips_pcaps_it_has_no_time_for(caplog):
    root = _new_root()
    capture, decryption = _decrypted_capture(root)
    keylog = root.add_file_observable(SSLKEYLOG)

    # a tshark run (240 s) no longer fits in what is left of maximum_analysis_time
    analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG, maximum_analysis_time=120)
    with caplog.at_level(logging.INFO):
        assert analyzer.execute_analysis(keylog) == AnalysisExecutionResult.COMPLETED

    analysis = keylog.get_analysis(TlsKeylogAnalysis)
    assert analysis.details["applied_to"] == []
    assert analysis.details["skipped"] == [capture.sha256_hash]
    assert analysis.generate_summary().endswith(", not applied to 1 pcaps (out of time)")
    assert decryption.details["keylogs"] == []
    (record,) = [r for r in caplog.records if "out of time to apply TLS key log" in r.getMessage()]
    assert record.levelno == logging.INFO
    assert record.pcap_sha256 == [capture.sha256_hash]


@pytest.mark.integration
def test_apply_keylogs_runs_tshark_for_rsa_keys(tmp_path):
    # an RSA line is keyed by the encrypted pre-master secret, so no client random can match it
    rsa = tmp_path / "rsa.keys"
    rsa.write_text(f"RSA {'ab' * 8} {'cd' * 48}\n")
    root = _new_root()
    capture, decryption = _decrypted_capture(root)
    keylog = root.add_file_observable(str(rsa))
    core = capture.get_analysis(PcapAnalysis)

    pcap.apply_keylogs(_pcap_config(), capture, core, decryption, [keylog])
    assert decryption.error is None
    assert decryption.details["sessions_with_keys"] == 0
    # tshark ran: the decryption has an index of its own
    assert decryption.details[pcap.KEY_INDEX] is not None


@pytest.mark.integration
def test_field_packet_limit(tmp_path):
    index = pcap.dissect(_pcap_config(max_field_packets=10), HTTP_TLS_PCAPNG, str(tmp_path / "http_tls.pcapng.pcap_objects"))

    # the HTTP request (frame 4) is inside the limit, the TLS handshakes (frames 16 and 31) are not
    assert [r["url"] for r in index[CATEGORY_HTTP]] == ["http://pcap-http.example:18080/payload.txt"]
    assert index[CATEGORY_TLS] == []
    # the statistics and the object export still cover every packet
    assert index["statistics"]["packets"] == 41
    assert [o["file_name"] for o in index["objects"]] == ["payload.txt"]
    assert index["field_packet_limit"] == 10

    (http,) = pcap.index_tables(index, CATEGORY_HTTP, index["capture"])
    assert http["note"] == "Read from the first 10 of the capture's 41 packets only."
    (files,) = pcap.index_tables(index, CATEGORY_FILES, index["capture"])
    assert files["note"] is None


@pytest.mark.unit
def test_packet_limit_note():
    assert pcap._packet_limit_note(50000, {"packets": 50000}) is None
    assert pcap._packet_limit_note(50000, {"packets": 1234567}) == (
        "Read from the first 50,000 of the capture's 1,234,567 packets only.")
    assert pcap._packet_limit_note(50000, None) is None
    assert pcap._packet_limit_note(None, {"packets": 1234567}) is None

    index = {CATEGORY_TLS: [{"server": "s", "sni": None, "ja4": None, "certificates": []}], "field_packet_limit": 10}
    (table,) = pcap.index_tables(index, CATEGORY_TLS, {"packets": 11})
    assert table["note"] == f"{pcap.JA4_NOTE} Read from the first 10 of the capture's 11 packets only."


@pytest.mark.integration
def test_keylog_matches_sessions_past_the_table_rows(monkeypatch, tmp_path):
    # the TLS table keeps one row (the TLS 1.2 session); the key log is only for the TLS 1.3 one
    monkeypatch.setattr(get_config().pcap, "max_table_rows", 1)
    tls13 = _write_keylog(tmp_path, "tls13.keys", lambda line: not line.startswith("CLIENT_RANDOM "))
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    keylog = root.add_file_observable(tls13)
    assert _adapter(PcapAnalyzer, root).execute_analysis(capture) == AnalysisExecutionResult.COMPLETED
    core = capture.get_analysis(PcapAnalysis)
    assert len(core.index[CATEGORY_TLS]) == 1
    assert len(core.index[pcap.KEY_CLIENT_RANDOMS]) == 2
    assert ", 2 TLS sessions" in core.generate_summary()

    decryption = PcapTlsDecryptionAnalysis()
    capture.add_analysis(decryption)
    pcap.apply_keylogs(_pcap_config(), capture, core, decryption, [keylog])

    assert (decryption.details["sessions"], decryption.details["sessions_with_keys"]) == (2, 1)
    assert {o.file_name for o in decryption.get_observables_by_type(F_FILE)} == {"secret13.txt"}
    # only the plaintext index carries the session list
    assert pcap.KEY_CLIENT_RANDOMS not in decryption.details[pcap.KEY_INDEX]


@pytest.mark.unit
def test_shared_pcap_config_reaches_every_module(monkeypatch):
    # one setting in the pcap section, not one per module block
    monkeypatch.setattr(get_config().pcap, "max_keylog_size", 10)
    root = _new_root()
    keylog = root.add_file_observable(SSLKEYLOG)
    analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG)
    assert analyzer.execute_analysis(keylog) == AnalysisExecutionResult.COMPLETED
    assert keylog.get_analysis(TlsKeylogAnalysis) is None


@pytest.mark.unit
def test_read_embedded_secrets_stops_at_a_file_cut_inside_a_block(tmp_path):
    path = tmp_path / "cut.pcapng"
    block = _dsb("<", 0x544C534B, b"CLIENT_RANDOM " + b"a" * 64 + b" " + b"b" * 96 + b"\n")
    # the block's type, length and secrets type survive; its secrets length does not
    path.write_bytes(_pcapng("<") + block[:12])
    assert pcap.read_embedded_secrets(str(path), max_tls_bytes=1024) is None


@pytest.mark.integration
def test_hidden_mime_leaves_captures_alone(tmp_path):
    # a capture of an email sent over plain SMTP holds the MIME body in its raw bytes
    body = (b"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\n"
            b"hello\r\n--b1--\r\n")
    capture = tmp_path / "smtp.pcap"
    capture.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                        + struct.pack("<IIII", 1767225600, 0, len(body), len(body)) + body)
    assert is_pcap_file(str(capture))
    # without the check the module would extract it
    assert parse_mime(str(capture), str(tmp_path / "out"))

    root = _new_root()
    observable = root.add_file_observable(str(capture))
    analyzer = AnalysisModuleAdapter(HiddenMIMEAnalyzer(context=create_test_context(root=root),
                                                        config=get_analysis_module_config(ANALYSIS_MODULE_HIDDEN_MIME)))
    analyzer.root = root
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(HiddenMIMEAnalysis) is None
    assert not os.path.exists(f"{observable.full_path}.mime")


@pytest.mark.unit
def test_apply_keylogs_reports_a_node_problem_at_error(monkeypatch, caplog):
    monkeypatch.setattr(pcap, "landlock_available", lambda: False)
    root = _new_root()
    capture, decryption = _decrypted_capture(root)
    keylog = root.add_file_observable(SSLKEYLOG)
    with caplog.at_level(logging.INFO):
        pcap.apply_keylogs(_pcap_config(), capture, capture.get_analysis(PcapAnalysis), decryption, [keylog])

    assert "Landlock" in decryption.error
    assert any(r.levelno == logging.ERROR and "unable to decrypt pcap" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_a_url_that_does_not_parse_is_skipped():
    # tshark builds http.request.full_uri from the Host header the client sent
    index = {
        CATEGORY_HTTP: [{"method": "GET", "url": "http://[x/a.js", "host": "[x", "user_agent": None},
                        {"method": "GET", "url": "http://ok.example/b.js", "host": "ok.example", "user_agent": None}],
        "objects": [{"protocol": "http", "file_name": "a.js", "sha256": "11" * 32, "size": 1, "path": "x/a.js"},
                    {"protocol": "http", "file_name": "b.js", "sha256": "22" * 32, "size": 1, "path": "x/b.js"}],
    }
    pcap._link_http_objects(index)
    assert [o["url"] for o in index["objects"]] == [None, "http://ok.example/b.js"]
    urls = {i.value for i in collect_observables(index, []) if i.o_type == F_URL}
    assert urls == {"http://ok.example/b.js"}


@pytest.mark.integration
def test_a_tshark_that_cannot_start_is_an_operators_problem(monkeypatch, caplog):
    monkeypatch.setattr(get_config().pcap, "tshark_path", "/nonexistent/tshark")
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    with caplog.at_level(logging.INFO):
        assert _adapter(PcapAnalyzer, root).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert "could not be run in the sandbox" in observable.get_analysis(PcapAnalysis).error
    assert any(r.levelno == logging.ERROR and "unable to dissect pcap" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_an_unexpected_error_is_left_to_the_engine(monkeypatch):
    # the executor's crash report keeps the capture that triggered it
    def _bug(*args, **kwargs):
        raise KeyError("layers")

    monkeypatch.setattr(pcap, "dissect", _bug)
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    with pytest.raises(KeyError):
        _adapter(PcapAnalyzer, root).execute_analysis(observable)
    assert observable.get_analysis(PcapAnalysis) is None


@pytest.mark.unit
def test_pcap_analyzer_skips_a_capture_the_pass_has_no_time_for(caplog):
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(PcapAnalyzer, root)
    # the engine gives this call 100 s
    analyzer.set_analysis_deadline(time.monotonic() + 100)
    with caplog.at_level(logging.INFO):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(PcapAnalysis)
    assert analysis.error.startswith("skipped: dissecting this capture can take 330 s and only 100 s are left")
    assert analysis.index is None
    (record,) = [r for r in caplog.records if "not dissecting pcap" in r.getMessage()]
    assert record.levelno == logging.INFO


@pytest.mark.unit
def test_decryption_skips_a_capture_the_pass_has_no_time_for():
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}],
                                    pcap.KEY_CLIENT_RANDOMS: [CLIENT_RANDOM_12]}
    capture.add_analysis(core)
    root.add_file_observable(SSLKEYLOG)

    decryptor = _adapter(pcap.PcapTlsDecryptor, root, ANALYSIS_MODULE_PCAP_TLS_DECRYPTION)
    decryptor.set_analysis_deadline(time.monotonic() + 100)
    assert decryptor.execute_final_analysis(capture) == AnalysisExecutionResult.COMPLETED
    decryption = capture.get_analysis(PcapTlsDecryptionAnalysis)
    assert decryption.error.startswith("skipped: dissecting this capture can take 150 s")
    assert decryption.details[pcap.KEY_INDEX] is None


def _shutting_down(monkeypatch, module_class):
    monkeypatch.setattr(module_class, "shutdown", property(lambda self: True))


@pytest.mark.unit
def test_pcap_analyzer_records_nothing_when_the_engine_stops(monkeypatch, caplog):
    _shutting_down(monkeypatch, PcapAnalyzer)
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(PcapAnalyzer, root)
    with caplog.at_level(logging.INFO):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.INCOMPLETE

    # no analysis: the capture is dissected again when the work item is picked up again
    assert observable.get_analysis(PcapAnalysis) is None
    assert "the engine is shutting down" in caplog.text
    # cancelled, so a dependency on it stays unresolved even before the engine cancels
    assert analyzer.is_canceled_analysis()


@pytest.mark.unit
def test_decryption_records_nothing_when_the_engine_stops(monkeypatch):
    _shutting_down(monkeypatch, pcap.PcapTlsDecryptor)
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}],
                                    pcap.KEY_CLIENT_RANDOMS: [CLIENT_RANDOM_12]}
    capture.add_analysis(core)
    root.add_file_observable(SSLKEYLOG)

    decryptor = _adapter(pcap.PcapTlsDecryptor, root, ANALYSIS_MODULE_PCAP_TLS_DECRYPTION)
    assert decryptor.execute_final_analysis(capture) == AnalysisExecutionResult.INCOMPLETE
    assert capture.get_analysis(PcapTlsDecryptionAnalysis) is None


@pytest.mark.unit
def test_keylog_analyzer_records_nothing_when_the_engine_stops(monkeypatch):
    _shutting_down(monkeypatch, pcap.TlsKeylogAnalyzer)
    root = _new_root()
    capture, decryption = _decrypted_capture(root)
    keylog = root.add_file_observable(SSLKEYLOG)

    analyzer = _adapter(pcap.TlsKeylogAnalyzer, root, ANALYSIS_MODULE_TLS_KEYLOG)
    assert analyzer.execute_analysis(keylog) == AnalysisExecutionResult.INCOMPLETE
    # the key log is applied again when the work item is picked up again
    assert keylog.get_analysis(TlsKeylogAnalysis) is None
    assert decryption.details["keylogs"] == []


def _carving_workdir(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "secret.txt").write_bytes(b"not tshark's to take")
    return workdir, victim


@pytest.mark.unit
def test_carving_never_follows_a_symlinked_directory(tmp_path):
    # tshark may create symlinks in its workdir; ACE moves the carved files out unsandboxed
    workdir, victim = _carving_workdir(tmp_path)
    (workdir / "objects").mkdir()
    (workdir / "objects" / "http").symlink_to(victim)
    objects, _ = pcap._collect_carved_files(str(workdir), str(tmp_path / "out"), [], max_files=10, known_sha256=set())
    assert objects == []
    assert (victim / "secret.txt").read_bytes() == b"not tshark's to take"

    # the objects directory itself replaced by a link
    workdir, victim = _carving_workdir(tmp_path / "second")
    (victim / "http").mkdir()
    (victim / "http" / "secret.txt").write_bytes(b"not tshark's to take")
    (workdir / "objects").symlink_to(victim)
    objects, _ = pcap._collect_carved_files(str(workdir), str(tmp_path / "out2"), [], max_files=10, known_sha256=set())
    assert objects == []
    assert (victim / "http" / "secret.txt").exists()


@pytest.mark.unit
def test_carving_never_takes_a_linked_file(tmp_path):
    workdir, victim = _carving_workdir(tmp_path)
    http = workdir / "objects" / "http"
    http.mkdir(parents=True)
    (http / "symlinked.txt").symlink_to(victim / "secret.txt")
    os.link(victim / "secret.txt", http / "hardlinked.txt")
    (http / "carved.txt").write_bytes(b"carved")
    objects, _ = pcap._collect_carved_files(str(workdir), str(tmp_path / "out"), [], max_files=10, known_sha256=set())
    assert [o["file_name"] for o in objects] == ["carved.txt"]
    assert (victim / "secret.txt").read_bytes() == b"not tshark's to take"


@pytest.mark.unit
@pytest.mark.parametrize("returncode,error", [
    # the tool never ran: no capture can be dissected on this node
    (EXIT_SANDBOX_FAILURE, pcap.PcapNodeError),
    (126, pcap.PcapNodeError),
    (127, pcap.PcapNodeError),
    # the launcher's verdict on a run that did start: this capture's problem
    (EXIT_PROCESS_LIMIT, PcapError),
    (EXIT_DEADLINE, PcapError),
])
def test_launcher_failure_is_told_from_a_capture_failure(monkeypatch, tmp_path, returncode, error):
    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", lambda *args, **kwargs: SandboxResult(returncode, "", "sandbox: failed"))
    with pytest.raises(error) as raised:
        pcap._run_tshark(_pcap_config(), "capture.pcap", str(tmp_path), [], _never)
    assert type(raised.value) is error


@pytest.mark.integration
def test_a_running_tool_stops_when_the_engine_stops(tmp_path):
    started = time.monotonic()
    with pytest.raises(SandboxCancelled, match="the analysis was stopped"):
        pcap._run_tool(_pcap_config(), "capture.pcap", str(tmp_path), ["/usr/bin/sleep", "60"], 120,
                       lambda: time.monotonic() - started > 1)
    # stopped in the middle of the run, not at its timeout
    assert time.monotonic() - started < 30


@pytest.mark.integration
def test_a_failed_statistics_pass_keeps_the_rest(monkeypatch, caplog):
    run_tool = pcap._run_tool

    def _statistics_over_the_cap(config, pcap_path, workdir, command, timeout_seconds, stopping):
        if "io,stat,0" in command:
            raise PcapError("tshark failed: command wrote more than 67108864 bytes of output")
        return run_tool(config, pcap_path, workdir, command, timeout_seconds, stopping)

    monkeypatch.setattr(pcap, "_run_tool", _statistics_over_the_cap)
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    with caplog.at_level(logging.INFO):
        assert _adapter(PcapAnalyzer, root).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    core = observable.get_analysis(PcapAnalysis)
    assert core.error is None
    # the field pass still ran
    assert {r["name"] for r in core.index[CATEGORY_DNS]} >= {"www.pcap-dns.example"}
    assert core.index["capture"]["packets"] == 5
    assert core.generate_summary().startswith("PCAP Analysis: no packet statistics (tshark failed: command wrote more")
    assert "No endpoint or flow tables" in PcapAnalysisPresenter(core).notice
    (record,) = [r for r in caplog.records if "no packet statistics for pcap" in r.getMessage()]
    assert record.levelno == logging.INFO


@pytest.mark.unit
def test_observable_limit_is_per_capture_across_its_nodes():
    root = _new_root()
    pcap_file = root.add_file_observable(HTTP_TLS_PCAPNG)
    core = PcapAnalysis()
    pcap_file.add_analysis(core)
    added, _ = add_pcap_observables(core, pcap_file, [PcapObservable(CATEGORY_HOSTS, F_FQDN, f"a{i}.example") for i in range(2)],
                                    max_per_type=3)
    assert added == {F_FQDN: 2}

    # another node of the same capture gets what is left of the capture's limit
    decryption = PcapTlsDecryptionAnalysis()
    pcap_file.add_analysis(decryption)
    added, omitted = add_pcap_observables(decryption, pcap_file,
                                          [PcapObservable(CATEGORY_TLS, F_FQDN, f"b{i}.example") for i in range(2)],
                                          max_per_type=3)
    assert (added, omitted) == ({F_FQDN: 1}, {F_FQDN: 1})


def _secrets_pcapng(tmp_path) -> str:
    # the secrets come third, after the section header and one other block
    path = tmp_path / "late_secrets.pcapng"
    path.write_bytes(_pcapng("<", _block("<", 0x00000001, b"\x01\x00\x00\x00\xff\xff\x00\x00"),
                             _dsb("<", 0x544C534B, f"CLIENT_RANDOM {CLIENT_RANDOM_12} {'b' * 96}\n".encode())))
    return str(path)


@pytest.mark.unit
def test_embedded_secrets_scan_is_bounded(monkeypatch, tmp_path, caplog):
    path = _secrets_pcapng(tmp_path)
    assert pcap.read_embedded_secrets(path, max_tls_bytes=1024)["types"] == {"TLS": 1}

    monkeypatch.setattr(pcap, "EMBEDDED_SECRETS_MAX_BLOCKS", 2)
    with caplog.at_level(logging.INFO):
        assert pcap.read_embedded_secrets(path, max_tls_bytes=1024) is None
    assert "stopped looking for decryption secrets" in caplog.text


@pytest.mark.unit
def test_embedded_secrets_scan_stops_with_the_engine(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "EMBEDDED_SECRETS_STOP_CHECK_BLOCKS", 1)
    with pytest.raises(SandboxCancelled):
        pcap.read_embedded_secrets(_secrets_pcapng(tmp_path), max_tls_bytes=1024, stopping=lambda: True)


@pytest.mark.unit
def test_category_without_pcap_analysis_adds_nothing(monkeypatch):
    # pcap_analyzer answered without an analysis: a stopped one leaves the dependency unresolved
    # rather than returning here, so this capture has nothing in the category
    monkeypatch.setattr(pcap.PcapCategoryAnalyzer, "wait_for_analysis", lambda self, *args, **kwargs: None)
    root = _new_root()
    capture = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(pcap.PcapCategoryAnalyzer, root, ANALYSIS_MODULE_PCAP_DNS)
    assert analyzer.execute_analysis(capture) == AnalysisExecutionResult.COMPLETED
    assert not capture.get_analysis(PcapCategoryAnalysis, instance=CATEGORY_DNS)


def _run_dns_engine():
    engine = Engine()
    for module in (ANALYSIS_MODULE_PCAP_ANALYZER, ANALYSIS_MODULE_PCAP_DNS):
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)


@pytest.mark.integration
def test_category_is_added_after_pcap_analyzer_is_stopped(root_analysis, monkeypatch, caplog):
    # pcap_analyzer sees the shutdown itself (module.shutdown) before the worker's watcher has
    # cancelled the engine: pcap_dns's dependency on it must still survive the requeue unresolved
    state = {"runs": 0, "shutdown": False}
    execute_analysis = PcapAnalyzer.execute_analysis

    def _execute_analysis(self, _file):
        # run 1 is the plain pass and answers nothing, so pcap_dns waits on it; run 2 resolves that
        # dependency and is stopped by the shutdown; run 3 is the requeued pass
        state["runs"] += 1
        if state["runs"] == 1:
            return AnalysisExecutionResult.INCOMPLETE
        state["shutdown"] = state["runs"] == 2
        return execute_analysis(self, _file)

    monkeypatch.setattr(PcapAnalyzer, "execute_analysis", _execute_analysis)
    monkeypatch.setattr(PcapAnalyzer, "shutdown", property(lambda self: state["shutdown"]))

    root_analysis.analysis_mode = "test_groups"
    capture = root_analysis.add_file_observable(NETWORK_PCAP)
    root_analysis.save()
    root_analysis.schedule()
    with caplog.at_level(logging.INFO):
        _run_dns_engine()

    root = load_root(get_storage_dir(root_analysis.uuid))
    observable = root.get_observable(capture.uuid)
    assert state["runs"] == 2
    assert [d.status for d in observable.dependencies] == ["ready"]
    assert observable.get_analysis(PcapAnalysis) is None
    # not even a "no analysis" marker, which would keep pcap_dns from running again
    assert observable.get_analysis(PcapCategoryAnalysis, instance=CATEGORY_DNS) is None
    assert "leaving it unresolved" in caplog.text

    root.schedule()
    _run_dns_engine()

    root = load_root(get_storage_dir(root_analysis.uuid))
    observable = root.get_observable(capture.uuid)
    dns = observable.get_and_load_analysis(PcapCategoryAnalysis, instance=CATEGORY_DNS)
    assert "www.pcap-dns.example" in _values(dns, F_FQDN)
    assert not [d for d in observable.dependencies if d.failed]


@pytest.mark.unit
def test_decryption_knows_every_file_found_before(monkeypatch):
    seen = {}

    def _dissect(config, pcap_path, target_dir, keylog_lines=None, known_sha256=None, statistics=True, stopping=None):
        seen["known"] = set(known_sha256)
        return build_index([], [], [], max_rows=500)

    monkeypatch.setattr(pcap, "dissect", _dissect)
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    keylog = root.add_file_observable(SSLKEYLOG)
    core = PcapAnalysis()
    # the plaintext tables kept one object row of three carved files
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}],
                                    pcap.KEY_CLIENT_RANDOMS: [CLIENT_RANDOM_12],
                                    "objects": [{"sha256": "11" * 32}],
                                    pcap.KEY_CARVED_SHA256: ["11" * 32, "22" * 32, "33" * 32]}
    decryption = PcapTlsDecryptionAnalysis()
    # an earlier key log's run listed a file it did not carve
    decryption.details[pcap.KEY_INDEX] = {"objects": [], pcap.KEY_CARVED_SHA256: ["44" * 32]}
    capture.add_analysis(decryption)

    pcap.apply_keylogs(_pcap_config(), capture, core, decryption, [keylog])
    assert seen["known"] == {"11" * 32, "22" * 32, "33" * 32, "44" * 32}
    assert decryption.details[pcap.KEY_INDEX][pcap.KEY_CARVED_SHA256] == ["44" * 32]


def _carved(root, pcap_file, category: str, name: str, no_crawl: bool = False) -> PcapObservable:
    path = os.path.join(os.path.dirname(pcap_file.full_path), name)
    with open(path, "wb") as fp:
        fp.write(name.encode())
    return PcapObservable(category, F_FILE, sha256_bytes(name.encode()), path=name, no_crawl=no_crawl)


@pytest.mark.unit
def test_payload_files_come_before_certificates():
    root = _new_root()
    pcap_file = root.add_file_observable(HTTP_TLS_PCAPNG)
    certificates = [_carved(root, pcap_file, CATEGORY_TLS, f"c{i}.der", no_crawl=True) for i in range(3)]
    payloads = [_carved(root, pcap_file, CATEGORY_FILES, f"p{i}.bin") for i in range(2)]

    # one call, certificates listed first (as collect_observables lists them for decryption)
    decryption = PcapTlsDecryptionAnalysis()
    pcap_file.add_analysis(decryption)
    added, omitted = add_pcap_observables(decryption, pcap_file, certificates + payloads, max_per_type=3)
    assert (added, omitted) == ({F_FILE: 3}, {F_FILE: 2})
    assert {o.file_name for o in decryption.get_observables_by_type(F_FILE)} == {"p0.bin", "p1.bin", "c0.der"}


@pytest.mark.unit
def test_tls_node_keeps_room_for_the_files_nodes_payloads():
    root = _new_root()
    pcap_file = root.add_file_observable(HTTP_TLS_PCAPNG)
    certificates = [_carved(root, pcap_file, CATEGORY_TLS, f"c{i}.der", no_crawl=True) for i in range(3)]
    payloads = [_carved(root, pcap_file, CATEGORY_FILES, f"p{i}.bin") for i in range(2)]

    # the TLS node runs first and leaves the payloads their room
    tls = PcapCategoryAnalysis()
    tls.instance = CATEGORY_TLS
    pcap_file.add_analysis(tls)
    added, omitted = add_pcap_observables(tls, pcap_file, certificates, max_per_type=3, reserved=payloads)
    assert (added, omitted) == ({F_FILE: 1}, {F_FILE: 2})

    files = PcapCategoryAnalysis()
    files.instance = CATEGORY_FILES
    pcap_file.add_analysis(files)
    added, omitted = add_pcap_observables(files, pcap_file, payloads, max_per_type=3)
    assert (added, omitted) == ({F_FILE: 2}, {})


@pytest.mark.integration
def test_category_analyzer_reserves_the_payloads(monkeypatch):
    monkeypatch.setattr(get_config().pcap, "max_observables_per_type", 2)
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    assert _adapter(PcapAnalyzer, root).execute_analysis(capture) == AnalysisExecutionResult.COMPLETED
    core = capture.get_analysis(PcapAnalysis)
    core.completed = True
    index = core.index
    # two more payloads than the capture really carved, beside it like the real one
    pcap_dir = os.path.dirname(capture.full_path)
    for name in ("extra0.bin", "extra1.bin"):
        with open(os.path.join(pcap_dir, name), "wb") as fp:
            fp.write(name.encode())
        index["objects"].append({"protocol": "http", "file_name": name, "sha256": sha256_bytes(name.encode()),
                                 "size": len(name), "path": name})

    tls = _adapter(pcap.PcapCategoryAnalyzer, root, ANALYSIS_MODULE_PCAP_TLS)
    assert tls.execute_analysis(capture) == AnalysisExecutionResult.COMPLETED
    # three payloads reserve the whole budget of two: no certificate takes a payload's room
    assert _category(capture, CATEGORY_TLS).get_observables_by_type(F_FILE) == []
