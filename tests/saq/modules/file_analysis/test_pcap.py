import logging
import os
import shutil
import zipfile

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_ARCHIVE,
    ANALYSIS_MODULE_FILE_TYPE,
    ANALYSIS_MODULE_PCAP_ANALYZER,
    ANALYSIS_MODULE_PCAP_DNS,
    ANALYSIS_MODULE_PCAP_FILES,
    ANALYSIS_MODULE_PCAP_HTTP,
    ANALYSIS_MODULE_PCAP_TLS,
    ANALYSIS_MODULE_PCAP_TLS_DECRYPTION,
    ANALYSIS_MODULE_TLS_KEYLOG,
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
from saq.sandbox.runner import SandboxResult
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
    (b"\x0a\x0d\x0d\x0a", True),
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
    return [{"sha256": "11" * 32, "der_hex": "308201", "path": "c.pcap.extracted/certificates/1.der"},
            {"sha256": "22" * 32, "der_hex": "308202", "path": None}]


@pytest.mark.unit
def test_build_index():
    objects = [{"protocol": "http", "file_name": "a.exe", "sha256": "33" * 32, "size": 3, "path": "x/a.exe"}]
    index = build_index(_packets(), _certificates(), objects, max_rows=500)

    dns = {r["name"]: r for r in index[CATEGORY_DNS]}
    assert set(dns) == {"www.example.com", "cdn.example.com"}
    assert dns["www.example.com"]["answers"] == ["198.51.100.7", "cdn.example.com"]

    (session,) = index[CATEGORY_TLS]
    assert session["client"] == "10.0.0.1:50000"
    assert session["server"] == "198.51.100.7:443"
    assert session["sni"] == "tls.example.com"
    assert session["ja4"] == "t13d0312h1_aaa_bbb"
    assert session["client_random"] == CLIENT_RANDOM_12
    assert session["certificates"] == ["11" * 32, "22" * 32]

    requests = {r["url"]: r for r in index[CATEGORY_HTTP]}
    assert requests["http://web.example.com:8080/a.exe"]["status"] == "200"
    assert requests["http://web.example.com:8080/a.exe"]["user_agent"] == "agent, with comma"
    assert requests["https://h2.example.com/x"]["user_agent"] == "h2-agent"
    assert requests["https://h2.example.com/y"]["method"] == "POST"

    assert {h["name"] for h in index["hostnames"]} == {"Workstation-1", "NBHOST"}
    assert index["certificates"] == [{"sha256": "11" * 32, "path": "c.pcap.extracted/certificates/1.der"},
                                     {"sha256": "22" * 32, "path": None}]


@pytest.mark.unit
def test_build_index_caps_rows():
    index = build_index(_packets(), [], [], max_rows=1)
    assert len(index[CATEGORY_HTTP]) == 1
    assert index[f"{CATEGORY_HTTP}_total"] == 3


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
    index[CATEGORY_DNS].append({"name": "1.0.0.10.in-addr.arpa", "answers": ["printer.local"], "count": 1})

    items = collect_observables(index, [".arpa", ".local"])
    by_category: dict[str, set] = {}
    for item in items:
        by_category.setdefault(item.category, set()).add((item.o_type, item.value, item.volatile))

    assert by_category[CATEGORY_HOSTS] == {
        (F_IP, "10.0.0.1", True), (F_IP, "2001:db8::1", True), (F_MAC_ADDRESS, "02:00:00:aa:00:01", True),
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

    items = [PcapObservable(CATEGORY_DNS, F_FQDN, f"host{i}.example.com") for i in range(3)]
    items.append(PcapObservable(CATEGORY_DNS, F_FQDN, "not a valid fqdn!"))
    items.append(PcapObservable(CATEGORY_DNS, F_IP, "198.51.100.7", volatile=True))

    added, omitted = add_pcap_observables(analysis, pcap_file, items, max_per_type=2)
    assert added == {F_FQDN: 2, F_IP: 1}
    assert omitted == {F_FQDN: 2}
    assert analysis.get_observables_by_type(F_IP)[0].volatile
    assert analysis.get_observables_by_type(F_FQDN)[0].sort_order == pcap.SORT_ORDER[F_FQDN]

    # a second call adds nothing it already has and still respects the limit
    added, omitted = add_pcap_observables(analysis, pcap_file, items, max_per_type=2)
    assert added == {}
    assert omitted == {F_FQDN: 2}


@pytest.mark.unit
def test_run_tshark_refuses_without_landlock(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "landlock_available", lambda: False)
    with pytest.raises(PcapError, match="Landlock"):
        pcap._run_tshark(_config(), str(tmp_path), [])


@pytest.mark.unit
def test_run_tshark_failure_without_output(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", lambda *args, **kwargs: SandboxResult(2, "", "file is damaged"))
    with pytest.raises(PcapError, match="file is damaged"):
        pcap._run_tshark(_config(), str(tmp_path), [])


@pytest.mark.unit
def test_run_tshark_timeout(monkeypatch, tmp_path):
    def _timeout(*args, **kwargs):
        raise RuntimeError("command timed out after 0:04:00")

    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", _timeout)
    with pytest.raises(PcapError, match="timed out"):
        pcap._run_tshark(_config(), str(tmp_path), [])


@pytest.mark.unit
def test_run_tshark_keeps_output_of_a_truncated_capture(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(pcap, "landlock_available", lambda: True)
    monkeypatch.setattr(pcap, "run_sandboxed", lambda *args, **kwargs: SandboxResult(2, "[]", "cut short"))
    with caplog.at_level(logging.INFO):
        assert pcap._run_tshark(_config(), str(tmp_path), []) == "[]"
    assert "cut short" in caplog.text


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
def test_pcap_analyzer_oversized(tmp_path):
    root = _new_root()
    observable = root.add_file_observable(NETWORK_PCAP)
    analyzer = _adapter(PcapAnalyzer, root, max_file_size=10)
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
    with caplog.at_level(logging.ERROR):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(PcapAnalysis).error == "tshark exited with 2: damaged"
    assert any(r.levelno == logging.ERROR and "unable to dissect pcap" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_presenter_tables():
    category = PcapCategoryAnalysis()
    category.details = {"category": CATEGORY_DNS, "rows": [{"name": "a.example.com", "answers": ["1.2.3.4"], "count": 2}],
                        "total": 7}
    (table,) = PcapAnalysisPresenter(category).tables
    assert table["title"] == "DNS"
    assert table["rows"] == [["a.example.com", "1.2.3.4", 2]]
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
    assert _values(core, F_MAC_ADDRESS) == {"02:00:00:aa:00:01", "02:00:00:bb:00:02"}
    assert _values(core, F_HOSTNAME) == {"pcap-workstation", "PCAPNBNSHOST"}
    assert all(o.volatile for o in core.observables)

    dns = _category(network, CATEGORY_DNS)
    assert _values(dns, F_FQDN) == {"www.pcap-dns.example", "cdn.pcap-dns.example"}
    assert _values(dns, F_IP) == {"198.51.100.7"}
    assert "PCAP DNS" in dns.summary
    # nothing of these categories in the synthesized frames: no node in the tree
    assert not _category(network, CATEGORY_TLS)
    assert not network.get_and_load_analysis(PcapTlsDecryptionAnalysis)

    # loopback addresses and MACs are filtered out
    core = http_tls.get_and_load_analysis(PcapAnalysis)
    assert core.observables == []
    assert len(core.index[CATEGORY_TLS]) == 2

    tls = _category(http_tls, CATEGORY_TLS)
    assert _values(tls, F_FQDN) == {"pcap-tls12.example", "pcap-tls13.example"}
    assert len(_values(tls, F_JA4)) == 2
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

    with caplog.at_level(logging.ERROR):
        root = _run_engine(root_analysis)

    capture = root.get_observable(capture.uuid)
    core = capture.get_and_load_analysis(PcapAnalysis)
    assert core.error
    assert any(r.levelno == logging.ERROR and "unable to dissect pcap" in r.getMessage() for r in caplog.records)
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
    assert titles[0] == "Key Logs" and "HTTP Requests" in titles and "Carved Files" in titles

    keylog_analysis = keylog.get_analysis(TlsKeylogAnalysis)
    assert keylog_analysis.display_name == "TLS Key Log"
    assert keylog_analysis.generate_summary().endswith("applied to 1 pcaps")

    # applying it again adds nothing
    before = len(decryption.observables)
    second = root.add_file_observable(SSLKEYLOG)
    assert second is keylog
    pcap.apply_keylogs(_config(ANALYSIS_MODULE_PCAP_TLS_DECRYPTION), capture, core_analysis, decryption, [keylog])
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
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}]}
    decryption = PcapTlsDecryptionAnalysis()
    capture.add_analysis(decryption)

    with caplog.at_level(logging.ERROR):
        pcap.apply_keylogs(_config(ANALYSIS_MODULE_PCAP_TLS_DECRYPTION), capture, core, decryption, [keylog])

    assert decryption.error == "tshark failed: command timed out after 0:04:00"
    assert decryption.generate_summary() == "PCAP TLS Decryption: failed: tshark failed: command timed out after 0:04:00"
    assert decryption.details["sessions_with_keys"] == 1
    assert any(r.levelno == logging.ERROR and "unable to decrypt pcap" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_apply_keylogs_skips_tshark_without_matching_keys(monkeypatch, tmp_path):
    monkeypatch.setattr(pcap, "dissect", lambda *args, **kwargs: pytest.fail("tshark must not run"))
    root = _new_root()
    capture = root.add_file_observable(HTTP_TLS_PCAPNG)
    other = tmp_path / "other.keys"
    other.write_text(f"CLIENT_RANDOM {'0' * 64} {'1' * 96}\n")
    keylog = root.add_file_observable(str(other))
    core = PcapAnalysis()
    core.details[pcap.KEY_INDEX] = {CATEGORY_TLS: [{"client_random": CLIENT_RANDOM_12}]}
    decryption = PcapTlsDecryptionAnalysis()
    capture.add_analysis(decryption)

    pcap.apply_keylogs(_config(ANALYSIS_MODULE_PCAP_TLS_DECRYPTION), capture, core, decryption, [keylog])
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
    target = tmp_path / "capture.pcap.extracted"
    # an earlier run left a file of the same name
    (target / "http").mkdir(parents=True)
    (target / "http" / "a.bin").write_bytes(b"older")

    packets = [{"tls.handshake.certificate": ["30:82:01", "zz-not-hex", "308201"]}]
    known = {pcap.hashlib.sha256(b"known").hexdigest()}
    objects, certificates = pcap._collect_carved_files(str(workdir), str(target), packets, max_files=3, known_sha256=known)

    assert len(certificates) == 1
    assert certificates[0]["path"] == f"capture.pcap.extracted/certificates/{certificates[0]['sha256']}.der"
    assert [(o["protocol"], o["file_name"], o["path"]) for o in objects] == [
        ("http", "a.bin", "capture.pcap.extracted/http/a_1.bin"),
        ("http", "late.bin", "capture.pcap.extracted/http/late.bin"),
        ("smb", "a.bin", None),
    ]
    assert (target / "http" / "a_1.bin").read_bytes() == b"first"


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
    assert PcapAnalysisPresenter(keylog).tables == [{"title": "Secrets", "columns": ["Label", "Count"], "rows": [], "total": 0}]


@pytest.mark.unit
def test_dissect_gives_tshark_a_copy_of_the_evidence(monkeypatch, tmp_path):
    evidence = tmp_path / "capture.pcap"
    shutil.copy(NETWORK_PCAP, evidence)
    inodes = []

    def _fake_tshark(config, workdir, args):
        inodes.append(os.stat(os.path.join(workdir, "input")).st_ino)
        return "" if "-T" in args else STATISTICS_OUTPUT

    monkeypatch.setattr(pcap, "_run_tshark", _fake_tshark)
    index = pcap.dissect(_config(), str(evidence), str(tmp_path / "capture.pcap.extracted"))

    assert inodes and all(inode != os.stat(evidence).st_ino for inode in inodes)
    assert index["statistics"]["packets"] == 5
    assert index[CATEGORY_TLS] == []
