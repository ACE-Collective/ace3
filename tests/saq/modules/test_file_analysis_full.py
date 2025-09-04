import hashlib
import os
import uuid
import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import DIRECTIVE_CRAWL, DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_SANDBOX, F_FILE, F_URI_PATH, F_URL, F_YARA_RULE, R_EXTRACTED_FROM
from saq.crypto import decrypt
from saq.database.model import load_alert
from saq.database.pool import get_db
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_data_dir
from saq.modules.file_analysis.archive import ArchiveAnalysis
from saq.modules.file_analysis.html import MHTMLAnalysis
from saq.modules.file_analysis.is_file_type import is_msi_file, is_ole_file
from saq.modules.file_analysis.msoffice import OfficeFileArchiveAction
from saq.modules.file_analysis.pdf import PDFAnalysis
from saq.modules.file_analysis.upx import UPXAnalysis
from saq.modules.file_analysis.url_extraction import URLExtractionAnalysis
from saq.modules.file_analysis.vbs import PCodeAnalysis
from saq.modules.file_analysis.xml import XMLPlainTextAnalysis
from saq.modules.file_analysis.yara import YaraScanResults_v3_4
from saq.observables.file import FileObservable
from saq.util.hashing import sha256_file
from saq.yara_scanning_service import YSSService
from tests.saq.helpers import create_root_analysis, log_count

UNITTEST_SOCKET_DIR = 'socket_unittest'

@pytest.fixture(autouse=True, scope="function")
def setup(datadir):
    service_config = get_config()['service_yara']
    service_config['socket_dir'] = UNITTEST_SOCKET_DIR
    service_config['signature_dir'] = str(datadir / 'yara_rules')

@pytest.fixture
def yss_server():
    yara_service = YSSService()
    yara_service.start()
    yara_service.wait_for_start()
    yield yara_service
    yara_service.stop()
    yara_service.wait()

@pytest.mark.integration
def test_file_analysis_000_url_extraction_001_pdfparser(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    
    file_observable = root_analysis.add_file_observable(str(datadir / "pdf/Payment_Advice.pdf"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_pdf_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_url_extraction', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_parse_url', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    
    file_observable = root_analysis.get_observable(file_observable.id)
    assert file_observable
    pdf_analysis = file_observable.get_and_load_analysis(PDFAnalysis)
    assert pdf_analysis
    # this now has 2 file observables since we also run ghostscript now
    pdfparser_files = pdf_analysis.get_observables_by_type(F_FILE)
    assert len(pdfparser_files) == 2
    pdfparser_file = [_ for _ in pdfparser_files if not _.file_name.endswith(".gs.pdf")][0]
    url_analysis = pdfparser_file.get_and_load_analysis(URLExtractionAnalysis)
    assert url_analysis
    # should have a bad url in it
    bad_url = 'http://www.williamtoms.com/wp-includes/354387473a/autodomain/autodomain/autodomain/autofil'
    assert bad_url in [url.value for url in url_analysis.get_observables_by_type(F_URL)]

@pytest.mark.integration
def test_file_analysis_000_url_extraction_002_gs(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"

    file_observable = root_analysis.add_file_observable(str(datadir / "pdf/ComplaintApril_424256637.pdf"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_pdf_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_url_extraction', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_parse_url', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    file_observable = root_analysis.get_observable(file_observable.id)
    assert file_observable
    pdf_analysis = file_observable.get_and_load_analysis(PDFAnalysis)
    assert pdf_analysis
    # should have a single file observable
    pdfparser_files = pdf_analysis.get_observables_by_type(F_FILE)
    assert len(pdfparser_files) == 2
    pdfparser_file = [_ for _ in pdfparser_files if _.file_name.endswith(".gs.pdf")][0]
    url_analysis = pdfparser_file.get_and_load_analysis(URLExtractionAnalysis)
    assert url_analysis
    # should have a bad url in it
    bad_url = 'http://12tkj5.my.id/blog/642ec2b466aed.zip'
    assert bad_url in [url.value for url in url_analysis.get_observables_by_type(F_URL)]

KEY_STORAGE_DIR = 'storage_dir'
KEY_TAGS = 'tags'
KEY_MACRO_COUNT = 'macro_count'
KEY_OID = 'oid'
KEY_SANDBOX = 'sandbox'

@pytest.mark.parametrize("result_map", [
    {
        'Past Due Invoices.doc': {
            KEY_TAGS: [ 'microsoft_office', 'ole' ],
            KEY_MACRO_COUNT: 4,
            KEY_SANDBOX: True,
        }, 
    },
    {
        'Outstanding Invoices.doc': {
            KEY_TAGS: [ 'microsoft_office', 'ole' ],
            KEY_MACRO_COUNT: 3,
            KEY_SANDBOX: True,
        }, 
    },
    {
        'Paid Invoice.doc': {
            KEY_TAGS: [ 'microsoft_office', 'ole' ],
            KEY_MACRO_COUNT: 3,
            KEY_SANDBOX: True,
        }, 
    },
    {
        'mortgage_payment-0873821-0565.docm': {
            KEY_TAGS: [ 'microsoft_office' ],
            KEY_MACRO_COUNT: 1,
            KEY_SANDBOX: True,
        }, 
    },
    {
        'receipt_687790.doc': {
            KEY_TAGS: [ 'microsoft_office' ],
            KEY_MACRO_COUNT: 5,
            KEY_SANDBOX: True,
        }, 
    },
])
@pytest.mark.integration
def test_file_analysis_001_oletools_000(root_analysis, result_map, datadir):

    for file_name, expected_results in result_map.items():
        root_analysis.analysis_mode = "test_groups"

        file_observable = root_analysis.add_file_observable(str(datadir / f"ole_files/{file_name}"))
        root_analysis.save()
        root_analysis.schedule()

        engine = Engine()
        engine.configuration_manager.enable_module('analysis_module_olevba_v1_2', 'test_groups')
        engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
        engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

        root_analysis = load_root(root_analysis.storage_dir)
        file_observable = root_analysis.get_observable(file_observable.id)
        assert file_observable
        if expected_results[KEY_SANDBOX]:
            assert file_observable.has_directive(DIRECTIVE_SANDBOX)
        for tag in expected_results[KEY_TAGS]:
            assert file_observable.has_tag(tag)

        macro_count = len([f for f in root_analysis.all_observables if f.type == F_FILE and f.has_tag('macro')])
        assert macro_count == expected_results[KEY_MACRO_COUNT]

@pytest.mark.integration
def test_file_analysis_002_archive_000_zip(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "zip/test.zip"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root_analysis.uuid)
    assert alert
    _file = alert.root_analysis.get_observable(_file.id)
    assert _file
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert analysis.file_count == 1
    _file = analysis.get_observables_by_type(F_FILE)
    assert len(_file) == 1

@pytest.mark.integration
def test_file_analysis_002_archive_001_rar(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"

    _file = root_analysis.add_file_observable(str(datadir / "rar/test.r07"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root_analysis.uuid)
    _file = alert.root_analysis.get_observable(_file.id)
    
    from saq.modules.file_analysis import ArchiveAnalysis
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert analysis.file_count == 1
    _file = analysis.get_observables_by_type(F_FILE)
    assert len(_file) == 1

@pytest.mark.integration
def test_file_analysis_archive_skip_ole(root_analysis):
    # make sure OLE files are skipped by this module

    root_analysis.analysis_mode = "test_groups"

    target_path = root_analysis.create_file_path("sample.doc")
    with open(target_path, 'wb') as f:
        f.write(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1')

    _file = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    # this should return False since OLE files are not analyzed by the archive analyzer
    assert not analysis

@pytest.mark.integration
def test_file_analysis_archive_malicious_msi(root_analysis, datadir):
    root_analysis.analysis_mode = "test_groups"

    _file = root_analysis.add_file_observable(str(datadir / "msi/84ec41afdc49c2ee8dff9ba07ba5c9a4"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis

    # there should be 2 files extracted from this malicious sample
    assert analysis.file_count == 2

    observable_map = { _.file_path: _ for _ in analysis.get_observables_by_type(F_FILE) }
    assert '84ec41afdc49c2ee8dff9ba07ba5c9a4.extracted/svchost.bin' in observable_map
    assert '84ec41afdc49c2ee8dff9ba07ba5c9a4.extracted/svchost.exe' in observable_map

@pytest.mark.unit
def test_file_analysis_msi_identification(tmpdir, datadir):

    # this should return True since it's technically an OLE file
    assert is_ole_file(str(datadir / "msi/84ec41afdc49c2ee8dff9ba07ba5c9a4"))

    # this should als return True since it's actually an MSI file
    assert is_msi_file(str(datadir / "msi/84ec41afdc49c2ee8dff9ba07ba5c9a4"))

@pytest.mark.integration
def test_file_analysis_archive_7z_under(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / '7z/under.7z'))

    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert analysis.file_count == 1
    _file = analysis.get_observables_by_type(F_FILE)
    assert len(_file) == 1

@pytest.mark.integration
def test_file_analysis_002_archive_002_ace(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"

    _file = root_analysis.add_file_observable(str(datadir / "ace/dhl_report.ace"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root_analysis.uuid)
    root_analysis = alert.root_analysis
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert analysis.file_count == 1
    _file = analysis.get_observables_by_type(F_FILE)
    assert len(_file) == 1

@pytest.mark.integration
def test_file_analysis_002_archive_003_jar(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "jar/test.jar"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert analysis.file_count == 42

@pytest.mark.integration
def test_file_analysis_002_archive_malicious_jar(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"

    _file = root_analysis.add_file_observable(str(datadir / "jar/malicious.jar"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert analysis.file_count == 68

@pytest.mark.integration
def test_file_analysis_002_archive_004_jar(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'jar/too_many_files.jar'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert isinstance(analysis, ArchiveAnalysis)
    assert analysis.file_count == 1037
    # defined in config as 30
    assert len(analysis.extracted_files) == 30

@pytest.mark.integration
def test_file_analysis_004_yara_001_local_scan(root_analysis, datadir):
    
    # we do not initalize the local yss scanner so it should not be available for scanning

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'scan_targets/match'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    #assert log_count('with yss (matches found: True)') == 0
    assert log_count('failed to connect to yara socket server') == 1
    assert log_count('initializing local yara scanner') == 1
    assert log_count('got yara results for') == 1

    alert = load_alert(root_analysis.uuid)
    _file = alert.root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the file should be instructed to go to the sandbox
    assert _file.has_directive(DIRECTIVE_SANDBOX)
    # and should have a single tag
    assert len(_file.tags) == 1
    # the analysis should have a yara_rule observable
    yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
    assert len(yara_rule) == 1
    yara_rule = yara_rule[0]
    # the yara rule should have detections
    assert yara_rule.detections

@pytest.mark.integration
def test_file_analysis_004_yara_002_no_alert(yss_server, datadir):
    
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    _file = root.add_file_observable(str(datadir / 'scan_targets/no_alert'))
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    #assert log_count('with yss (matches found: True)') == 1

    root.load()
    _file = root.get_observable(_file.id)
    
    from saq.modules.file_analysis import YaraScanResults_v3_4
    analysis = _file.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the file should NOT be instructed to go to the sandbox
    assert not _file.has_directive(DIRECTIVE_SANDBOX)
    # the analysis should have a yara_rule observable
    yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
    assert len(yara_rule) == 1
    yara_rule = yara_rule[0]
    # the yara rule should NOT have detections
    assert not yara_rule.detections

@pytest.mark.integration
def test_file_analysis_004_yara_003_directives(yss_server, datadir):
    
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    _file = root.add_file_observable(str(datadir / 'scan_targets/add_directive'))
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    #assert log_count('with yss (matches found: True)') == 1

    alert = load_alert(root.uuid)
    root = alert.root_analysis
    _file = root.get_observable(_file.id)
    
    from saq.modules.file_analysis import YaraScanResults_v3_4
    analysis = _file.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the file should be instructed to go to the sandbox
    assert _file.has_directive(DIRECTIVE_SANDBOX)
    # the analysis should have a yara_rule observable
    yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
    assert len(yara_rule) == 1
    yara_rule = yara_rule[0]
    # the yara rule should have detections
    assert yara_rule.detections

    # and we should have an extra directive
    assert _file.has_directive(DIRECTIVE_EXTRACT_URLS)

@pytest.mark.integration
def test_file_analysis_004_yara_004_directives_redirection(yss_server, root_analysis, datadir):
    
    root_analysis.analysis_mode = "test_groups"
    parent_file = root_analysis.add_file_observable(str(datadir / 'scan_targets/parent_file'))
    child_file = root_analysis.add_file_observable(str(datadir / 'scan_targets/add_directive'))
    child_file.redirection = parent_file
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    #assert log_count('with yss (matches found: True)') == 1

    alert = load_alert(root_analysis.uuid)
    child_file_observable = alert.root_analysis.get_observable(child_file.id)
    parent_file_observable = alert.root_analysis.get_observable(parent_file.id)
    
    analysis = child_file_observable.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the parent file should be instructed to go to the sandbox
    assert parent_file_observable.has_directive(DIRECTIVE_SANDBOX)
    # the child file analysis should have a yara_rule observable
    yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
    assert len(yara_rule) == 1
    yara_rule = yara_rule[0]
    # the yara rule should have detections
    assert yara_rule.detections

@pytest.mark.integration
def test_file_analysis_004_yara_006_whitelist(yss_server, root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'scan_targets/whitelist'))
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # scanned file /opt/saq/var/test/91b55d6f-fe82-4508-ac68-bbc519693d12/scan.target with yss (matches found: True)
    #assert log_count('with yss (matches found: True)') == 1

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    
    analysis = _file.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the file should have a single tag
    assert len(_file.tags) == 1
    # the tag should be "whitelisted"
    assert _file.tags[0].name == "whitelisted"
    # the root analysis object should be whitelisted
    assert root_analysis.whitelisted

@pytest.mark.integration
def test_file_analysis_004_yara_007_qa_modifier(yss_server, root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'scan_targets/qa_modifier_target'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # scanned file /opt/saq/var/test/91b55d6f-fe82-4508-ac68-bbc519693d12/scan.target with yss (matches found: True)
    #assert log_count('with yss (matches found: True)') == 1

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert isinstance(_file, FileObservable)

    analysis = _file.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the file should *not* have any detection points

    # the yara rule should NOT have detections
    assert len(root_analysis.all_detection_points) == 0
    # there should be a file named after the md5 of the file
    target_dir = os.path.join(get_data_dir(), get_config()['analysis_module_yara_scanner_v3_4']['qa_dir'])
    target_path = os.path.join(target_dir, 'test_qa_modifier', f"{_file.file_path}-{_file.sha256_hash}")
    assert os.path.exists(target_path)
    assert os.path.exists(f'{target_path}.json')

@pytest.mark.integration
def test_file_analysis_004_yara_008_for_detection(yss_server, root_analysis, datadir):
    # Make sure there is one observable in the database
    from saq.database.model import Observable as DBObservable
    db_observable = DBObservable(id=1, type='uri_path', value=b'test_uri_path', sha256=b'asdf')
    get_db().add(db_observable)
    get_db().commit()

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'scan_targets/for_detection'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    #assert log_count('with yss (matches found: True)') == 1

    alert = load_alert(root_analysis.uuid)
    _file = alert.root_analysis.get_observable(_file.id)

    analysis = _file.get_and_load_analysis(YaraScanResults_v3_4)
    assert analysis

    # the file should be instructed to go to the sandbox
    assert _file.has_directive(DIRECTIVE_SANDBOX)
    # the analysis should have a yara_rule observable
    yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
    assert len(yara_rule) == 1
    yara_rule = yara_rule[0]
    # the yara rule should have detections
    assert yara_rule.detections

    # we should have a single uri_path observable
    uri_path_observable = analysis.get_observables_by_type(F_URI_PATH)
    assert len(uri_path_observable) == 1

@pytest.mark.integration
def test_file_analysis_005_pcode_000_extract_pcode(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "ole_files/word2013_macro_stripped.doc"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_pcodedmp', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(PCodeAnalysis)
    assert analysis
    # we should have extracted 11 lines of macro
    assert analysis.line_count == 11
    # and we should have a file with the macros
    _file = analysis.get_observables_by_type(F_FILE)
    assert len(_file) == 1
    _file = _file[0]
    # and that should have a redirection
    assert _file.redirection

@pytest.mark.integration
def test_file_analysis_005_office_file_archiver_000_archive(root_analysis, tmpdir, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "ole_files/Paid Invoice.doc"))
    sha256 = _file.sha256_hash
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_office_file_archiver', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(OfficeFileArchiveAction)
    assert analysis
    
    # the details of the analysis should be the FULL path to the archived file
    assert analysis.details
    assert os.path.exists(analysis.details)

    # make sure we can decrypt it
    target_path = str(tmpdir / _file.file_name)
    decrypt(analysis.details, target_path)
    h = hashlib.sha256()
    with open(target_path, 'rb') as fp:
        h.update(fp.read())

    assert sha256_file(target_path) == sha256.lower()

    root_analysis = create_root_analysis(analysis_mode="test_groups")
    root_analysis.initialize_storage()
    _file = root_analysis.add_file_observable(target_path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_office_file_archiver', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(OfficeFileArchiveAction)
    assert analysis
    
    # the details of the analysis should be the FULL path to the archived file
    assert analysis.details
    assert os.path.exists(analysis.details)

    # but it should also be a duplicate so the name should have the number prefix
    assert os.path.basename(analysis.details).startswith('000000_')

@pytest.mark.integration
def test_file_analysis_006_extracted_ole_000_js(root_analysis, datadir):
    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "docx/js_ole_obj.docx"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_extracted_ole_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_officeparser3', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root_analysis.uuid)
    root_analysis = alert.root_analysis
    _file = root_analysis.get_observable(_file.id)
    assert _file
    assert any([d for d in root_analysis.all_detection_points if 'compiles as JavaScript' in d.description])

@pytest.mark.integration
def test_open_office_extraction(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "openoffice/demo.odt"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert len(analysis.get_observables_by_type(F_FILE)) == 12

@pytest.mark.integration
def test_crawl_extracted_urls(yss_server, root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'url_extraction/simple.txt'))
    _file.add_directive(DIRECTIVE_EXTRACT_URLS)
    _file.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_url_extraction', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(URLExtractionAnalysis)
    assert analysis

    # since the DIRECTIVE_CRAWL_EXTRACTED_URLS is on the file the all the URLs should be crawled
    assert len(analysis.observables) == 2
    for observable in analysis.observables:
        assert observable.has_directive(DIRECTIVE_CRAWL)

@pytest.mark.skip("missing file")
@pytest.mark.integration
def test_correlated_tag(yss_server, root_analysis):

    source_path = os.path.join("test_data", "ppt", "Payment_Details.ppsx")

    if not os.path.exists(source_path):
        pytest.skip(f"missing {source_path}")

    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(os.path.join('test_data', 'ppt', 'Payment_Details.ppsx'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_correlated_tag_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should have an alert
    assert load_alert(root_analysis.uuid)

@pytest.mark.skip("missing file")
@pytest.mark.integration
def test_mhtml_analysis(root_analysis):

    source_path = os.path.join('test_data', 'mhtml', 'Invoice_PDF.mht')
    if not os.path.exists(source_path):
        pytest.skip(f"missing {source_path}")

    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(source_path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_mhtml', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    file_observable = root_analysis.get_observable(file_observable.id)
    assert file_observable

    analysis = file_observable.get_and_load_analysis(MHTMLAnalysis)
    assert analysis
    # should have extracted a single file
    assert len(analysis.details) == 1
    assert len(analysis.get_observables_by_type(F_FILE)) == 1

@pytest.mark.system
def test_officeparser_macro_extraction(root_analysis, datadir):

    get_config()['analysis_module_officeparser3']['merge_macros'] = False

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "doc/DOC_PO_10142020EX.doc"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_officeparser3', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    # this sample should have the following three macros extracted
    for macro_name in [ 'D6imzn9bmimax3kt20.bas', 'Vufp3qemgme18z3.cls', 'Yan8boy3v12dg.frm' ]:
        assert root_analysis.find_observable(lambda o: o.type == F_FILE and os.path.basename(o.file_name) == macro_name)

@pytest.mark.integration
def test_officeparser_macro_extraction_merged(root_analysis, datadir):

    get_config()['analysis_module_officeparser3']['merge_macros'] = True

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "doc/DOC_PO_10142020EX.doc"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_officeparser3', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    # this sample should have the following three macros all merged into one
    for macro_name in [ 'D6imzn9bmimax3kt20.bas', 'Vufp3qemgme18z3.cls', 'Yan8boy3v12dg.frm' ]:
        assert root_analysis.find_observable(lambda o: o.type == F_FILE and os.path.basename(o.file_name) == macro_name) is None

    assert root_analysis.find_observable(lambda o: o.type == F_FILE and os.path.basename(o.file_name) == 'macros.bas')

@pytest.mark.integration
def test_olevba_macro_extraction(root_analysis, datadir):

    get_config()['analysis_module_olevba_v1_2']['merge_macros'] = False

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "doc/DOC_PO_10142020EX.doc"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_olevba_v1_2', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_configuration_defined_tagging', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root_analysis.uuid)
    _file = alert.root_analysis.get_observable(_file.id)
    assert _file

    # this sample should have the following three macros extracted
    for macro_name in [ 'macro_0.bas', 'macro_1.bas', 'macro_2.bas' ]:
        assert alert.root_analysis.find_observable(lambda o: o.type == F_FILE and os.path.basename(o.file_name) == macro_name)

@pytest.mark.integration
def test_olevba_macro_extraction_merged(root_analysis, datadir):

    get_config()['analysis_module_olevba_v1_2']['merge_macros'] = True

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / "doc/DOC_PO_10142020EX.doc"))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_archive', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_olevba_v1_2', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_file_type', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_configuration_defined_tagging', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root_analysis.uuid)
    _file = alert.root_analysis.get_observable(_file.id)
    assert _file

    # this sample should have the following three macros all merged into one
    for macro_name in ['macro_0.bas', 'macro_1.bas', 'macro_2.bas']:
        assert alert.root_analysis.find_observable(lambda o: o.type == F_FILE and os.path.basename(o.file_name) == macro_name) is None

    assert alert.root_analysis.find_observable(lambda o: o.type == F_FILE and os.path.basename(o.file_name) == 'macros.bas')

@pytest.mark.integration
def test_upx(root_analysis, datadir):

    root_analysis.analysis_mode = "test_groups"
    _file = root_analysis.add_file_observable(str(datadir / 'exe/cmd-upx.exe'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_upx', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(UPXAnalysis)
    assert analysis
    assert analysis.details['error'] is None

    target_file = analysis.get_observables_by_type(F_FILE)[0]
    assert target_file
    assert target_file.has_tag('upx')
    assert target_file.has_relationship(R_EXTRACTED_FROM)

@pytest.mark.integration
def test_xml_plain_text_analysis(root_analysis):

    root_analysis.analysis_mode = "test_groups"
    target_path = root_analysis.create_file_path('test.xml')
    with open(target_path, 'w') as fp:
        fp.write("""<?xml version="1.0"?>
<catalog>
   <book id="bk101">
      <author>Gambardella, Matthew</author>
   </book>
</catalog>""")

    _file = root_analysis.add_file_observable(target_path)

    # this is all required for this analysis module
    dummy_path = root_analysis.create_file_path('test.docx')
    with open(dummy_path, 'w') as fp:
        fp.write('blah')

    source_file = root_analysis.add_file_observable(dummy_path)
    _file.add_relationship(R_EXTRACTED_FROM, source_file)
    source_file.add_tag('microsoft_office')

    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_xml_plain_text_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(XMLPlainTextAnalysis)
    assert analysis

    # should have a single file as output here
    output_file = analysis.get_observables_by_type(F_FILE)
    output_file = output_file[0]
    assert output_file.file_name.endswith('.noxml')

    with open(output_file.full_path, 'r') as fp:
        assert fp.read().strip() == 'Gambardella, Matthew'

@pytest.mark.integration
def test_xml_plain_text_analysis_file_too_large(root_analysis):

    get_config()['analysis_module_xml_plain_text_analyzer']['maximum_size'] = 0

    root_analysis.analysis_mode = "test_groups"
    target_path = root_analysis.create_file_path('test.xml')
    with open(target_path, 'w') as fp:
        fp.write("""<?xml version="1.0"?>
<catalog>
   <book id="bk101">
      <author>Gambardella, Matthew</author>
   </book>
</catalog>""")

    _file = root_analysis.add_file_observable(target_path)

    # this is all required for this analysis module
    dummy_path = root_analysis.create_file_path('test.docx')
    with open(dummy_path, 'w') as fp:
        fp.write('blah')

    source_file = root_analysis.add_file_observable(dummy_path)
    _file.add_relationship(R_EXTRACTED_FROM, source_file)
    source_file.add_tag('microsoft_office')

    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_xml_plain_text_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)
    _file = root_analysis.get_observable(_file.id)
    assert _file

    analysis = _file.get_and_load_analysis(XMLPlainTextAnalysis)
    assert not analysis
