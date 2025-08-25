
import base64
import os
import pathlib
import tempfile

import pytest

from saq.analysis import Observable
from saq.configuration import get_config
from saq.constants import DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL, F_FILE, F_URL, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules.file_analysis import ArchiveAnalysis, ArchiveAnalyzer, AutoItAnalyzer, De4dotAnalyzer, ExifAnalyzer, FileHashAnalysis, FileHashAnalyzer, FileTypeAnalysis, FileTypeAnalyzer, HTMLDataURLAnalysis, HTMLDataURLAnalyzer, LnkParseAnalyzer, OCRAnalysis, OCRAnalyzer, QRCodeAnalysis, QRCodeAnalyzer, SynchronyFileAnalysis, SynchronyFileAnalyzer, URLExtractionAnalysis, URLExtractionAnalyzer
from saq.modules.file_analysis.dotnet import De4dotAnalysis
from saq.modules.file_analysis.is_file_type import is_autoit, is_chm_file, is_dotnet, is_image, is_jar_file, is_javascript_file, is_lnk_file, is_pe_file, is_x509
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context

@pytest.mark.unit
def test_is_pe_file(tmp_path):
    target = str(tmp_path / 'test.exe')
    # test valid MZ
    with open(target, 'wb') as fp:
        fp.write(b'MZ')

    assert is_pe_file(target)

    # test invalid MZ
    with open(target, 'wb') as fp:
        fp.write(b'PDF%')

    assert not is_pe_file(target)

    # test empty file
    with open(target, 'wb') as fp:
        fp.write(b'')

    assert not is_pe_file(target)

    # test missing file
    os.remove(target)

@pytest.mark.unit
def test_is_jar_file(datadir, tmp_path):
    target = str(datadir / 'zipped.jar')
    # test valid JAR
    assert is_jar_file(target)

    target = str(datadir / 'zipped.zip')
    # test invalid JAR
    assert not is_jar_file(target)

    target = str(tmp_path / 'test.exe')
    # test empty file
    with open(target, 'wb') as fp:
        fp.write(b'')

    assert not is_jar_file(target)

    # test missing file
    os.remove(target)
    assert not is_jar_file(target)

class MockAnalysis(object):
    def __init__(self):
        self.details = {}
        self.observables = []

    def add_observable(self, *args, **kwargs):
        self.observables.append(args)


class MockAnalysisModule(object):
    def __init__(self, test_file):
        self.mime_type = f"text/{test_file[len('sample_'):]}"

    @staticmethod
    def wait_for_analysis():
        pass


class TestUrlExtraction:
    @pytest.mark.unit
    def test_order_urls_by_interest(self, test_context):
        extracted_urls_unordered = ['https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                    'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                    'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                    'https://www.wellsfargo.com/help/secure-email',
                                    'https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm']

        expected_extracted_urls_ordered = ['https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm',
                                           'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                           'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                           'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                           'https://www.wellsfargo.com/help/secure-email']

        expected_extracted_urls_grouping = {
                'wellsfargo.com':
                    ['https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                     'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                     'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                     'https://www.wellsfargo.com/help/secure-email'],
                'wellsfargoadvisors.com':
                    ['https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm']}

        url_extraction_analyzer = URLExtractionAnalyzer(context=test_context)
        extracted_urls_ordered, extracted_urls_grouping = url_extraction_analyzer.order_urls_by_interest(extracted_urls_unordered)

        assert extracted_urls_ordered == expected_extracted_urls_ordered
        assert extracted_urls_grouping == expected_extracted_urls_grouping

    @pytest.mark.unit
    def test_exclude_filtered_domains(self, test_context):
        extracted_urls_unfiltered = ['http://schemas.microsoft.com/office/2004/12/omml',
                                     'http://www.w3.org/TR/REC-html40',
                                     'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                     'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                     'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                     'https://www.wellsfargo.com/help/secure-email',
                                     'https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm',
                                     'https://blue',
                                     'https://center',
                                     'https://top']

        expected_extracted_urls_filtered = ['https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                            'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                            'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                            'https://www.wellsfargo.com/help/secure-email',
                                            'https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm']

        url_extraction_analyzer = URLExtractionAnalyzer(context=test_context)
        extracted_urls_filtered = list(filter(url_extraction_analyzer.filter_excluded_domains, extracted_urls_unfiltered))

        assert expected_extracted_urls_filtered == extracted_urls_filtered

    @pytest.mark.parametrize('test_file', ['sample_html', 'sample_xml', 'sample_dat', 'sample_rfc822', 'sample_rfc822_plaintext_body'])
    @pytest.mark.unit
    def test_execute_analysis(self, monkeypatch, datadir, test_file, root_analysis, test_context):
        def mock_analysis_module(*args, **kwargs):
            return MockAnalysisModule(test_file)

        monkeypatch.setattr("saq.modules.AnalysisModule.wait_for_analysis", mock_analysis_module)

        url_extraction_analyzer = AnalysisModuleAdapter(URLExtractionAnalyzer(context=create_test_context(root=root_analysis)))
        file_observable = root_analysis.add_file_observable(datadir / f"{test_file}.in")

        url_extraction_completed = url_extraction_analyzer.execute_analysis(file_observable)
        analysis = file_observable.get_and_load_analysis(URLExtractionAnalysis)
        assert isinstance(analysis, URLExtractionAnalysis)

        expected_analysis_observables = list()
        with open(datadir / f'{test_file}.out') as f:
            expected_urls = f.read().splitlines()

        assert url_extraction_completed == AnalysisExecutionResult.COMPLETED
        assert set([_.value for _ in analysis.observables if _.type == F_URL]) == set(expected_urls)


@pytest.mark.parametrize('test_bytes', [b'not a certificate', b'badly formatted certificate CERTIFICATE-----'])
@pytest.mark.integration
def test_is_x509_not_a_cert_return_false(test_bytes):
    """Verify is_x509 returns False if file is not an x509 certificate."""
    # setup
    with tempfile.TemporaryDirectory() as d:
        path_to_file = str(pathlib.Path(d).joinpath('not_a_real_cert.pem'))
        with open(path_to_file, 'wb') as f:
            f.write(test_bytes)

        # verify
        assert not is_x509(path_to_file)


@pytest.mark.parametrize('test_cert', ['pem-encoded', 'der-encoded'])
@pytest.mark.integration
def test_is_x509_return_true(test_cert, cert_on_disk):
    """Verify is_x509 returns True for various certificate formats."""
    assert is_x509(cert_on_disk[test_cert])


@pytest.mark.integration
def test_is_autoit(datadir, tmp_path):
    # Decode the test data file...
    with open(datadir / 'hello_world.exe.hex') as f:
        data = bytes.fromhex(f.read())

    # ...and write it to a temp file
    hello_world_temp_path = tmp_path / 'hello_world.exe'
    with open(hello_world_temp_path, 'wb') as f:
        f.write(data)

    assert is_autoit(hello_world_temp_path) is False
    assert is_autoit(datadir / 'hello_autoit.exe') is True

@pytest.mark.integration
def test_is_autoit_au3(datadir, tmp_path):
    with open(datadir / 'ymehvz.au3.b64') as fp:
        data = fp.read()

    # ...and write it to a temp file
    target_path = str(tmp_path / 'ymehvz.au3')
    with open(target_path, 'wb') as fp:
        fp.write(base64.b64decode(data))

    # with the file extension we can tell it is
    assert is_autoit(target_path) is True

    # without it we don't check because we can't check every file like that
    os.rename(target_path, str(tmp_path / 'ymehvz'))
    assert is_autoit(str(tmp_path / 'ymehvz')) is False


@pytest.mark.integration
def test_autoit_decompilation(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with a file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_path = datadir / 'hello_autoit.exe'
    observable = root.add_file_observable(target_path)

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(AutoItAnalyzer(context=create_test_context(root=root)))
    analysis = analyzer.execute_analysis(observable)

    assert analysis == AnalysisExecutionResult.COMPLETED
    assert 'AutoIt decompiled 1 scripts' in caplog.text

@pytest.mark.integration
def test_is_lnk(datadir, tmp_path):
    # Decode the test data file...
    with open(datadir / 'hello_world.exe.hex') as f:
        data = bytes.fromhex(f.read())

    # ...and write it to a temp file
    hello_world_temp_path = tmp_path / 'hello_world.exe'
    with open(hello_world_temp_path, 'wb') as f:
        f.write(data)

    assert is_lnk_file(hello_world_temp_path) is False
    assert is_lnk_file(datadir / 'google_chrome.lnk') is True


@pytest.mark.integration
def test_lnk_parser(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with a file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_path = datadir / 'google_chrome.lnk'
    observable = root.add_file_observable(target_path)

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(LnkParseAnalyzer(context=create_test_context(root=root)))
    analysis = analyzer.execute_analysis(observable)

    assert analysis == AnalysisExecutionResult.COMPLETED
    assert 'Parsed 1 lnk file' in caplog.text
   

    
class MockYaraAnalysis(object):
    def __init__(self, rule):
        self.rule = rule
        pass

    def has_observable(self, _type, val):
        print(f'MockYaraAnalysis checking for observable {val} against mocked result {self.rule}')
        if val == self.rule:
            return True
        else:
            return False

class MockYaraAnalysisModule(object):
    def __init__(self):
        pass

    def wait_for_analysis(self):
        return MockYaraAnalysis()

@pytest.mark.integration
def test_is_dotnet(datadir, tmp_path):
    # Decode the test data file...
    with open(datadir / 'hello_world.exe.hex') as f:
        data = bytes.fromhex(f.read())

    # ...and write it to a temp file
    hello_world_temp_path = tmp_path / 'hello_world.exe'
    with open(hello_world_temp_path, 'wb') as f:
        f.write(data)

    assert is_dotnet(hello_world_temp_path) is False
    target_path = os.path.join( datadir /  'malicious.exe')
    with open(str(datadir / '6346eea9dff4eac53113fc2ba3b8a497.hex'), 'r') as fp_in:
        with open(target_path, 'wb') as fp_out:
            for line in fp_in:
                line = line.strip()
                fp_out.write(bytes.fromhex(line))
    assert is_dotnet(target_path) is True

@pytest.mark.integration
def test_de4dot_analyzer(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    target_path = root.create_file_path('malicious.exe')
    with open(str(datadir / '6346eea9dff4eac53113fc2ba3b8a497.hex'), 'r') as fp_in:
        with open(target_path, 'wb') as fp_out:
            for line in fp_in:
                line = line.strip()
                fp_out.write(bytes.fromhex(line))

    observable = root.add_file_observable(target_path)
    analyzer = De4dotAnalyzer(context=create_test_context(root=root))
    analysis_result = analyzer.execute_analysis(observable)

    assert analysis_result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(De4dotAnalysis)
    assert analysis.deobfuscated
    
    # there should be a single file observable
    assert isinstance(analysis, De4dotAnalysis)
    assert len(analysis.observables) == 1
    assert analysis.observables[0].type == F_FILE
    assert analysis.observables[0].file_path == 'malicious.exe.deobfuscated/dotnet_deobfuscated_malicious.exe'
    assert analysis.observables[0].redirection == observable
    assert analysis.observables[0].has_relationship(R_EXTRACTED_FROM)

@pytest.mark.integration
def test_zipped_jar(datadir, monkeypatch, test_context):
    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    #target_path = root.storage_dir, 'zipped.jar')
    #copyfile(str(datadir / 'zipped.jar'), target_path)
    observable = root.add_file_observable(datadir / 'zipped.jar')

    # add file type analysis
    file_type_analysis = FileTypeAnalysis()
    observable.add_analysis(file_type_analysis)
    file_type_analysis.details = {
        'type': 'Microsoft Excel 2007+',
        'mime': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }

    # mock popen to check params then stop
    class StopAnalysisException(Exception):
        pass
    def popen(params, **kwags):
        #assert params == ['bin/unjar', 'data/work/14ca0ff2-ff7e-4fa1-a375-160dc072ab02/zipped.jar', '-d', 'data/work/14ca0ff2-ff7e-4fa1-a375-160dc072ab02/zipped.jar.extracted']
        raise StopAnalysisException()
    
    import saq.modules.file_analysis.archive
    monkeypatch.setattr(saq.modules.file_analysis.archive, "popen_wrapper", popen)

    # run the module
    get_config()['analysis_module_config'] = {
        'max_jar_file_count': 100,
    }
    analyzer = AnalysisModuleAdapter(ArchiveAnalyzer(context=create_test_context(root=root)))
    with pytest.raises(StopAnalysisException):
        analyzer.execute_analysis(observable)


@pytest.mark.integration
def test_exif_analysis(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with an office document
    root = create_root_analysis(analysis_mode='test-single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'doc.docx')

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(ExifAnalyzer(context=create_test_context(root=root)))
    analysis = analyzer.execute_analysis(observable)

    assert analysis == AnalysisExecutionResult.COMPLETED
    assert 'Exif data collection completed.' in caplog.text

    # Create a second test alert with a non document file observable
    # This should fail because it's not an office document
    root = create_root_analysis(analysis_mode='test-single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'hello_world.exe')
    if observable:

        # Execute the analysis
        analyzer = AnalysisModuleAdapter(ExifAnalyzer(context=create_test_context(root=root)))
        analysis = analyzer.execute_analysis(observable)

        assert analysis is False

    # Create a third test alert with an ole
    root = create_root_analysis(analysis_mode='test-single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'doc.doc')

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(ExifAnalyzer(context=create_test_context(root=root)))
    analysis = analyzer.execute_analysis(observable)

    assert analysis == AnalysisExecutionResult.COMPLETED

@pytest.mark.integration
def test_is_image(datadir):
    assert is_image(datadir / 'hello_world.exe') is False
    assert is_image(datadir / 'fraudulent_text.png') is True

@pytest.mark.parametrize('valid_analysis_modes,analysis_mode, valid_alert_types,alert_type,expected_result', [
    ( '', 'email', '', 'manual', True),
    ( 'email', 'email', '', 'manual', True),
    ( 'email,http', 'email', '', 'manual', True),
    ( 'email,http', 'http', '', 'manual', True),
    ( 'email', 'correlation', '', 'manual', False),
    ( '', 'email', 'manual', 'manual', True),
    ( '', 'email', 'manual,specific', 'manual', True),
    ( '', 'email', 'manual,specific', 'specific', True),
    ( '', 'email', 'manual', 'automation', False),
])
@pytest.mark.integration
def test_ocr_analyzer_limits(monkeypatch, valid_analysis_modes, analysis_mode, valid_alert_types, alert_type, expected_result, test_context):
    monkeypatch.setitem(get_config()['analysis_module_ocr'], 'valid_analysis_modes', valid_analysis_modes)
    monkeypatch.setitem(get_config()['analysis_module_ocr'], 'valid_alert_types', valid_alert_types)
    root = create_root_analysis(analysis_mode=analysis_mode, alert_type=alert_type)
    analyzer = OCRAnalyzer(context=create_test_context(root=root))
    assert analyzer.custom_requirement(Observable(F_FILE, 'blah')) == expected_result


@pytest.mark.integration
def test_ocr_analyzer_omp_thread_limit_set(monkeypatch, datadir, test_context):
    import saq.modules.file_analysis
    monkeypatch.delenv('OMP_THREAD_LIMIT', raising=False)
    def get_omp_thread_limit(self):
        return "1"

    monkeypatch.setattr(saq.modules.file_analysis.OCRAnalyzer, 'omp_thread_limit', property(get_omp_thread_limit))

    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'fraudulent_text.png')
    
    # Create the OCRAnalyzer
    analyzer = AnalysisModuleAdapter(OCRAnalyzer(context=create_test_context(root=root)))
    
    # Perform the OCR analysis
    result = analyzer.execute_analysis(observable)

    # ensure we set the env var
    assert os.environ['OMP_THREAD_LIMIT'] == '1'

@pytest.mark.integration
def test_ocr_analyzer_omp_thread_limit_notset(monkeypatch, datadir, test_context):
    import saq.modules.file_analysis
    monkeypatch.delenv('OMP_THREAD_LIMIT', raising=False)
    def get_omp_thread_limit(self):
        return ""

    monkeypatch.setattr(saq.modules.file_analysis.OCRAnalyzer, 'omp_thread_limit', property(get_omp_thread_limit))

    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_file = datadir / 'fraudulent_text.png'
    observable = root.add_file_observable(target_file)
    
    # Create the OCRAnalyzer
    analyzer = AnalysisModuleAdapter(OCRAnalyzer(context=create_test_context(root=root)))
    
    # Perform the OCR analysis
    result = analyzer.execute_analysis(observable)

    # ensure we set the env var
    assert 'OMP_THREAD_LIMIT' not in os.environ


@pytest.mark.parametrize('test_filename,expected_strings,expected_urls,expected_result', [
    ('fraudulent_text.png', ['https://rb.gy/foytnk'], ['https://rb.gy/foytnk'], AnalysisExecutionResult.COMPLETED),
    ('cv2_None.gif', [], [], AnalysisExecutionResult.COMPLETED),
])
@pytest.mark.integration
def test_ocr_analyzer(datadir, monkeypatch, test_filename, expected_strings, expected_urls, expected_result, test_context):
    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_file = datadir / test_filename
    observable = root.add_file_observable(target_file)
    
    # Create the OCRAnalyzer
    analyzer = OCRAnalyzer(context=create_test_context(root=root))
    
    # Perform the OCR analysis
    result = analyzer.execute_analysis(observable)
    assert result == expected_result
    if not expected_strings:
        return

    analysis = observable.get_and_load_analysis(OCRAnalysis)
    assert isinstance(analysis, OCRAnalysis)

    # It should have an output file observable
    assert len(analysis.observables) == 1

    # The file observable should have the expected text
    all_expected_text_exists = True
    with open(analysis.observables[0].full_path, 'r') as fp:
        text = fp.read()
        for expected_string in expected_strings:
            if expected_string not in text:
                all_expected_text_exists = False

    assert all_expected_text_exists

    # The analysis should apply the directives to extract URLs (and domains) from the text file
    assert analysis.observables[0].has_directive(DIRECTIVE_EXTRACT_URLS)
    assert analysis.observables[0].has_directive(DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL)

    # Which will kick off the URLExtractionAnalyzer...
    def mock_analysis_module(*args, **kwargs):
        return MockAnalysisModule(test_filename)

    def mock_get_local_file_path(*args, **kwargs):
        return os.path.join(root.storage_dir, analysis.observables[0].value)
    
    monkeypatch.setattr("saq.modules.AnalysisModule.wait_for_analysis", mock_analysis_module)
    monkeypatch.setattr("saq.modules.file_analysis.url_extraction.get_local_file_path", mock_get_local_file_path)
    monkeypatch.setattr("os.path.exists", lambda x: 1 == 1)  # return true that path exists
    monkeypatch.setattr("os.path.getsize", lambda x: 1)  # arbitrary filesize

    text_file_observable = analysis.observables[0]
    analyzer = AnalysisModuleAdapter(URLExtractionAnalyzer(context=create_test_context(root=root)))

    # Perform the URL extraction analysis
    result = analyzer.execute_analysis(text_file_observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = text_file_observable.get_and_load_analysis(URLExtractionAnalysis)
    assert isinstance(analysis, URLExtractionAnalysis)

    url_observable_values = [o.value for o in analysis.observables]
    assert all(expected_url in url_observable_values for expected_url in expected_urls)

@pytest.mark.unit
def test_decompile_java_class_file(tmp_path, datadir):
    from saq.modules.file_analysis.archive import decompile_java_class_file
    class_file = str(datadir / 'jar/VxUGJsAplRNavewkjKujp.class')
    assert os.path.exists(class_file)

    output_directory = tmp_path / 'output'
    output_directory.mkdir()
    output_directory = str(output_directory)
    decompile_java_class_file(class_file, output_directory)
    java_file = os.path.join(output_directory, 'VxUGJsAplRNavewkjKujp.class-0-decompiled.java')
    assert os.path.getsize(java_file) > 0

    with open(java_file) as fp:
        java_code = fp.read()
        assert 'HBrowserNativeApis.PygDMDiPgHIHFKYIMuHMd' in java_code

    # if we do it a second time we'll get a different file name
    decompile_java_class_file(class_file, output_directory)
    java_file = os.path.join(output_directory, 'VxUGJsAplRNavewkjKujp.class-1-decompiled.java')
    assert os.path.exists(java_file)

    # if we pass a missing file we get None back
    assert decompile_java_class_file('does_not_exist.java', output_directory) is None

    # if we pass something that is not a java class file we get None back
    not_class_file = tmp_path / 'not_a_class_file.class'
    not_class_file.write_text("This is not a class file.")
    not_class_file = str(not_class_file)

    assert decompile_java_class_file(not_class_file, output_directory) is None

@pytest.mark.unit
def test_html_data_url_extraction(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "ref.html")
    
    analyzer = HTMLDataURLAnalyzer(context=create_test_context(root=root))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(HTMLDataURLAnalysis)
    assert isinstance(analysis, HTMLDataURLAnalysis)

    assert analysis.count == 2

@pytest.mark.unit
def test_one_file_in_zip_detection(datadir):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    #shutil.copy(str(datadir / "evil.zip"), root.storage_dir)
    observable = root.add_file_observable(datadir / "evil.zip")

    analyzer = AnalysisModuleAdapter(FileTypeAnalyzer(context=create_test_context(root=root)))
    analyzer.execute_analysis(observable)
    
    analyzer = AnalysisModuleAdapter(ArchiveAnalyzer(context=create_test_context(root=root)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(ArchiveAnalysis)
    assert analysis.has_tag("one_in_zip")

@pytest.mark.parametrize('file_name', [
    'chm-sample-01.chm',
    'chm-sample-02.chm',
    'chm-sample-03.chm',
    'chm-sample-04',
])
@pytest.mark.integration
def test_is_chm_file(datadir, file_name):
    assert is_chm_file(str(datadir / file_name))

@pytest.mark.parametrize('file_name,expected_result', [
    ('is_javascript.js', True),
    ('is_javascript', True),
    ('is_not_javascript', False),
])
@pytest.mark.integration
def test_is_javascript_file(datadir, file_name, expected_result):
    assert is_javascript_file(str(datadir / file_name)) == expected_result

@pytest.mark.unit
def test_synchrony_analyzer(datadir, test_context, monkeypatch):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "sample_obsfucated_javascript.js")
    
    # Mock FileTypeAnalysis to return a non-JSON mime type
    class MockFileTypeAnalysis:
        def __init__(self):
            self.mime_type = "text/plain"
    
    def mock_wait_for_analysis(observable, analysis_class):
        if analysis_class.__name__ == 'FileTypeAnalysis':
            return MockFileTypeAnalysis()

        return None
    
    synchrony_analyzer = SynchronyFileAnalyzer(context=create_test_context(root=root))
    monkeypatch.setattr(synchrony_analyzer, "wait_for_analysis", mock_wait_for_analysis)
    analyzer = AnalysisModuleAdapter(synchrony_analyzer)
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(SynchronyFileAnalysis)
    assert isinstance(analysis, SynchronyFileAnalysis)
    assert analysis.returncode == 0
    assert len(analysis.extracted_files) == 1
    assert os.path.basename(analysis.extracted_files[0]).startswith("synchrony-")

@pytest.mark.unit
def test_synchrony_analyzer_skips_json_files(datadir, test_context, monkeypatch):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "sample_obsfucated_javascript.js")
    
    # mock FileTypeAnalysis to return JSON mime type
    class MockFileTypeAnalysis:
        def __init__(self):
            self.mime_type = "application/json"
    
    def mock_wait_for_analysis(observable, analysis_class):
        if analysis_class.__name__ == 'FileTypeAnalysis':
            return MockFileTypeAnalysis()

        return None
    
    synchrony_analyzer = SynchronyFileAnalyzer(context=create_test_context(root=root))
    monkeypatch.setattr(synchrony_analyzer, "wait_for_analysis", mock_wait_for_analysis)
    analyzer = AnalysisModuleAdapter(synchrony_analyzer)
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(SynchronyFileAnalysis)

    # should be None because JSON files are skipped
    assert analysis is None

@pytest.mark.unit
def test_empty_file_hash(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "empty")
    
    analyzer = AnalysisModuleAdapter(FileHashAnalyzer(context=create_test_context(root=root)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(FileHashAnalysis)
    assert analysis is None

@pytest.mark.unit
def test_qrcode(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "2910293944.gif")
    
    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(context=create_test_context(root=root)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(QRCodeAnalysis)
    assert isinstance(analysis, QRCodeAnalysis)
    assert analysis.extracted_text == "https://qrco.de/be1uHX"
    assert not analysis.inverted
    file_observable = analysis.get_observables_by_type(F_FILE)[0]
    assert file_observable
    assert file_observable.has_tag("qr-code")
    assert not file_observable.has_tag("qr-code-inverted")
    assert file_observable.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)

@pytest.mark.unit
def test_qrcode_inverted(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "inverted_qr.jpg")
    
    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(context=create_test_context(root=root)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(QRCodeAnalysis)
    assert isinstance(analysis, QRCodeAnalysis)
    assert analysis.extracted_text == "https://5a0c0828.9af44fd92300e6757f227f5d.workers.dev?qrc=mhamadeh@ashland.com"
    assert analysis.inverted
    file_observable = analysis.get_observables_by_type(F_FILE)[0]
    assert file_observable
    assert file_observable.has_tag("qr-code")
    assert file_observable.has_tag("qr-code-inverted")
    assert file_observable.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)

@pytest.mark.unit
def test_qrcode_shipping_label(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "fedex.png")
    
    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(context=create_test_context(root=root)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(QRCodeAnalysis)
    assert analysis is None
