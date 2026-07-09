
import os

import pytest
from PIL import Image

from saq.analysis import Observable
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_ARCHIVE, ANALYSIS_MODULE_AUTOIT, ANALYSIS_MODULE_DE4DOT, ANALYSIS_MODULE_EXIF, ANALYSIS_MODULE_FILE_HASH_ANALYZER, ANALYSIS_MODULE_FILE_TYPE, ANALYSIS_MODULE_HTML_DATA_URL_EXTRACTION, ANALYSIS_MODULE_LNK_PARSER, ANALYSIS_MODULE_OCR, ANALYSIS_MODULE_QRCODE, ANALYSIS_MODULE_URL_EXTRACTION, DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL, F_FILE, F_URL, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules.file_analysis import ArchiveAnalysis, ArchiveAnalyzer, AutoItAnalyzer, De4dotAnalyzer, ExifAnalyzer, FileHashAnalysis, FileHashAnalyzer, FileTypeAnalysis, FileTypeAnalyzer, HTMLDataURLAnalysis, HTMLDataURLAnalyzer, LnkParseAnalyzer, OCRAnalysis, OCRAnalyzer, QRCodeAnalysis, QRCodeAnalyzer, URLExtractionAnalysis, URLExtractionAnalyzer
from saq.modules.file_analysis.dotnet import De4dotAnalysis

from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context





class MockAnalysis(object):
    def __init__(self):
        self.details = {}
        self.observables = []

    def add_observable(self, *args, **kwargs):
        self.observables.append(args)


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

        url_extraction_analyzer = URLExtractionAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_URL_EXTRACTION))
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

        url_extraction_analyzer = URLExtractionAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_URL_EXTRACTION))
        extracted_urls_filtered = list(filter(url_extraction_analyzer.filter_excluded_domains, extracted_urls_unfiltered))

        assert expected_extracted_urls_filtered == extracted_urls_filtered

    @pytest.mark.parametrize('test_file', ['sample_html', 'sample_xml', 'sample_dat', 'sample_rfc822', 'sample_rfc822_plaintext_body'])
    @pytest.mark.unit
    def test_execute_analysis(self, monkeypatch, datadir, test_file, root_analysis, test_context):
        url_extraction_analyzer = AnalysisModuleAdapter(URLExtractionAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_URL_EXTRACTION)))
        file_observable = root_analysis.add_file_observable(datadir / f"{test_file}.in")

        # file type analysis is a declared dependency; provide it directly since we
        # invoke execute_analysis outside the engine (which would normally seed it)
        file_type_analysis = FileTypeAnalysis()
        file_observable.add_analysis(file_type_analysis)
        file_type_analysis.details = {"type": "", "mime": f"text/{test_file[len('sample_'):]}"}

        url_extraction_completed = url_extraction_analyzer.execute_analysis(file_observable)
        analysis = file_observable.get_and_load_analysis(URLExtractionAnalysis)
        assert isinstance(analysis, URLExtractionAnalysis)

        expected_analysis_observables = list()
        with open(datadir / f'{test_file}.out') as f:
            expected_urls = f.read().splitlines()

        assert url_extraction_completed == AnalysisExecutionResult.COMPLETED
        assert set([_.value for _ in analysis.observables if _.type == F_URL]) == set(expected_urls)

    def _run_url_extraction(self, root_analysis, target_path, yara_meta=None):
        """Runs URLExtractionAnalyzer over target_path and returns the extracted F_URL values."""
        url_extraction_analyzer = AnalysisModuleAdapter(URLExtractionAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_URL_EXTRACTION)))

        file_observable = root_analysis.add_file_observable(target_path)
        file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
        file_observable.add_directive(DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL)
        if yara_meta:
            file_observable.add_yara_meta(*yara_meta)

        # file type analysis is a declared dependency; provide it directly since we
        # invoke execute_analysis outside the engine (which would normally seed it)
        file_type_analysis = FileTypeAnalysis()
        file_observable.add_analysis(file_type_analysis)
        file_type_analysis.details = {"type": "", "mime": "text/plain"}

        result = url_extraction_analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = file_observable.get_and_load_analysis(URLExtractionAnalysis)
        if analysis is None:
            return None
        return set(_.value for _ in analysis.observables if _.type == F_URL)

    # might_be_html() is satisfied by any blob containing < > = : / anywhere in it, which is true of
    # almost any OCR transcription. find_urls() would therefore build an HTML tree out of the text.
    # The observable difference is relative href resolution against <base>: only the HTML finder
    # does it. An absolute URL inside an attribute is found either way, because the text tokenizer
    # splits on quotes.
    OCR_TEXT_THAT_LOOKS_LIKE_HTML = (
        '<base href="https://example.com"> see <a href=index.php>here</a>\n'
        'or visit https://example.com/landing for details\n'
    )

    @pytest.mark.unit
    def test_ocr_text_is_not_parsed_as_html(self, tmpdir, root_analysis):
        """OCR text must route to urlfinderlib's text finder, not its HTML finder."""
        target_path = str(tmpdir / "screenshot.png.ocr")
        with open(target_path, "w") as fp:
            fp.write(self.OCR_TEXT_THAT_LOOKS_LIKE_HTML)

        urls = self._run_url_extraction(root_analysis, target_path, yara_meta=("type", "document.text.ocr"))

        assert urls == {"https://example.com", "https://example.com/landing"}
        # no HTML tree was built, so the relative href was never resolved against <base>
        assert "https://example.com/index.php" not in urls

    @pytest.mark.unit
    def test_non_ocr_text_is_still_parsed_as_html(self, tmpdir, root_analysis):
        """The text-finder routing is scoped to OCR; everything else keeps find_urls()' sniffing."""
        target_path = str(tmpdir / "page.txt")
        with open(target_path, "w") as fp:
            fp.write(self.OCR_TEXT_THAT_LOOKS_LIKE_HTML)

        urls = self._run_url_extraction(root_analysis, target_path)

        assert "https://example.com/index.php" in urls

    @pytest.mark.unit
    def test_ocr_malformed_urls_are_dropped(self, tmpdir, root_analysis):
        """urlfinderlib validates the percent-encoded form but ACE stores the raw value.

        Garbled OCR text like  https://example.net/sh", *5{margin  is laundered into a "valid"
        URL. For OCR the source text is itself a guess, so require raw validity.
        """
        ocr_text = 'x https://example.net/sh", *5{margin y https://example.net/sh z\n'

        target_path = str(tmpdir / "screenshot.png.ocr")
        with open(target_path, "w") as fp:
            fp.write(ocr_text)

        urls = self._run_url_extraction(root_analysis, target_path, yara_meta=("type", "document.text.ocr"))
        assert urls == {"https://example.net/sh"}
        assert not any('"' in url or "{" in url for url in urls)

    @pytest.mark.unit
    def test_non_ocr_text_keeps_malformed_urls(self, tmpdir, root_analysis):
        """The raw-validity filter is scoped to OCR. Elsewhere the bytes are ground truth.

        A URL that needs percent-encoding to validate really is present in a non-OCR source, so we
        keep it. Note the fixture has no space before the '*' -- with one, the tokenizer splits
        cleanly and never produces a raw-invalid value at all.
        """
        text = 'https://example.net/sh",*5{margin\n'

        target_path = str(tmpdir / "notes.txt")
        with open(target_path, "w") as fp:
            fp.write(text)

        urls = self._run_url_extraction(root_analysis, target_path)
        assert 'https://example.net/sh"' in urls












@pytest.mark.integration
def test_autoit_decompilation(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with a file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_path = datadir / 'hello_autoit.exe'
    observable = root.add_file_observable(target_path)

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(AutoItAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT)))
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    from saq.modules.file_analysis.autoit import AutoItAnalysis
    analysis = observable.get_and_load_analysis(AutoItAnalysis)
    assert isinstance(analysis, AutoItAnalysis)
    assert analysis.scripts == ['script_1.au3']

@pytest.mark.integration
def test_lnk_parser(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with a file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_path = datadir / 'google_chrome.lnk'
    observable = root.add_file_observable(target_path)

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(LnkParseAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_LNK_PARSER)))
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    from saq.modules.file_analysis.lnk_parser import LnkParseAnalysis
    analysis = observable.get_and_load_analysis(LnkParseAnalysis)
    assert isinstance(analysis, LnkParseAnalysis)
    assert analysis.icon_location == 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
    assert analysis.working_directory == 'C:\\Program Files\\Google\\Chrome\\Application'

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
    analyzer = De4dotAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))
    analysis_result = analyzer.execute_analysis(observable)

    assert analysis_result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(De4dotAnalysis)
    assert analysis.deobfuscated
    
    # there should be a single file observable
    assert isinstance(analysis, De4dotAnalysis)
    assert len(analysis.observables) == 1
    assert analysis.observables[0].type == F_FILE
    assert analysis.observables[0].file_path == 'malicious.exe.deobfuscated'
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
    monkeypatch.setattr(saq.modules.file_analysis.archive, "Popen", popen)

    # run the module
    get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE).max_jar_file_count = 100
    analyzer = AnalysisModuleAdapter(ArchiveAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE)))
    with pytest.raises(StopAnalysisException):
        analyzer.execute_analysis(observable)


@pytest.mark.integration
def test_exif_analysis(caplog, datadir, monkeypatch, test_context):
    # Create a test alert with an office document
    root = create_root_analysis(analysis_mode='test-single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'doc.docx')

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(ExifAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_EXIF)))
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
        analyzer = AnalysisModuleAdapter(ExifAnalyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_EXIF)))
        analysis = analyzer.execute_analysis(observable)

        assert analysis is False

    # Create a third test alert with an ole
    root = create_root_analysis(analysis_mode='test-single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'doc.doc')

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(ExifAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_EXIF)))
    analysis = analyzer.execute_analysis(observable)

    assert analysis == AnalysisExecutionResult.COMPLETED



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
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_OCR), 'valid_analysis_modes', valid_analysis_modes)
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_OCR), 'valid_alert_types', valid_alert_types)
    root = create_root_analysis(analysis_mode=analysis_mode, alert_type=alert_type)
    analyzer = OCRAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR))
    assert analyzer.custom_requirement(Observable(F_FILE, 'blah')) == expected_result


@pytest.mark.integration
def test_ocr_analyzer_omp_thread_limit_set(monkeypatch, datadir, test_context):
    monkeypatch.delenv('OMP_THREAD_LIMIT', raising=False)
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_OCR), 'omp_thread_limit', '1')
    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / 'fraudulent_text.png')
    
    # Create the OCRAnalyzer
    analyzer = AnalysisModuleAdapter(OCRAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR)))
    
    # Perform the OCR analysis
    result = analyzer.execute_analysis(observable)

    # ensure we set the env var
    assert os.environ['OMP_THREAD_LIMIT'] == '1'

@pytest.mark.integration
def test_ocr_analyzer_omp_thread_limit_notset(monkeypatch, datadir, test_context):
    monkeypatch.delenv('OMP_THREAD_LIMIT', raising=False)
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_OCR), 'omp_thread_limit', None)

    # Create a test alert with file observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    target_file = datadir / 'fraudulent_text.png'
    observable = root.add_file_observable(target_file)
    
    # Create the OCRAnalyzer
    analyzer = AnalysisModuleAdapter(OCRAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR)))
    
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
    analyzer = OCRAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR))
    
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
    monkeypatch.setattr("os.path.exists", lambda x: 1 == 1)  # return true that path exists
    monkeypatch.setattr("os.path.getsize", lambda x: 1)  # arbitrary filesize

    text_file_observable = analysis.observables[0]

    # file type analysis is a declared dependency; provide it directly since we
    # invoke execute_analysis outside the engine (which would normally seed it)
    file_type_analysis = FileTypeAnalysis()
    text_file_observable.add_analysis(file_type_analysis)
    file_type_analysis.details = {"type": "", "mime": f"text/{test_filename[len('sample_'):]}"}

    analyzer = AnalysisModuleAdapter(URLExtractionAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_URL_EXTRACTION)))

    # Perform the URL extraction analysis
    result = analyzer.execute_analysis(text_file_observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = text_file_observable.get_and_load_analysis(URLExtractionAnalysis)
    assert isinstance(analysis, URLExtractionAnalysis)

    url_observable_values = [o.value for o in analysis.observables]
    assert all(expected_url in url_observable_values for expected_url in expected_urls)

@pytest.mark.unit
def test_html_data_url_extraction(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "ref.html")
    
    analyzer = HTMLDataURLAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_DATA_URL_EXTRACTION))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(HTMLDataURLAnalysis)
    assert isinstance(analysis, HTMLDataURLAnalysis)

    assert analysis.count == 2

    # Extracted data-URL images skip expensive OCR but must still be scanned
    # for QR codes -- an embedded data-URL image is a common quishing vector.
    for extracted in analysis.get_observables_by_type(F_FILE):
        excluded = " ".join(extracted.excluded_analysis)
        assert "OCRAnalyzer" in excluded
        assert "QRCodeAnalyzer" not in excluded

@pytest.mark.unit
def test_one_file_in_zip_detection(datadir):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    #shutil.copy(str(datadir / "evil.zip"), root.storage_dir)
    observable = root.add_file_observable(datadir / "evil.zip")

    analyzer = AnalysisModuleAdapter(FileTypeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_FILE_TYPE)))
    analyzer.execute_analysis(observable)
    
    analyzer = AnalysisModuleAdapter(ArchiveAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(ArchiveAnalysis)
    assert analysis.has_tag("one_in_zip")


@pytest.mark.unit
def test_file_type_image_yara_meta(datadir):
    """FileTypeAnalyzer stamps image files with yara_meta:type=image (and non-images without it)."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    image = root.add_file_observable(datadir / "2910293944.gif")
    non_image = root.add_file_observable(datadir / "evil.zip")

    analyzer = AnalysisModuleAdapter(FileTypeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_FILE_TYPE)))

    assert analyzer.execute_analysis(image) == AnalysisExecutionResult.COMPLETED
    assert "yara_meta:type=image" in image.directives
    assert "type=image" in image.yara_meta_tags

    assert analyzer.execute_analysis(non_image) == AnalysisExecutionResult.COMPLETED
    assert "yara_meta:type=image" not in non_image.directives





@pytest.mark.unit
def test_empty_file_hash(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "empty")
    
    analyzer = AnalysisModuleAdapter(FileHashAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_FILE_HASH_ANALYZER)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(FileHashAnalysis)
    assert analysis is None

@pytest.mark.unit
def test_qrcode(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "2910293944.gif")
    
    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE)))
    
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
def test_qrcode_custom_requirement(datadir, tmp_path, test_context):
    """qrcode declares valid_observable_types = F_FILE but only scans images
    and PDFs. custom_requirement gates out every other file type *before* the
    engine consults the cache, so non-image/non-PDF files no longer incur a
    cache lookup (which always missed and never produced a cacheable result)."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    text_path = tmp_path / "note.txt"
    text_path.write_text("just some text, not an image or a pdf")
    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"")

    image_obs = root.add_file_observable(datadir / "2910293944.gif")
    pdf_obs = root.add_file_observable(datadir / "sample_pdf_with_qr_code.pdf")
    text_obs = root.add_file_observable(str(text_path))
    empty_obs = root.add_file_observable(str(empty_path))

    analyzer = QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE))

    assert analyzer.custom_requirement(image_obs) is True
    assert analyzer.custom_requirement(pdf_obs) is True
    assert analyzer.custom_requirement(text_obs) is False
    assert analyzer.custom_requirement(empty_obs) is False


@pytest.mark.unit
def test_qrcode_inverted(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "inverted_qr.jpg")
    
    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE)))
    
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
    """A shipping label's barcodes decode cleanly but yield no URLs — that
    is a *negative* result, now recorded as an empty (summary-less)
    analysis so it can be cached."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "fedex.png")

    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE)))

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(QRCodeAnalysis)
    assert isinstance(analysis, QRCodeAnalysis)
    assert not analysis.extracted_text
    assert analysis.generate_summary() is None
    assert not analysis.observables

def _make_blank_png(directory) -> str:
    """A synthesized image with no QR code and no text — the negative case."""
    path = os.path.join(str(directory), "blank.png")
    Image.new("RGB", (64, 64), "white").save(path)
    return path


@pytest.mark.unit
def test_qrcode_negative_records_empty_analysis(tmp_path, test_context):
    """No QR code + clean scans → an empty analysis is recorded so the
    negative result is cacheable. Its summary must be None so the alert
    view is not cluttered with empty QR analyses for every image."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(_make_blank_png(tmp_path))

    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE)))

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(QRCodeAnalysis)
    assert isinstance(analysis, QRCodeAnalysis)
    assert not analysis.extracted_text
    assert not analysis.inverted
    assert analysis.generate_summary() is None
    assert not analysis.observables


@pytest.mark.unit
def test_qrcode_scan_failure_records_no_analysis(tmp_path, test_context, monkeypatch):
    """A failed scan (timeout / zbarimg error) means 'unknown', not 'no QR
    code' — nothing is recorded, so the failure can never be cached as a
    negative result."""
    monkeypatch.setattr(QRCodeAnalyzer, "_scan_image", lambda self, path: None)
    monkeypatch.setattr(QRCodeAnalyzer, "_scan_inverted_image", lambda self, path: None)

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(_make_blank_png(tmp_path))

    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE)))

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(QRCodeAnalysis) is None


@pytest.mark.unit
def test_ocr_negative_records_empty_analysis(tmp_path, test_context, monkeypatch):
    """OCR passes complete with no text → an empty analysis is recorded
    (cacheable negative), with a None summary."""
    monkeypatch.setattr("saq.modules.file_analysis.ocr.get_image_text", lambda image: "")

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(_make_blank_png(tmp_path))

    analyzer = AnalysisModuleAdapter(OCRAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR)))

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(OCRAnalysis)
    assert isinstance(analysis, OCRAnalysis)
    assert analysis.ocr is False
    assert analysis.generate_summary() is None
    assert not analysis.observables


@pytest.mark.unit
def test_ocr_failure_records_no_analysis(tmp_path, test_context, monkeypatch):
    """An OCR pass raising means 'unknown' — nothing is recorded."""
    def _raise(image):
        raise RuntimeError("tesseract crashed")

    monkeypatch.setattr("saq.modules.file_analysis.ocr.get_image_text", _raise)

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(_make_blank_png(tmp_path))

    analyzer = AnalysisModuleAdapter(OCRAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_OCR)))

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(OCRAnalysis) is None


@pytest.mark.unit
def test_qrcode_pdf_with_qr_code_at_end(datadir, test_context):
    """Tests that a QR code at the end of a PDF is extracted correctly."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "sample_pdf_with_qr_code.pdf")
    
    analyzer = AnalysisModuleAdapter(QRCodeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_QRCODE)))
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(QRCodeAnalysis)
    assert isinstance(analysis, QRCodeAnalysis)
    assert analysis.extracted_text == "https://sever.emmetcrcs.org/#"
    assert len(analysis.get_observables_by_type(F_FILE)) == 1
    with open(analysis.get_observables_by_type(F_FILE)[0].full_path, 'r') as fp:
        text = fp.read()
        assert text.strip() == "https://sever.emmetcrcs.org/#"