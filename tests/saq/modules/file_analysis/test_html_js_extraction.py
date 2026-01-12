import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_HTML_JS_EXTRACTION, F_FILE, F_URL, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules.file_analysis.html_js_extraction import (
    HTMLJavaScriptExtractor,
    HTMLJavaScriptExtractionAnalysis,
)
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
def test_extract_inline_scripts(tmpdir, test_context):
    """Test extraction of inline <script> tags."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML file with inline JavaScript
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <script>
        console.log("Hello World");
        alert("Test Alert");
    </script>
    <script type="text/javascript">
        function testFunction() {
            return "test";
        }
    </script>
</head>
<body>
    <h1>Test</h1>
</body>
</html>"""

    target_path = root.create_file_path("test_inline.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have extracted 2 inline scripts
    assert len(analysis.extracted_files) == 2
    assert analysis.script_count == 2
    assert len(analysis.extracted_urls) == 0


@pytest.mark.unit
def test_extract_external_urls(tmpdir, test_context):
    """Test extraction of external script URLs."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML file with external script references
    html_content = """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.example.com/jquery.min.js"></script>
    <script src="/static/app.js"></script>
    <script src="https://evil.com/malware.js"></script>
</head>
<body>
    <h1>Test</h1>
</body>
</html>"""

    target_path = root.create_file_path("test_external.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have extracted 3 external URLs
    assert len(analysis.extracted_urls) == 3
    assert analysis.script_count == 3
    assert len(analysis.extracted_files) == 0

    # Verify URL observables were created
    url_observables = [o for o in analysis.observables if o.type == F_URL]
    assert len(url_observables) == 3

    # Check that URLs have R_EXTRACTED_FROM relationship
    for url_obs in url_observables:
        assert url_obs.has_relationship(R_EXTRACTED_FROM)


@pytest.mark.unit
def test_extract_event_handlers(tmpdir, test_context):
    """Test extraction of inline event handlers."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML file with event handlers
    html_content = """<!DOCTYPE html>
<html>
<body>
    <button onclick="handleClick()">Click Me</button>
    <img src="test.jpg" onerror="console.log('Error loading image')">
    <div onload="initializeApp()">Content</div>
    <input type="text" onchange="validateInput(this.value)">
</body>
</html>"""

    target_path = root.create_file_path("test_events.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have extracted event handlers
    assert len(analysis.inline_handlers) >= 3
    assert analysis.script_count >= 3


@pytest.mark.unit
def test_deduplication(tmpdir, test_context):
    """Test that duplicate scripts are skipped."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML file with duplicate scripts
    html_content = """<!DOCTYPE html>
<html>
<head>
    <script>
        console.log("Same script");
    </script>
    <script>
        console.log("Same script");
    </script>
    <script>
        console.log("Different script");
    </script>
</head>
</html>"""

    target_path = root.create_file_path("test_duplicates.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have found 3 scripts but only extracted 2 (1 duplicate)
    assert analysis.script_count == 3
    assert len(analysis.extracted_files) == 2
    assert analysis.duplicate_count == 1


@pytest.mark.unit
def test_min_size_threshold(tmpdir, test_context):
    """Test that small scripts are skipped."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML file with very small scripts
    html_content = """<!DOCTYPE html>
<html>
<head>
    <script>x</script>
    <script>y=1</script>
    <script>
        // This is a larger script that should be extracted
        console.log("This script is long enough to be extracted");
    </script>
</head>
</html>"""

    target_path = root.create_file_path("test_minsize.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have extracted only the larger script
    assert len(analysis.extracted_files) == 1


@pytest.mark.unit
def test_svg_parsing(tmpdir, test_context):
    """Test SVG file parsing and extraction."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create SVG file with embedded JavaScript
    svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
    <script type="text/javascript">
        <![CDATA[
        function maliciousFunction() {
            alert("Malicious SVG");
        }
        ]]>
    </script>
    <circle cx="50" cy="50" r="40" onclick="maliciousFunction()" />
</svg>"""

    target_path = root.create_file_path("test.svg")
    with open(target_path, "w") as fp:
        fp.write(svg_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have extracted the inline script and event handler
    assert len(analysis.extracted_files) >= 1


@pytest.mark.unit
def test_malformed_html(tmpdir, test_context):
    """Test handling of malformed HTML."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create malformed HTML
    html_content = """<html>
<script>
    console.log("Missing closing tag");
<div>
<script>
    // Another script
    alert("test");
</script>
</html>"""

    target_path = root.create_file_path("test_malformed.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    # Should complete without errors
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)


@pytest.mark.unit
def test_skip_json_script_type(tmpdir, test_context):
    """Test that scripts with type=application/json are skipped."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML with JSON script tag (should be skipped)
    html_content = """<!DOCTYPE html>
<html>
<head>
    <script type="application/json">
        {"key": "value", "data": [1, 2, 3]}
    </script>
    <script type="text/javascript">
        console.log("This should be extracted");
    </script>
</head>
</html>"""

    target_path = root.create_file_path("test_json.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should only extract the JavaScript, not the JSON
    assert len(analysis.extracted_files) == 1


@pytest.mark.unit
def test_mixed_content(tmpdir, test_context):
    """Test HTML with mix of inline, external, and event handlers."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    # Create HTML with all types of JavaScript
    html_content = """<!DOCTYPE html>
<html>
<head>
    <script>
        console.log("Inline script 1");
    </script>
    <script src="https://cdn.example.com/lib.js"></script>
    <script>
        console.log("Inline script 2");
    </script>
</head>
<body>
    <button onclick="handleClick()">Click</button>
    <img src="test.jpg" onerror="console.log('error')">
</body>
</html>"""

    target_path = root.create_file_path("test_mixed.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Should have extracted 2 inline scripts
    assert len(analysis.extracted_files) == 2

    # Should have extracted 1 external URL
    assert len(analysis.extracted_urls) == 1

    # Should have extracted 2 event handlers
    assert len(analysis.inline_handlers) == 2

    # Total script count should be 5
    assert analysis.script_count == 5

    # Verify relationships
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    for file_obs in file_observables:
        assert file_obs.has_relationship(R_EXTRACTED_FROM)


@pytest.mark.unit
def test_empty_file(tmpdir, test_context):
    """Test that empty files are skipped."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    target_path = root.create_file_path("empty.html")
    with open(target_path, "w") as fp:
        fp.write("")

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    # Analysis should not be created for empty files
    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert analysis is None


@pytest.mark.unit
def test_file_naming(tmpdir, test_context):
    """Test that extracted files have correct naming pattern."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    html_content = """<!DOCTYPE html>
<html>
<head>
    <script>console.log("test1");</script>
    <script>console.log("test2");</script>
</head>
<body>
    <button onclick="handleClick()">Click</button>
</body>
</html>"""

    target_path = root.create_file_path("sample.html")
    with open(target_path, "w") as fp:
        fp.write(html_content)

    observable = root.add_file_observable(target_path)

    analyzer = AnalysisModuleAdapter(HTMLJavaScriptExtractor(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_HTML_JS_EXTRACTION)))
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(HTMLJavaScriptExtractionAnalysis)
    assert isinstance(analysis, HTMLJavaScriptExtractionAnalysis)

    # Check that file observables have the expected naming pattern
    file_observables = [o for o in analysis.observables if o.type == F_FILE]

    for file_obs in file_observables:
        # Filename should match pattern: sample_js_<type>_<index>_<hash>.js
        assert file_obs.file_name.startswith("sample_js_")
        assert file_obs.file_name.endswith(".js")
