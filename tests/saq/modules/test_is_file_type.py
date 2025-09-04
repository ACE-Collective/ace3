import base64
import os
import pathlib
import tempfile

import pytest

from saq.modules.file_analysis.is_file_type import (
    is_autoit, is_chm_file, is_dotnet, is_empty_macro, is_email_file, 
    is_image, is_jar_file, is_java_class_file, is_javascript_file, is_lnk_file, is_macro_ext, 
    is_msi_file, is_office_ext, is_office_file, is_ole_file, is_onenote_file, 
    is_pdf_file, is_pe_file, is_rtf_file, is_x509, is_zip_file
)


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


@pytest.mark.parametrize('test_bytes', [b'not a certificate', b'badly formatted certificate CERTIFICATE-----'])
@pytest.mark.unit
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
@pytest.mark.unit
def test_is_x509_return_true(test_cert, cert_on_disk):
    """Verify is_x509 returns True for various certificate formats."""
    assert is_x509(cert_on_disk[test_cert])


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
def test_is_image(datadir):
    assert is_image(datadir / 'hello_world.exe') is False
    assert is_image(datadir / 'fraudulent_text.png') is True


@pytest.mark.parametrize('file_name', [
    'chm-sample-01.chm',
    'chm-sample-02.chm',
    'chm-sample-03.chm',
    'chm-sample-04',
])
@pytest.mark.unit
def test_is_chm_file(datadir, file_name):
    assert is_chm_file(str(datadir / file_name))


@pytest.mark.parametrize('file_name,expected_result', [
    ('is_javascript.js', True),
    ('is_javascript', True),
    ('is_not_javascript', False),
])
@pytest.mark.unit
def test_is_javascript_file(datadir, file_name, expected_result):
    assert is_javascript_file(str(datadir / file_name)) == expected_result


@pytest.mark.unit
def test_is_office_ext():
    assert is_office_ext("test.docx") is True
    assert is_office_ext("test.xlsx") is True
    assert is_office_ext("test.pptx") is True
    assert is_office_ext("test.doc") is True
    assert is_office_ext("test.xls") is True
    assert is_office_ext("test.ppt") is True
    assert is_office_ext("test.odt") is True
    assert is_office_ext("test.rtf") is True
    assert is_office_ext("test.csv") is True
    
    # test non-office extensions
    assert is_office_ext("test.txt") is False
    assert is_office_ext("test.pdf") is False
    assert is_office_ext("test.exe") is False
    assert is_office_ext("test.jpg") is False
    assert is_office_ext("test") is False


@pytest.mark.unit
def test_is_office_file(datadir, test_context):
    from tests.saq.helpers import create_root_analysis
    from saq.modules.file_analysis.file_type import FileTypeAnalysis
    from tests.saq.test_util import create_test_context
    
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # test with actual Office document
    observable = root.add_file_observable(datadir / 'doc.docx')
    assert is_office_file(observable) is True
    
    # test with non-Office file
    observable = root.add_file_observable(datadir / 'hello_world.exe.hex')
    assert is_office_file(observable) is False
    
    # test file with office extension but no FileTypeAnalysis
    observable = root.add_file_observable(datadir / 'doc.doc')
    assert is_office_file(observable) is True


@pytest.mark.unit
def test_is_macro_ext():
    assert is_macro_ext("test.bas") is True
    assert is_macro_ext("test.frm") is True
    assert is_macro_ext("test.cls") is True
    
    # test non-macro extensions
    assert is_macro_ext("test.txt") is False
    assert is_macro_ext("test.py") is False
    assert is_macro_ext("test.js") is False
    assert is_macro_ext("test") is False


@pytest.mark.unit
def test_is_ole_file(datadir, tmp_path):
    # test with real OLE file
    assert is_ole_file(datadir / 'doc.doc') is True
    
    # test with non-OLE file
    target = str(tmp_path / 'test.txt')
    with open(target, 'wb') as fp:
        fp.write(b'not an ole file')

    assert is_ole_file(target) is False
    
    # test with file containing OLE signature
    target = str(tmp_path / 'fake_ole.doc')
    with open(target, 'wb') as fp:
        fp.write(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1')

    assert is_ole_file(target) is True


@pytest.mark.unit
def test_is_rtf_file(tmp_path):
    # test valid RTF file with \rt prefix
    target = str(tmp_path / 'test.rtf')
    with open(target, 'wb') as fp:
        fp.write(b'\\rtf1\\ansi\\deff0')

    assert is_rtf_file(target) is True
    
    # test valid RTF file with {\rt prefix
    target = str(tmp_path / 'test2.rtf')
    with open(target, 'wb') as fp:
        fp.write(b'{\\rtf1\\ansi\\deff0')

    assert is_rtf_file(target) is True
    
    # test invalid RTF file
    target = str(tmp_path / 'test3.rtf')
    with open(target, 'wb') as fp:
        fp.write(b'not an rtf file')

    assert is_rtf_file(target) is False


@pytest.mark.unit
def test_is_pdf_file(tmp_path):
    # test valid PDF file
    target = str(tmp_path / 'test.pdf')
    with open(target, 'wb') as fp:
        fp.write(b'%PDF-1.4\n')

    assert is_pdf_file(target) is True
    
    # test PDF signature later in file (within 1024 bytes)
    target = str(tmp_path / 'test2.pdf')
    with open(target, 'wb') as fp:
        fp.write(b'some header data %PDF-1.5')

    assert is_pdf_file(target) is True
    
    # test invalid PDF file
    target = str(tmp_path / 'test3.pdf')
    with open(target, 'wb') as fp:
        fp.write(b'not a pdf file')

    assert is_pdf_file(target) is False


@pytest.mark.unit
def test_is_zip_file(datadir, tmp_path):
    # test valid ZIP file
    assert is_zip_file(datadir / 'zipped.zip') is True
    
    # test invalid ZIP file
    target = str(tmp_path / 'test.zip')
    with open(target, 'wb') as fp:
        fp.write(b'not a zip file')

    assert is_zip_file(target) is False
    
    # test empty file
    target = str(tmp_path / 'empty.zip')
    with open(target, 'wb') as fp:
        fp.write(b'')

    assert is_zip_file(target) is False


@pytest.mark.unit
def test_is_empty_macro(tmp_path):
    # test empty macro file
    target = str(tmp_path / 'empty.bas')
    with open(target, 'wb') as fp:
        fp.write(b'')

    assert is_empty_macro(target) is True
    
    # test macro with only whitespace
    target = str(tmp_path / 'whitespace.bas')
    with open(target, 'wb') as fp:
        fp.write(b'\n\n   \n\n')

    assert is_empty_macro(target) is True
    
    # test macro with only Attribute lines
    target = str(tmp_path / 'attributes.bas')
    with open(target, 'wb') as fp:
        fp.write(b'Attribute VB_Name = "Module1"\nAttribute VB_Description = "Test"\n')

    assert is_empty_macro(target) is True
    
    # test macro with actual content
    target = str(tmp_path / 'content.bas')
    with open(target, 'wb') as fp:
        fp.write(b'Attribute VB_Name = "Module1"\nSub Test()\nEnd Sub\n')

    assert is_empty_macro(target) is False


@pytest.mark.unit
def test_is_msi_file(tmp_path):
    # Create a mock MSI file by writing content that would be detected by 'file' command
    # Since we can't easily create a real MSI file, we'll test the basic functionality
    target = str(tmp_path / 'test.msi')
    with open(target, 'wb') as fp:
        fp.write(b'not an msi file')
    
    # This will return False for our fake file
    assert is_msi_file(target) is False


@pytest.mark.unit
def test_is_onenote_file(datadir, tmp_path):
    # test file with .one extension
    target = str(tmp_path / 'test.one')
    with open(target, 'wb') as fp:
        fp.write(b'any content')

    assert is_onenote_file(target) is True
    
    # test file with OneNote header signature
    target = str(tmp_path / 'onenote_header')
    with open(target, 'wb') as fp:
        fp.write(b'\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3')

    assert is_onenote_file(target) is True
    
    # test file without OneNote characteristics
    target = str(tmp_path / 'not_onenote')
    with open(target, 'wb') as fp:
        fp.write(b'not a onenote file')

    assert is_onenote_file(target) is False
    
    # test None path
    assert is_onenote_file(None) is False


@pytest.mark.unit
def test_is_email_file(tmp_path):
    # test valid email file with all required headers
    target = str(tmp_path / 'valid.eml')
    with open(target, 'w', encoding='utf-8') as fp:
        fp.write('From: sender@example.com\n')
        fp.write('To: recipient@example.com\n')
        fp.write('Subject: Test Email\n')
        fp.write('Date: Mon, 1 Jan 2024 12:00:00 +0000\n')
        fp.write('Message-ID: <test@example.com>\n')
        fp.write('\n')
        fp.write('Email body content\n')

    assert is_email_file(target) is True
    
    # test email with indented headers (continuation)
    target = str(tmp_path / 'indented.eml')
    with open(target, 'w', encoding='utf-8') as fp:
        fp.write('From: sender@example.com\n')
        fp.write(' continued header\n')
        fp.write('To: recipient@example.com\n')
        fp.write('Subject: Test Email\n')
        fp.write('Date: Mon, 1 Jan 2024 12:00:00 +0000\n')
        fp.write('Message-ID: <test@example.com>\n')
        fp.write('\n')

    assert is_email_file(target) is True
    
    # test file with some headers but no empty line (would return False at end)
    target = str(tmp_path / 'partial.eml')
    with open(target, 'w', encoding='utf-8') as fp:
        fp.write('From: sender@example.com\n')
        fp.write('Subject: Test Email\n')

    assert is_email_file(target) is False
    
    # test file with invalid header format
    target = str(tmp_path / 'invalid.eml')
    with open(target, 'w', encoding='utf-8') as fp:
        fp.write('From: sender@example.com\n')
        fp.write('invalid line without colon\n')

    assert is_email_file(target) is False
    
    # test binary file (non-UTF-8)
    target = str(tmp_path / 'binary.eml')
    with open(target, 'wb') as fp:
        fp.write(b'\xff\xfe\x00\x00')

    assert is_email_file(target) is False


@pytest.mark.parametrize('file_content,expected_result', [
    (b'\xCA\xFE\xBA\xBE', True),  # valid Java class file magic number
    (b'\xCA\xFE\xBA\xBE\x00\x00\x00\x34', True),  # valid with additional data
    (b'\xCA\xFE\xBA', False),  # incomplete magic number
    (b'\xCA\xFE\xBA\xBF', False),  # invalid magic number
    (b'not a class file', False),  # text content
    (b'', False),  # empty file
    (b'\x00\x00', False),  # short binary content
])
@pytest.mark.unit
def test_is_java_class_file(tmp_path, file_content, expected_result):
    target = str(tmp_path / 'test.class')
    with open(target, 'wb') as fp:
        fp.write(file_content)

    assert is_java_class_file(target) == expected_result


@pytest.mark.unit  
def test_is_java_class_file_missing_file(tmp_path):
    # test missing file
    target = str(tmp_path / 'nonexistent.class')
    assert is_java_class_file(target) is False
