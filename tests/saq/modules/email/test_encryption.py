import io
import logging
import subprocess
import zipfile
from email.message import EmailMessage
from pathlib import Path

import msoffcrypto
import pytest
from msoffcrypto.format.ooxml import OOXMLFile

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_MSOFFICE_ENCRYPTION_ANALYZER,
    ANALYSIS_MODULE_RAR_ENCRYPTION_ANALYZER,
    ANALYSIS_MODULE_ZIP_ENCRYPTION_ANALYZER,
    ANALYSIS_TYPE_MAILBOX,
    F_FILE,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email import EmailAnalysis
from saq.modules.email.encryption.msoffice import MSOfficeEncryptionAnalysis
from saq.modules.email.encryption.rar import RarEncryptionAnalysis
from saq.modules.email.encryption.zip import ZipEncryptionAnalysis
from saq.signatures.builtin import EMAIL_ENCRYPTED_DECRYPTED
from saq.util.uuid import get_storage_dir

PASSWORD = "Secr3tPw"


def _encrypted_zip(tmp_path: Path, password: str = PASSWORD, plain_entry: bool = False) -> Path:
    payload = tmp_path / "invoice.txt"
    payload.write_text("the decrypted payload https://payload.example.com/x\n")
    archive = tmp_path / "invoice.zip"
    subprocess.run(["7z", "a", "-tzip", f"-p{password}", str(archive), str(payload)], check=True, capture_output=True)
    if plain_entry:
        # appended without a password, so the archive's last entry is not encrypted
        with zipfile.ZipFile(archive, "a") as zip_fp:
            zip_fp.writestr("readme.txt", "not encrypted")
    return archive


def _email(tmp_path: Path, attachment: Path, body: str = f"The password for the attached invoice is {PASSWORD} thanks", subtype: str = "zip") -> Path:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = "invoice"
    message["Message-ID"] = "<encrypted-zip-test@example.com>"
    message.set_content(body)
    message.add_attachment(attachment.read_bytes(), maintype="application", subtype=subtype, filename=attachment.name)
    path = tmp_path / "message.email.rfc822"
    path.write_bytes(bytes(message))
    return path


def _analyze(root_analysis, email_path: Path, modules=("file_type", "email_analyzer", ANALYSIS_MODULE_ZIP_ENCRYPTION_ANALYZER)):
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    email_observable = root_analysis.add_file_observable(str(email_path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in modules:
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root, root.get_observable(email_observable.uuid)


def _attachment(email_observable, file_name: str):
    email_analysis = email_observable.get_and_load_analysis(EmailAnalysis)
    assert email_analysis
    return email_analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == file_name)


@pytest.mark.integration
def test_decrypts_zip_with_password_from_email_body(root_analysis, tmp_path):
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path)))

    attachment = _attachment(email_observable, "invoice.zip")
    assert attachment.has_tag("encrypted_zip")
    analysis = attachment.get_and_load_analysis(ZipEncryptionAnalysis)
    assert analysis.password == PASSWORD
    assert analysis.email
    assert PASSWORD in analysis.email_body
    assert PASSWORD in analysis.word_list
    assert analysis.error is None
    assert analysis.summary == f"Zip Encryption Analysis: password {PASSWORD}"

    decrypted = analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == "invoice.txt")
    assert decrypted
    assert [d.signature_uuid for d in decrypted.detections] == [EMAIL_ENCRYPTED_DECRYPTED.uuid]
    assert decrypted.has_directive("extract_urls")


@pytest.mark.integration
def test_detects_encryption_when_only_some_entries_are_encrypted(root_analysis, tmp_path):
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path, plain_entry=True)))

    analysis = _attachment(email_observable, "invoice.zip").get_and_load_analysis(ZipEncryptionAnalysis)
    assert analysis
    assert analysis.password == PASSWORD


@pytest.mark.integration
def test_ignores_zip_that_is_not_encrypted(root_analysis, tmp_path):
    archive = tmp_path / "plain.zip"
    with zipfile.ZipFile(archive, "w") as zip_fp:
        zip_fp.writestr("readme.txt", "not encrypted")

    _, email_observable = _analyze(root_analysis, _email(tmp_path, archive))

    attachment = _attachment(email_observable, "plain.zip")
    assert not attachment.get_and_load_analysis(ZipEncryptionAnalysis)
    assert not attachment.has_tag("encrypted_zip")


@pytest.mark.integration
def test_password_not_in_email(root_analysis, tmp_path):
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path), body="please see the attached invoice"))

    attachment = _attachment(email_observable, "invoice.zip")
    analysis = attachment.get_and_load_analysis(ZipEncryptionAnalysis)
    assert analysis.password is None
    assert analysis.error == "ZipEncryptionAnalyzer was unable to crack the password"
    assert not analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == "invoice.txt")


@pytest.mark.integration
def test_encrypted_zip_without_an_email(root_analysis, tmp_path):
    root_analysis.analysis_mode = "test_groups"
    zip_observable = root_analysis.add_file_observable(str(_encrypted_zip(tmp_path)))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_ZIP_ENCRYPTION_ANALYZER, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root.get_observable(zip_observable.uuid).get_and_load_analysis(ZipEncryptionAnalysis)
    assert not analysis.email
    assert analysis.word_list == []
    assert analysis.error == "ZipEncryptionAnalyzer was unable to crack the password"


@pytest.mark.integration
def test_zip2john_failure_is_recorded(root_analysis, tmp_path, monkeypatch):
    real_popen = subprocess.Popen

    def _popen(args, *a, **kw):
        if args[0].endswith("zip2john"):
            # a zip2john that prints nothing and complains
            args = ["sh", "-c", "echo 'cannot read archive' >&2"]
        return real_popen(args, *a, **kw)

    monkeypatch.setattr("saq.modules.email.encryption.zip.Popen", _popen)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path)))

    analysis = _attachment(email_observable, "invoice.zip").get_and_load_analysis(ZipEncryptionAnalysis)
    assert analysis.error == "zip2john failed: cannot read archive\n"
    assert analysis.summary == "Zip Encryption Analysis: zip2john failed: cannot read archive\n"


@pytest.mark.integration
def test_crack_failure_is_logged(root_analysis, tmp_path, monkeypatch, caplog):
    def _crack(*args, **kwargs):
        raise FileNotFoundError("john binary not found")

    monkeypatch.setattr("saq.modules.email.encryption.zip.crack_password", _crack)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path)))

    analysis = _attachment(email_observable, "invoice.zip").get_and_load_analysis(ZipEncryptionAnalysis)
    assert analysis.password is None
    assert any(r.levelno == logging.ERROR and "error encountered when trying to crack password" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_extraction_timeout_stops_7z(root_analysis, tmp_path, monkeypatch, caplog):
    get_analysis_module_config(ANALYSIS_MODULE_ZIP_ENCRYPTION_ANALYZER).extract_timeout = 1
    real_popen = subprocess.Popen
    extractions = []

    def _popen(args, *a, **kw):
        if args[0] == "7z":
            # a 7z that never finishes
            process = real_popen(["sleep", "60"], *a, **kw)
            extractions.append(process)
            return process
        return real_popen(args, *a, **kw)

    monkeypatch.setattr("saq.modules.email.encryption.zip.Popen", _popen)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path)))

    assert len(extractions) == 1
    # killed, not left running
    assert extractions[0].returncode == -9
    assert any(r.levelno == logging.ERROR and "Unable to extract data from encrypted zip" in r.getMessage() for r in caplog.records)

    analysis = _attachment(email_observable, "invoice.zip").get_and_load_analysis(ZipEncryptionAnalysis)
    assert analysis.password == PASSWORD
    assert not analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == "invoice.txt")


#
# msoffice
#

DOCUMENT = "<w:document>" + "statement " * 500 + "</w:document>"


def _encrypted_docx(tmp_path: Path, password: str = PASSWORD) -> Path:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as zip_fp:
        zip_fp.writestr("[Content_Types].xml", "<?xml version='1.0'?><Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>")
        # msoffcrypto can't decrypt what it encrypted when the package is tiny
        zip_fp.writestr("word/document.xml", DOCUMENT)
    package.seek(0)

    path = tmp_path / "statement.docx"
    with open(path, "wb") as fp:
        OOXMLFile(package).encrypt(password, fp)
    return path


def _fail_encryption_check(monkeypatch, message: str):
    """msoffcrypto raises this from is_encrypted() for the module only; other code may open the file too"""
    real_office_file = msoffcrypto.OfficeFile

    def _office_file(fp):
        office_file = real_office_file(fp)

        def _is_encrypted():
            raise Exception(message)

        office_file.is_encrypted = _is_encrypted
        return office_file

    monkeypatch.setattr("saq.modules.email.encryption.msoffice.msoffcrypto.OfficeFile", _office_file)


MSOFFICE_MODULES = ("file_type", "email_analyzer", ANALYSIS_MODULE_MSOFFICE_ENCRYPTION_ANALYZER)


@pytest.mark.integration
def test_msoffice_decrypts_with_password_from_email_body(root_analysis, tmp_path):
    email_path = _email(tmp_path, _encrypted_docx(tmp_path), subtype="vnd.openxmlformats-officedocument.wordprocessingml.document")
    _, email_observable = _analyze(root_analysis, email_path, MSOFFICE_MODULES)

    attachment = _attachment(email_observable, "statement.docx")
    assert attachment.has_tag("encrypted_msoffice")
    analysis = attachment.get_and_load_analysis(MSOfficeEncryptionAnalysis)
    assert analysis.password == PASSWORD
    decrypted = analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == "statement.docx.decrypted")
    assert decrypted.has_tag("decrypted_msoffice")
    assert [d.signature_uuid for d in decrypted.detections] == [EMAIL_ENCRYPTED_DECRYPTED.uuid]
    with zipfile.ZipFile(decrypted.full_path) as zip_fp:
        assert zip_fp.read("word/document.xml") == DOCUMENT.encode()


@pytest.mark.integration
def test_msoffice_password_not_found(root_analysis, tmp_path):
    email_path = _email(tmp_path, _encrypted_docx(tmp_path), body="see attached", subtype="octet-stream")
    _, email_observable = _analyze(root_analysis, email_path, MSOFFICE_MODULES)

    analysis = _attachment(email_observable, "statement.docx").get_and_load_analysis(MSOfficeEncryptionAnalysis)
    assert analysis.password is None
    # the well known default passwords are always tried first
    assert analysis.word_list[:2] == ["VelvetSweatshop", "/01Hannes Ruescher/01"]
    assert analysis.summary == "MSOffice Encryption Analysis: could not crack password"


@pytest.mark.integration
def test_msoffice_office2john_failure_is_recorded(root_analysis, tmp_path, monkeypatch):
    real_popen = subprocess.Popen

    def _popen(args, *a, **kw):
        if args[-2].endswith("office2john.py"):
            args = ["sh", "-c", "echo 'unsupported document' >&2"]
        return real_popen(args, *a, **kw)

    monkeypatch.setattr("saq.modules.email.encryption.msoffice.Popen", _popen)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_docx(tmp_path), subtype="octet-stream"), MSOFFICE_MODULES)

    analysis = _attachment(email_observable, "statement.docx").get_and_load_analysis(MSOfficeEncryptionAnalysis)
    assert analysis.error == "office2john.py failed: unsupported document\n"


@pytest.mark.integration
def test_msoffice_unsupported_encryption(root_analysis, tmp_path, monkeypatch):
    _fail_encryption_check(monkeypatch, "Unsupported encryption method")
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_docx(tmp_path), subtype="octet-stream"), MSOFFICE_MODULES)

    attachment = _attachment(email_observable, "statement.docx")
    assert attachment.has_tag("encrypted_msoffice")
    analysis = attachment.get_and_load_analysis(MSOfficeEncryptionAnalysis)
    assert analysis.error == "Unsupported encryption method"


@pytest.mark.integration
@pytest.mark.parametrize("message, logged", [
    ("unpack requires a buffer of 4 bytes", False),
    ("something unexpected", True),
])
def test_msoffice_encryption_check_failure(root_analysis, tmp_path, monkeypatch, caplog, message, logged):
    _fail_encryption_check(monkeypatch, message)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_docx(tmp_path), subtype="octet-stream"), MSOFFICE_MODULES)

    assert not _attachment(email_observable, "statement.docx").get_and_load_analysis(MSOfficeEncryptionAnalysis)
    errors = [r for r in caplog.records if r.levelno == logging.ERROR and "Unable to check encryption status" in r.getMessage()]
    assert bool(errors) == logged


@pytest.mark.integration
def test_msoffice_ignores_files_that_are_not_office_documents(root_analysis, tmp_path):
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path)), MSOFFICE_MODULES)

    assert not _attachment(email_observable, "invoice.zip").get_and_load_analysis(MSOfficeEncryptionAnalysis)


#
# rar
#
# nothing here can create a rar archive, so these replace rarfile and rar2john and check what the
# module does around them

class _FakeRarFile:
    """An encrypted rar holding one file."""

    extracted_with = []

    def __init__(self, path):
        with open(path, "rb") as fp:
            if not fp.read().startswith(b"Rar!"):
                raise Exception("Not a RAR file")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def needs_password(self):
        return True

    def extractall(self, path, pwd=None):
        _FakeRarFile.extracted_with.append(pwd)
        Path(path, "payload.exe").write_bytes(b"MZ payload")


@pytest.fixture
def fake_rar(monkeypatch, tmp_path):
    import rarfile

    _FakeRarFile.extracted_with = []
    monkeypatch.setattr(rarfile, "RarFile", _FakeRarFile)
    real_popen = subprocess.Popen

    def _popen(args, *a, **kw):
        if args[0].endswith("rar2john"):
            args = ["echo", "payload.rar:$rar5$fakehash"]
        return real_popen(args, *a, **kw)

    monkeypatch.setattr("saq.modules.email.encryption.rar.Popen", _popen)

    archive = tmp_path / "payload.rar"
    archive.write_bytes(b"Rar!\x1a\x07\x01\x00 not really")
    return archive


RAR_MODULES = ("file_type", "email_analyzer", ANALYSIS_MODULE_RAR_ENCRYPTION_ANALYZER)


@pytest.mark.integration
def test_rar_cracks_with_a_wordlist_from_the_email_body(root_analysis, tmp_path, fake_rar, monkeypatch):
    wordlists = []

    def _crack(john_bin_path, hash_file, filename, mode):
        with open(mode.removeprefix("--wordlist=")) as fp:
            words = fp.read().split()
        wordlists.append(words)
        return PASSWORD if PASSWORD in words else None

    monkeypatch.setattr("saq.modules.email.encryption.rar.crack_password", _crack)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, fake_rar, subtype="x-rar"), RAR_MODULES)

    attachment = _attachment(email_observable, "payload.rar")
    assert attachment.has_tag("encrypted_rar")
    analysis = attachment.get_and_load_analysis(RarEncryptionAnalysis)
    assert analysis.email
    assert PASSWORD in analysis.email_body
    assert len(wordlists) == 1 and PASSWORD in wordlists[0]
    assert analysis.password == PASSWORD
    assert _FakeRarFile.extracted_with == [PASSWORD]

    payload = analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == "payload.exe")
    assert [d.signature_uuid for d in payload.detections] == [EMAIL_ENCRYPTED_DECRYPTED.uuid]


@pytest.mark.integration
def test_rar_password_not_found(root_analysis, tmp_path, fake_rar, monkeypatch):
    monkeypatch.setattr("saq.modules.email.encryption.rar.crack_password", lambda *args: None)
    _, email_observable = _analyze(root_analysis, _email(tmp_path, fake_rar, subtype="x-rar"), RAR_MODULES)

    analysis = _attachment(email_observable, "payload.rar").get_and_load_analysis(RarEncryptionAnalysis)
    assert analysis.error == "RarEncryptionAnalyzer could not crack password!"
    assert _FakeRarFile.extracted_with == []


@pytest.mark.integration
def test_rar_ignores_files_that_are_not_rar_archives(root_analysis, tmp_path, fake_rar):
    _, email_observable = _analyze(root_analysis, _email(tmp_path, _encrypted_zip(tmp_path)), RAR_MODULES)

    assert not _attachment(email_observable, "invoice.zip").get_and_load_analysis(RarEncryptionAnalysis)
