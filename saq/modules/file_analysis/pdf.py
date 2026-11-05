import base64
import logging
import os
import re
from subprocess import PIPE
from typing import Type, override
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, DIRECTIVE_EXTRACT_URLS, F_FILE, R_EXTRACTED_FROM
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.exif import ExifAnalyzer
from saq.modules.file_analysis.is_file_type import is_pdf_file
from saq.observables.file import FileObservable

# how long ghostscript may take to rewrite a PDF
GS_TIMEOUT_SECONDS = 10
# how long pdfparser may take to dump a PDF's objects
PDFPARSER_TIMEOUT_SECONDS = 10


# PDFAnalysis.details key: the encryption dictionary of a PDF that opens without a password
KEY_ENCRYPTION = "encryption"


class PDFAnalysis(Analysis):
    @override
    @property
    def display_name(self) -> str:
        return "PDF Analysis"

    @property
    def encryption(self) -> dict | None:
        return self.details.get(KEY_ENCRYPTION) if self.details else None

    @override
    def generate_summary(self) -> str | None:
        if not self.encryption:
            return None

        return (f"{self.display_name}: encrypted ({self.encryption['method']} {self.encryption['bits']}-bit, "
                f"R{self.encryption['R']}, P {self.encryption['P']}), opens with an empty user password")

class PDFAnalyzerConfig(AnalysisModuleConfig):
    pdfparser_path: str = Field(..., description="Path to pdfparser executable.")

class PDFAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return PDFAnalyzerConfig

    """What is the raw PDF data after removing stream filters?"""

    def verify_environment(self):
        self.verify_path_exists(self.config.pdfparser_path)

    @property
    def pdfparser_path(self):
        path = self.config.pdfparser_path
        if os.path.isabs(path):
            return path
        return os.path.join(get_base_dir(), path)

    @property
    def generated_analysis_type(self):
        return PDFAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # do not analyze our own output
        if local_file_path.endswith('.pdfparser'):
            return AnalysisExecutionResult.COMPLETED

        # do not analyze OCR output
        if local_file_path.endswith('.ocr'):
            return AnalysisExecutionResult.COMPLETED

        # this file must actually be a PDF
        with open(local_file_path, 'rb') as fp:
            # the header can be anywhere in the first 1024 bytes
            # they released a change to the spec
            header = fp.read(1024)
            if b'%PDF-' not in header:
                #logging.debug("{0} is not a PDF file".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

        logging.debug("analyzing file {}".format(local_file_path))
        analysis = self.create_analysis(_file)
        self.run_pdfparser(_file, f"{local_file_path}.pdfparser", analysis, redirection=_file)

        # gs -sDEVICE=pdfwrite -dNOPAUSE -dBATCH -sOutputFile=output.pdf -c ".setpdfwrite <</NeverEmbed [ ]>> setdistillerparams" -f input.pdf
        # evaluate with ghostscript as well to try to get the URLs out of AES encrypted PDFs
        # changing command line to match our needs as the old commands were tailed for Qakbot PDFs we no longer observe
        gs_output_file = f"{local_file_path}.gs.pdf"
        # ghostscript interprets the document, and its -dSAFER mode has been escaped many times
        self.run_sandboxed_tool(["gs", "-sDEVICE=pdfwrite", "-o", "output.pdf", "-f", local_file_path], local_file_path,
                                timeout=GS_TIMEOUT_SECONDS, outputs={"output.pdf": gs_output_file})

        if os.path.exists(gs_output_file) and os.path.getsize(gs_output_file) > 0:
            file_observable = analysis.add_file_observable(gs_output_file, volatile=True)

            if file_observable:
                # point actions back at the source ole file
                file_observable.redirection = _file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                # extract URLs from this file
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                file_observable.exclude_analysis(self)
                file_observable.add_yara_meta("type", "document.pdf.rendered")

        # use pikepdf to extract annotations, form field payloads, and JavaScript. Imported here: the search indexer
        # and the GUI import this module only to read PDFTextAnalysis
        import pikepdf

        try:
            pdf = pikepdf.open(local_file_path)

            # an encrypted PDF that opens without a password has an empty user password, and pdfparser reads
            # only ciphertext in its strings and streams. A PDF that needs a user password raises PasswordError
            # and is left to PDFEncryptionAnalyzer
            if pdf.is_encrypted:
                self.save_decrypted_copy(pdf, _file, analysis)

            # extract URIs from PDF annotations
            # this handles AES-encrypted PDFs that ghostscript may not fully decrypt
            uris_output_file = f"{local_file_path}.annotation_uris.txt"
            try:
                uris = []
                for page in pdf.pages:
                    annots = page.get('/Annots')
                    if not annots:
                        continue
                    for annot in annots:
                        action = annot.get('/A')
                        if action:
                            uri = action.get('/URI')
                            if uri:
                                uris.append(str(uri))

                if uris:
                    with open(uris_output_file, 'w') as fp:
                        fp.write('\n'.join(uris))

                    file_observable = analysis.add_file_observable(uris_output_file, volatile=True)
                    if file_observable:
                        file_observable.redirection = _file
                        file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                        file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                        file_observable.exclude_analysis(self)
                        file_observable.add_yara_meta("type", "document.pdf.annotation_uris")
            except Exception as e:
                logging.warning(f"pikepdf annotation extraction failed for {local_file_path}: {e}")

            # extract base64-encoded form field values from AcroForm
            try:
                acroform = pdf.Root.get('/AcroForm')
                if acroform:
                    fields = acroform.get('/Fields', [])
                    for field in fields:
                        field_name_raw = str(field.get('/T', 'unknown'))
                        field_name = re.sub(r'[^A-Za-z0-9_-]', '_', field_name_raw)
                        value = field.get('/V')
                        if value is None:
                            continue
                        if not isinstance(value, pikepdf.Name):
                            continue
                        candidate = str(value).lstrip('/')
                        if len(candidate) < 64:
                            continue
                        if not re.fullmatch(r'[A-Za-z0-9+/=]+', candidate):
                            continue
                        try:
                            decoded = base64.b64decode(candidate)
                        except Exception:
                            continue
                        if len(decoded) < 32:
                            continue
                        field_output_file = f"{local_file_path}.field_{field_name}_decoded.bin"
                        with open(field_output_file, 'wb') as fp:
                            fp.write(decoded)
                        file_observable = analysis.add_file_observable(field_output_file, volatile=True)
                        if file_observable:
                            file_observable.redirection = _file
                            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                            file_observable.exclude_analysis(self)
                            file_observable.add_yara_meta("type", "document.pdf.form_field")
            except Exception as e:
                logging.warning(f"pikepdf form field extraction failed for {local_file_path}: {e}")

            # extract JavaScript from /Names /JavaScript tree
            try:
                names = pdf.Root.get('/Names')
                if names:
                    js_names_tree = names.get('/JavaScript')
                    if js_names_tree:
                        names_array = js_names_tree.get('/Names', [])
                        for i in range(0, len(names_array) - 1, 2):
                            js_name_raw = str(names_array[i])
                            js_name = re.sub(r'[^A-Za-z0-9_-]', '_', js_name_raw)
                            action = names_array[i + 1]
                            js_value = action.get('/JS')
                            if js_value is None:
                                continue
                            if isinstance(js_value, pikepdf.Stream):
                                js_content = js_value.read_bytes().decode('utf-8', errors='replace')
                            else:
                                js_content = str(js_value)
                            if not js_content.strip():
                                continue
                            js_output_file = f"{local_file_path}.js_{js_name}.js"
                            with open(js_output_file, 'w', encoding='utf-8') as fp:
                                fp.write(js_content)
                            file_observable = analysis.add_file_observable(js_output_file, volatile=True)
                            if file_observable:
                                file_observable.redirection = _file
                                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                                file_observable.exclude_analysis(self)
                                file_observable.add_yara_meta("type", "script.javascript")
            except Exception as e:
                logging.warning(f"pikepdf JavaScript extraction failed for {local_file_path}: {e}")

            pdf.close()
        except Exception as e:
            logging.warning(f"pikepdf failed to open {local_file_path}: {e}")

        return AnalysisExecutionResult.COMPLETED

    def run_pdfparser(self, _file: FileObservable, output_path: str, analysis: PDFAnalysis, redirection: FileObservable):
        """Adds pdfparser's dump of the objects in _file, with its stream filters decoded, as a file to scan."""
        # a pdfparser that is stopped still leaves what it wrote in output_path, which is scanned
        with open(output_path, 'wb') as fp:
            result = self.run_tool(['python3', self.pdfparser_path, '-f', '-w', '-v', '-c', '--debug', _file.full_path],
                                   _file.full_path, timeout=PDFPARSER_TIMEOUT_SECONDS, stdout=fp, stderr=PIPE)

        if result and result.stderr:
            logging.warning("pdfparser returned errors for {}".format(_file.full_path))

        # add the output file as a new file to scan
        # the FILE type indicators are relative to the alert storage directory
        file_observable = analysis.add_file_observable(output_path, volatile=True)

        if file_observable:
            # point actions back at the source pdf
            file_observable.redirection = redirection
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            # extract URLs from this file
            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
            file_observable.add_yara_meta("type", "document.pdf.object")

    def save_decrypted_copy(self, pdf, _file: FileObservable, analysis: PDFAnalysis):
        """Adds an unencrypted copy of the opened, encrypted pdf and pdfparser's dump of it, so the
        type=document.pdf.object output holds the plaintext objects."""
        # imported here for the same reason as in execute_analysis, which has already loaded it
        import pikepdf

        encryption = pdf.encryption
        analysis.details[KEY_ENCRYPTION] = {
            "filter": str(pdf.trailer.Encrypt.get("/Filter", "")),
            "V": encryption.V,
            "R": encryption.R,
            "P": encryption.P,
            "bits": encryption.bits,
            # RC4 before V4 has no crypt filters, which pikepdf reports as a stream method of none
            "method": "rc4" if encryption.V < 4 else encryption.stream_method.name,
            "owner_password_empty": pdf.owner_password_matched,
            "permissions": pdf.allow._asdict(),
        }
        _file.add_tag("encrypted_pdf_empty_password")

        output_file = self.get_root().create_output_file(f"{_file.file_name}.decrypted.pdf")
        try:
            # saved through the file create_output_file made: given a path, pikepdf writes a temporary file beside
            # it with a longer name, which a long attachment name pushes past NAME_MAX. Saving without encryption=
            # drops the encryption. The streams are copied as they are, still filtered: decoding them here would run
            # in this process with no time limit, and a nested-Flate stream of a few KB inflates to gigabytes.
            # pdfparser decodes them under its timeout. A deterministic /ID gives the copy the same sha256 every
            # time, so results cached on it are reused
            with open(output_file, "wb") as fp:
                pdf.save(fp, stream_decode_level=pikepdf.StreamDecodeLevel.none, compress_streams=False,
                         deterministic_id=True)
        except Exception as e:
            # WARNING, as for every other pikepdf failure here: a damaged PDF is the sender's doing, not something
            # an operator can fix. The original's own pdfparser output is still scanned
            logging.warning(f"cannot save a decrypted copy of {_file.full_path}: {e}", exc_info=True,
                            extra={"path": _file.full_path, "root_uuid": self.get_root().uuid})
            os.remove(output_file)
            return

        decrypted_file = analysis.add_file_observable(output_file, volatile=True)
        if decrypted_file:
            decrypted_file.redirection = _file
            decrypted_file.add_relationship(R_EXTRACTED_FROM, _file)
            decrypted_file.add_tag("decrypted_pdf")
            decrypted_file.add_yara_meta("type", "document.pdf")

            # only pdfparser needs the plaintext. Ghostscript, poppler and pikepdf open the original with its empty
            # password, so on the copy they, and this module's own extraction, would only repeat their work.
            # Imported here: qrcode imports PIL, and the search indexer and the GUI import this module only to read
            # PDFTextAnalysis
            from saq.modules.file_analysis.qrcode import QRCodeAnalyzer
            for module in (self, PDFTextAnalyzer, ExifAnalyzer, QRCodeAnalyzer):
                decrypted_file.exclude_analysis(module)

            # named through create_output_file, which keeps it within NAME_MAX after a long attachment name
            self.run_pdfparser(decrypted_file,
                               self.get_root().create_output_file(f"{decrypted_file.file_name}.pdfparser"),
                               analysis, redirection=_file)

KEY_STDOUT = 'stdout'
KEY_STDERR = 'stderr'
KEY_OUTPUT_PATH = 'output_path'

class PDFTextAnalysis(Analysis):
    """Converts a PDF to text for simple yara scanning."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_OUTPUT_PATH: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "PDF Text Analysis"

    @property
    def stdout(self):
        return self.details[KEY_STDOUT]

    @stdout.setter
    def stdout(self, value):
        self.details[KEY_STDOUT] = value

    @property
    def stderr(self):
        return self.details[KEY_STDERR]

    @stderr.setter
    def stderr(self, value):
        self.details[KEY_STDERR] = value

    @property
    def output_path(self):
        return self.details[KEY_OUTPUT_PATH]

    @output_path.setter
    def output_path(self, value):
        self.details[KEY_OUTPUT_PATH] = value

    def generate_summary(self):
        if not self.output_path:
            return None
        
        return self.display_name
    
class PDFTextAnalyzerConfig(AnalysisModuleConfig):
    pdftotext_path: str = Field(..., description="Path to pdftotext executable.")
    timeout: int = Field(..., description="Timeout in seconds for pdftotext execution.")

class PDFTextAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return PDFTextAnalyzerConfig

    @property
    def pdftotext_path(self):
        return self.config.pdftotext_path

    @property
    def timeout(self):
        return self.config.timeout

    def verify_environment(self):
        self.verify_path_exists(self.config.pdftotext_path)

    @property
    def generated_analysis_type(self):
        return PDFTextAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.archive import ArchiveAnalyzer
        
        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # is this a PDF file?
        if not is_pdf_file(local_file_path):
            logging.debug("{} is not a pdf file".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        if local_file_path.lower().endswith('.pdf'):
            output_path = '{}.txt'.format(local_file_path)
        else:
            output_path = '{}.pdf.txt'.format(local_file_path)

        result = self.run_sandboxed_tool([self.pdftotext_path, local_file_path, "output.txt"], local_file_path,
                                         timeout=self.timeout, outputs={"output.txt": output_path})
        if result is None:
            return AnalysisExecutionResult.COMPLETED

        analysis.stdout, analysis.stderr = result.stdout, result.stderr
        if len(analysis.stderr) > 0:
            logging.debug("pdftotext returned errors for {}".format(local_file_path))

        # add the output file as a new file to scan
        # the FILE type indicators are relative to the alert storage directory
        if os.path.exists(output_path):
            file_observable = analysis.add_file_observable(output_path, volatile=True)

            if file_observable:
                # point actions back at the source ole file
                file_observable.redirection = _file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                analysis.output_path = file_observable.value
                # avoid analyzing these files with archive analyzer
                # 7z tends to choke
                file_observable.exclude_analysis(ArchiveAnalyzer)
                file_observable.add_yara_meta("type", "document.pdf.text")

        return AnalysisExecutionResult.COMPLETED