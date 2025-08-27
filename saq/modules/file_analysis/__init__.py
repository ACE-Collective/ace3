from saq.modules.file_analysis.archive import ArchiveAnalysis, ArchiveAnalyzer
from saq.modules.file_analysis.autoit import AutoItAnalysis, AutoItAnalyzer
from saq.modules.file_analysis.binary import BinaryFileAnalysis, BinaryFileAnalyzer
from saq.modules.file_analysis.cve import CVE_2021_30657_Analysis, CVE_2021_30657_Analyzer
from saq.modules.file_analysis.dmg import DMGAnalysis, DMGAnalyzer
from saq.modules.file_analysis.dotnet import De4dotAnalysis, De4dotAnalyzer
from saq.modules.file_analysis.exif import ExifAnalysis, ExifAnalyzer
from saq.modules.file_analysis.file_type import FileTypeAnalysis, FileTypeAnalyzer
from saq.modules.file_analysis.hash import FileHashAnalysis, FileHashAnalyzer
from saq.modules.file_analysis.html import MetaRefreshExtractionAnalysis, MetaRefreshExtractionAnalyzer, MHTMLAnalysis, MHTMLAnalysisModule, HTMLDataURLAnalysis, HTMLDataURLAnalyzer
from saq.modules.file_analysis.java import JavaClassDecompilerAnalysis, JavaClassDecompilerAnalysisModule
from saq.modules.file_analysis.js import SynchronyFileAnalysis, SynchronyFileAnalyzer
from saq.modules.file_analysis.lnk_parser import LnkParseAnalysis, LnkParseAnalyzer
from saq.modules.file_analysis.mime import ActiveMimeAnalysis, ActiveMimeAnalyzer, HiddenMIMEAnalysis, HiddenMIMEAnalyzer
from saq.modules.file_analysis.mse import MicrosoftScriptEncodingAnalysis, MicrosoftScriptEncodingAnalyzer
from saq.modules.file_analysis.msoffice import OfficeXMLRelationshipExternalURLAnalysis, OfficeXMLRelationshipExternalURLAnalyzer, OfficeFileArchiveAction, OfficeFileArchiver
from saq.modules.file_analysis.ocr import OCRAnalysis, OCRAnalyzer
from saq.modules.file_analysis.officeparser3 import OfficeParserAnalysis3, OfficeParserAnalyzer3
from saq.modules.file_analysis.ole import ExtractedOLEAnalysis, ExtractedOLEAnalyzer
from saq.modules.file_analysis.ole_archiver import OLEArchiver_v1_0, OLEArchiverAnalysis_v1_0
from saq.modules.file_analysis.olevba import OLEVBA_Analysis_v1_2, OLEVBA_Analyzer_v1_2
from saq.modules.file_analysis.one_note import OneNoteFileAnalysis, OneNoteFileAnalyzer
from saq.modules.file_analysis.pdf import PDFAnalysis, PDFAnalyzer, PDFTextAnalysis, PDFTextAnalyzer
from saq.modules.file_analysis.qrcode import QRCodeAnalysis, QRCodeAnalyzer
from saq.modules.file_analysis.rtf import RTFOLEObjectAnalysis, RTFOLEObjectAnalyzer, ExtractedRTFAnalysis, ExtractedRTFAnalyzer, NoWhiteSpaceAnalysis, NoWhiteSpaceAnalyzer
from saq.modules.file_analysis.ssdeep import SsdeepAnalysis, SsdeepAnalyzer
from saq.modules.file_analysis.upx import UPXAnalysis, UPXAnalyzer
from saq.modules.file_analysis.url_extraction import URLExtractionAnalysis, URLExtractionAnalyzer
from saq.modules.file_analysis.vbs import VBScriptAnalysis, VBScriptAnalyzer, PCodeAnalysis, PCodeAnalyzer
from saq.modules.file_analysis.xlm import XLMMacroDeobfuscatorAnalysis, XLMMacroDeobfuscatorAnalyzer
from saq.modules.file_analysis.xml import XMLBinaryDataAnalysis, XMLBinaryDataAnalyzer, XMLPlainTextAnalysis, XMLPlainTextAnalyzer
from saq.modules.file_analysis.yara import YaraScanner_v3_4, YaraScanResults_v3_4

from saq.modules.file_analysis.is_file_type import is_office_ext, is_office_file, is_macro_ext, is_pe_file, is_ole_file, is_rtf_file, is_pdf_file, is_zip_file, is_javascript_file, is_lnk_file, is_jar_file, is_empty_macro, is_x509, is_autoit, is_dotnet, is_msi_file, is_image, is_onenote_file, is_chm_file

import warnings

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
warnings.filterwarnings("ignore", category=RuntimeWarning, module='bs4')