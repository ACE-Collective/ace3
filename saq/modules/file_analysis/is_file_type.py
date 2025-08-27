# known file extensions for microsoft office files
# see https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions
# 2/19/2018 - removed MSO file ext (relying on OLE format instead)
# 6/29/2018 - https://docs.google.com/spreadsheets/d/1LXneVF8VxmOgkt2W_NG5Kl3lzWW45prE7gxtuPcO-4o/edit#gid=1950593040
import logging
import os
import re
from subprocess import PIPE, Popen
import uuid
import zipfile

from saq.observables.file import FileObservable
from saq.x509 import is_der_bytes, is_pem_bytes, load_cert

from PIL import Image


KNOWN_OFFICE_EXTENSIONS = [ '.{}'.format(ext) for ext in [ 
    # Microsoft Word
    'doc',
    'docb',
    'dochtml',
    'docm',
    'docx',
    'docxml',
    'dot',
    'dothtml',
    'dotm',
    'dotx',
    'odt',
    'rtf',
    'wbk',
    'wiz',
    # Microsoft Excel
    'csv',
    'dqy',
    'iqy',
    'odc',
    'ods',
    'slk',
    'xla',
    'xlam',
    'xlk',
    'xll',
    'xlm',
    'xls',
    'xlsb',
    'xlshtml',
    'xlsm',
    'xlsx',
    'xlt',
    'xlthtml',
    'xltm',
    'xltx',
    'xlw',
    # Microsoft Powerpoint
    'odp',
    'pot',
    'pothtml',
    'potm',
    'potx',
    'ppa',
    'ppam',
    'pps',
    'ppsm',
    'ppsx',
    'ppt',
    'ppthtml',
    'pptm',
    'pptx',
    'pptxml',
    'pwz',
    'sldm',
    'sldx',
    'thmx',
    # OpenOffice
    'odt',
]]

    #'mso',
    #'ppt', 'pot', 'pps', 'pptx', 'pptm', 'potx', 'potm', 'ppam', 'ppsx', 'ppsm', 'sldx', 'sldm', 'rtf', 'pub' ]]

# same thing for macros extracted from office documents
KNOWN_MACRO_EXTENSIONS = [ '.bas', '.frm', '.cls' ]

def is_office_ext(path):
    """Returns True if the given path has a file extension that would be opened by microsoft office."""
    root, ext = os.path.splitext(path)
    return ext in KNOWN_OFFICE_EXTENSIONS

def is_office_file(_file: FileObservable):
    """Returns True if we think this is probably an Office file of some kind."""
    from saq.modules.file_analysis.file_type import FileTypeAnalysis
    assert isinstance(_file, FileObservable)

    result = is_office_ext(_file.file_name)
    file_type_analysis = _file.get_and_load_analysis(FileTypeAnalysis)
    if not file_type_analysis:
        return result

    result |= 'microsoft powerpoint' in file_type_analysis.file_type.lower()
    result |= 'microsoft excel' in file_type_analysis.file_type.lower()
    result |= 'microsoft word' in file_type_analysis.file_type.lower()
    result |= 'microsoft ooxml' in file_type_analysis.file_type.lower()
    result |= 'opendocument' in file_type_analysis.file_type.lower()
    return result

def is_macro_ext(path):
    root, ext = os.path.splitext(path)
    return ext in KNOWN_MACRO_EXTENSIONS

def is_pe_file(path):
    """Returns True if the file at path is a portable executable file."""
    try:
        with open(path, 'rb') as fp:
            return fp.read(2) == b'MZ'
    except Exception as e:
        logging.debug(f"is_pe_file failed for {path}: {e}")
        return False

def is_ole_file(path):
    with open(path, 'rb') as fp:
        return fp.read(8) == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

def is_rtf_file(path):
    with open(path, 'rb') as fp:
        data = fp.read(4)
        return data[:3] == b'\\rt' or data == b'{\\rt'

def is_pdf_file(path):
    with open(path, 'rb') as fp:
        return b'%PDF-' in fp.read(1024)

def is_zip_file(path):
    # we used to check for PK as the first two bytes of the file
    # but look here: https://stackoverflow.com/questions/1887041/what-is-a-good-way-to-test-a-file-to-see-if-its-a-zip-file#comment2347749_1887113
    try:
        with zipfile.ZipFile(path, "r") as zfile:
            if zfile.namelist():
                return True
    except Exception:
        pass

    return False

def is_javascript_file(path):
    # we use node --check to see if a given file is a javascript file
    # but the tool requires that the file name end with .js
    # this may not always be the case for malicious js depending on the stage of the attack
    # so we hard link the file to one with a .js extension just for this test
    # if it doesn't have the extension already
    target = path
    if not path.lower().endswith(".js"):
        try:
            target = f"{path}-{uuid.uuid4()}.js"
            os.link(path, target)
        except Exception as e:
            logging.warning(f"unable to hard link {path} to {target}: {e}")
            return False

    p = Popen(['node', '--check', target], stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    # if we hard linked then we remove the link when we're done
    if target != path:
        try:
            os.unlink(target)
        except Exception as e:
            logging.warning(f"unable to unlink {target}: {e}")

    return p.returncode == 0

def is_lnk_file(path):
    with open(path, 'rb') as fp:
        return fp.read(8) == b'\x4C\x00\x00\x00\x01\x14\x02\x00'

def is_jar_file(path):
    try:
        with zipfile.ZipFile(path, "r") as zfile:
            if 'META-INF/MANIFEST.MF' in zfile.namelist():
                return True
    except Exception as e:
        logging.debug(f"is_jar_file failed for {path}: {e}")
        return False

    return False

def is_java_class_file(path):
    """Returns True if the given file path is a Java class file."""
    try:
        with open(path, "rb") as fp:
            if fp.read(4) == b'\xCA\xFE\xBA\xBE':
                return True
    except Exception as e:
        logging.debug(f"is_java_class_file failed for {path}: {e}")
        return False

    return False

def is_empty_macro(path):
    """Returns True if the given macro file only has empty lines and/or Attribute settings."""
    with open(path, 'rb') as fp:
        for line in fp:
            # if the line is empty keep moving
            if line.strip() == b'':
                continue

            # or if it starts with one of these lines
            if line.startswith(b'Attribute VB_'):
                continue

            # otherwise it's something else, so return False
            return False

    return True


def is_x509(path):
    """Return True if file can be parsed as a pem or der encoded x509 file.

    We don't want to load the whole file and cause performance issues until we're
    sure it's a PEM or DER encoded file. Once we know it is either a PEM or DER,
    then we can try to load/parse as a certificate.

    We read in 8192 bytes, which is OVERKILL for checking if it's a PEM file; However,
    the pyans1 der decoder reads the byte/bit in the ASN1 encoding that tells it how
    long the content will be. So, if you do not read in the entire thing, it will may
    throw a `SubstrateUnderrunError`.

    We read in 8192 because if the file is any larger than that, the DER file is probably
    not an x509 certificate. DER should contain only one certificate, so we can take some
    comfort that it is not a chain of DER files which cause it to go over 8192 bytes.
    """

    with open(path, 'rb') as f:
        data_bytes = f.read(8192)

    # Check to see if file is PEM or DER formatted/encoded based on first so many bytes.
    try:
        if not is_pem_bytes(data_bytes) and not is_der_bytes(data_bytes):
            return False
    except Exception as e:
        logging.debug(f"is_x509 failed for {path}: {e}")
        return False

    # We already determined the file contained evidence it is PEM/DER formatted or encoded,
    # so now we can attempt to load the whole file.
    with open(path, 'rb') as f:
        full_bytes = f.read()

    if load_cert(full_bytes) is not None:
        return True
    return False


def is_autoit(path) -> bool:
    """Returns True/False if the given file path is an AutoIt compiled executable"""

    if not path:
        return False

    if not is_pe_file(path) and not path.lower().endswith(".au3"):
        return False

    p = Popen(['unautoit', 'list', path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    if not stderr and b'autoit script' in stdout.lower():
        return True

    return False

def is_dotnet(path) -> bool:
    """Returns True/False if the given file path is a .NET executable"""

    if not is_pe_file(path):
        return False

    p = Popen(['file', '-b', '-L', path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    if not stderr and b'.net assembly' in stdout.lower():
        return True

    return False

def is_msi_file(path) -> bool:
    """ Returns True/False if the given file path is an MSI file"""

    p = Popen(['file', '-b', '-L', path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    if not stderr and b'msi installer' in stdout.lower():
        return True

    return False

def is_image(path) -> bool:
    """Returns True/False is the given file path is an image"""
    
    # see https://pillow.readthedocs.io/en/stable/handbook/tutorial.html#identify-image-files
    try:
        with Image.open(path) as im:
            return True
    except OSError:
        return False
    except Exception:
        return False

def is_onenote_file(path) -> bool:
    """Returns True/False if the given file looks like it might be a OneNote file. Not exact."""
    if not path:
        return False

    if path.lower().endswith(".one"):
        return True # sure

    # https://github.com/target/strelka/pull/298/files#diff-bcec487503194dd9409711578598d29a257e2c4c33b023aed7f55709c7a48eaaR318
    with open(path, "rb") as fp:
        header = fp.read(16)

    return header == b'\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3'

def is_chm_file(path) -> bool:
    """Returns True/False if the given file looks like it might be a CHM file. Not exact."""
    if not path:
        return False

    if path.lower().endswith(".chm"):
        return True

    p = Popen(['file', '-b', '-L', path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    if not stderr and b'ms windows htmlhelp data' in stdout.lower():
        return True

    # https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help#File_format
    # The file starts with bytes "ITSF" (in ASCII), for "Info-Tech Storage Format", which is the internal name given by Microsoft to the generic storage file format used in with CHM files.
    with open(path, "rb") as fp:
        header = fp.read(4)

    return header == b'ITSF'

RE_EMAIL_HEADER = re.compile(r"^([A-Za-z0-9\-]+):\s?.*$")
RE_EMAIL_HEADER_INDENTED = re.compile(r"^\s+\S+")
COMMON_EMAIL_HEADERS = [
    "from",
    "subject",
    "message-id",
]
def is_email_file(path) -> bool:
    """Returns True if the given file looks like it might be an email file."""
    try:
        common_headers_found = set()
        with open(path, "r", encoding="utf-8") as fp:
            for line in fp:
                # if the line contains any non 7-bit ASCII characters, we assume it's not an email file
                if not all(0 <= ord(c) <= 127 for c in line):
                    return False

                # ignore lines that have content but start with whitespace
                if RE_EMAIL_HEADER_INDENTED.match(line):
                    continue

                # if we got this far and hit an empty line we assume it's an email file
                # as it would be end of the headers
                if line.strip() == "":
                    return False

                # otherwise we're checking for email headers
                m = RE_EMAIL_HEADER.match(line)
                if not m:
                    return False
                
                # grab the header we found
                header = m.group(1)
                if header.lower() in COMMON_EMAIL_HEADERS:
                    common_headers_found.add(header.lower())

                # if we've found all the common headers, we can return True
                if len(common_headers_found) == len(COMMON_EMAIL_HEADERS):
                    return True

            # otherwise we return False
            return False

    except UnicodeDecodeError:
        logging.debug("unable to read file %s due to unicode decode error", path)
        return False
    except Exception as e:
        logging.debug("unable to read file %s: %s", path, e)
        return False
