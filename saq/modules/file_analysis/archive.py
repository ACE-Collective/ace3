import logging
import os
import re
from subprocess import PIPE, Popen, TimeoutExpired
from typing import override
import zipfile
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_SANDBOX, F_FILE, R_EXTRACTED_FROM
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_msi_file, is_office_file, is_ole_file
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary

def order_archive_file_list(file_list: list[str]) -> list[str]:
    """Order the list of file paths by priority of extraction."""
    # handle edge cases first
    if not file_list:
        return []

    # Define extension groups by priority
    attack_exts = [
        ".lnk", ".one", ".jnlp", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".msi", ".hta", ".chm", ".cpl", ".scr"
    ]
    executable_exts = [
        ".exe", ".dll", ".com", ".bat", ".cmd", ".jar", ".ps1", ".msi", ".sys", ".drv", ".class"
    ]
    script_exts = [
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".sh", ".py", ".rb", ".pl", ".php", ".asp", ".aspx"
    ]
    office_pdf_exts = [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp", ".pdf", ".mht", ".mhtml", ".xml"
    ]

    def get_priority(file_path):
        lower = file_path.lower()
        for ext in attack_exts:
            if lower.endswith(ext):
                return 0
        for ext in executable_exts:
            if lower.endswith(ext):
                return 1
        for ext in script_exts:
            if lower.endswith(ext):
                return 2
        for ext in office_pdf_exts:
            if lower.endswith(ext):
                return 3
        return 4

    # sort file_list by priority, preserving original order within each group
    return sorted(file_list, key=get_priority)

KEY_FILE_COUNT = 'file_count'
KEY_EXTRACTED_FILES = 'extracted_files'


class ArchiveAnalysis(Analysis):
    """Is this an archive file?  What files are in this archive?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_FILE_COUNT: None,
            KEY_EXTRACTED_FILES: [],
        }

    @override
    @property
    def display_name(self):
        return "Archive Analysis"

    @property
    def file_count(self) -> int:
        return self.details[KEY_FILE_COUNT]

    @file_count.setter
    def file_count(self, value: int):
        self.details[KEY_FILE_COUNT] = value

    @property
    def extracted_files(self) -> list[str]:
        return self.details[KEY_EXTRACTED_FILES]

    @extracted_files.setter
    def extracted_files(self, value: list[str]):
        self.details[KEY_EXTRACTED_FILES] = value

    def generate_summary(self):
        if not self.file_count:
            return None

        result = f"{self.display_name}: extracted {len(self.extracted_files)} of {self.file_count} files"
        if self.extracted_files:
            result += f": ({format_item_list_for_summary(self.extracted_files)})"

        return result

# 2018-02-19 12:15:48          319534300    299585795  155 files, 47 folders
# 2022-04-27 08:55:00                          180304  3 files
#                                  27033        14595  14 files, 2 folders
Z7_SUMMARY_REGEX = re.compile(rb'^\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.+\D(\d+)\sfiles')
# looser regex if the previous one fails
Z7_SUMMARY_REGEX_ALT = re.compile(rb'\s(\d+)\sfiles')

COMPRESSION_RATIO_MIN_ALERT = 16
COMPRESSION_MIN_SIZE = 2**16

# listed: 1 files, totaling 711.168 bytes (compressed 326.520)
UNACE_SUMMARY_REGEX = re.compile(rb'^listed: (\d+) files,.*')

class ArchiveAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('max_file_count')
        self.verify_config_exists('max_jar_file_count')
        self.verify_config_exists('timeout')
        self.verify_program_exists('7z')
        self.verify_program_exists('unrar')
        self.verify_program_exists('unace')
        self.verify_program_exists('unzip')
        self.verify_program_exists('java')

    @property
    def max_file_count(self):
        return self.config.getint('max_file_count')

    @property
    def max_jar_file_count(self):
        return self.config.getint('max_jar_file_count')

    @property
    def java_class_decompile_limit(self):
        """Returns the maximum number of java class files to decompile."""
        return self.config.getint('java_class_decompile_limit', fallback=100)

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def excluded_mime_types(self):
        if 'excluded_mime_types' in self.config:
            return map(lambda x: x.strip(), self.config['excluded_mime_types'].split(','))
        return []

    @property
    def generated_analysis_type(self):
        return ArchiveAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
        

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        # 10/19/2021
        if 'email.rfc822' in _file.file_path:
            return AnalysisExecutionResult.COMPLETED

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None or file_type_analysis.details is None:
            return AnalysisExecutionResult.COMPLETED

        # there are some we exclude
        for excluded_mime_type in self.excluded_mime_types:
            if file_type_analysis.mime_type.lower().startswith(excluded_mime_type.lower()):
                logging.debug("skipping excluded mime type {} on archive file {}".format(excluded_mime_type, _file))
                return AnalysisExecutionResult.COMPLETED

            # we also do not extract OLE compound documents (we have other modules that do a better job)
            if is_ole_file(local_file_path) and not is_msi_file(local_file_path):
                logging.debug("skipping archive extraction of OLE file {}".format(_file))
                return AnalysisExecutionResult.COMPLETED

        # special logic for cab files
        is_cab_file = 'ms-cab' in file_type_analysis.mime_type.lower()
        is_cab_file |= 'cabinet archive' in file_type_analysis.file_type.lower()

        # special logic for rar files
        is_rar_file = 'RAR archive data' in file_type_analysis.file_type
        is_rar_file |= file_type_analysis.mime_type == 'application/x-rar'

        # and special logic for some types of zip files
        is_zip_file = 'Microsoft Excel 2007+' in file_type_analysis.file_type
        is_zip_file |= file_type_analysis.mime_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        # special logic for jar files
        is_jar_file = file_type_analysis.mime_type == 'application/java-archive' or file_type_analysis.is_jar_file

        # special logic for microsoft office files
        is_office_document = is_office_file(_file)
        #is_office_document = is_office_ext(os.path.basename(local_file_path))
        #is_office_document |= 'microsoft powerpoint' in file_type_analysis.file_type.lower()
        #is_office_document |= 'microsoft excel' in file_type_analysis.file_type.lower()
        #is_office_document |= 'microsoft word' in file_type_analysis.file_type.lower()
        #is_office_document |= 'microsoft ooxml' in file_type_analysis.file_type.lower()

        # notice that we pass in a password of "infected" here even if we're not prompted for one
        # infosec commonly use that as the password, and if it's not right then it just fails because
        # we don't know it anyways

        # special logic for ACE files
        is_ace_file = 'ACE archive data' in file_type_analysis.file_type
        is_ace_file |= _file.file_path.lower().endswith('.ace')

        count = 0

        if is_rar_file:
            logging.debug("using unrar to extract files from {}".format(local_file_path))
            p = Popen(['unrar', 'la', local_file_path], stdout=PIPE, stderr=PIPE)
            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired:
                logging.error("timed out tryign to extract files from {} with unrar".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

            if b'is not RAR archive' in stdout:
                return AnalysisExecutionResult.COMPLETED

            start_flag = False
            for line in stdout.split(b'\n'):
                if not start_flag:
                    if line.startswith(b'-----------'):
                        start_flag = True
                        continue

                    continue

                if line.startswith(b'-----------'):
                    break

                count += 1

        elif is_jar_file:
            try:
                with zipfile.ZipFile(local_file_path, "r") as zfile:
                    count = len(zfile.namelist())
            except Exception:
                logging.error("unable to read jar file")

        elif is_zip_file:
            logging.debug("using unzip to extract files from {}".format(local_file_path))
            p = Popen(['unzip', '-l', '-P', 'infected', local_file_path], stdout=PIPE, stderr=PIPE)
            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired:
                logging.error("timed out trying to list files from {} with unzip".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

            if b'End-of-central-directory signature not found.' in stdout:
                return AnalysisExecutionResult.COMPLETED

            start_flag = False
            for line in stdout.split(b'\n'):
                if not start_flag:
                    if line.startswith(b'---------'):
                        start_flag = True
                        continue

                    continue

                if line.startswith(b'---------'):
                    break

                if b'META-INF/MANIFEST.MF' in line:
                    is_jar_file = True

                if b'ppt/slides/_rels' in line:
                    is_office_document = True

                if b'word/document.xml' in line:
                    is_office_document = True

                if b'xl/embeddings/oleObject' in line:
                    is_office_document = True

                if b'xl/worksheets/sheet' in line:
                    is_office_document = True

                count += 1

            # 01/17/2017 - docx sample 42f587b277f02445b526e3887893c2c5 file command does not indicate docx
            # we can use presence of ole file as indicator
            # NOTE the uses of regex wildcard match for file separator, sometimes windows sometimes unix
            ole_object_regex = re.compile(b'word.embeddings.oleObject1\\.bin', re.M)
            is_office_document |= (ole_object_regex.search(stdout) is not None)
                
        elif is_ace_file:
            p = Popen(['unace', 'l', local_file_path], stdout=PIPE, stderr=PIPE)

            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired:
                logging.error("timed out trying to extract files from {} with 7z".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

            for line in stdout.split(b'\n'):
                m = UNACE_SUMMARY_REGEX.match(line)
                if m:
                    count = int(m.group(1))
                    break

        else:
            logging.debug("using 7z to extract files from {}".format(local_file_path))
            p = Popen(['7z', '-y', '-pinfected', 'l', local_file_path], stdout=PIPE, stderr=PIPE)
            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired:
                logging.warning("timed out trying to extract files from {} with 7z".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

            if b'Error: Can not open file as archive' in stdout:
                return AnalysisExecutionResult.COMPLETED

            alt_count = 0
            for line in stdout.split(b'\n'):
                m = Z7_SUMMARY_REGEX.match(line)
                if m:
                    count = int(m.group(1))

                # this uses a looser regex to try to match 7z output if the first one fails
                # hard to tell what its going to output
                alt_m = Z7_SUMMARY_REGEX_ALT.search(line)
                if alt_m:
                    alt_count = int(alt_m.group(1))

                #if line.startswith(b'Testing'):
                    #count += 1

                if b'ppt/slides/_rels' in line:
                    is_office_document = True

                if b'word/document.xml' in line:
                    is_office_document = True

                if b'xl/embeddings/oleObject' in line:
                    is_office_document = True

                if b'xl/worksheets/sheet' in line:
                    is_office_document = True

            # if we could not find the count then see if the looser regex matched
            if not count:
                count = alt_count

            # 01/17/2017 - docx sample 42f587b277f02445b526e3887893c2c5 file command does not indicate docx
            # we can use presence of ole file as indicator
            # NOTE the uses of regex wildcard match for file separator, sometimes windows sometimes unix
            ole_object_regex = re.compile(b'word.embeddings.oleObject1\\.bin', re.M)
            is_office_document |= (ole_object_regex.search(stdout) is not None)

        if count == 0:
            logging.debug(f"no files found in {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        analysis.file_count = count

        # this deteremine if we're limiting the number of files extracted
        limit_file_extraction = False
        limit_file_count = self.max_file_count

        # skip archives with lots of files
        if is_jar_file:
            if self.max_jar_file_count != 0 and count > self.max_jar_file_count:
                limit_file_extraction = True
                limit_file_count = self.max_jar_file_count
                logging.info("archive analysis of {} will limit file extraction: file count {} exceeds configured maximum {} in max_jar_file_count setting".format(
                    local_file_path, count, self.max_jar_file_count))
        elif not is_office_document:
            if self.max_file_count != 0 and count > self.max_file_count:
                limit_file_extraction = True
                limit_file_count = self.max_file_count
                logging.info("archive analysis of {} will limit file extraction: file count {} exceeds configured maximum {} in max_file_count setting".format(
                    local_file_path, count, self.max_file_count))

        # we need a place to store these things
        extracted_path = '{}.extracted'.format(local_file_path).replace('*', '_') # XXX need a normalize function
        if not os.path.isdir(extracted_path):
            try:
                os.makedirs(extracted_path)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(extracted_path, e))
                return AnalysisExecutionResult.COMPLETED

        logging.debug("extracting {} files from archive {} into {}".format(count, local_file_path, extracted_path))

        params = []
        kwargs = { 'stdout': PIPE, 'stderr': PIPE }

        if is_rar_file:
            params = ['unrar', 'e', '-y', '-o+', local_file_path, extracted_path]
        elif is_jar_file:
            # Disabled on 02/17/2021 since the procyon_decompiler.jar version we have is old and busted. They moved
            # from Bitbucket to GitHub at some point and no longer have precompiled releases available.
            # Until we have an effective way to decompile, we will just use 7z to extract.
            # decompiler_path = os.path.join(get_base_dir(), "bin", "procyon_decompiler.jar")
            # Updated 05/17/2021 JA - We have a new Java decompiler and we are reenabling this for improved detection capability
            # Note: We decompile to a single file to avoid writing large quantities of files when decompiling
            # params = ['java', '-jar', decompiler_path, '-jar', local_file_path, '-o', extracted_path]
            # params = ['7z', '-y', '-o{}'.format(extracted_path), 'x', local_file_path]
            # params = ['java', '-jar', '/usr/local/bin/cfr.jar', local_file_path]
            # Updated 09/16/2021 JA - New decompiler doesn't like zip JARs, so we now extract class files and run decompiler on each individually
            params = ['bin/unjar', local_file_path, '-d', extracted_path]
        elif is_zip_file:
            # avoid the numerious XML documents in excel files
            params = ['unzip', local_file_path, '-x', 'xl/activeX/*', 
                                                '-x', 'xl/activeX/_rels/*', 
                                                '-x', 'xl/ctrlProps/*.xml',
                      '-d', extracted_path]
        elif is_msi_file(local_file_path):
            params = ['7z', '-y', '-o{}'.format(extracted_path), 'x', local_file_path] 
        elif is_ace_file:
            # for some reason, unace doesn't let you use a full path
            params = ['unace', 'x', '-y', '-o', os.path.relpath(local_file_path, start=extracted_path)]
            kwargs['cwd'] = extracted_path
        else:
            params = ['7z', '-y', '-pinfected', '-o{}'.format(extracted_path), 'x', local_file_path]

        if params:
            p = Popen(params, **kwargs)

            try:
                (stdout, stderr) = p.communicate(timeout=self.timeout)
            except TimeoutExpired:
                logging.warning(f"archive extraction timeout on {local_file_path}: params {params} kwargs {kwargs}")
                p.kill()
                (stdout, stderr) = p.communicate()

        # files we've removed because we've hit the limit
        removed_files = []

        # generate the full list of extracted files
        extracted_files = []
        for root, dirs, files in os.walk(extracted_path):
            for file_name in files:
                extracted_file = os.path.join(root, file_name)
                extracted_files.append(extracted_file)

        # filter the list of extracted files
        extracted_files = order_archive_file_list(extracted_files)

        # rather than parse the output we just go find all the files we've created in that directory
        for extracted_file in extracted_files:
            logging.debug("extracted_file = {}".format(extracted_file))

            # if we've hit the limit, remove the file instead of processing it
            if limit_file_extraction and len(analysis.extracted_files) >= limit_file_count:
                removed_files.append(extracted_file)
                os.remove(extracted_file)
                continue

            file_observable = analysis.add_file_observable(extracted_file, volatile=True)

            if not file_observable:
                continue

            analysis.extracted_files.append(os.path.relpath(extracted_file, start=extracted_path))

            # add a relationship back to the original file
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)

            # if we extracted an office document then we want everything to point back to that document
            # so that we sandbox the right thing
            if is_office_document:
                file_observable.redirection = _file

            # https://github.com/IntegralDefense/ACE/issues/12 - also fixed for xps
            if file_observable.ext in [ 'xps', 'rels', 'xml' ]:
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)

            # a single file inside of a zip file is always suspect
            if analysis.file_count == 1:
                logging.debug("archive file {} has one file inside (always suspect)".format(_file))
                analysis.add_tag('single_file_zip')

                # and then we want to sandbox it
                file_observable.add_directive(DIRECTIVE_SANDBOX)

                # but an executable or script file (js, vbs, etc...) is an alert
                for extracted_file in analysis.observables:
                    for ext in [ '.exe', '.scr', '.cpl', '.jar', '.class' ]:
                        if extracted_file.file_name.lower().endswith(ext):
                            analysis.add_tag('exe_in_zip')
                            file_observable.add_detection_point("An archive contained a single file that was an executable")
                    for ext in [ '.vbe', '.vbs', '.jse', '.js', '.bat', '.wsh', '.ps1' ]:
                        if extracted_file.file_name.lower().endswith(ext):
                            analysis.add_tag('script_in_zip')
                            file_observable.add_detection_point("An archive contained a single file that was a script")
                    for ext in [ '.lnk' ]:
                        if extracted_file.file_name.lower().endswith(ext):
                            analysis.add_tag('lnk_in_zip')
                            file_observable.add_detection_point("An archive contained a single file that was a shortcut")
                    for ext in ['.jnlp']:
                        if extracted_file.file_name.lower().endswith(ext):
                            analysis.add_tag('jnlp_in_zip')
                            file_observable.add_detection_point("An archive contained a single file that was a Java Web Start application")
                    for ext in ['.one']:
                        if extracted_file.file_name.lower().endswith(ext):
                            analysis.add_tag('one_in_zip')
                            file_observable.add_detection_point("An archive contained a single file that was a OneNote document")

        if len(removed_files) > 0:
            logging.info("removed {} files because we've hit the limit".format(len(removed_files)))

        #
        # adjust file permission to be readable by anyone
        #

        try:
            for root, dirs, files in os.walk(extracted_path):
                for _dir in dirs:
                    full_path = os.path.join(root, _dir)
                    try:
                        os.chmod(full_path, 0o775)
                    except Exception as e:
                        logging.error("unable to adjust permissions on dir {}: {}".format(full_path, e))

                for _file in files:
                    full_path = os.path.join(root, _file)
                    try:
                        os.chmod(full_path, 0o664)
                    except Exception as e:
                        logging.error("unable to adjust permissions on file {}: {}".format(full_path, e))

        except Exception as e:
            logging.error("some error was reported when trying to recursively chmod {}: {}".format(extracted_path, e))
            report_exception()

        return AnalysisExecutionResult.COMPLETED