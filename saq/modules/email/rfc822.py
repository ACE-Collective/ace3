from datetime import datetime
import email
from functools import cached_property
import hashlib
import logging
import os
import re
import shutil
from subprocess import PIPE, Popen
from typing import Type, override
import uuid

import dateutil
import pytz
from saq.analysis.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.constants import DIRECTIVE_EXTRACT_URLS, DIRECTIVE_ORIGINAL_EMAIL, DIRECTIVE_PREVIEW, DIRECTIVE_REMEDIATE, DIRECTIVE_RENAME_ANALYSIS, DIRECTIVE_RENDER, F_EMAIL_ADDRESS, F_EMAIL_CONVERSATION, F_EMAIL_DELIVERY, F_EMAIL_SUBJECT, F_EMAIL_X_MAILER, F_FILE, F_FQDN, F_IPV4, F_MESSAGE_ID, F_USER_AGENT, AnalysisExecutionResult, create_email_conversation, create_email_delivery
from saq.email import decode_rfc2822, is_local_email_domain, normalize_email_address, normalize_message_id
from saq.environment import get_base_dir, get_data_dir, get_local_timezone
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.email.constants import KEY_CC, KEY_DECODED_SUBJECT, KEY_EMAIL, KEY_ENV_MAIL_FROM, KEY_ENV_RCPT_TO, KEY_FROM, KEY_FROM_ADDRESS, KEY_HEADERS, KEY_LOG_ENTRY, KEY_MESSAGE_ID, KEY_ORIGINATING_IP, KEY_PARSING_ERROR, KEY_REPLY_TO, KEY_REPLY_TO_ADDRESS, KEY_RETURN_PATH, KEY_SUBJECT, KEY_TO, KEY_TO_ADDRESSES, KEY_USER_AGENT, KEY_X_AUTH_ID, KEY_X_MAILER, KEY_X_ORIGINAL_SENDER, KEY_X_SENDER, KEY_X_SENDER_ID, KEY_X_SENDER_IP
from saq.observables.file import FileObservable
from saq.whitelist import WHITELIST_TYPE_SMTP_FROM, WHITELIST_TYPE_SMTP_TO, BrotexWhitelist

TAG_OUTBOUND_EMAIL = 'outbound_email'
TAG_OUTBOUND_EXCEPTION_EMAIL = 'outbound_email_exception'

# regex to match Received date
RE_EMAIL_RECEIVED_DATE = re.compile(r';\s?(.+)$')

def get_received_time(received_header):
    m = RE_EMAIL_RECEIVED_DATE.search(received_header, re.M)
    if m:
        try:
            return dateutil.parser.parse(m.group(1)).astimezone(pytz.UTC)
        except Exception as e:
            logging.debug(f"unable to parse {m.group(1)} as date time: {e}")

    return None

def get_address_list(email_obj, header_name):
    header = email_obj.get_all(header_name, [])
    addresses = email.utils.getaddresses(header)
    return [x[1] for x in addresses]


class EmailAnalysis(Analysis):
    """What are all the contents of this email?"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_PARSING_ERROR: None,
            KEY_EMAIL: None
        }

    @override
    @property
    def display_name(self) -> str:
        return "Email Analysis"
        
    @property
    def parsing_error(self):
        return self.details[KEY_PARSING_ERROR]

    @parsing_error.setter
    def parsing_error(self, value):
        self.details[KEY_PARSING_ERROR] = value

    @property
    def email(self):
        if not self.details:
            return {}

        if KEY_EMAIL not in self.details:
            return {}

        return self.details[KEY_EMAIL]

    @email.setter
    def email(self, value):
        self.details[KEY_EMAIL] = value

    @property
    def env_mail_from(self):
        if self.email and KEY_ENV_MAIL_FROM in self.email:
            return self.email[KEY_ENV_MAIL_FROM]

        return None

    @env_mail_from.setter
    def env_mail_from(self, value):
        self.email[KEY_ENV_MAIL_FROM] = value

    @property
    def env_rcpt_to(self):
        if self.email and KEY_ENV_RCPT_TO in self.email:
            return self.email[KEY_ENV_RCPT_TO]

        return None

    @env_rcpt_to.setter
    def env_rcpt_to(self, value):
        self.email[KEY_ENV_RCPT_TO] = value

    @property
    def mail_from(self):
        if self.email and KEY_FROM in self.email:
            return self.email[KEY_FROM]

        return None

    @property
    def mail_from_address(self):
        if self.email and KEY_FROM_ADDRESS in self.email:
            return self.email[KEY_FROM_ADDRESS]

        return None

    @property
    def mail_to(self):
        if self.email and KEY_TO in self.email:
            return self.email[KEY_TO]

        return []

    @property
    def mail_to_addresses(self):
        if self.email and KEY_TO_ADDRESSES in self.email:
            return self.email[KEY_TO_ADDRESSES]

        return []

    @property
    def cc(self):
        if self.email and KEY_CC in self.email:
            return self.email[KEY_CC]

        return []

    @property
    def reply_to(self):
        if self.email and KEY_REPLY_TO in self.email:
            return self.email[KEY_REPLY_TO]

        return None

    @property
    def reply_to_address(self):
        if self.email and KEY_REPLY_TO_ADDRESS in self.email:
            return self.email[KEY_REPLY_TO_ADDRESS]

        return None

    @property
    def subject(self):
        if self.email and KEY_SUBJECT in self.email:
            return self.email[KEY_SUBJECT]

        return None

    @property
    def decoded_subject(self):
        if self.email and KEY_DECODED_SUBJECT in self.email:
            return self.email[KEY_DECODED_SUBJECT]

        return None

    @property
    def message_id(self):
        if self.email and KEY_MESSAGE_ID in self.email:
            if self.email[KEY_MESSAGE_ID]:
                return self.email[KEY_MESSAGE_ID].strip()
            else:
                return self.email[KEY_MESSAGE_ID] 

        return None

    @property
    def originating_ip(self):
        if self.email and KEY_ORIGINATING_IP in self.email:
            return self.email[KEY_ORIGINATING_IP]

        return None

    @property
    def reply_to(self):
        if self.email and KEY_REPLY_TO in self.email:
            return self.email[KEY_REPLY_TO]

        return None

    @property
    def return_path(self):
        if self.email and KEY_RETURN_PATH in self.email:
            return self.email[KEY_RETURN_PATH]

        return None

    @property
    def user_agent(self):
        if self.email and KEY_USER_AGENT in self.email:
            return self.email[KEY_USER_AGENT]

        return None

    @property
    def x_mailer(self):
        if self.email and KEY_X_MAILER in self.email:
            return self.email[KEY_X_MAILER]

        return None

    @property
    def x_sender_ip(self):
        if self.email and KEY_X_SENDER_IP in self.email:
            return self.email[KEY_X_SENDER_IP]

        return None

    @property
    def x_sender(self):
        if self.email and KEY_X_SENDER in self.email:
            return self.email[KEY_X_SENDER]

        return None

    @property
    def x_sender_id(self):
        if self.email and KEY_X_SENDER_ID in self.email:
            return self.email[KEY_X_SENDER_ID]

        return None

    @property
    def x_auth_id(self):
        if self.email and KEY_X_AUTH_ID in self.email:
            return self.email[KEY_X_AUTH_ID]

        return None

    @property
    def x_original_sender(self):
        if self.email and KEY_X_ORIGINAL_SENDER in self.email:
            return self.email[KEY_X_ORIGINAL_SENDER]

        return None

    @property
    def received(self):
        """Returns the list of Received: headers of the email, or None if the headers are not available."""
        if not self.headers:
            return None

        result = []

        for key, value in self.headers:
            if key == 'Received':
                result.append(value)

        return result

    @property
    def received_time(self):
        if self.received:
            return get_received_time(self.received[0])

        return None

    @property
    def headers(self):
        if self.email and KEY_HEADERS in self.email:
            return self.email[KEY_HEADERS]

        return None

    @property
    def headers_formatted(self) -> str:
        headers = ''
        if self.headers:
            for header in self.headers:
                headers = f'{headers}{header[0]}: {header[1]}\n'
        return headers

    @property
    def log_entry(self):
        if not self.email:
            return None

        if KEY_LOG_ENTRY in self.email:
            return self.email[KEY_LOG_ENTRY]

        return None

    @property
    def body_html(self) -> str:
        body_observable = next(
            (o for o in self.observables if o.type == F_FILE and o.file_name.endswith('unknown_text_html_000')), None)

        if body_observable:
            path = body_observable.full_path
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return f.read().decode('utf-8', errors='ignore')

        return ''

    @property
    def body_text(self) -> str:
        body_observable = next(
            (o for o in self.observables if o.type == F_FILE and o.file_name.endswith('unknown_text_plain_000')), None)

        if body_observable:
            path = body_observable.full_path
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    return f.read().decode('utf-8', errors='ignore')

        return ''
    
    @property
    def body(self):
        """Returns the file observable that should be considered the body of the email, or None if one cannot be found."""

        if hasattr(self, '_body'):
            return self._body

        # keep track of the first plain text and html files we find
        first_html = None
        first_plain_text = None

        for _file in self.observables:
            if _file.type != F_FILE:
                continue

            if '.unknown_' not in _file.file_name:
                continue

            # if all we have is a single text_plain file then that is the body of the email
            plain_text_files = list(filter(lambda o: o.type == F_FILE and 'unknown_text_plain' in o.file_name, self.observables))
            html_files = list(filter(lambda o: o.type == F_FILE and 'unknown_text_html' in o.file_name, self.observables))

            if len(plain_text_files) == 1 and len(html_files) == 0:
                self._body = plain_text_files[0]
                return self._body

            # otherwise we always skip this one first
            if '.unknown_text_plain_000' in _file.file_name:
                continue

            if first_html is None and 'unknown_text_html' in _file.file_name:
                first_html = _file
                continue

            if first_plain_text is None and 'unknown_text_plain' in _file.file_name:
                first_plain_text = _file
                continue

        # if we found html then we return that as the body
        if first_html:
            self._body = first_html
        else:
            # otherwise we return the plain text
            self._body = first_plain_text # if there isn't one then it returns None anyways

        return self._body

    @property
    def attachments(self):
        """Returns the list of F_FILE observables that were attachments to the email (not considered the body.)"""
        result = []

        for _file in self.observables:
            if _file.type != F_FILE:
                continue

            # skip any file with an auto-generated name (these are typically part of the body)
            # XXX hack
            if "email.rfc822" in _file.file_name:
                continue

            result.append(_file)

        return result

    @property
    def attachment_names(self):
        """Returns the list of the attachment filenames."""
        return [
            attachment.file_path for attachment in self.attachments
            if not attachment.file_path.endswith('unknown_text_plain_000')
            and not attachment.file_path.endswith('unknown_text_html_000')
            and not attachment.file_path.endswith('rfc822.headers')
        ]

    @property
    def jinja_template_path(self):
        return "analysis/email_analysis.html"
        
    def generate_summary(self):
        if self.parsing_error:
            return self.parsing_error

        if self.observable.has_tag('whitelisted'):
            return "Email Analysis: (whitelisted email)"

        if self.email:
            result = "Email Analysis:"
            if KEY_FROM in self.email:
                result = "{} From {}".format(result, self.email[KEY_FROM])
            if KEY_ENV_RCPT_TO in self.email and self.email[KEY_ENV_RCPT_TO]:
                result = "{} To {}".format(result, self.email[KEY_ENV_RCPT_TO][0])
            elif KEY_TO in self.email and self.email[KEY_TO]:
                result = "{} To {}".format(result, self.email[KEY_TO][0])
            if KEY_DECODED_SUBJECT in self.email:
                result = "{} Subject {}".format(result, self.email[KEY_DECODED_SUBJECT])
            elif KEY_SUBJECT in self.email:
                result = "{} Subject {}".format(result, self.email[KEY_SUBJECT])

            return result

        return None

# example
#Received: from BN6PR1601CA0006.namprd16.prod.outlook.com (10.172.104.144) by
 #BN6PR1601MB1156.namprd16.prod.outlook.com (10.172.107.18) with Microsoft SMTP
 #Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384) id
 #15.1.707.6; Thu, 10 Nov 2016 15:47:33 +0000

_PATTERN_RECEIVED_IPADDR = re.compile(r'from\s\S+\s\(([^)]+)\)\s', re.M)
class EmailAnalyzer(AnalysisModule):
    @override
    def get_presenter_class(self) -> Type[AnalysisPresenter]:
        return EmailAnalysisPresenter

    def verify_environment(self):
        self.verify_config_exists('whitelist_path')
        self.verify_path_exists(self.config['whitelist_path'])
        self.verify_config_exists('scan_inbound_only')
        self.verify_config_exists('outbound_exceptions')

    @cached_property
    def whitelist(self) -> BrotexWhitelist:
        result = BrotexWhitelist(os.path.join(get_base_dir(), self.config['whitelist_path']))
        result.check_whitelist()
        return result

    #def load_config(self):
        #self.whitelist = BrotexWhitelist(os.path.join(get_base_dir(), self.config['whitelist_path']))
        #self.auto_reload()

    def auto_reload(self):
        # make sure the whitelist if up-to-date
        self.whitelist.check_whitelist()
        
    @property
    def generated_analysis_type(self):
        return EmailAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def outbound_exception_list(self):
        return self.config['outbound_exceptions'].split(',')

    def analyze_rfc822(self, _file):
        assert isinstance(_file, FileObservable)
        from saq.modules.email.message_id import MessageIDAnalyzerV2

        # if this is a headers file then we skip it
        # this will look like a legit email file
        # XXX take this out an add an exclusion when we add it
        if _file.full_path.endswith('.headers'):
            return False

        # parse the email
        unparsed_email = None
        parsed_email = None

        # sometimes the actual email we want will be an attachment
        # this will point to a MIME part
        target_email = None

        #
        # something changed at some point with office365 journaled emails
        # we used to be able to use the header X-MS-Exchange-Organization-OriginalEnvelopeRecipients
        # to determine who the email was *actually* delivered to
        # this appears to not be the case anymore
        #

        #
        # so in the case of office365 journal emails we will see something like the following:
        #
        # --_f72c3c83-af4f-4c48-af8e-4aaa9b7206c6_
        # Content-Type: text/plain; charset="us-ascii"
        # Content-Transfer-Encoding: 7bit
        #
        # Sender: H.Abdelrahim@rbht.nhs.uk
        # Subject: Completed: Order No.2739382. 
        # Message-Id: <B2810E1E-329D-494C-B84F-1B10F18FD41C@rbht.nhs.uk>
        # Recipient: Timothy.Spence@53.mail.onmicrosoft.com
        #
        # This is the only part that contains who the *actual* recipient was.
        # I'm calling this the "meta block" of journaled email messages.
        # There's an assumption that the information follows the following regex format.
        # If Microsoft ever decides to change that then this will break.
        #
        # this suff points to that part if it exists
        #

        o365_meta_part = None
        o365_meta_re = re.compile(r'^Sender: (.+)^Subject: (.+)^Message-Id: (.+)^Recipient: (.+)', re.M | re.DOTALL)
        o365_meta_sender = None
        o365_meta_subject = None
        o365_meta_message_id = None
        o365_meta_recipient = None

        try:
            logging.debug("parsing email file {}".format(_file))
            with open(_file.full_path, 'r', errors='ignore') as fp:
                # we ignore any leading and/or trailing whitespace
                # this isn't technically "correct" but some systems make mistakes
                unparsed_email = fp.read().strip()
            
            # by default we target the parsed email (see NOTE A)
            target_email = parsed_email = email.parser.Parser().parsestr(unparsed_email)

        except Exception as e:
            logging.error("unable to parse email {}: {}".format(_file, e))

            try:
                # if Python's email parsing library can't parse it then we copy it off to the side
                # for analysis later
                src_path = _file.full_path
                dst_path = os.path.join(get_data_dir(), 'review', 'rfc822', str(uuid.uuid4()))
                shutil.copy(src_path, dst_path)

                with open('{}.unparsed'.format(dst_path), 'w') as fp:
                    fp.write(unparsed_email)

            except Exception as e:
                logging.error("unable to save file for review: {}".format(e))

            return False

        email_details = {}
        target_message_id = None # the message-id we've identified as the main one
        is_office365 = False # is this an office365 journaled message?

        # NOTE A
        # find the email we actually want to target
        # by default we target the entire email itself
        for part in parsed_email.walk():
            # look for what looks like the office365 meta part
            if o365_meta_part is None:
                if part.get_content_type() == 'text/plain':
                    target_payload = part.get_payload()
                    m = o365_meta_re.search(target_payload)
                    if m:
                        o365_meta_sender = m.group(1).strip()
                        o365_meta_subject = m.group(2).strip()
                        o365_meta_message_id = m.group(3).strip()
                        o365_meta_recipient = m.group(4).strip()
                        o365_meta_part = part
                        logging.info(f"parsed o365 meta block sender [{o365_meta_sender}] "
                                     f"subject [{o365_meta_subject}] "
                                     f"message id [{o365_meta_message_id}] "
                                     f"recipient [{o365_meta_recipient}]")

            # look for office365 header indicating a parent message-id
            if 'X-MS-Exchange-Parent-Message-Id' in part:
                is_office365 = True # we use this to identify this is an office365 journaled message
                target_message_id = part['X-MS-Exchange-Parent-Message-Id'].strip()
                logging.debug("found office365 parent message-id {}".format(target_message_id))
                continue

            if 'message-id' in part:
                # if we are looking for a specific message-id...
                if target_message_id:
                    if part['message-id'].strip() == target_message_id:
                        # found the part we're looking for
                        target_email = part
                        logging.debug("found target email using message-id{}".format(target_message_id))
                        break

        # at this point target_email either points at the original parse email
        # or it points to a MIME part (an attachment inside the email)

        # START WHITELISTING

        # check to see if the sender or receiver has been whitelisted
        # this is useful to filter out internally sourced garbage
        if 'from' in target_email:
            file_path, address = email.utils.parseaddr(target_email['from'])
            if address != '':
                if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, address):
                    _file.whitelist()
                    return False

        header_tos = [] # list of header-to addresses
        env_rcpt_to = [] # list of env-to addresses 
        env_mail_from = None # the smtp envelope MAIL FROM

        # if this is an office365 email then we know who the email was actually delivered to
        if is_office365 and 'X-MS-Exchange-Organization-OriginalEnvelopeRecipients' in target_email:
            file_path, address = email.utils.parseaddr(target_email['X-MS-Exchange-Organization-OriginalEnvelopeRecipients'])
            if address:
                env_rcpt_to = [ address ]

        # same as above but we pull this information out of what I'm calling the "meta block"
        # for lack of a better term
        if o365_meta_part:
            if o365_meta_recipient:
                file_path, address = email.utils.parseaddr(o365_meta_recipient)
                env_rcpt_to = [ address ]

            if o365_meta_sender:
                file_path, address = email.utils.parseaddr(o365_meta_sender)
                env_mail_from = address

        # if we know this is an office365 journaled email AND we did not find the "meta block"
        # then at least log that something is wrong
        if is_office365 and not o365_meta_part:
            try:
                message_id = parsed_email['message_id']
            except:
                message_id = "unknown"

            logging.info(f"unable to find meta block for message-id {message_id} in {self.get_root().storage_dir}")

        # emails that come from the SMTP collector should already have observables added with tags smtp_mail_from and 
        # smtp_rctp_to
        for smtp_rcpt_to in [o.value for o in self.get_root().find_observables(
                lambda o: o.type == F_EMAIL_ADDRESS and o.has_tag('smtp_rcpt_to'))]:
            if smtp_rcpt_to not in env_rcpt_to:
                env_rcpt_to.append(smtp_rcpt_to)

        mail_from = self.get_root().find_observable(
                lambda o: o.type == F_EMAIL_ADDRESS and o.has_tag('smtp_mail_from'))
        if mail_from:
            env_mail_from = mail_from.value

        # we also have what To: addrsses are in the headers
        for mail_to in target_email.get_all('to', []):
            address = normalize_email_address(mail_to)
            if address:
                header_tos.append(address)

        for address in header_tos + env_rcpt_to:
            if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address):
                _file.whitelist()
                return False

        # for office365 we check to see if this email is inbound
        # this only applies to the original email, not email attachments
        if is_office365 and _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
            if 'X-MS-Exchange-Organization-MessageDirectionality' in target_email:
                if target_email['X-MS-Exchange-Organization-MessageDirectionality'] != 'Incoming':
                    _file.add_tag(TAG_OUTBOUND_EMAIL)
                    if self.config.getboolean('scan_inbound_only'):
                        # do we have a configured exception?
                        for email_exception in self.outbound_exception_list:
                            logging.debug("searching header To addresses ({}) for '{}'".format(header_tos,
                                                                                               email_exception))
                            if email_exception in header_tos:
                                _file.add_tag(TAG_OUTBOUND_EXCEPTION_EMAIL)
                                logging.info("Outbound office365 email exception found: {}".format(email_exception))
                                break
                        else:
                            logging.info("skipping outbound office365 email {}".format(_file))
                            _file.whitelist()
                            return False

        # END WHITELISTING

        analysis = self.create_analysis(_file)

        # if it's not whitelisted we'll want to archive it
        #_file.add_directive(DIRECTIVE_ARCHIVE)

        # parse out important email header information and add observables

        # capture all email headers
        email_details[KEY_HEADERS] = []
        for header, value in target_email.items():
            email_details[KEY_HEADERS].append([header, value])

        # who did the email come from and who did it go to?
        # with office365 journaling all you have is the header from
        mail_from = None # str
        mail_to = None # strt

        received_time = None

        # figure out when the email was received
        if 'received' in target_email:
            # use the last received email header as the date
            received_time = get_received_time(target_email.get_all('received')[0])

        if 'from' in target_email:
            email_details[KEY_FROM] = decode_rfc2822(target_email['from'])
            from_address = get_address_list(target_email, 'from')
            if len(from_address):
                email_details[KEY_FROM_ADDRESS] = from_address[0]

            address = normalize_email_address(email_details[KEY_FROM])
            if address:
                mail_from = address

                from_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if from_address:
                    from_address.add_tag('mail_from')

                    if '@' in address:
                        from_domain = analysis.add_observable_by_spec(F_FQDN, address.split('@')[1])
                        if from_domain:
                            from_domain.add_tag('from_domain')

        email_details[KEY_ENV_RCPT_TO] = env_rcpt_to
        email_details[KEY_ENV_MAIL_FROM] = env_mail_from

        for rcpt_to in email_details[KEY_ENV_RCPT_TO]:
            address = normalize_email_address(rcpt_to)
            if address:
                if mail_to is None:
                    mail_to = address

                to_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if to_address and mail_from:
                    to_address.add_tag('to_address')
                    analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(mail_from, address))

        email_details[KEY_TO] = target_email.get_all('to', [])
        email_details[KEY_TO_ADDRESSES] = get_address_list(target_email, 'to')
        for addr in email_details[KEY_TO]:
            address = normalize_email_address(decode_rfc2822(addr))
            if address:
                # if we don't know who it was delivered to yet then we grab the first To:
                if mail_to is None:
                    mail_to = address

                to_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if to_address:
                    to_address.add_tag('mail_to')
                    if mail_from:
                        analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(mail_from, address))

        if 'cc' in target_email:
            email_details[KEY_CC] = get_address_list(target_email, 'cc')
            for address in email_details[KEY_CC]:

                cc_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if cc_address:
                    cc_address.add_tag('cc')
                    if mail_from:
                        analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(mail_from, address))

        if 'x-sender' in target_email:
            address = normalize_email_address(target_email['x-sender'])
            if address:
                email_details[KEY_X_SENDER] = address
                x_sender_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if x_sender_address:
                    x_sender_address.add_tag('x-sender')

        if 'x-sender-id' in target_email:
            address = normalize_email_address(target_email['x-sender-id'])
            if address:
                email_details[KEY_X_SENDER_ID] = address
                x_sender_id_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if x_sender_id_address:
                    x_sender_id_address.add_tag('x-sender-id')

        if 'x-auth-id' in target_email:
            address = normalize_email_address(target_email['x-auth-id'])
            if address:
                email_details[KEY_X_AUTH_ID] = address
                x_auth_id_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if x_auth_id_address:
                    x_auth_id_address.add_tag('x-auth-id')

        if 'x-original-sender' in target_email:
            address = normalize_email_address(target_email['x-original-sender'])
            if address:
                email_details[KEY_X_ORIGINAL_SENDER] = address
                x_original_sender_address = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if x_original_sender_address:
                    x_original_sender_address.add_tag('x-original-sender')

        if 'reply-to' in target_email:
            address = normalize_email_address(target_email['reply-to'])
            if address:
                email_details[KEY_REPLY_TO] = address
                email_details[KEY_REPLY_TO_ADDRESS] = address
                reply_to = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if reply_to:
                    reply_to.add_tag('reply-to')

        if 'return-path' in target_email:
            address = normalize_email_address(target_email['return-path'])
            email_details[KEY_RETURN_PATH] = address
            if address:
                return_path = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address)
                if return_path:
                    return_path.add_tag('return-path')

        if 'subject' in target_email:
            email_details[KEY_SUBJECT] = target_email['subject']
            if target_email['subject']:
                analysis.add_observable_by_spec(F_EMAIL_SUBJECT, target_email['subject'])

        if 'message-id' in target_email:
            email_details[KEY_MESSAGE_ID] = target_email['message-id']
            message_id_observable = analysis.add_observable_by_spec(
                    F_MESSAGE_ID,
                    normalize_message_id(target_email['message-id']),
                    o_time=received_time)

            if message_id_observable:
                # this module will extract an email from the archives based on the message-id
                # we don't want to do that here so we exclude that analysis
                message_id_observable.exclude_analysis(MessageIDAnalyzerV2)

            if mail_to:
                if is_local_email_domain(mail_to):
                    email_delivery_observable = analysis.add_observable_by_spec(F_EMAIL_DELIVERY,
                                                create_email_delivery(email_details[KEY_MESSAGE_ID], mail_to))

                    if email_delivery_observable:
                        # if a message_id observable has the DIRECTIVE_REMEDIATE directive
                        # then that directive gets copied to the delivery observable
                        # so that the remediation system knows where to find the email
                        for _ in self.get_root().get_observables_by_type(F_MESSAGE_ID):
                            if message_id_observable and _.value == message_id_observable.value and _.has_directive(DIRECTIVE_REMEDIATE):
                                logging.info(f"copying directive {DIRECTIVE_REMEDIATE} from message-id {_.value} to {email_delivery_observable.value}")
                                email_delivery_observable.add_directive(DIRECTIVE_REMEDIATE)

            for rcpt_to in env_rcpt_to:
                if is_local_email_domain(rcpt_to):
                    email_delivery_observable = analysis.add_observable_by_spec(F_EMAIL_DELIVERY,
                                                create_email_delivery(email_details[KEY_MESSAGE_ID], rcpt_to))

            # when the have the SMTP envelope data

        # the rest of these details are for the generate logging output

        # extract CC and BCC recipients
        cc = []
        if 'cc' in target_email:
            cc = [e.strip() for e in target_email['cc'].split(',')]

        bcc = []
        if 'bcc' in target_email:
            bcc = [e.strip() for e in target_email['bcc'].split(',')]

        path = []
        for header in target_email.get_all('received', []):
            m = _PATTERN_RECEIVED_IPADDR.match(header)
            if not m:
                continue

            path_item = m.group(1)
            path.append(path_item)

        user_agent = None
        if 'user-agent' in target_email:
            email_details[KEY_USER_AGENT] = target_email['user-agent']
            user_agent = target_email['user-agent']
            analysis.add_observable_by_spec(F_USER_AGENT, user_agent)

        x_mailer = None
        if 'x-mailer' in target_email:
            email_details[KEY_X_MAILER] = target_email['x-mailer']
            x_mailer = target_email['x-mailer']
            analysis.add_observable_by_spec(F_EMAIL_X_MAILER, x_mailer)

        # sender IP address (office365)
        if 'x-originating-ip' in target_email:
            value = target_email['x-originating-ip']
            value = re.sub(r'[^0-9\.]', '', value) # these seem to have extra characters added
            email_details[KEY_ORIGINATING_IP] = value
            ipv4 = analysis.add_observable_by_spec(F_IPV4, value, o_time=received_time)
            if ipv4:
                ipv4.add_tag('sender_ip')
                ipv4.add_tag('x-originating-ip')

        if 'x-sender-ip' in target_email:
            value = target_email['x-sender-ip']
            value = re.sub(r'[^0-9\.]', '', value)  # these seem to have extra characters added
            email_details[KEY_X_SENDER_IP] = value
            ipv4 = analysis.add_observable_by_spec(F_IPV4, value, o_time=received_time)
            if ipv4:
                ipv4.add_tag('sender_ip')
                ipv4.add_tag('x-sender-ip')

        # is the subject rfc2822 encoded?
        if KEY_SUBJECT in email_details:
            email_details[KEY_DECODED_SUBJECT] = decode_rfc2822(email_details[KEY_SUBJECT])

        # get the first and last received header values
        last_received = None
        first_received = None
        path = None
        for header, value in email_details[KEY_HEADERS]:
            if header.lower().startswith('received'):
                if not last_received:
                    last_received = value
                first_received = value

        # START ATTACHMENT PARSING

        unknown_index = 0

        # we use this later when we write the log message
        attachments = [] # of ( size, type, name, sha256 )

        def __recursive_parser(target):
            nonlocal target_message_id

            # if this attachment is an email and it's not the target email
            # OR this attachment is not a multipart attachment (is a single file)
            # THEN we want to extract it as a another file for analysis

            # is this another email or a single file attachment?
            if target.get_content_type() == 'message/rfc822' or not target.is_multipart():

                file_name = None

                # do not extract the target email
                if target.get_content_type() == 'message/rfc822':
                    # the actual message-id will be in one of the payloads of the email
                    for payload in target.get_payload():
                        if 'message-id' in payload and payload['message-id'].strip() == target_message_id:
                            return

                    # if we are going to extract it then we name it here
                    file_name = '{}.email.rfc822'.format(_file.file_path)

                # extract it
                if not file_name:
                    file_name = target.get_filename()

                if file_name:
                    decoded_header = email.header.decode_header(file_name)
                    if decoded_header:
                        decoded_header, charset = decoded_header[0]
                        if charset:
                            try:
                                file_name = decoded_header.decode(charset, errors='replace')
                            except LookupError as e:
                                logging.warning(str(e))

                    file_name = re.sub(r'[\r\n]', '', file_name)

                else:
                    file_name = '{}.unknown_{}_{}_000'.format(_file.file_path, target.get_content_maintype(), 
                                                                           target.get_content_subtype())

                # sanitize the file name
                sanitized_file_name = re.sub(r'_+', '_', re.sub(r'\.\.', '_', re.sub(r'/', '_', file_name)))
                if file_name != sanitized_file_name:
                    logging.debug("changed file name from {} to {}".format(file_name, sanitized_file_name))
                    file_name = sanitized_file_name

                if not file_name:
                    file_name = '{}.unknown_{}_{}_000'.format(_file.file_path, target.get_content_maintype(), 
                                                                           target.get_content_subtype())

                # make sure the file name isn't too long
                if len(file_name) > 120:
                    logging.debug("file name {} is too long".format(file_name))
                    _file_name, _file_ext = os.path.splitext(file_name)
                    # this can be wrong too
                    if len(_file_ext) > 40:
                        _file_ext = '.unknown'
                    file_name = '{}{}'.format(file_name[:120], _file_ext)

                # make sure it's unique
                file_path = self.get_root().create_file_path(file_name)
                while True:
                    if not os.path.exists(file_path):
                        break

                    _file_name, _file_ext = os.path.splitext(os.path.basename(file_path))
                    m = re.match('(.+)_([0-9]{3})$', _file_name)
                    if m:
                        _file_name = m.group(1)
                        index = int(m.group(2)) + 1
                    else:
                        index = 0

                    _file_name = '{}_{:03}'.format(_file_name, index)
                    file_path = '{}{}'.format(_file_name, _file_ext)
                    file_path = os.path.join(self.get_root().storage_dir, file_path)

                # figure out what the payload should be
                if target.get_content_type() == 'message/rfc822':
                    part = target.get_payload()
                    part = part[0]
                    payload = part.as_bytes()
                elif target.is_multipart():
                    # in the case of email attachments we need the whole things (including headers)
                    payload = target.as_bytes()
                else:
                    # otherwise we just need the decoded contents as bytes
                    payload = target.get_payload(decode=True)

                with open(file_path, 'wb') as fp:
                    fp.write(payload)

                logging.debug("extracted {} from {}".format(file_path, _file))

                extracted_file = analysis.add_file_observable(file_path)

                if extracted_file: 
                    extracted_file.add_directive(DIRECTIVE_EXTRACT_URLS)

                    if target.get_content_type() == 'text/plain':
                        extracted_file.add_directive(DIRECTIVE_PREVIEW)
                    else:
                        extracted_file.add_directive(DIRECTIVE_RENDER)

                # XXX I can't remember why we are still doing the attachment thing
                attachments.append((len(payload), target.get_content_type(), 
                                    _file.file_path, hashlib.sha256(payload).hexdigest()))
                 
            # otherwise, if it's a multi-part then we want to recurse into it
            elif target.is_multipart():
                for part in target.get_payload():
                    _recursive_parser(part)

            else:
                raise RuntimeError("parsing logic error: {}".format(_file))

        def _recursive_parser(*args, **kwargs):
            try:
                return __recursive_parser(*args, **kwargs)
            except Exception as e:
                logging.warning("recursive parsing failed on {}: {}".format(_file, e))
                #report_exception()
                target_path = os.path.join(get_data_dir(), 'review', 'rfc822', '{}.{}'.format(
                                           _file.file_path, datetime.now().strftime('%Y%m%d%H%M%S')))
                shutil.copy(_file.full_path, target_path)

        _recursive_parser(target_email)

        # END ATTACHMENT PARSING

        # generate data suitable for logging
        log_entry = {
            'date': get_local_timezone().localize(datetime.now()).strftime('%Y-%m-%d %H:%M:%S.%f %z'),
            'first_received': first_received,
            'last_received': last_received,
            'env_mail_from': email_details[KEY_ENV_MAIL_FROM] if KEY_ENV_MAIL_FROM in email_details else None,
            'env_rcpt_to': email_details[KEY_ENV_RCPT_TO] if KEY_ENV_RCPT_TO in email_details else [],
            'mail_from': email_details[KEY_FROM] if KEY_FROM in email_details else None,
            'mail_to': email_details[KEY_TO] if KEY_TO in email_details else [],
            'reply_to': email_details[KEY_REPLY_TO] if KEY_REPLY_TO in email_details else None,
            'cc': cc,
            'bcc': bcc,
            'message_id': email_details[KEY_MESSAGE_ID] if KEY_MESSAGE_ID in email_details else None,
            'subject': email_details[KEY_SUBJECT] if KEY_SUBJECT in email_details else None,
            'path': path,
            'size': _file.size,
            'user_agent': user_agent,
            'x_mailer': x_mailer,
            'originating_ip': email_details[KEY_ORIGINATING_IP] if KEY_ORIGINATING_IP in email_details else None,
            'headers': ['{}: {}'.format(h[0], re.sub('[\t\n]', '', h[1])) for h in email_details[KEY_HEADERS] if not h[0].lower().startswith('x-ms-exchange-')] if KEY_HEADERS in email_details else None,
            'attachment_count': len(attachments),
            'attachment_sizes': [a[0] for a in attachments],
            'attachment_types': [a[1] for a in attachments],
            'attachment_names': [a[2] for a in attachments],
            'attachment_hashes': [a[3] for a in attachments],
            'thread_topic': target_email['thread-topic'] if 'thread-topic' in target_email else None,
            'thread_index': target_email['thread-index'] if 'thread-index' in target_email else None,
            'refereneces': target_email['references'] if 'references' in target_email else None,
            'x_sender': target_email['x-sender'] if 'x-sender' in target_email else None,
        }

        email_details[KEY_LOG_ENTRY] = log_entry
        analysis.email = email_details

        # create a file with just the header information and scan that separately
        headers_path = None
        if KEY_HEADERS in email_details:
            headers_path = self.get_root().create_file_path('{}.headers'.format(_file.file_path))
            if os.path.exists(headers_path):
                logging.debug("headers file {} already exists".format(headers_path))
            else:
                with open(headers_path, 'w') as fp:
                    fp.write('\n'.join(['{}: {}'.format(h[0], h[1]) for h in email_details[KEY_HEADERS]]))

                headers_file = analysis.add_file_observable(headers_path)

                # we don't want to analyze this with the email analyzer
                if headers_file: 
                    headers_file.exclude_analysis(self)

        # combine the header and the decoded parts of the email into a single buffer for scanning with yara
        # we only combine the un-named html and text parts, not additional attachements
        if headers_path:
            combined_path = self.get_root().create_file_path('{}.combined'.format(_file.file_path))
            if os.path.exists(combined_path):
                logging.debug(f"combined path {combined_path} already exists")
            else:
                # copy the headers over first
                shutil.copy(headers_path, combined_path)
                with open(combined_path, 'ab') as fp:
                    fp.write(b'\n\n')

                    # copy each attachment in the order it was seen in the email if it has 'unknown_' in the name
                    for size, type, file_path, sha256 in attachments:
                        if 'unknown_' in file_path:
                            attachment_path = self.get_root().create_file_path(file_path)
                            try:
                                with open(attachment_path, 'rb') as fp_in:
                                    shutil.copyfileobj(fp_in, fp)

                                fp.write(b'\n\n')

                            except Exception as e:
                                logging.error(f"unable to copy {attachment_path} to {combined_path}: {e}")
                                report_exception()

                    combined_file = analysis.add_file_observable(combined_path)

                    # we don't want to analyze this with the email analyzer
                    if combined_file: 
                        combined_file.exclude_analysis(self)

        # are we renaming the root analysis?
        if _file.has_directive(DIRECTIVE_RENAME_ANALYSIS):
            if KEY_SUBJECT in email_details and email_details[KEY_SUBJECT]:
                self.get_root().description += ' - ' + email_details[KEY_SUBJECT]

        mail_rcpt_to = log_entry['env_rcpt_to'] if log_entry['env_rcpt_to'] else log_entry['mail_to']
        logging.info("scanning email [{}] {} from {} to {} subject {}".format(
                     self.get_root().uuid,
                     log_entry['message_id'], log_entry['mail_from'], mail_rcpt_to,
                     log_entry['subject']))

        return True

    def analyze_missing_stream(self, _file):
        """Analyzes the output of bro failing to capture the stream data but still extracted protocol meta and files."""
        assert isinstance(_file, FileObservable)

        from saq.modules.email.stream import pattern_brotex_connection

        file_path = _file.full_path
        extracted_dir = '{}.extracted'.format(file_path)
        if not os.path.isdir(extracted_dir):
            try:
                os.mkdir(extracted_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(extracted_dir, e))
                return False

        analysis = self.create_analysis(_file)

        # extract all the things into the brotex_dir
        p = Popen(['tar', 'xf', file_path, '-C', extracted_dir], 
                  stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()
        p.wait()

        if p.returncode:
                logging.warning("unable to extract files from {} (tar returned error code {}".format(
                                _file, p.returncode))
                return False

        if stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, stderr))

        # iterate over all the extracted files
        # map message numbers to the connection file
        connection_files = {} # key = message_number, value = path to connection file
        for dirpath, dirnames, filenames in os.walk(extracted_dir):
            for file_name in filenames:
                m = pattern_brotex_connection.match(file_name)
                if m:
                    # keep track of the largest trans_depth
                    trans_depth = m.group(1)
                    connection_files[trans_depth] = os.path.join(dirpath, file_name)

                full_path = os.path.join(dirpath, file_name)
                # go ahead and add every file to be scanned
                _file = analysis.add_file_observable(full_path)
                if _file:
                    _file.add_directive(DIRECTIVE_EXTRACT_URLS)

        def _parse_bro_mv(value):
            """Parse bro multivalue field."""
            # interpreting what I see here...
            if not value.startswith('{^J^I') and value.endswith('^J}'):
                return [ value ]

            return value[len('{^J^I]')-1:-len('^J}')].split(',^J^I')

        # parse each message
        for message_number in connection_files.keys():
            details = { }

            # parse the connection file
            logging.debug("parsing bro connection file {}".format(connection_files[message_number]))
            with open(connection_files[message_number], 'r') as fp:
                # these files are generated by the brotex.bro script in the brotex git repo
                # they are stored in the following order
                uid = fp.readline().split(' = ', 1)[1].strip()
                mailfrom = fp.readline().split(' = ', 1)[1].strip()
                rcptto = fp.readline().split(' = ', 1)[1].strip()
                from_ = fp.readline().split(' = ', 1)[1].strip()
                to_ = fp.readline().split(' = ', 1)[1].strip()
                reply_to = fp.readline().split(' = ', 1)[1].strip()
                in_reply_to = fp.readline().split(' = ', 1)[1].strip()
                msg_id = fp.readline().split(' = ', 1)[1].strip()
                subject= fp.readline().split(' = ', 1)[1].strip()
                x_originating_ip = fp.readline().split(' = ', 1)[1].strip()

            # some of these fields are multi value fields
            rcptto = _parse_bro_mv(rcptto)
            to_ = _parse_bro_mv(to_)

            details[KEY_ENV_MAIL_FROM] = mailfrom
            details[KEY_ENV_RCPT_TO] = rcptto
            details[KEY_FROM] = from_
            details[KEY_TO] = to_
            details[KEY_SUBJECT] = subject
            details[KEY_REPLY_TO] = reply_to
            #details[KEY_IN_REPLY_TO] = in_reply_to
            details[KEY_MESSAGE_ID] = msg_id
            details[KEY_ORIGINATING_IP] = x_originating_ip

            analysis.email = details

            # add the appropriate observables
            mailfrom_n = None
            if mailfrom:
                mailfrom_n = normalize_email_address(mailfrom)
                if mailfrom_n:
                    analysis.add_observable_by_spec(F_EMAIL_ADDRESS, mailfrom_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, mailfrom_n):
                        _file.whitelist()
            
            for address in rcptto:
                if address:
                    address_n = normalize_email_address(address)
                    if address_n:
                        analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address_n)
                        if mailfrom_n:
                            analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(mailfrom,
                                                    address_n))
                            if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address_n):
                                _file.whitelist()

            from_n = None
            if from_:
                from_n = normalize_email_address(from_)
                if from_n:
                    analysis.add_observable_by_spec(F_EMAIL_ADDRESS, from_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, from_n):
                        _file.whitelist()

            for address in to_:
                address_n = normalize_email_address(address_n)
                if address_n:
                    analysis.add_observable_by_spec(F_EMAIL_ADDRESS, address_n)
                    if self.whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, address_n):
                        _file.whitelist()

                if from_:
                    analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(
                                            normalize_email_address(from_),
                                            normalize_email_address(address)))

            if x_originating_ip:
                analysis.add_observable_by_spec(F_IPV4, x_originating_ip)

        return True


    def execute_analysis(self, _file) -> AnalysisExecutionResult:

        from saq.modules.file_analysis import FileTypeAnalysis
        from saq.modules.email.stream import pattern_brotex_missing_stream_package

        # is this a "missing stream archive" that gets generated by the BrotexSMTPPackageAnalyzer module?
        if pattern_brotex_missing_stream_package.match(os.path.basename(_file.file_name)):
            self.analyze_missing_stream(_file)
            return AnalysisExecutionResult.COMPLETED

        # is this an RFC 822 email?
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis or not file_type_analysis.file_type:
            logging.debug("missing file type analysis for {}:".format(_file))
            return AnalysisExecutionResult.COMPLETED

        is_email = 'RFC 822 mail' in file_type_analysis.file_type
        is_email |= 'message/rfc822' in file_type_analysis.file_type
        is_email |= 'message/rfc822' in file_type_analysis.mime_type
        is_email |= _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL)
        if file_type_analysis is not None:
            is_email |= file_type_analysis.is_email_file

        if not is_email:
            logging.debug("unsupported file type for email analysis: {} {}".format(
                          file_type_analysis.file_type,
                          file_type_analysis.mime_type))
            return AnalysisExecutionResult.COMPLETED

        self.analyze_rfc822(_file)
        return AnalysisExecutionResult.COMPLETED

class EmailAnalysisPresenter(AnalysisPresenter):
    """Presenter for EmailAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/email_analysis.html"

register_analysis_presenter(EmailAnalysis, EmailAnalysisPresenter)