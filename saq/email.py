# vim: sw=4:ts=4:et:cc=120

import logging
import re

from email.utils import parseaddr
from email.header import decode_header
from saq.configuration import get_config
from saq.util import is_subdomain

# returns all substrings after removing the domain and non-alphabetic characters
lower_alpha_re = re.compile('[^a-z]')
def tokenize_email_address(email_address):
    name = lower_alpha_re.sub('', email_address.split('@', 1)[0])
    return set([name[i: j] for i in range(len(name)) for j in range(i + 1, len(name) + 1)])

# return the percent similarity by averaging the fraction of common tokens in a and b
def email_address_similarity(email_address_a, email_address_b):
    try:
        a = tokenize_email_address(email_address_a)
        if len(a) == 0:
            return 0
        b = tokenize_email_address(email_address_b)
        if len(b) == 0:
            return 0
        intersection = len(a.intersection(b))
        ia = intersection / len(a)
        ib = intersection / len(b)
        return 100 * (ia + ib) / 2

    # return 0 if we fail to parse the email address
    except:
        return 0


def normalize_email_address(email_address):
    """Returns a normalized version of email address.  Returns None if the address cannot be parsed."""
    if email_address is None:
        return None
    if not isinstance(email_address, str):
        # email.message.Message[header] can return an email.header.Header under
        # compat32 policy; decode to str so substring/parseaddr operations work.
        email_address = decode_rfc2822(email_address)
    name, address = parseaddr(email_address)
    if not address:
        # attempt to fix known cases the stdlib has, like <<person@example.com>>
        while email_address and '<<' in email_address and '>>'  in email_address:
            email_address = email_address.replace('<<','<').replace('>>','>')
        name, address = parseaddr(email_address)
        if not address:
            return None

    address = address.strip()

    while address and address.startswith('<'):
        address = address[1:]

    while address and address.endswith('>'):
        address = address[:-1]

    if not address:
        return None

    return address.lower()

def parse_display_email(email):
    match = re.search(r'<([^><]*)>', email)
    if match is None:
        return email

    return normalize_email_address(match.group(1))

def get_email_domain(email_address):
    try:
        return email_address.split('@', 1)[1]
    except Exception as e:
        logging.debug(f"email address {email_address} failed to split on @: {e}")
    return None

def decode_rfc2822(header_value):
    """Returns the value of the rfc2822 decoded header, or the header_value as-is if it's not encoded."""
    result = []
    for binary_value, charset in decode_header(header_value):
        decoded_value = None
        if isinstance(binary_value, str):
            result.append(binary_value)
            continue

        if charset is not None:
            try:
                decoded_value = binary_value.decode(charset, errors='ignore')
            except Exception as e:
                logging.warning(f"unable to decode for charset {charset}: {e}")

        if decoded_value is None:
            try:
                decoded_value = binary_value.decode('utf8', errors='ignore')
            except Exception as e:
                logging.warning(f"unable to decode email header at all (defaulting to hex rep): {e}")
                decoded_value = 'HEX({})'.format(binary_value.hex())

        result.append(decoded_value)

    return ''.join(result)

# returns true if the email domain is a sub domain of a domain listed in the global-local email domains settings list
def is_local_email_domain(email_address):
    email_address = normalize_email_address(email_address)
    email_domain = get_email_domain(email_address)
    if email_domain is not None:
        # if that doesn't work then use the old-style configuration option
        local_domains = get_config().global_settings.local_email_domains

        for local_domain in local_domains:
            if is_subdomain(email_domain, local_domain):
                return True

    return False

class EmailArchiveEntry:
    def __init__(self, archive_id):
        self.archive_id = archive_id
        self.message_id = None
        self.recipient = None
        self.subject = None
        self.sender = None
        self.remediation_history = []

    @property
    def remediated(self):
        result = False
        for history in self.remediation_history:
            if history['action'] == 'remove' and history['successful']:
                result = True
            if history['action'] == 'restore' and history['successful']:
                result = False

        return result

    @property
    def key(self):
        return '{}:{}'.format(self.message_id, self.recipient)

    @property
    def json(self):
        return {
            'archive_id': self.archive_id,
            'message_id': self.message_id,
            'recipient': self.recipient,
            'sender': self.sender,
            'subject': self.subject,
            'remediated': self.remediated,
            'remediation_history': self.remediation_history }

def get_email_archive_sections():
    """Returns the list of configuration sections for email archives.
       Includes the primary and any secondary."""

    result = []
    if get_config().email_archive.primary:
        result.append(get_config().email_archive.primary)
    
    for section in get_config().raw._data.keys():
        if section.startswith('database_email_archive_'):
            if section not in result:
                result.append(section[len('database_'):])

    return result

def normalize_message_id(message_id):
    """Returns message id with < and > prepended and appended respectively

    Required format for exchangelib filter."""
    if message_id is None:
        return None
    if not isinstance(message_id, str):
        message_id = decode_rfc2822(message_id)
    message_id = message_id.strip()
    if not message_id.startswith("<"):
        message_id = f"<{message_id}"
    if not message_id.endswith(">"):
        message_id = f"{message_id}>"
    return message_id