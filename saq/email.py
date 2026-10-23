# vim: sw=4:ts=4:et:cc=120

import logging

from email.utils import parseaddr
from email.header import decode_header
from saq.configuration import get_config
from saq.util import is_subdomain

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