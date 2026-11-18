"""Module to aid working with x509 certificates.

Use `load_cert-pem(pem_content_in_bytes)` to receive a
cryptography.x509.Certificate object. The x509.Certificate object
can be passed in to the rest of the functions in this module to
extract certain sections of the certificate."""


import datetime
import hashlib
import logging
import re
from typing import List, Union

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der.decoder import decode as pyasn1_der_decode
from pyasn1.error import PyAsn1Error


# List of strings that can determine if file is a PEM-encoded
# certificate.
# See section four of RFC 7468.  Opting for the END of the header since
# strings can vary towards the front.
# For example:  '-----BEGIN DSA PRIVATE KEY-----'
# Instead of accounting for all algorithms like 'DSA', just check for the
# ending portion of the label 'PRIVATE KEY-----'.
PEM_LABEL_ENDINGS = [
    b'CERTIFICATE-----',
    b'X509 CRL-----',
    b'CERTIFICATE REQUEST-----',
    b'PKCS7-----',
    b'CMS-----',
    b'PRIVATE KEY-----',
    b'ENCRYPTED PRIVATE KEY-----',
    b'ATTRIBUTE CERTIFICATE-----',
    b'PUBLIC KEY-----',
]


def load_cert_pem(cert_content: bytes, x509_lib=None, backend=None) -> Union[x509.Certificate, None]:
    """Return x509.Certificate object from pem contents."""
    _x509 = x509_lib or x509
    _backend = backend or default_backend()
    try:
        return _x509.load_pem_x509_certificate(cert_content, _backend)
    except ValueError:  # Thrown when unable to load as PEM-encoded certificate
        return None


def load_cert_der(cert_content: bytes, x509_lib=None, backend=None) -> Union[x509.Certificate, None]:
    """Return x509.Certificate object from DER data."""
    _x509 = x509_lib or x509
    _backend = backend or default_backend()
    try:
        return _x509.load_der_x509_certificate(cert_content, backend=None)
    except ValueError:  # Thrown when unable to load as DER-encoded certificate
        return None


def load_cert(cert_content: bytes, x509_lib=None, backend=None) -> Union[x509.Certificate, None]:
    """Return x509.Certificate object from either DER or PEM.

    Best to use this when encoding is unknown."""
    cert = load_cert_pem(cert_content, x509_lib=x509_lib, backend=backend)
    if cert is not None:
        return cert
    return load_cert_der(cert_content, x509_lib=x509_lib, backend=backend)


def sha1(cert: x509.Certificate) -> str:
    """Return sha1 of certificate.

    Note, sha1 hashes are taken of the DER encoded version
    of the certificate. This function handles converting to the
    DER encoding before hashing."""
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha1(der).hexdigest()


def sha256(cert: x509.Certificate) -> str:
    """Return sha256 of certificate.

    Note, sha256 hashes are taken of the DER encoded version
    of the certificate. This function handles converting to the
    DER encoding before hashing."""
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def serial_number(cert: x509.Certificate) -> int:
    """Return serial number of certificate."""
    return cert.serial_number


def issuer(cert: x509.Certificate) -> str:
    """Return issuer of certificate."""
    return cert.issuer.rfc4514_string()


def subject(cert: x509.Certificate) -> str:
    """Return subject of certificate."""
    return cert.subject.rfc4514_string()


def not_valid_before(cert: x509.Certificate) -> datetime.datetime:
    """Return not valid after datetime."""
    return cert.not_valid_before_utc


def not_valid_after(cert: x509.Certificate) -> datetime.datetime:
    """Return not valid after datetime."""
    return cert.not_valid_after_utc


def common_name(cert: x509.Certificate) -> str | None:
    """Return the common name from the subject, or None if it has none."""
    # read the parsed attribute rather than the RFC 4514 string, whose escaping (\, \+ ...) a regex can't undo
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    # a parsed certificate can carry an empty CN, which would otherwise become the URL http://
    if not common_names or not common_names[-1].value:
        return None

    # with more than one CN, use the last (most specific) RDN, which is the first one subject() shows
    return common_names[-1].value


def _get_san_extension(cert: x509.Certificate) -> Union[x509.Extension, None]:
    """Return the Subject Alternative Name extension from a certificate or None"""
    try:
        return cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return None


def san_dns_names(cert: x509.Certificate) -> List[str]:
    """Return list of dns names from names from certificate's Subject Alternative Names extension."""
    san_extension = _get_san_extension(cert)
    if san_extension is None:
        return []
    return san_extension.value.get_values_for_type(x509.DNSName)


def san_ip_addresses(cert: x509.Certificate) -> List[str]:
    """Return list of ip addresses from certificate's Subject Alternative Names extension."""
    san_extension = _get_san_extension(cert)
    if san_extension is None:
        return []
    return [str(ip_address) for ip_address in san_extension.value.get_values_for_type(x509.IPAddress)]


def remove_wildcard(wildcard_dns_name: Union[str, bytes]) -> Union[str, bytes]:
    """Remove wildcard from dns name."""
    if wildcard_dns_name.startswith('*.'):
        return wildcard_dns_name[len('*.'):]
    return wildcard_dns_name


def is_pem_bytes(byte_string: bytes) -> bool:
    """Return true if a PEM header/label is found in a bytes string."""
    for label_ending in PEM_LABEL_ENDINGS:
        if label_ending in byte_string:
            return True
    return False


def is_der_bytes(bytes_string: bytes) -> bool:
    """Return true if bytes are consistent with DER-encoding."""
    try:
        _ = pyasn1_der_decode(bytes_string)
    except PyAsn1Error:
        return False
    else:
        return True


# The following code is for parsing the certificate extensions into a format that
# is presentable to the analyst

X509_CLASS_REGEX = re.compile(r'^<([^\(]+)')


def x509_object_name(x509_object):
    """Get extension/object name from the classes string representation.

    I hope someday someone will find an easier way to access the name..."""
    default = 'ERROR_GETTING_FIELD_NAME'
    string_format = str(x509_object)

    # x509.ObjectIdentifiers do not have a useful name in the string
    # representation of the object.
    try:
        if isinstance(x509_object, x509.ObjectIdentifier):
            return x509_object._name  # I know... yucky
    except AttributeError:
        return f'{default}-{string_format}'

    # Pull the useful name out of the class's string representation
    try:
        return X509_CLASS_REGEX.search(string_format).group(1)
    except AttributeError:
        return f'{default}-{string_format}'
    except IndexError:
        return f'{default}-{string_format}'


def get_extension_attributes(extension) -> List[str]:
    """Return extension/x509 object attributes.

    It would be a bear to write code specific to each extension's attributes, so
    we grab all attributes that are not protected and add them tot he output."""
    return [attribute for attribute in dir(extension) if not attribute.startswith('_')]


def parse_x509_details(details, critical=False) -> Union[str, list, dict]:
    """Return readable info for an extension.

    This is a recursive function. Base case is if the x509_object/details is not
    iterable. Thus, it can be considered the last node/leaf of the tree.

    If the object is iterable, then we run this function recursively over it.

    Since it would be a real bear to accomodate each possible extension, we will read
    the attributes of the x509 objects and then call the unprotected attributes to make
    the extension details readable."""
    name = x509_object_name(details)

    # Should only be used for the top level x509.Extention objects
    if critical:
        name = f'{name}: CRITICAL'

    # Try to iterate over the object and see if there are more edges to traverse.
    try:
        return {name: [parse_x509_details(x509_object) for x509_object in details]}

    # If not iterable, then we are at the end node/leaf.
    except TypeError:
        attributes = get_extension_attributes(details)

        # Decipher_only and encipher_only throw errors if key_agreement is false
        if ('decipher_only' in attributes) or ('encipher_only' in attributes):
            if not details.key_agreement:
                attributes = [
                    attribute for attribute in attributes if attribute not in ['decipher_only', 'encipher_only']
                ]
        # If only one attribute available and it is 'value', we can put the name and value on the same line
        # instead of nesting
        # Convert attribute value to string in case it is a method, class, or other unexpected object
        if len(attributes) == 1:
            if attributes[0] == 'value':
                return f'{name}: {str(details.value)}'
            return {
                name: {
                    attributes[0]: str(getattr(details, attributes[0]))
                }
            }

        # Otherwise, set the attribute name as the name and the attribute value as the value
        # TODO - call attributes that are methods
        return {name: [f'{attribute}: {str(getattr(details, attribute))}' for attribute in attributes]}


def build_extension_output(x509_extensions: x509.Extensions) -> list:
    """Return list of extensions"""
    return [parse_x509_details(extension.value, critical=extension.critical) for extension in x509_extensions]


def get_readable_extensions(cert: x509.Certificate) -> Union[list, None]:
    """Return readable x509 extension information."""
    try:
        return build_extension_output(cert.extensions)
    except Exception as e:
        logging.error(f'unable to parse extensions for certificate: {e.__class__}, {e}')
        return None
