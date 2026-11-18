
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
import pytest

from saq import x509 as saq_x509

# A leaf for CN=leaf.example signed by CN=Example CA (serial 0x1234), made with openssl. The expected
# fingerprints and names below are openssl's own output for it (x509 -fingerprint, -nameopt RFC2253).
FIXED_CERT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIBjzCCATSgAwIBAgICEjQwCgYIKoZIzj0EAwIwLTETMBEGA1UEAwwKRXhhbXBs
ZSBDQTEWMBQGA1UECgwNQUNFIEVjb3N5c3RlbTAeFw0yNjExMDQxNDIyMDRaFw0z
NjExMDExNDIyMDRaMC8xFTATBgNVBAMMDGxlYWYuZXhhbXBsZTEWMBQGA1UECgwN
QUNFIEVjb3N5c3RlbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF3oOayo9Sdj
3AceRFupC73raCn+YbrE0uIPqXW7sSYsF9kJhEC492tiHoNdxC6JtHwynmBdfJZT
Hx26aXaH/Y2jQjBAMB0GA1UdDgQWBBT22DsFBqEo5dDBeyjsR4r7Ua9rCjAfBgNV
HSMEGDAWgBT/gOQvCmGqwEcbqqwR5kL2E6VKLTAKBggqhkjOPQQDAgNJADBGAiEA
jWxMMvUBXbcCuTI0zAe6OFPaCrG5dutejVQQXnp2aZYCIQDVL2JRb73EorGFfT5k
ynIp7FlUXeuN6ReC9KgoQGvyZw==
-----END CERTIFICATE-----
"""


@pytest.fixture(scope="module")
def fixed_cert():
    return saq_x509.load_cert(FIXED_CERT_PEM)


@pytest.mark.unit
def test_load_cert_general_func_with_pem_byte_string(cert_pem_bytes):
    """Validate the general load cert function loads PEM-encoded certificates."""

    # setup
    cert = saq_x509.load_cert(cert_pem_bytes)

    # verify
    assert isinstance(cert, x509.Certificate)
    assert cert_pem_bytes == cert.public_bytes(encoding=serialization.Encoding.PEM)


@pytest.mark.unit
def test_load_cert_general_func_with_der_byte_string(cert_der_bytes):
    """Validate the general load cert function loads DER-encoded certificates."""

    # setup
    cert = saq_x509.load_cert(cert_der_bytes)

    # verify
    assert isinstance(cert, x509.Certificate)
    assert cert_der_bytes == cert.public_bytes(encoding=serialization.Encoding.DER)


@pytest.mark.unit
def test_load_cert_general_func_not_a_valid_cert_byte_string():
    """Validate the general load cert function loads DER-encoded certificates."""

    cert = saq_x509.load_cert(b'not a real certificate')

    assert cert is None


@pytest.mark.unit
def test_sha1(fixed_cert):
    """The fingerprint is the sha1 of the DER encoding, as openssl shows it."""
    assert saq_x509.sha1(fixed_cert) == "c81eabaeb53ee99068a1dc3db3949e8919fa6363"


@pytest.mark.unit
def test_sha256(fixed_cert):
    """The fingerprint is the sha256 of the DER encoding, as openssl shows it."""
    assert saq_x509.sha256(fixed_cert) == "32b8b53215ffc237f2de0523783dba64a1ff4eb718f53fe1b34f03fca135fac4"


@pytest.mark.unit
def test_serial_number(fixed_cert):
    assert saq_x509.serial_number(fixed_cert) == 0x1234


@pytest.mark.unit
def test_issuer(fixed_cert):
    """The issuer, not the subject: the fixed certificate is not self-signed."""
    assert saq_x509.issuer(fixed_cert) == "O=ACE Ecosystem,CN=Example CA"


@pytest.mark.unit
def test_subject(fixed_cert):
    assert saq_x509.subject(fixed_cert) == "O=ACE Ecosystem,CN=leaf.example"


@pytest.mark.unit
def test_not_valid_before(cert, x509_constants):
    """Validate the correct 'not valid before' datetime object is returned."""
    assert x509_constants.NOT_VALID_BEFORE == saq_x509.not_valid_before(cert)


@pytest.mark.unit
def test_not_valid_after(cert, x509_constants):
    """Validate the correct 'not valid after' datetime object is returned."""
    assert x509_constants.NOT_VALID_AFTER == saq_x509.not_valid_after(cert)


@pytest.mark.unit
def test_get_alternative_dns_names(cert, x509_constants):
    """Validate a list of alternative names is returned."""
    assert x509_constants.SUBJECT_ALTERNATIVE_DNS_NAMES == saq_x509.san_dns_names(cert)


@pytest.mark.unit
def test_san_dns_names_missing_san_extension(cert_no_alt):
    """If no alternate names available, then the function should
    return back an empty list."""
    assert [] == saq_x509.san_dns_names(cert_no_alt)


@pytest.mark.unit
def test_san_ip_addresses(cert, x509_constants):
    """Test if IP Addresses are pulled from certificate SAN extension."""
    assert x509_constants.SUBJECT_ALTERNATIVE_IP_ADDRESSES == saq_x509.san_ip_addresses(cert)


@pytest.mark.unit
def test_san_ip_addresses_missing_san_extension(cert_no_alt):
    """Verify empty list is returned if san extension is missing from certificate."""
    assert [] == saq_x509.san_ip_addresses(cert_no_alt)


@pytest.mark.unit
def test_common_name_success_unmocked_cert(cert, x509_constants):
    """Verify that common name is pulled out of the cert subject when subject
    only contains the common name."""
    assert x509_constants.NAME_ATTRIBUTES[NameOID.COMMON_NAME] == saq_x509.common_name(cert)


def _cert_with_subject(private_key, x509_constants, attributes):
    name = x509.Name([x509.NameAttribute(oid, value) for oid, value in attributes])
    return x509.CertificateBuilder()\
        .subject_name(name)\
        .issuer_name(name)\
        .public_key(private_key.public_key())\
        .serial_number(x509_constants.SERIAL_NUMBER)\
        .not_valid_before(x509_constants.NOT_VALID_BEFORE)\
        .not_valid_after(x509_constants.NOT_VALID_AFTER)\
        .sign(private_key, hashes.SHA256())


@pytest.mark.unit
def test_common_name_with_escaped_comma(private_key, x509_constants):
    cert = _cert_with_subject(private_key, x509_constants, [
        (NameOID.ORGANIZATION_NAME, 'ACE Ecosystem'),
        (NameOID.COMMON_NAME, 'Example, Inc'),
    ])

    assert cert.subject.rfc4514_string() == 'CN=Example\\, Inc,O=ACE Ecosystem'
    assert 'Example, Inc' == saq_x509.common_name(cert)


@pytest.mark.unit
def test_common_name_with_other_escaped_characters(private_key, x509_constants):
    """The value comes back unescaped, not as it appears in the RFC 4514 subject string."""
    value = 'a+b "c" <d>; \\e'
    cert = _cert_with_subject(private_key, x509_constants, [(NameOID.COMMON_NAME, value)])

    assert cert.subject.rfc4514_string() != f'CN={value}'
    assert value == saq_x509.common_name(cert)


@pytest.mark.unit
def test_common_name_not_taken_from_another_attribute(private_key, x509_constants):
    """CN= inside another attribute's value is not the common name."""
    cert = _cert_with_subject(private_key, x509_constants, [
        (NameOID.ORGANIZATION_NAME, 'ACE CN=evil.example'),
    ])

    assert saq_x509.common_name(cert) is None


@pytest.mark.unit
def test_common_name_multiple_uses_most_specific(private_key, x509_constants):
    cert = _cert_with_subject(private_key, x509_constants, [
        (NameOID.COMMON_NAME, 'outer.example'),
        (NameOID.ORGANIZATION_NAME, 'ACE Ecosystem'),
        (NameOID.COMMON_NAME, 'inner.example'),
    ])

    assert 'inner.example' == saq_x509.common_name(cert)


@pytest.mark.unit
def test_common_name_empty(private_key, x509_constants):
    """An empty CN is treated as no CN."""
    # cryptography warns about (but, unvalidated, allows) a CN shorter than 1 character, both building and parsing it
    with pytest.warns(UserWarning, match="length must be >= 1"):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, '', _validate=False),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ACE Ecosystem'),
        ])
        cert = x509.CertificateBuilder()\
            .subject_name(name)\
            .issuer_name(name)\
            .public_key(private_key.public_key())\
            .serial_number(x509_constants.SERIAL_NUMBER)\
            .not_valid_before(x509_constants.NOT_VALID_BEFORE)\
            .not_valid_after(x509_constants.NOT_VALID_AFTER)\
            .sign(private_key, hashes.SHA256())
        cert = saq_x509.load_cert(cert.public_bytes(serialization.Encoding.DER))

        assert cert.subject.rfc4514_string() == 'O=ACE Ecosystem,CN='
        assert saq_x509.common_name(cert) is None


@pytest.mark.unit
def test_remove_wildcard_when_wildcard_exists():
    """Make sure prepending wildcards are removed. Specifically used
    for DNS domains / wildcard certificates."""
    domain = 'test.domain'
    domain_wildcard = f'*.{domain}'

    assert domain == saq_x509.remove_wildcard(domain_wildcard)


@pytest.mark.unit
def test_remove_wildcard_no_wildcard_to_remove():
    """make sure domain is returned unchanged if not prepended
    with a wildcard."""
    domain = 'my.test.domain'
    assert domain == saq_x509.remove_wildcard(domain)


# RFC 7468 labels; ENCRYPTED PRIVATE KEY and ATTRIBUTE CERTIFICATE end in two of these, so they add no case
@pytest.mark.parametrize('label', [
    'CERTIFICATE', 'X509 CRL', 'CERTIFICATE REQUEST', 'PKCS7', 'CMS', 'PRIVATE KEY', 'PUBLIC KEY',
])
@pytest.mark.unit
def test_is_pem_bytes_found_pem_label_or_header(label):
    """Return true if bytes string contains one of the known pem label/header endings."""
    bytes_string = f"abcdefg12345-----BEGIN {label}-----hijklmnop67890".encode('utf-8')

    assert saq_x509.is_pem_bytes(bytes_string)


@pytest.mark.unit
def test_is_pem_bytes_not_valid_pem_byte_string():
    """Return false if bytes_string does not contain a pem label/header ending."""
    bytes_string = b'abcdefg12345hijklmnop67890'

    assert not saq_x509.is_pem_bytes(bytes_string)


@pytest.mark.unit
def test_is_der_bytes_valid_der(cert_der_bytes):
    """Verify is_der_bytes returns true if bytes strin gis DER-encoded."""

    assert saq_x509.is_der_bytes(cert_der_bytes)


@pytest.mark.unit
def test_is_der_bytes_not_valid_der():
    """Verify is_der_bytes returns false if bytes string is not DER-encoded."""
    bytes_string = b'abcdefg12345hijklmnop67890'

    assert not saq_x509.is_der_bytes(bytes_string)