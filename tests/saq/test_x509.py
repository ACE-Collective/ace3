
import hashlib

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
import pytest

from saq import x509 as saq_x509


@pytest.mark.unit
def test_load_cert_pem(cert_pem_bytes):
    """Validate the pem byte string is turned into an x509.Certificate
    and that it has the same PEM encoding content as the original certificate."""

    # setup
    cert = saq_x509.load_cert_pem(cert_pem_bytes)

    # verify
    assert isinstance(cert, x509.Certificate)
    assert cert_pem_bytes == cert.public_bytes(encoding=serialization.Encoding.PEM)


@pytest.mark.unit
def test_load_cert_pem_return_none(cert_der_bytes):
    """Validate that None is returned when byte string is not a PEM-encoded certificate."""

    # setup
    cert = saq_x509.load_cert_pem(cert_der_bytes)

    # verify
    assert cert is None


@pytest.mark.unit
def test_load_cert_der(cert_der_bytes):
    """Validate the pem byte string is turned into an x509.Certificate
    and that it has the same PEM encoding content as the original certificate."""

    # setup
    cert = saq_x509.load_cert_der(cert_der_bytes)

    # verify
    assert isinstance(cert, x509.Certificate)
    assert cert_der_bytes == cert.public_bytes(encoding=serialization.Encoding.DER)


@pytest.mark.unit
def test_load_cert_der_return_none(cert_pem_bytes):
    """Validate that None is returned when byte string is not a DER-encoded certificate."""

    # setup
    cert = saq_x509.load_cert_der(cert_pem_bytes)

    # verify
    assert cert is None


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
def test_sha1(cert):
    """Validate the DER sha1 hash of the cert is returned."""
    # setup
    expected_der = cert.public_bytes(encoding=serialization.Encoding.DER)
    expected_sha1 = hashlib.sha1(expected_der).hexdigest()

    # verify
    assert expected_sha1 == saq_x509.sha1(cert)


@pytest.mark.unit
def test_sha256(cert):
    """Validate the DER sha256 hash of the cert is returned."""
    # setup
    expected_der = cert.public_bytes(encoding=serialization.Encoding.DER)
    expected_sha256 = hashlib.sha256(expected_der).hexdigest()

    # verify
    assert expected_sha256 == saq_x509.sha256(cert)


@pytest.mark.unit
def test_serial_number(cert):
    """Validate certificate serial number is returned as expected."""
    assert cert.serial_number == saq_x509.serial_number(cert)


@pytest.mark.unit
def test_issuer(cert):
    """Validate certificate issuer is returned as expected."""
    assert cert.issuer.rfc4514_string() == saq_x509.issuer(cert)


@pytest.mark.unit
def test_subject(cert):
    """Validate certificate subject is returned as expected."""
    assert cert.subject.rfc4514_string() == saq_x509.subject(cert)


@pytest.mark.unit
def test_not_valid_before(cert, x509_constants):
    """Validate the correct 'not valid before' datetime object is returned."""
    assert x509_constants.NOT_VALID_BEFORE == saq_x509.not_valid_before(cert)


@pytest.mark.unit
def test_not_valid_after(cert, x509_constants):
    """Validate the correct 'not valid after' datetime object is returned."""
    assert x509_constants.NOT_VALID_AFTER == saq_x509.not_valid_after(cert)


@pytest.mark.unit
def test_get_san_extension_valid_extension(cert):
    """Validate SAN extension is returned when it exists in a certificate"""
    extension = saq_x509._get_san_extension(cert)

    assert x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME == extension.oid


@pytest.mark.unit
def test_get_san_extension_extension_not_found(cert_no_alt):
    """Validate 'None' is returned when SAN extension is not found."""
    assert saq_x509._get_san_extension(cert_no_alt) is None


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
def test_san_dns_names_no_names_included_but_san_exists(cert_ip_alternative_only):
    """If alternative names exist, but none are DNSNames, then it should return
    an empty list."""
    assert [] == saq_x509.san_dns_names(cert_ip_alternative_only)


@pytest.mark.unit
def test_san_ip_addresses(cert, x509_constants):
    """Test if IP Addresses are pulled from certificate SAN extension."""
    assert x509_constants.SUBJECT_ALTERNATIVE_IP_ADDRESSES == saq_x509.san_ip_addresses(cert)


@pytest.mark.unit
def test_san_ip_addresses_missing_san_extension(cert_no_alt):
    """Verify empty list is returned if san extension is missing from certificate."""
    assert [] == saq_x509.san_ip_addresses(cert_no_alt)


@pytest.mark.unit
def test_san_ip_addresses_no_ip_included_but_san_exists(cert_dns_alternative_only):
    """Verify empty list is returned if san exists, but does not include IP Addresses."""
    assert [] == saq_x509.san_ip_addresses(cert_dns_alternative_only)


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
def test_common_name_success_long_subject(private_key, x509_constants):
    """Tests that regex pulls out the domain when the CN is not the only
    attribute in the subject."""

    # setup
    domain = 'test.local'
    cert = _cert_with_subject(private_key, x509_constants, [
        (NameOID.COUNTRY_NAME, 'US'),
        (NameOID.STATE_OR_PROVINCE_NAME, 'Ohio'),
        (NameOID.LOCALITY_NAME, 'Cincinnati'),
        (NameOID.ORGANIZATION_NAME, 'ACE, Inc'),
        (NameOID.COMMON_NAME, domain),
    ])

    # verify
    assert cert.subject.rfc4514_string() == f'CN={domain},O=ACE\\, Inc,L=Cincinnati,ST=Ohio,C=US'
    assert domain == saq_x509.common_name(cert)


@pytest.mark.unit
def test_common_name_success_cn_only(private_key, x509_constants):
    """Tests that regex pulls out the domain when the CN is the only
    attribute in the subject."""

    # setup
    domain = 'test.local'
    cert = _cert_with_subject(private_key, x509_constants, [(NameOID.COMMON_NAME, domain)])

    # verify
    assert domain == saq_x509.common_name(cert)


@pytest.mark.unit
@pytest.mark.xfail(strict=True, reason="common_name's regex CN=([^,$]+) stops at the backslash of an RFC 4514 escaped comma")
def test_common_name_with_escaped_comma(private_key, x509_constants):
    cert = _cert_with_subject(private_key, x509_constants, [
        (NameOID.ORGANIZATION_NAME, 'ACE Ecosystem'),
        (NameOID.COMMON_NAME, 'Example, Inc'),
    ])

    assert 'Example, Inc' == saq_x509.common_name(cert)


@pytest.mark.unit
def test_common_name_failed_subject_doesnt_contain_common_name(private_key, x509_constants):
    """Test attribute error is handled appropriately when regex doesn't
    match because the CN is missing from the subject."""

    # setup
    cert = _cert_with_subject(private_key, x509_constants, [
        (NameOID.COUNTRY_NAME, 'US'),
        (NameOID.STATE_OR_PROVINCE_NAME, 'Ohio'),
        (NameOID.LOCALITY_NAME, 'Cincinnati'),
        (NameOID.ORGANIZATION_NAME, 'ACE Ecosystem'),
    ])

    # verify
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


@pytest.mark.parametrize('test_bytes', saq_x509.PEM_LABEL_ENDINGS)
@pytest.mark.unit
def test_is_pem_bytes_found_pem_label_or_header(test_bytes):
    """Return true if bytes string contains one of the known pem label/header endings."""
    utf_8 = f"abcdefg12345{test_bytes.decode('utf-8')}hijklmnop67890"
    bytes_string = utf_8.encode('utf-8')

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