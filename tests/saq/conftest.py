from datetime import UTC, date, datetime
import ipaddress
import pytest

#
# X509 test support
#

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from saq.database.pool import get_db

# Fixtures for x509 testing. Used in saq.509.py and saq.modules.509.py
@pytest.fixture(scope='module')
def x509_constants():
    class Constants:
        SUBJECT_ALTERNATIVE_DNS_NAMES = ["alternate1.local", "alternate2.local", "subdomain.alternate2.local"]
        SUBJECT_ALTERNATIVE_IP_ADDRESSES = ["1.1.1.1", "2.2.2.2"]
        SUBJECT_ALTERNATIVE_IP_ADDRESSES_OBJECTS = [
            ipaddress.IPv4Address(ip_address) for ip_address in SUBJECT_ALTERNATIVE_IP_ADDRESSES
        ]
        NOT_VALID_BEFORE = datetime.strptime('October 6 2020 1:00PM', '%B %d %Y %I:%M%p').astimezone(UTC)
        NOT_VALID_AFTER = datetime.strptime('December 6 2020 12:59PM', '%B %d %Y %I:%M%p').astimezone(UTC)
        NAME_ATTRIBUTES = {
            NameOID.COUNTRY_NAME: "US",
            NameOID.STATE_OR_PROVINCE_NAME: "Ohio",
            NameOID.LOCALITY_NAME: "Cincinnati",
            NameOID.ORGANIZATION_NAME: "ACE Ecosystem",
            NameOID.COMMON_NAME: "common-name.local",
        }
        SERIAL_NUMBER = 555555555555555555555555555555555555555555

    yield Constants


@pytest.fixture(scope="module")
def private_key():
    """Yield an x509 private key."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )
    yield key


@pytest.fixture(scope="module")
def cert(private_key, x509_constants):
    """Yield self-signed x509.Certificate object (public key) with both DNS Names and IP Addresses in SAN extension."""
    issuer = x509.Name([
        x509.NameAttribute(attr_name, value) for attr_name, value in x509_constants.NAME_ATTRIBUTES.items()
    ])

    alternative_names = [x509.DNSName(dns_name) for dns_name in x509_constants.SUBJECT_ALTERNATIVE_DNS_NAMES]
    alternative_names += [
        x509.IPAddress(ip_address) for ip_address in x509_constants.SUBJECT_ALTERNATIVE_IP_ADDRESSES_OBJECTS
    ]

    cert = x509.CertificateBuilder()\
        .subject_name(issuer)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509_constants.SERIAL_NUMBER)\
        .not_valid_before(x509_constants.NOT_VALID_BEFORE)\
        .not_valid_after(x509_constants.NOT_VALID_AFTER)\
        .add_extension(
            x509.SubjectAlternativeName(alternative_names),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

    yield cert


@pytest.fixture(scope="module")
def cert_no_alt(private_key, x509_constants):
    """Yield x509.Certificate with no SAN extension."""
    issuer = x509.Name([x509.NameAttribute(attr_name, value) for attr_name, value in x509_constants.NAME_ATTRIBUTES.items()])

    cert = x509.CertificateBuilder() \
        .subject_name(issuer) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(x509_constants.SERIAL_NUMBER) \
        .not_valid_before(x509_constants.NOT_VALID_BEFORE) \
        .not_valid_after(x509_constants.NOT_VALID_AFTER).sign(private_key, hashes.SHA256(), default_backend())

    yield cert


@pytest.fixture(scope="module")
def cert_pem_bytes(cert):
    """Yield PEM byte string of the certificate."""
    yield cert.public_bytes(encoding=serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def cert_der_bytes(cert):
    """Yield DER byte string of the certificate."""
    yield cert.public_bytes(encoding=serialization.Encoding.DER)


@pytest.fixture(scope='function')
def der_cert_file(cert_der_bytes, tmp_path):
    """Create a temporary der-encoded certificate on disk."""
    path_to_file = str(tmp_path.joinpath('test_cert.der'))
    with open(path_to_file, 'wb') as f:
        f.write(cert_der_bytes)
    yield path_to_file


@pytest.fixture(scope='function')
def pem_cert_file(cert_pem_bytes, tmp_path):
    """Create a temporary pem-encoded certificate on disk."""
    path_to_file = str(tmp_path.joinpath('test_cert.pem'))
    with open(path_to_file, 'wb') as f:
        f.write(cert_pem_bytes)
    yield path_to_file


@pytest.fixture(scope='function')
def cert_on_disk(der_cert_file, pem_cert_file):
    """For parametrization purposes to test multiple certificate encodings with
    the same test."""
    yield {
        'pem-encoded': pem_cert_file,
        'der-encoded': der_cert_file,
    }

#
# END X509 test support
#

@pytest.fixture(scope='function')
def db_event():
    """Creates an empty Event and adds it to the database."""
    import saq
    from saq.database import Event, EventPreventionTool, EventRemediation, EventRiskLevel, EventStatus, EventType, EventVector

    # Add the required event prevention tool
    prevention_tool = EventPreventionTool(value='test_prevention_tool')
    get_db().add(prevention_tool)

    # Add the required event remediation
    remediation = EventRemediation(value='test_remediation')
    get_db().add(remediation)

    # Add the required event risk level
    risk_level = EventRiskLevel(value='test_risk_level')
    get_db().add(risk_level)

    # Add the required event status
    status = EventStatus(value='OPEN')
    get_db().add(status)

    # Add the required event type
    event_type = EventType(value='test_type')
    get_db().add(event_type)

    # Add the required event vector
    vector = EventVector(value='test_vector')
    get_db().add(vector)

    # Create the actual event
    event = Event(
        name='Test Event',
        creation_date=date.today(),
        prevention_tool=prevention_tool,
        remediation=remediation,
        risk_level=risk_level,
        status=status,
        type=event_type,
        vector=vector
    )

    get_db().add(event)
    get_db().commit()

    return event
