import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from saq.analysis.root import load_root
from saq.constants import ANALYSIS_MODULE_FILE_TYPE, ANALYSIS_MODULE_X509_ANALYZER, F_FQDN
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.x509 import X509Analysis
from saq.util.uuid import get_storage_dir

WHITESPACE = b" \t\n\r\x0b\x0c"


def _certificate(trailing_whitespace: bool) -> x509.Certificate:
    """A certificate for leaf.example.com whose DER encoding does, or does not, end in a whitespace byte.
    The last byte is part of the signature, so about 2% of certificates end in one."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("alt.example.com")]), critical=False))
    # ECDSA signatures are randomized, so signing again gives a different last byte
    while True:
        certificate = builder.sign(key, hashes.SHA256())
        der = certificate.public_bytes(serialization.Encoding.DER)
        if (der[-1] in WHITESPACE) == trailing_whitespace:
            return certificate


def _analyze(root_analysis, path: str) -> X509Analysis:
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_file_observable(path)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_FILE_TYPE, "test_groups")
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_X509_ANALYZER, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(observable.uuid).get_and_load_analysis(X509Analysis)


@pytest.mark.integration
def test_der_certificate_ending_in_whitespace_byte(root_analysis, tmp_path):
    path = tmp_path / "leaf.der"
    path.write_bytes(_certificate(trailing_whitespace=True).public_bytes(serialization.Encoding.DER))

    analysis = _analyze(root_analysis, str(path))

    assert analysis is not None
    assert analysis.common_name == "leaf.example.com"
    assert {o.value for o in analysis.get_observables_by_type(F_FQDN)} == {"leaf.example.com", "alt.example.com"}


@pytest.mark.integration
def test_pem_certificate_with_surrounding_whitespace(root_analysis, tmp_path):
    pem = _certificate(trailing_whitespace=False).public_bytes(serialization.Encoding.PEM)
    path = tmp_path / "leaf.pem"
    path.write_bytes(b"\n\n  " + pem.replace(b"\n", b"\r\n") + b"\r\n\n  ")

    analysis = _analyze(root_analysis, str(path))

    assert analysis is not None
    assert analysis.common_name == "leaf.example.com"
