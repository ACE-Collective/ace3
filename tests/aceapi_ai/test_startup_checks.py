"""One test per custody rule, constructing the violating (and passing) configurations directly.

The checks run only in the api_ai_uvicorn entrypoint -- the unit-test environment legitimately
has SAQ_ENC and no sentinels -- so these tests call the check functions themselves.
"""

import pytest

from aceapi_ai.startup_checks import (
    AI_UNUSED_SENTINEL,
    advisory_plaintext_sweep,
    check_backend_credentials,
    check_infra_secrets_neutralized,
    check_local_overlay_skipped,
    check_no_encryption_capability,
    check_secret_literal_allowlist,
    run_startup_checks,
)
from saq.configuration.config import get_config
from saq.configuration.secret_ref import SecretRef
from saq.environment import get_global_runtime_settings

pytestmark = pytest.mark.integration


@pytest.fixture
def failures() -> list[str]:
    return []


class TestEncryptionCapability:
    def test_saq_enc_present_fails(self, failures, monkeypatch):
        monkeypatch.setenv("SAQ_ENC", "test")
        check_no_encryption_capability(failures)
        assert any("SAQ_ENC" in f for f in failures)

    def test_unlocked_encryption_fails(self, failures, monkeypatch):
        monkeypatch.delenv("SAQ_ENC", raising=False)
        monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", "unlocked")
        check_no_encryption_capability(failures)
        assert any("secrets table" in f for f in failures)

    def test_locked_and_unset_passes(self, failures, monkeypatch):
        monkeypatch.delenv("SAQ_ENC", raising=False)
        monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)
        check_no_encryption_capability(failures)
        assert failures == []


class TestLocalOverlay:
    def test_missing_env_var_fails(self, failures, monkeypatch):
        monkeypatch.delenv("SAQ_SKIP_LOCAL_SAQ_YAML", raising=False)
        check_local_overlay_skipped(failures)
        assert len(failures) == 1

    def test_set_env_var_passes(self, failures, monkeypatch):
        monkeypatch.setenv("SAQ_SKIP_LOCAL_SAQ_YAML", "1")
        check_local_overlay_skipped(failures)
        assert failures == []


@pytest.fixture
def sentineled_infra(monkeypatch):
    config = get_config()
    monkeypatch.setattr(config.api, "secret_key", AI_UNUSED_SENTINEL)
    monkeypatch.setattr(config.api, "api_key", AI_UNUSED_SENTINEL)
    monkeypatch.setattr(config.gui, "secret_key", AI_UNUSED_SENTINEL)


class TestInfraSecrets:
    def test_unittest_config_fails(self, failures):
        # the test config carries real (test) flask/node keys -- exactly what must fail
        check_infra_secrets_neutralized(failures)
        assert len(failures) == 3

    def test_sentineled_config_passes(self, failures, sentineled_infra):
        check_infra_secrets_neutralized(failures)
        assert failures == []


@pytest.fixture
def splunk_readonly_token(monkeypatch):
    monkeypatch.setattr(
        get_config().get_splunk_config("test_api"), "token", SecretRef(literal="readonly-token"))


@pytest.fixture
def no_stray_literals(monkeypatch):
    # the unittest config carries a plaintext shodan test key, which the allow-list correctly
    # flags; clear it so these tests exercise the rule, not the test fixture data
    monkeypatch.setattr(get_config().shodan, "api_key", None)


class TestBackendCredentials:
    def test_missing_backend_credential_fails(self, failures):
        # the unittest splunk config has no credential at all
        check_backend_credentials(failures)
        assert any(f.startswith("backend splunk:") for f in failures)

    def test_backends_with_credentials_pass(self, failures, splunk_readonly_token):
        declared = check_backend_credentials(failures)
        assert failures == []
        assert declared == ["splunk_config_test_api.token"]


class TestSecretLiteralAllowlist:
    def test_declared_literal_passes(self, failures, splunk_readonly_token, no_stray_literals):
        check_secret_literal_allowlist(failures, ["splunk_config_test_api.token"])
        assert failures == []

    def test_undeclared_literal_fails(self, failures, splunk_readonly_token, no_stray_literals):
        check_secret_literal_allowlist(failures, [])
        assert len(failures) == 1
        assert "splunk_config_test_api.token" in failures[0]

    def test_stray_literal_in_unittest_config_is_flagged(self, failures):
        # the shodan test key present in the unittest config is exactly the kind of stray
        # plaintext credential the rule exists for
        check_secret_literal_allowlist(failures, [])
        assert any("shodan.api_key" in f for f in failures)

    def test_encrypted_refs_elsewhere_are_permitted(self, failures, no_stray_literals, monkeypatch):
        # a key= ref is unreadable in this process by construction; only literals are custody
        monkeypatch.setattr(
            get_config().get_splunk_config("default"), "token", SecretRef(key="splunk_token"))
        check_secret_literal_allowlist(failures, [])
        assert failures == []


class TestRunStartupChecks:
    def test_unittest_environment_refuses_boot(self, monkeypatch):
        monkeypatch.setenv("SAQ_ENC", "test")
        with pytest.raises(RuntimeError, match="custody checks failed"):
            run_startup_checks()

    def test_conforming_environment_boots(self, monkeypatch, sentineled_infra, splunk_readonly_token, no_stray_literals):
        monkeypatch.delenv("SAQ_ENC", raising=False)
        monkeypatch.setenv("SAQ_SKIP_LOCAL_SAQ_YAML", "1")
        monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)
        run_startup_checks()


@pytest.mark.usefixtures("sentineled_infra")
def test_advisory_sweep_flags_plaintext_looking_fields(monkeypatch):
    config = get_config()
    monkeypatch.setattr(config.sip, "api_key", "a-real-looking-value")
    warnings = advisory_plaintext_sweep()
    assert "sip.api_key" in warnings
    # infrastructure exclusions stay silent
    assert "redis.password" not in warnings
