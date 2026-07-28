"""Tests for the aceapi_v2 encrypted-secrets service."""

import pytest

from aceapi_v2.secrets import service
from aceapi_v2.secrets.schemas import validate_secret_key
from saq.configuration.encryption import (
    delete_password,
    find_effective_encrypted_config_references,
    find_encrypted_config_references,
    list_encrypted_password_keys,
)

pytestmark = pytest.mark.integration


class TestGetSecretsPage:
    @pytest.mark.asyncio
    async def test_merges_stored_and_referenced(self, monkeypatch):
        monkeypatch.setattr(service, "list_encrypted_password_keys", lambda: ["stored.only", "both"])
        monkeypatch.setattr(service, "find_encrypted_config_references", lambda: {"both", "ref.only"})
        # every declared marker still resolves from the store -> nothing is overridden
        monkeypatch.setattr(service, "find_effective_encrypted_config_references", lambda: {"both", "ref.only"})

        page = await service.get_secrets_page()
        by_key = {s.key: s for s in page.secrets}

        # sorted union of both sets
        assert [s.key for s in page.secrets] == ["both", "ref.only", "stored.only"]
        assert by_key["stored.only"].is_set and not by_key["stored.only"].is_referenced
        assert by_key["ref.only"].is_referenced and not by_key["ref.only"].is_set
        assert by_key["both"].is_set and by_key["both"].is_referenced
        assert not any(s.is_overridden for s in page.secrets)

    @pytest.mark.asyncio
    async def test_plaintext_override_flagged(self, monkeypatch):
        """A declared, unset name whose marker is masked in the effective config is 'overridden'."""
        monkeypatch.setattr(service, "list_encrypted_password_keys", lambda: [])
        monkeypatch.setattr(service, "find_encrypted_config_references", lambda: {"overridden.key", "live.key"})
        # only live.key still carries its marker in the effective config; overridden.key was masked
        monkeypatch.setattr(service, "find_effective_encrypted_config_references", lambda: {"live.key"})

        page = await service.get_secrets_page()
        by_key = {s.key: s for s in page.secrets}
        assert by_key["overridden.key"].is_overridden is True
        assert by_key["overridden.key"].is_referenced is True
        assert by_key["live.key"].is_overridden is False

    @pytest.mark.asyncio
    async def test_set_secret_is_not_flagged_overridden(self, monkeypatch):
        """A stored value is in use regardless of the effective-config walk, so never 'overridden'."""
        monkeypatch.setattr(service, "list_encrypted_password_keys", lambda: ["set.key"])
        monkeypatch.setattr(service, "find_encrypted_config_references", lambda: {"set.key"})
        monkeypatch.setattr(service, "find_effective_encrypted_config_references", lambda: set())

        page = await service.get_secrets_page()
        entry = page.secrets[0]
        assert entry.is_set is True
        assert entry.is_overridden is False

    @pytest.mark.asyncio
    async def test_never_returns_a_value(self, monkeypatch):
        """The page schema must not carry a plaintext value anywhere."""
        monkeypatch.setattr(service, "list_encrypted_password_keys", lambda: ["a"])
        monkeypatch.setattr(service, "find_encrypted_config_references", lambda: set())
        monkeypatch.setattr(service, "find_effective_encrypted_config_references", lambda: set())
        page = await service.get_secrets_page()
        assert "value" not in page.secrets[0].model_dump()


class TestSetSecret:
    @pytest.mark.asyncio
    async def test_locked_raises(self, monkeypatch):
        monkeypatch.setattr(service, "encryption_unlocked", lambda: False)
        with pytest.raises(service.SecretsLockedError):
            await service.set_secret("x.y", "value")

    @pytest.mark.asyncio
    async def test_round_trip_set_and_delete(self):
        """A real encrypt/store then delete against the encrypted_passwords table."""
        key = "test.svc_round_trip"
        try:
            entry = await service.set_secret(key, "s3cr3t")
            assert entry.key == key
            assert entry.is_set is True
            assert key in list_encrypted_password_keys()
        finally:
            assert await service.delete_secret(key) is True
        assert key not in list_encrypted_password_keys()

    @pytest.mark.asyncio
    async def test_delete_unknown_returns_false(self):
        assert await service.delete_secret("test.does_not_exist_xyz") is False


class TestFindConfigReferences:
    def test_walks_loaded_files_for_encrypted_prefix(self, monkeypatch, tmp_path):
        # a config file the "running process" is pretending to have loaded
        cfg = tmp_path / "refs.yaml"
        cfg.write_text(
            "virustotal:\n"
            "  api_key: encrypted:vt.api_key\n"
            "nested:\n"
            "  deep:\n"
            "    pw: encrypted:deep.pw\n"
            "listy:\n"
            "  - plain\n"
            "  - encrypted:list.item\n"
            "plain: not-a-secret\n"
        )

        import types
        fake_config = types.SimpleNamespace(raw=types.SimpleNamespace(loaded_files={str(cfg)}))
        monkeypatch.setattr("saq.configuration.config.get_config", lambda name=None: fake_config)

        refs = find_encrypted_config_references()
        assert refs == {"vt.api_key", "deep.pw", "list.item"}

    def test_effective_walk_reads_live_config(self, monkeypatch):
        import types
        fake_config = types.SimpleNamespace(raw=types.SimpleNamespace(_data={
            "virustotal": {"api_key": "encrypted:vt.api_key"},   # marker survives -> in use
            "rapid7": {"api_key": "cebafe17-plaintext"},          # overridden -> no marker
        }))
        monkeypatch.setattr("saq.configuration.config.get_config", lambda name=None: fake_config)
        assert find_effective_encrypted_config_references() == {"vt.api_key"}


class TestKeyValidation:
    def test_accepts_config_safe_names(self):
        assert validate_secret_key(" vt.api_key ") == "vt.api_key"

    @pytest.mark.parametrize("bad", ["", "   ", "has space", "semi;colon", "a" * 257])
    def test_rejects_bad_names(self, bad):
        with pytest.raises(ValueError):
            validate_secret_key(bad)


@pytest.fixture(autouse=True)
def _cleanup_leaked_keys():
    """Belt-and-suspenders: remove any test.* secrets a failed test may have committed."""
    yield
    for key in list_encrypted_password_keys():
        if key.startswith("test."):
            delete_password(key)
