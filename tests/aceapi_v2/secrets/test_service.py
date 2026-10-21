"""Tests for the aceapi_v2 encrypted-secrets service."""

import pytest
import yaml

from aceapi_v2.secrets import service
from aceapi_v2.secrets.schemas import validate_secret_key
from saq.configuration.config import get_config
from saq.configuration.encryption import (
    delete_password,
    encrypt_password,
    find_effective_encrypted_config_references,
    find_encrypted_config_references,
    list_encrypted_password_keys,
)
from saq.environment import get_global_runtime_settings

pytestmark = pytest.mark.integration


def _declare(monkeypatch, tmp_path, declared: set[str], effective: set[str]):
    """Has a loaded config file declare ``encrypted:<name>`` for each of ``declared``, and leaves
    the marker in the effective config only for ``effective`` (the rest were masked by a later
    plaintext value)."""
    cfg = tmp_path / "secrets.yaml"
    cfg.write_text(yaml.safe_dump({"test_secrets": {name: f"encrypted:{name}" for name in sorted(declared)}}))
    raw = get_config().raw
    monkeypatch.setattr(raw, "loaded_files", raw.loaded_files | {str(cfg)})
    monkeypatch.setitem(raw._data, "test_secrets", {
        name: f"encrypted:{name}" if name in effective else "plaintext-override" for name in sorted(declared)})


def _test_entries(page):
    return {s.key: s for s in page.secrets if s.key.startswith("test.")}


class TestGetSecretsPage:
    @pytest.mark.asyncio
    async def test_merges_stored_and_referenced(self, monkeypatch, tmp_path):
        encrypt_password("test.stored_only", "v")
        encrypt_password("test.both", "v")
        # every declared marker still resolves from the store -> nothing is overridden
        _declare(monkeypatch, tmp_path, {"test.both", "test.ref_only"}, {"test.both", "test.ref_only"})

        page = await service.get_secrets_page()
        by_key = _test_entries(page)

        # sorted union of both sets
        assert [s.key for s in page.secrets if s.key in by_key] == ["test.both", "test.ref_only", "test.stored_only"]
        assert [s.key for s in page.secrets] == sorted(s.key for s in page.secrets)
        assert by_key["test.stored_only"].is_set and not by_key["test.stored_only"].is_referenced
        assert by_key["test.ref_only"].is_referenced and not by_key["test.ref_only"].is_set
        assert by_key["test.both"].is_set and by_key["test.both"].is_referenced
        assert not any(s.is_overridden for s in by_key.values())
        assert page.encryption_unlocked is True

    @pytest.mark.asyncio
    async def test_plaintext_override_flagged(self, monkeypatch, tmp_path):
        """A declared, unset name whose marker is masked in the effective config is 'overridden'."""
        # only test.live still carries its marker in the effective config; test.overridden was masked
        _declare(monkeypatch, tmp_path, {"test.overridden", "test.live"}, {"test.live"})

        page = await service.get_secrets_page()
        by_key = _test_entries(page)
        assert by_key["test.overridden"].is_overridden is True
        assert by_key["test.overridden"].is_referenced is True
        assert by_key["test.live"].is_overridden is False

    @pytest.mark.asyncio
    async def test_set_secret_is_not_flagged_overridden(self, monkeypatch, tmp_path):
        """A stored value is in use regardless of the effective-config walk, so never 'overridden'."""
        encrypt_password("test.set_key", "v")
        _declare(monkeypatch, tmp_path, {"test.set_key"}, set())

        page = await service.get_secrets_page()
        entry = _test_entries(page)["test.set_key"]
        assert entry.is_set is True
        assert entry.is_overridden is False

    @pytest.mark.asyncio
    async def test_never_returns_a_value(self):
        """The page schema must not carry a plaintext value anywhere."""
        encrypt_password("test.a", "s3cr3t")
        page = await service.get_secrets_page()
        entry = _test_entries(page)["test.a"]
        assert "value" not in entry.model_dump()
        assert "s3cr3t" not in page.model_dump_json()


class TestSetSecret:
    @pytest.mark.asyncio
    async def test_locked_raises(self, monkeypatch):
        monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)
        with pytest.raises(service.SecretsLockedError):
            await service.set_secret("test.locked", "value")
        assert "test.locked" not in list_encrypted_password_keys()

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
        monkeypatch.setattr(get_config().raw, "loaded_files", {str(cfg)})

        refs = find_encrypted_config_references()
        assert refs == {"vt.api_key", "deep.pw", "list.item"}

    def test_effective_walk_reads_live_config(self, monkeypatch):
        monkeypatch.setattr(get_config().raw, "_data", {
            "virustotal": {"api_key": "encrypted:vt.api_key"},   # marker survives -> in use
            "rapid7": {"api_key": "cebafe17-plaintext"},          # overridden -> no marker
        })
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
