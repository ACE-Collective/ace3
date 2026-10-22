"""Tests for lazy encrypted-secret resolution (SecretRef + get_secret TTL cache)."""

from typing import Optional
from unittest.mock import Mock

import pytest
from pydantic import BaseModel

from saq.configuration import secret_ref
from saq.configuration.config import _assert_no_unresolved_encrypted_markers
from saq.configuration.encryption import decrypt_password, delete_password, encrypt_password
from saq.configuration.secret_ref import (
    SecretRef,
    clear_secret_cache,
    get_secret,
    resolve_secret,
)
from saq.crypto import set_encryption_password


@pytest.fixture(autouse=True, scope="function")
def _clear_secret_cache():
    clear_secret_cache()


@pytest.fixture
def _unlock_encryption():
    set_encryption_password("test")


class _Model(BaseModel):
    key: Optional[SecretRef] = None


@pytest.mark.unit
class TestSecretRefValidation:
    def test_encrypted_marker_becomes_key_ref(self):
        ref = _Model(key="encrypted:vendor.api_key").key
        assert ref.key == "vendor.api_key"
        assert ref.literal is None

    def test_plaintext_becomes_literal_ref(self):
        ref = _Model(key="plainvalue").key
        assert ref.key is None
        assert ref.literal == "plainvalue"

    def test_secret_ref_passthrough(self):
        original = SecretRef(key="x")
        assert _Model(key=original).key is original

    def test_none_stays_none(self):
        assert _Model().key is None

    def test_repr_redacts_literal(self):
        assert "plainvalue" not in repr(_Model(key="plainvalue").key)
        assert repr(_Model(key="encrypted:a.b").key) == "SecretRef(key='a.b')"

    def test_serializes_back_to_marker(self):
        # round-trippable, and never emits a resolved value
        assert _Model(key="encrypted:a.b").model_dump()["key"] == "encrypted:a.b"


@pytest.mark.unit
class TestResolveSecretHelper:
    def test_resolves_literal_ref(self):
        assert resolve_secret(SecretRef(literal="v")) == "v"

    def test_passes_through_plain_str(self):
        assert resolve_secret("already-plain") == "already-plain"

    def test_none(self):
        assert resolve_secret(None) is None


@pytest.mark.integration
@pytest.mark.usefixtures("_unlock_encryption")
class TestGetSecretTTLCache:
    @pytest.fixture
    def decrypt_spy(self, monkeypatch):
        # get_secret resolves decrypt_password from the secret_ref namespace (imported at module top)
        spy = Mock(wraps=decrypt_password)
        monkeypatch.setattr(secret_ref, "decrypt_password", spy)
        return spy

    @pytest.fixture
    def stored_key(self):
        key = "test.ttl_secret"
        yield key
        delete_password(key)

    def test_caches_within_ttl(self, decrypt_spy, stored_key):
        encrypt_password(stored_key, "value1")
        assert get_secret(stored_key, ttl_seconds=100) == "value1"
        assert get_secret(stored_key, ttl_seconds=100) == "value1"
        assert decrypt_spy.call_count == 1  # only one DB hit within the TTL

    def test_cached_value_survives_rotation_until_cleared(self, stored_key):
        encrypt_password(stored_key, "v1")
        assert get_secret(stored_key, ttl_seconds=100) == "v1"
        encrypt_password(stored_key, "v2")
        assert get_secret(stored_key, ttl_seconds=100) == "v1"
        clear_secret_cache()
        assert get_secret(stored_key, ttl_seconds=100) == "v2"

    def test_expiry_forces_refetch(self, stored_key):
        encrypt_password(stored_key, "v1")
        assert get_secret(stored_key, ttl_seconds=0) == "v1"  # already expired
        encrypt_password(stored_key, "v2")
        assert get_secret(stored_key, ttl_seconds=0) == "v2"

    def test_none_is_not_cached(self, decrypt_spy, stored_key):
        assert get_secret(stored_key, ttl_seconds=100) is None
        assert get_secret(stored_key, ttl_seconds=100) is None       # still refetching (None uncached)
        encrypt_password(stored_key, "eventually")
        assert get_secret(stored_key, ttl_seconds=100) == "eventually"
        assert decrypt_spy.call_count == 3


@pytest.mark.unit
class TestStartupGuard:
    def test_raises_on_marker_in_plain_str_field(self):
        class Bad(BaseModel):
            token: Optional[str] = None

        with pytest.raises(ValueError, match="unresolved encrypted"):
            _assert_no_unresolved_encrypted_markers(Bad(token="encrypted:oops"))

    def test_passes_for_secret_ref_field(self):
        # a SecretRef field holds a SecretRef object, never a str -> no offense
        _assert_no_unresolved_encrypted_markers(_Model(key="encrypted:fine.key"))

    def test_walks_nested_and_collections(self):
        class Nested(BaseModel):
            items: list[str] = []

        with pytest.raises(ValueError, match=r"items\[1\]"):
            _assert_no_unresolved_encrypted_markers(Nested(items=["ok", "encrypted:bad"]))


@pytest.mark.integration
@pytest.mark.usefixtures("_unlock_encryption")
class TestDynamicResolutionEndToEnd:
    """A SecretRef resolves the CURRENT stored value, picking up a change after the cache clears."""

    def test_set_resolve_update_resolve(self):
        key = "test.dynamic_secret"
        ref = _Model(key=f"encrypted:{key}").key
        try:
            encrypt_password(key, "first")
            clear_secret_cache()
            assert ref.resolve() == "first"

            # rotate the secret; a running process picks it up once its cache entry clears/expires
            encrypt_password(key, "second")
            clear_secret_cache()
            assert ref.resolve() == "second"
        finally:
            delete_password(key)

    def test_unset_secret_resolves_none(self):
        ref = _Model(key="encrypted:test.never_set_xyz").key
        clear_secret_cache()
        assert ref.resolve() is None
