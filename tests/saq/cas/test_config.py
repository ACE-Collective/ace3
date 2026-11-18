import pytest
from pydantic import ValidationError

from saq.configuration.schema import CASConfig, CASPoolConfig


@pytest.mark.unit
def test_defaults():
    config = CASConfig()
    assert config.gc_batch_size == 500
    assert config.gc_batch_pause_seconds == 0.5
    assert config.default_grace_seconds == 86400
    assert config.read_cache.dir == "cas_cache"
    assert config.read_cache.max_bytes == 10 * 1024 ** 3
    assert config.pools == {}

    pool = CASPoolConfig()
    assert (pool.backend, pool.encryption, pool.retention, pool.shared, pool.grace_seconds) == ("local", "none", "held", False, None)
    assert (pool.compression, pool.ttl_days, pool.index_database) == ("none", None, "ace")


@pytest.mark.unit
def test_ttl_requires_ttl_days():
    with pytest.raises(ValidationError, match="retention 'ttl' requires ttl_days"):
        CASPoolConfig(retention="ttl", index_database="email_archive")


@pytest.mark.unit
def test_ttl_index_never_goes_in_the_main_database():
    with pytest.raises(ValidationError, match="never the main database"):
        CASPoolConfig(retention="ttl", ttl_days=30)

    pool = CASPoolConfig(retention="ttl", ttl_days=30, index_database="email_archive")
    assert (pool.ttl_days, pool.index_database) == (30, "email_archive")


@pytest.mark.unit
def test_ttl_days_only_with_ttl():
    with pytest.raises(ValidationError, match="ttl_days is only valid with retention 'ttl'"):
        CASPoolConfig(retention="held", ttl_days=30)


@pytest.mark.unit
def test_unknown_index_database_and_compression_are_rejected():
    with pytest.raises(ValidationError):
        CASPoolConfig(index_database="brocess")

    with pytest.raises(ValidationError):
        CASPoolConfig(compression="zstd")


@pytest.mark.unit
def test_shared_local_is_rejected():
    with pytest.raises(ValidationError, match="shared: true requires"):
        CASPoolConfig(shared=True)


@pytest.mark.unit
def test_unknown_keys_are_rejected():
    with pytest.raises(ValidationError, match="bucket"):
        CASPoolConfig.model_validate({"backend": "local", "bucket": "x"})

    with pytest.raises(ValidationError, match="gc_batchsize"):
        CASConfig.model_validate({"gc_batchsize": 1})


@pytest.mark.unit
def test_s3_is_not_a_backend_yet():
    with pytest.raises(ValidationError):
        CASPoolConfig(backend="s3")


@pytest.mark.unit
def test_custom_requires_spec_and_root_is_local_only():
    with pytest.raises(ValidationError, match="requires a 'custom' spec"):
        CASPoolConfig(backend="custom")

    spec = {"python_module": "m", "python_class": "C"}
    with pytest.raises(ValidationError, match="only valid with backend 'custom'"):
        CASPoolConfig(backend="local", custom=spec)

    with pytest.raises(ValidationError, match="only valid with backend 'local'"):
        CASPoolConfig(backend="custom", custom=spec, root="x")

    # a shared custom pool passes the schema; whether the class is node-local is checked when it loads
    assert CASPoolConfig(backend="custom", custom=spec, shared=True).shared


@pytest.mark.unit
@pytest.mark.parametrize("name", ["Bad", "with-dash", "", "a" * 65, "sp ace"])
def test_pool_names_are_validated(name):
    with pytest.raises(ValidationError, match="must match"):
        CASConfig.model_validate({"pools": {name: {}}})
