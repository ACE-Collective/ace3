import pytest
from pydantic import ValidationError

from saq.configuration.config import get_analysis_module_config, get_config
from saq.configuration.schema import ACEConfig, SVSConfig
from saq.svs.yara.replay import ReplayError, _check_work_root


@pytest.mark.unit
def test_the_sample_pool_is_defined():
    config = get_config()
    assert config.svs.samples.pool == "svs_samples"
    pool = config.cas.pools["svs_samples"]
    assert pool.backend == "local"
    assert pool.encryption == "system"
    assert pool.retention == "held"
    assert not pool.shared


@pytest.mark.unit
def test_capture_runs_in_dispositioned_mode():
    assert get_analysis_module_config("svs_yara_sample_capture").enabled
    assert "svs_yara_sample_capture" in get_config().get_analysis_mode_config("dispositioned").enabled_modules


@pytest.mark.unit
def test_unknown_svs_keys_are_rejected():
    with pytest.raises(ValidationError):
        SVSConfig.model_validate({"samples": {"pool": "svs_samples", "nope": 1}})

    with pytest.raises(ValidationError):
        SVSConfig.model_validate({"nope": {}})


@pytest.mark.unit
@pytest.mark.parametrize("timings", [
    {"lease_seconds": 10, "heartbeat_interval_seconds": 30},    # the lease ends before the heartbeat
    {"lease_seconds": 60, "heartbeat_interval_seconds": 30},    # one late heartbeat loses it
])
def test_a_lease_its_heartbeat_cannot_keep_is_refused_when_the_configuration_is_read(timings):
    """Not only when service_svs starts: every process refuses the configuration."""
    raw = get_config().raw._data
    with pytest.raises(ValidationError, match="service_svs: .*must not exceed lease_seconds"):
        ACEConfig.model_validate({**raw, "service_svs": {**raw["service_svs"], **timings}})

    assert ACEConfig.model_validate({**raw, "service_svs": {**raw["service_svs"], "lease_seconds": 90,
                                                            "heartbeat_interval_seconds": 30}})


@pytest.mark.unit
def test_yara_validation_defaults():
    config = get_config().svs.yara
    assert config.repositories == []
    assert config.max_concurrent_validations == 1
    # the export of a commit is uncapped unless a site sets a limit
    assert config.max_archive_bytes is None
    assert config.max_archive_members is None
    # the compile and the scan get no network at all
    assert config.sandbox.allowed_tcp_ports == []

    with pytest.raises(ValidationError):
        SVSConfig.model_validate({"yara": {"nope": 1}})

    for key in ("max_archive_bytes", "max_archive_members"):
        assert getattr(SVSConfig.model_validate({"yara": {key: 10}}).yara, key) == 10
        with pytest.raises(ValidationError):
            SVSConfig.model_validate({"yara": {key: 0}})


@pytest.mark.unit
def test_a_work_dir_with_a_dot_is_refused(tmp_path):
    _check_work_root(str(tmp_path / "svs" / "work"))
    with pytest.raises(ReplayError, match="has a '.' in its path"):
        _check_work_root(str(tmp_path / "svs.d" / "work"))


@pytest.mark.unit
def test_coverage_defaults():
    assert get_config().svs.coverage.refresh_interval_seconds == 120
    with pytest.raises(ValidationError):
        SVSConfig.model_validate({"coverage": {"refresh_interval_seconds": 0}})
    with pytest.raises(ValidationError):
        SVSConfig.model_validate({"coverage": {"nope": 1}})
