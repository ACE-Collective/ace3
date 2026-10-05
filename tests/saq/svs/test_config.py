import pytest
from pydantic import ValidationError

from saq.configuration.config import get_analysis_module_config, get_config
from saq.configuration.schema import SVSConfig


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
