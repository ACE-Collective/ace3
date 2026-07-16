import pytest
import yaml


def pytest_configure(config):
    config.addinivalue_line("markers", "unit: unit tests")
    config.option.asyncio_mode = "auto"


@pytest.fixture
def sample_config_data():
    """returns a valid config dict matching the phishkit_config.yaml structure"""
    return {
        "skip_body_extensions": [".png", ".jpg", ".css"],
        "skip_body_url_patterns": ["googleapis.com", "google-analytics"],
        "bypasses": [
            {
                "type": "CloudFlare Phishing",
                "searches": ["flagged as phishing"],
                "selectors": ["button.cf-btn"],
            },
            {
                "type": "Antibot",
                "searches": ["Verify you are human"],
                "handler": "visual_checkbox_bypass",
            },
        ],
        "handlers": {
            "visual_checkbox_bypass": {
                "checkbox_pngs": ["iVBORw0KGgo="],
            }
        },
        "non_rendered_content_types": [
            "application/javascript",
            "application/json",
            "text/css",
            "text/javascript",
            "text/plain",
        ],
        "script_content_types": [
            "application/javascript",
            "application/x-javascript",
            "text/javascript",
        ],
    }


@pytest.fixture
def config_file(tmpdir, sample_config_data):
    """writes sample config to a YAML file and returns the path"""
    config_path = str(tmpdir.join("phishkit_config.yaml"))
    with open(config_path, "w") as f:
        yaml.dump(sample_config_data, f)
    return config_path


@pytest.fixture
def scanner(config_file):
    """returns a Scanner instance with test config"""
    from scanner import Scanner
    return Scanner(config_path=config_file)
