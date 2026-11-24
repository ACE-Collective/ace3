# The suite's fixtures and hooks are the plugin tests/harness.py, not a tests/conftest.py, because a
# conftest reaches only the tests in its own directory and below, and an integration's tests are
# under integrations/. pytest loads this file for every path in the checkout.
pytest_plugins = ["tests.harness"]

# the links to integrations' tests that `ace integration install` used to make: a checkout that still
# has one would run those tests twice
collect_ignore_glob = ["tests/test_external_integration_*"]
