from flask import url_for
import pytest

from saq.constants import DEFAULT_PRUNE_VOLATILE


@pytest.mark.integration
@pytest.mark.parametrize("endpoint, key, before, after", [
    # Critical Analysis is disabled, so toggle_prune always forces Detailed Analysis
    ("analysis.toggle_prune", "prune", None, False),
    ("analysis.toggle_prune", "prune", True, False),
    ("analysis.toggle_prune", "prune", False, False),
    # toggle_prune_volatile flips the value, starting from the default when there is none
    ("analysis.toggle_prune_volatile", "prune_volatile", None, not DEFAULT_PRUNE_VOLATILE),
    ("analysis.toggle_prune_volatile", "prune_volatile", True, False),
    ("analysis.toggle_prune_volatile", "prune_volatile", False, True),
    # a value that is not a bool is reset to the default before it is flipped (a falsy one, which
    # flipped as it is would give the opposite of the default)
    ("analysis.toggle_prune_volatile", "prune_volatile", 0, not DEFAULT_PRUNE_VOLATILE),
], ids=["prune-unset", "prune-true", "prune-false",
        "volatile-unset", "volatile-true", "volatile-false", "volatile-not-a-bool"])
def test_toggle_sets_the_session_value(web_client, endpoint, key, before, after):
    if before is not None:
        with web_client.session_transaction() as sess:
            sess[key] = before

    result = web_client.post(url_for(endpoint))

    assert result.status_code == 302
    assert result.location.endswith(url_for("analysis.index"))
    with web_client.session_transaction() as sess:
        assert sess[key] is after


@pytest.mark.integration
def test_toggle_prune_get_request_rejected(web_client):
    """toggle_prune mutates session state, so it is POST-only: a GET must not change anything."""
    result = web_client.get(url_for("analysis.toggle_prune"))
    assert result.status_code == 405

    with web_client.session_transaction() as sess:
        assert 'prune' not in sess


@pytest.mark.integration
def test_toggle_prune_with_alert_uuid(web_client):
    """Test toggle_prune with alert_uuid parameter."""
    test_uuid = "12345-67890-abcdef"

    result = web_client.post(url_for("analysis.toggle_prune"), data={"alert_uuid": test_uuid})

    assert result.status_code == 302
    # Check that redirect includes the alert_uuid
    assert f"alert_uuid={test_uuid}" in result.location

    with web_client.session_transaction() as sess:
        assert sess['prune'] is False


@pytest.mark.integration
def test_toggle_prune_volatile_get_request_rejected(web_client):
    """toggle_prune_volatile mutates session state, so it is POST-only."""
    result = web_client.get(url_for("analysis.toggle_prune_volatile"))
    assert result.status_code == 405

    with web_client.session_transaction() as sess:
        assert 'prune_volatile' not in sess


@pytest.mark.integration
def test_toggle_prune_volatile_with_alert_uuid(web_client):
    """Test toggle_prune_volatile with alert_uuid parameter."""
    test_uuid = "12345-67890-abcdef"
    
    result = web_client.post(url_for("analysis.toggle_prune_volatile"), data={"alert_uuid": test_uuid})
    
    assert result.status_code == 302
    # Check that redirect includes the alert_uuid
    assert f"alert_uuid={test_uuid}" in result.location
    
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is (not DEFAULT_PRUNE_VOLATILE)


@pytest.mark.integration
def test_both_prune_functions_independent(web_client):
    """Test that toggle_prune and toggle_prune_volatile work independently."""
    # Call toggle_prune (always sets to False)
    web_client.post(url_for("analysis.toggle_prune"))

    with web_client.session_transaction() as sess:
        prune_state = sess['prune']
        assert prune_state is False

    # Toggle prune_volatile
    web_client.post(url_for("analysis.toggle_prune_volatile"))

    with web_client.session_transaction() as sess:
        prune_volatile_state = sess['prune_volatile']
        # Prune state should remain False
        assert sess['prune'] is False

    # Toggle prune_volatile again
    web_client.post(url_for("analysis.toggle_prune_volatile"))

    with web_client.session_transaction() as sess:
        # prune_volatile state should be toggled
        assert sess['prune_volatile'] != prune_volatile_state
        # prune state should remain False
        assert sess['prune'] is False