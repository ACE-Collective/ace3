"""The /image_full page: the full-size view of an alert image, which embeds the image from
GET /api/v2/alerts/{alert_uuid}/observables/{observable_uuid}/image (tests/aceapi_v2/alerts/test_image.py)."""

import pytest
from flask import url_for

from saq.database.util.alert import ALERT


@pytest.mark.integration
def test_image_full_missing_alert_uuid(web_client):
    """Test image_full endpoint with missing alert_uuid parameter."""
    result = web_client.get(url_for("analysis.image_full"))
    assert result.status_code == 400


@pytest.mark.integration
def test_image_full_missing_observable_uuid(web_client, root_analysis):
    """Test image_full endpoint with missing observable_uuid parameter."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.image_full"),
                          query_string={'alert_uuid': alert.uuid})
    assert result.status_code == 400


@pytest.mark.integration
def test_image_full_success(web_client, root_analysis):
    """Test successful image_full endpoint rendering."""
    root_analysis.save()
    alert = ALERT(root_analysis)
    test_observable_uuid = "test-observable-uuid"

    result = web_client.get(url_for("analysis.image_full"),
                          query_string={
                              'alert_uuid': alert.uuid,
                              'observable_uuid': test_observable_uuid
                          })
    assert result.status_code == 200
    assert f'src="/api/v2/alerts/{alert.uuid}/observables/{test_observable_uuid}/image"'.encode() in result.data
