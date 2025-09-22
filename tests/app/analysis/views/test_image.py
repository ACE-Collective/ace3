import os
import pytest
from unittest.mock import patch, mock_open
from flask import url_for

from saq.constants import F_FILE
from saq.database.model import Alert
from saq.database.util.alert import ALERT
from saq.observables.file import FileObservable
from tests.saq.helpers import create_root_analysis, insert_alert

# a single pixel PNG image (1x1 transparent pixel)
TEST_IMAGE_DATA = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01' \
                   b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xdac\xf8\x0f' \
                   b'\x00\x01\x01\x01\x00\x18\xdd\x8d\x18\x00\x00\x00\x00IEND\xaeB`\x82'


@pytest.mark.integration
def test_image_missing_alert_uuid(web_client):
    """Test image endpoint with missing alert_uuid parameter."""
    result = web_client.get(url_for("analysis.image"))
    assert result.status_code == 400


@pytest.mark.integration
def test_image_missing_observable_uuid(web_client, root_analysis):
    """Test image endpoint with missing observable_uuid parameter."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.image"), 
                          query_string={'alert_uuid': alert.uuid})
    assert result.status_code == 400


@pytest.mark.integration
def test_image_invalid_alert_uuid(web_client):
    """Test image endpoint with invalid alert UUID."""
    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': 'invalid-uuid',
                              'observable_uuid': 'test-observable-uuid'
                          })
    assert result.status_code == 404


@pytest.mark.integration
def test_image_nonexistent_observable(web_client, root_analysis):
    """Test image endpoint with nonexistent observable UUID."""
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': alert.uuid,
                              'observable_uuid': 'nonexistent-uuid'
                          })
    assert result.status_code == 404
    assert b"unknown file" in result.data


@pytest.mark.integration
def test_image_success(web_client, root_analysis, tmpdir):
    """Test successful image endpoint with valid file."""
    # Create a test image file
    target_path = tmpdir / "test_image.png"
    image_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
    target_path.write_binary(image_data)

    # Add file observable
    file_observable = root_analysis.add_file_observable(str(target_path))
    assert file_observable.mime_type == "image/png"
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': alert.uuid,
                              'observable_uuid': file_observable.uuid
                          })
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'image/png'
    assert result.data == image_data


@pytest.mark.integration
def test_image_with_different_mime_type(web_client, root_analysis, tmpdir):
    """Test image endpoint with different MIME type."""
    # Create a test JPEG file
    target_path = tmpdir / "test_image.jpg"
    jpeg_data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb'
    target_path.write_binary(jpeg_data)

    # Add file observable
    file_observable = root_analysis.add_file_observable(str(target_path))
    assert file_observable.mime_type == "image/jpeg"
    root_analysis.save()
    alert = ALERT(root_analysis)

    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': alert.uuid,
                              'observable_uuid': file_observable.uuid
                          })
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'image/jpeg'
    assert result.data == jpeg_data


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
    assert b"analysis/image_full.html" in result.data or alert.uuid.encode() in result.data


@pytest.mark.integration
def test_image_success(tmpdir, web_client):
    """Test image endpoint with mocked dependencies."""
    root = create_root_analysis()
    target_path = tmpdir / "test.png"
    target_path.write_binary(TEST_IMAGE_DATA)
    file_observable = root.add_file_observable(str(target_path))
    root.save()
    alert = ALERT(root)

    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': alert.uuid,
                              'observable_uuid': file_observable.uuid
                          })
    
    assert result.status_code == 200
    assert result.headers['Content-Type'] == 'image/png'
    assert result.data == TEST_IMAGE_DATA


@pytest.mark.integration
def test_image_mocked_nonexistent_observable(web_client):
    """Test image endpoint with mocked nonexistent observable."""
    alert = insert_alert()

    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': alert.uuid,
                              'observable_uuid': 'nonexistent-uuid'
                          })
    
    assert result.status_code == 404
    assert b"unknown file" in result.data


@pytest.mark.integration
def test_image_mocked_file_not_exists(tmpdir, web_client):
    """Test image endpoint with mocked file that doesn't exist."""
    root = create_root_analysis()
    target_path = tmpdir / "test.png"
    target_path.write_binary(TEST_IMAGE_DATA)
    file_observable = root.add_file_observable(str(target_path))
    root.save()
    alert = ALERT(root)

    # remove the file
    os.unlink(file_observable.path)

    result = web_client.get(url_for("analysis.image"),
                          query_string={
                              'alert_uuid': root.uuid,
                              'observable_uuid': file_observable.uuid
                          })
    
    assert result.status_code == 404
    assert b"unknown file" in result.data