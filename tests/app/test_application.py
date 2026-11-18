import base64
import json
import logging

import pytest
from sqlalchemy import text

from app.application import (
    create_app,
    s64decode,
    s64encode,
    b64escape,
    b64decode_wrapper,
    btoa,
    dict_from_json_string,
    pprint_json_dict
)
from saq.database.pool import get_db


@pytest.mark.unit
class TestUtilityFunctions:
    """Test the utility functions in app.application module."""

    def test_hexdump_filter(self, app):
        result = app.jinja_env.from_string("{{ data | hexdump }}").render(data=b"Hello World")
        assert result == "00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64                 |Hello World|\n0000000b\n"

    def test_s64decode(self):
        """Test s64decode function."""
        # Test normal base64 encoded string
        test_string = "Hello World"
        encoded = base64.b64encode(test_string.encode('utf8')).decode('ascii')
        result = s64decode(encoded)
        assert result == test_string
        
        # Test with missing padding
        encoded_no_padding = encoded.rstrip('=')
        result = s64decode(encoded_no_padding)
        assert result == test_string

    def test_s64encode(self):
        """Test s64encode function."""
        test_string = "Hello World"
        result = s64encode(test_string)
        
        # Should return base64 encoded string
        assert isinstance(result, str)
        decoded = base64.b64decode(result).decode('utf8')
        assert decoded == test_string

    def test_b64escape(self):
        """Test b64escape function."""
        test_string = "Hello World!"
        result = b64escape(test_string)
        
        # Should return base64 encoded URL-quoted string
        assert isinstance(result, str)
        # Decode to verify it's properly encoded
        decoded_bytes = base64.b64decode(result)
        assert b"Hello%20World%21" == decoded_bytes

    def test_b64decode_wrapper_missing_padding(self):
        """Test b64decode_wrapper with missing padding."""
        test_data = b"Hello World"
        encoded = base64.b64encode(test_data).decode('ascii').rstrip('=')
        result = b64decode_wrapper(encoded)
        assert result == test_data

    def test_b64decode_wrapper_invalid(self, caplog):
        """Test b64decode_wrapper with invalid base64."""
        # one data character is never valid base64, whatever the padding; characters outside the
        # alphabet ("!!!") are only discarded, and decode to b'' without an error
        with caplog.at_level(logging.ERROR):
            assert b64decode_wrapper("a") == b''
        assert [r.getMessage() for r in caplog.records] == ["Unable to b64decode: a"]

    def test_btoa(self):
        """Test btoa function."""
        test_bytes = b"Hello World"
        result = btoa(test_bytes)
        assert result == "Hello World"
        assert isinstance(result, str)

    def test_dict_from_json_string_valid(self):
        """Test dict_from_json_string with valid JSON."""
        test_dict = {"key": "value", "number": 42}
        json_string = json.dumps(test_dict)
        result = dict_from_json_string(json_string)
        assert result == test_dict

    def test_dict_from_json_string_invalid(self):
        """Test dict_from_json_string with invalid JSON."""
        invalid_json = "{'invalid': json}"
        result = dict_from_json_string(invalid_json)
        assert result == {}

    def test_pprint_json_dict(self):
        """Test pprint_json_dict function."""
        test_dict = {"b_key": "value", "a_key": 42, "nested": {"z": 1, "a": 2}}
        result = pprint_json_dict(test_dict)
        
        # indented four spaces, keys sorted at every level
        assert result == '{\n    "a_key": 42,\n    "b_key": "value",\n    "nested": {\n        "a": 2,\n        "z": 1\n    }\n}'

@pytest.mark.integration
def test_the_gui_uses_the_ace_session_every_process_uses():
    session = get_db()
    create_app()
    assert get_db() is session

    # so the GUI's ORM runs at READ COMMITTED like every other engine, not the server's REPEATABLE-READ
    assert get_db().execute(text("SELECT @@transaction_isolation")).scalar() == "READ-COMMITTED"
