import base64
import json
import pytest

from app.application import (
    s64decode,
    s64encode,
    b64escape,
    b64decode_wrapper,
    btoa,
    dict_from_json_string,
    pprint_json_dict
)


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

    def test_b64decode_wrapper_valid(self):
        """Test b64decode_wrapper with valid base64."""
        test_data = b"Hello World"
        encoded = base64.b64encode(test_data).decode('ascii')
        result = b64decode_wrapper(encoded)
        assert result == test_data

    def test_b64decode_wrapper_missing_padding(self):
        """Test b64decode_wrapper with missing padding."""
        test_data = b"Hello World"
        encoded = base64.b64encode(test_data).decode('ascii').rstrip('=')
        result = b64decode_wrapper(encoded)
        assert result == test_data

    def test_b64decode_wrapper_invalid(self):
        """Test b64decode_wrapper with invalid base64."""
        # Test with truly invalid base64 that will cause an exception
        invalid_b64 = "!!!"
        result = b64decode_wrapper(invalid_b64)
        assert result == b''

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
        
        # Should be properly formatted JSON
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed == test_dict

@pytest.mark.unit
class TestJinjaFilters:
    """Test Jinja filter functions directly without full app setup."""

    def test_jinja_filter_functions(self):
        """Test that the Jinja filter functions work correctly."""
        # Test btoa filter
        assert btoa(b"test") == "test"
        
        # Test s64decode filter
        encoded = base64.b64encode("test".encode()).decode()
        assert s64decode(encoded) == "test"
        
        # Test s64encode filter
        assert s64encode("test") == base64.b64encode("test".encode()).decode()
        
        # Test dict_from_json_string filter
        json_str = '{"key": "value"}'
        assert dict_from_json_string(json_str) == {"key": "value"}
        
        # Test pprint_json_dict filter
        test_dict = {"key": "value"}
        result = pprint_json_dict(test_dict)
        assert json.loads(result) == test_dict
