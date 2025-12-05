import pytest

from saq.util.strings import (
    decode_ascii_hex,
    decode_base64,
    format_item_list_for_summary,
    is_base64,
)


class TestFormatItemListForSummary:
    
    @pytest.mark.unit
    @pytest.mark.parametrize("item_list, max_items, expected", [
        # Empty list
        ([], 20, ""),
        
        # Single item
        (["item1"], 20, "item1"),
        
        # Multiple items under limit
        (["item1", "item2", "item3"], 20, "item1, item2, item3"),
        
        # Exactly at limit
        (["item1", "item2"], 2, "item1, item2"),
        
        # Over limit - default max_items
        (["item1", "item2", "item3"], 2, "item1, item2 + 1 more"),
        
        # Over limit - larger case
        (["a", "b", "c", "d", "e", "f"], 3, "a, b, c + 3 more"),
        
        # Over limit - many items
        ([str(i) for i in range(100)], 5, "0, 1, 2, 3, 4 + 95 more"),
        
        # Custom max_items smaller than default
        (["x", "y", "z"], 1, "x + 2 more"),
        
        # List with one item over limit
        (["only", "two"], 1, "only + 1 more"),
        
        # String items with special characters
        (["item,with,commas", "item with spaces", "item-with-dashes"], 20, "item,with,commas, item with spaces, item-with-dashes"),
        
        # Large max_items with small list
        (["a", "b"], 100, "a, b"),
    ])
    def test_format_item_list_for_summary(self, item_list, max_items, expected):
        result = format_item_list_for_summary(item_list, max_items)
        assert result == expected
    
    @pytest.mark.unit
    def test_format_item_list_for_summary_default_max_items(self):
        # Test that default max_items is 20
        items = [f"item{i}" for i in range(25)]
        result = format_item_list_for_summary(items)
        expected_items = ", ".join([f"item{i}" for i in range(20)])
        expected = f"{expected_items} + 5 more"
        assert result == expected


class TestDecodeBase64:

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("Zm9v", b"foo"),
            (" Zm9vYmFyIA==\n", b"foobar "),
            ("Zm9vYmFy", b"foobar"),
            ("Zm9vYmF", b"fooba"),
            ("Zm9vYg", b"foob"),
        ],
    )
    def test_decode_base64_valid(self, value, expected):
        assert decode_base64(value) == expected

    @pytest.mark.unit
    def test_decode_base64_type_error(self):
        with pytest.raises(TypeError):
            decode_base64(b"Zm9v")

    @pytest.mark.unit
    def test_decode_base64_invalid_data(self):
        with pytest.raises(Exception):
            decode_base64("not-base64!")


class TestDecodeAsciiHex:

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("4d5a", b"MZ"),
            (" 4d5a ", b"MZ"),
            ("", b""),
        ],
    )
    def test_decode_ascii_hex_valid(self, value, expected):
        assert decode_ascii_hex(value) == expected

    @pytest.mark.unit
    def test_decode_ascii_hex_type_error(self):
        with pytest.raises(TypeError):
            decode_ascii_hex(b"4d5a")

    @pytest.mark.unit
    def test_decode_ascii_hex_odd_length(self, caplog):
        caplog.set_level("WARNING")
        result = decode_ascii_hex("4d5")
        assert result == b"M"
        assert "dropping trailing character" in caplog.text


class TestIsBase64:

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "value,expected",
        [
            # Valid standard base64 strings
            ("Zm9v", True),
            ("Zm9vYmFy", True),
            ("Zm9vYmFyIA==", True),
            ("SGVsbG8gV29ybGQ=", True),
            ("SGVsbG8gV29ybGQh", True),
            
            # Valid base64 with whitespace (should be trimmed)
            (" Zm9v ", True),
            ("\nZm9vYmFy\n", True),
            ("\tSGVsbG8=\t", True),
            
            # Valid URL-safe base64 strings
            ("Zm9vYmFy-_", True),
            ("SGVsbG8gV29ybGQh", True),
            
            # Valid base64 with missing padding (should be handled)
            ("Zm9vYmF", True),
            ("Zm9vYg", True),
            ("Zm9v", True),
            
            # Invalid base64 strings
            ("not-base64!", False),
            ("hello world", False),
            ("Zm9vYmFy!", False),
            ("Zm9vYmFy@", False),
            ("Zm9vYmFy#", False),
            ("Zm9vYmFy$", False),
            ("Zm9vYmFy%", False),
            ("Zm9vYmFy^", False),
            ("Zm9vYmFy&", False),
            ("Zm9vYmFy*", False),
            ("Zm9vYmFy(", False),
            ("Zm9vYmFy)", False),
            
            # Edge cases
            ("", False),
            ("   ", False),
            ("\n\t  \n", False),
            
            # is_base64 deals with invalid padding
            ("Z", False), # only invalid case
            ("Zm", True), # rest are fine because is_base64 deals with invalid padding
            ("Zm9", True),
            ("Zm9vYmFyIA", True),
            
            # Valid longer strings
            ("VGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==", True),
            ("VGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw", True),
        ],
    )
    def test_is_base64(self, value, expected):
        assert is_base64(value) is expected

    @pytest.mark.unit
    def test_is_base64_type_error(self):
        # Non-string types should return False
        assert is_base64(b"Zm9v") is False
        assert is_base64(123) is False
        assert is_base64(None) is False
        assert is_base64([]) is False
        assert is_base64({}) is False

    @pytest.mark.unit
    def test_is_base64_valid_standard_variants(self):
        # Test various valid standard base64 encodings
        import base64
        
        test_strings = [
            "Hello",
            "Hello World",
            "Hello World!",
            "Test123",
            "Special chars: !@#$%",
        ]
        
        for test_str in test_strings:
            encoded = base64.b64encode(test_str.encode('utf-8')).decode('ascii')
            assert is_base64(encoded) is True
            # Also test without padding
            encoded_no_pad = encoded.rstrip('=')
            assert is_base64(encoded_no_pad) is True

    @pytest.mark.unit
    def test_is_base64_valid_urlsafe_variants(self):
        # Test various valid URL-safe base64 encodings
        import base64
        
        test_strings = [
            "Hello",
            "Hello World",
            "Test123",
        ]
        
        for test_str in test_strings:
            encoded = base64.urlsafe_b64encode(test_str.encode('utf-8')).decode('ascii')
            assert is_base64(encoded) is True
            # Also test without padding
            encoded_no_pad = encoded.rstrip('=')
            assert is_base64(encoded_no_pad) is True