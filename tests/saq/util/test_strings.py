import pytest

from saq.util.strings import format_item_list_for_summary


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