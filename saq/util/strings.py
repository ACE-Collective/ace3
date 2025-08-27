def format_item_list_for_summary(item_list: list[str], max_items: int = 20) -> str:
    """Returns a string of the first max_items items in the list, separated by commas.
    If more than max_items, returns the first max_items and number of remaining items."""
    result = ", ".join(item_list[:max_items])
    if len(item_list) > max_items:
        result += f" + {len(item_list) - max_items} more"

    return result
