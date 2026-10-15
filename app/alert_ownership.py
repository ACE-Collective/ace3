"""The GUI side of the ownership check that bulk alert actions go through (see
check_alert_ownership in saq/database/util/alert.py): reading the analyst's confirmations
out of a form."""

# the form field carrying the alerts the analyst agreed to take from another analyst:
# comma-separated alert_uuid:owner_id pairs, the owner being who had the alert when the
# analyst looked (static/js/selection_guard.js fills it in)
TAKE_OWNED_FIELD = "take_owned"


def confirmed_takes_from_form(form) -> dict[str, int]:
    """Parses the TAKE_OWNED_FIELD of a submitted form. Malformed pairs are ignored: an alert
    they name is then treated as unconfirmed, which leaves it alone."""
    result = {}
    for pair in form.get(TAKE_OWNED_FIELD, "").split(","):
        alert_uuid, separator, owner_id = pair.strip().partition(":")
        if not separator:
            continue

        try:
            result[alert_uuid] = int(owner_id)
        except ValueError:
            continue

    return result
