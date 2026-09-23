"""The GUI side of the ownership check that bulk alert actions go through (see
check_alert_ownership in saq/database/util/alert.py): reading the analyst's confirmations
out of a form, and telling them which alerts were left alone."""

from collections import Counter

from saq.database.util.alert import OwnershipCheck

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


def describe_skipped(ownership: OwnershipCheck) -> str | None:
    """'left 3 alerts owned by jsmith alone', or None when nothing was skipped."""
    if not ownership.skipped:
        return None

    by_owner = Counter(ownership.skipped.values())
    total = len(ownership.skipped)
    plural = "" if total == 1 else "s"
    if len(by_owner) == 1:
        owner = next(iter(by_owner))
        return f"left {total} alert{plural} owned by {owner} alone"

    owners = ", ".join(f"{owner} {count}" for owner, count in by_owner.most_common())
    return f"left {total} alert{plural} owned by other analysts alone ({owners})"

