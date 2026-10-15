from flask import render_template
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.auth.permissions import require_permission
from app.blueprints import remediation
from saq.gui.filter_screens import REMEDIATIONS_SCREEN
from saq.remediation.target import get_observable_remediation_interface_registry


def get_remediatable_observable_types() -> list[str]:
    return sorted(get_observable_remediation_interface_registry().keys())


@remediation.route('/remediation/manage', methods=['GET'])
@require_permission('remediation', 'read')
def manage():
    # the page is a shell: its script loads everything from /api/v2/remediation, and its filters
    # and saved filters from /api/v2/filter-screens and /api/v2/saved-filters (screen
    # remediations). The write controls follow has_permission('remediation', 'write') in the
    # template, and the API enforces it regardless.
    #
    # A user new to the screen gets its default saved filters. This writes, which is why only
    # this real page render calls it.
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=REMEDIATIONS_SCREEN.name)
    return render_template(
        "remediation/manage.html",
        remediations_screen=REMEDIATIONS_SCREEN.name,
        observable_types=get_remediatable_observable_types(),
    )
