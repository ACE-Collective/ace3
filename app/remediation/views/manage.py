
from flask import render_template, session
from app.auth.permissions import require_permission
from app.blueprints import remediation
from app.remediation.constants import R_DEFAULT_SORT_FILTER, R_DEFAULT_SORT_FILTER_DIRECTION, R_PAGE_OFFSET, R_PAGE_SIZE, R_PAGE_SIZE_DEFAULT, R_SORT_FILTER, R_SORT_FILTER_DESC, RH_PAGE_OFFSET, RH_PAGE_SIZE, RH_PAGE_SIZE_DEFAULT
from app.remediation.views.remediations import get_current_pagination_size
from app.remediation.views.history import get_current_pagination_size as get_current_remediation_history_pagination_size
from saq.remediation.target import get_observable_remediation_interface_registry


def initialize_remediation_session():
    """Initializes default session variables for remediation management if not already set."""
    if R_PAGE_OFFSET not in session or R_PAGE_SIZE not in session:
        reset_remediation_pagination()
    if RH_PAGE_OFFSET not in session or RH_PAGE_SIZE not in session:
        reset_remediation_history_pagination()
    if R_SORT_FILTER not in session or R_SORT_FILTER_DESC not in session:
        reset_remediation_sort_filter()

def reset_remediation_pagination():
    session[R_PAGE_OFFSET] = 0
    if R_PAGE_SIZE not in session:
        session[R_PAGE_SIZE] = R_PAGE_SIZE_DEFAULT

def reset_remediation_history_pagination():
    session[RH_PAGE_OFFSET] = 0
    if RH_PAGE_SIZE not in session:
        session[RH_PAGE_SIZE] = RH_PAGE_SIZE_DEFAULT

def reset_remediation_sort_filter():
    session[R_SORT_FILTER] = R_DEFAULT_SORT_FILTER.value
    session[R_SORT_FILTER_DESC] = R_DEFAULT_SORT_FILTER_DIRECTION.value

def get_remediatable_observable_types() -> list[str]:
    return list(get_observable_remediation_interface_registry().keys())

@remediation.route('/remediation/manage', methods=['GET'])
@require_permission('remediation', 'read')
def manage():
    initialize_remediation_session()

    return render_template(
        "remediation/manage.html",
        page_size=get_current_pagination_size(),
        rh_page_size=get_current_remediation_history_pagination_size(),
        observable_types=get_remediatable_observable_types(),
    )