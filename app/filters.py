"""Flask-side filter plumbing for the alert management page.

The filter CLASSES and the query builder they feed live in `saq/gui/filter_query.py` so the
FastAPI layer can run the same filters without a browser request; they are re-exported here
because the GUI code and the filter-editor template refer to them by these names.

What genuinely belongs to Flask -- and stays here -- is `SearchFilter`, which reads a filter
widget's value out of `request.form` or the session.
"""

import logging
from flask import request, session
from flask_login import current_user

from saq.gui.filter_query import (
    ANY_OBSERVABLE_TYPE,
    AutoTextFilter,
    BoolFilter,
    DateRangeFilter,
    Filter,
    MultiSelectFilter,
    SelectFilter,
    TextFilter,
    TypeValueFilter,
    build_alert_query,
    count_alerts,
    create_filter,
    filter_alert_uuids,
    has_filter,
)


# the types of filters we currently support
FILTER_TYPE_CHECKBOX = 'checkbox'
FILTER_TYPE_TEXT = 'text'
FILTER_TYPE_SELECT = 'select'
FILTER_TYPE_MULTISELECT = 'multiselect'

class SearchFilter:
    def __init__(self, name, type, default_value, verification_function=None):
        self.name = name  # the "name" property of the <input> element in the <form>
        self.type = type  # the type (see above)
        self.default_value = default_value  # the value to return if the filter is reset to default state
        self._reset = False  # set to True to return default values
        # used to verify the current value when the value property is accessed
        # if this function returns False then the default value is used
        # a single parameter is passed which is the value to be verified
        self.verification_function = verification_function
        # if we need to force the value 
        self._modified_value = None

    @property
    def form_value(self):
        """Returns the form value of the filter.  Returns None if the form value is unavailable."""
        # did we set it ourselves?
        if self._reset:
            return None
        # if the current request is a POST then we load the filter from that
        elif request.method == 'POST':
            if self.type == FILTER_TYPE_MULTISELECT:
                return request.form.getlist(self.name)

            return request.form.get(self.name, '')
        # if that's not the case then we try to load our last filter from the user's session
        elif self.name in session:
            return session[self.name]
        # otherwise we return None to indicate nothing is available
        else:
            return None

    @property
    def value(self):
        """Returns the logical value of the filter to be used by the program.  For example, a checkbox would be True or False."""
        if self._modified_value is not None:
            return self._modified_value
        elif self._reset:
            # logging.debug("reset flag is set for {0} user {1}".format(self.name, current_user))
            return self.default_value
        # if the current request is a POST then we load the filter from that
        elif request.method == 'POST':
            if self.type == FILTER_TYPE_MULTISELECT:
                value = request.form.getlist(self.name)
            else:
                value = request.form.get(self.name, '')
            # logging.debug("loaded filter {0} value {1} from POST for user {2}".format(
            # self.name, value, current_user))
        # if that's not the case then we try to load our last filter from the user's session
        elif self.name in session:
            value = session[self.name]
            # logging.debug("loaded filter {0} value {1} from session for user {2}".format(
            # self.name, value, current_user))
        # otherwise we return the default value
        else:
            # logging.debug("using default value for filter {0} for user {1}".format(
            # self.name, current_user))
            return self.default_value

        if self.verification_function is not None:
            if not self.verification_function(value):
                logging.debug("filter item {0} failed verification with value {1} for user {2}".format(
                    self.name, value, current_user))
                return self.default_value

        # the result we return depends on the type of the filter
        # checkboxes return True or False
        if self.type == FILTER_TYPE_CHECKBOX:
            return value == 'on'

        # otherwise we just return the value
        return value

    @value.setter
    def value(self, value):
        self._modified_value = value

    @property
    def state(self):
        """Returns the state value, which is what is added to the HTML so that the <form> is recreated with all the filters set."""
        if self.type == FILTER_TYPE_CHECKBOX:
            return ' CHECKED ' if self.value else ''

        return self.value

    def reset(self):
        """Call to reset this filter item to it's default, which changes what the value and state properties return."""
        self._reset = True

def verify_integer(filter_value):
    """Used to verify that <input> type textboxes that should be integers actually are."""
    try:
        int(filter_value)
        return True
    except:
        return False

# the list of available filters that are hard coded into the filter dialog
# add new filters here
# NOTE that these do NOT include the dynamically generated filter fields
# NOTE these values ARE EQUAL TO the "name" field in the <form> of the filter dialog
FILTER_CB_OPEN = 'filter_open'
FILTER_CB_UNOWNED = 'filter_unowned'
FILTER_S_ALERT_QUEUE = 'filter_alert_queue'
FILTER_CB_ONLY_SLA = 'filter_sla'
FILTER_CB_ONLY_REMEDIATED = 'filter_only_remediated'
FILTER_CB_REMEDIATE_DATE = 'remediate_date'
FILTER_TXT_REMEDIATE_DATERANGE = 'remediate_daterange'
FILTER_CB_ONLY_UNREMEDIATED = 'filter_only_unremediated'
FILTER_CB_USE_DATERANGE = 'use_daterange'
FILTER_TXT_DATERANGE = 'daterange'
FILTER_CB_USE_SEARCH_OBSERVABLE = 'use_search_observable'
FILTER_S_SEARCH_OBSERVABLE_TYPE = 'search_observable_type'
FILTER_TXT_SEARCH_OBSERVABLE_VALUE = 'search_observable_value'
FILTER_CB_USE_DISPLAY_TEXT = 'use_display_text'
FILTER_TXT_DISPLAY_TEXT = 'display_text'
FILTER_CB_DIS_NONE = 'dis_none'
FILTER_CB_DIS_FALSE_POSITIVE = 'dis_false_positive'
FILTER_CB_DIS_IGNORE = 'dis_ignore'
FILTER_CB_DIS_UNKNOWN = 'dis_unknown'
FILTER_CB_DIS_REVIEWED = 'dis_reviewed'
FILTER_CB_DIS_GRAYWARE = 'dis_grayware'
FILTER_CB_DIS_POLICY_VIOLATION = 'dis_policy_violation'
FILTER_CB_DIS_RECONNAISSANCE = 'dis_reconnaissance'
FILTER_CB_DIS_WEAPONIZATION = 'dis_weaponization'
FILTER_CB_DIS_DELIVERY = 'dis_delivery'
FILTER_CB_DIS_EXPLOITATION = 'dis_exploitation'
FILTER_CB_DIS_INSTALLATION = 'dis_installation'
FILTER_CB_DIS_COMMAND_AND_CONTROL = 'dis_command_and_control'
FILTER_CB_DIS_EXFIL = 'dis_exfil'
FILTER_CB_DIS_DAMAGE = 'dis_damage'
FILTER_CB_DIS_INSIDER_DATA_CONTROL = 'dis_insider_data_control'
FILTER_CB_DIS_INSIDER_DATA_EXFIL = 'dis_insider_data_exfil'
FILTER_CB_USE_DIS_DATERANGE = 'use_disposition_daterange'
FILTER_TXT_DIS_DATERANGE = 'disposition_daterange'
FILTER_CB_USE_SEARCH_COMPANY = 'use_search_company'
FILTER_S_SEARCH_COMPANY = 'search_company'
FILTER_TXT_MIN_PRIORITY = 'min_priority'
FILTER_TXT_MAX_PRIORITY = 'max_priority'
FILTER_TXT_TAGS = 'tag_filters'

# valid fields to sort on
SORT_FIELD_DATE = 'date'
SORT_FIELD_COMPANY_ID = 'company_id'
SORT_FIELD_PRIORITY = 'priority'
SORT_FIELD_ALERT = 'alert'
SORT_FIELD_OWNER = 'owner'
SORT_FIELD_DISPOSITION = 'disposition'
VALID_SORT_FIELDS = [
    SORT_FIELD_DATE,
    SORT_FIELD_COMPANY_ID,
    SORT_FIELD_PRIORITY,
    SORT_FIELD_ALERT,
    SORT_FIELD_OWNER,
    SORT_FIELD_DISPOSITION]

# valid directions to sort
SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

# the default sort direction
SORT_DIRECTION_DEFAULT = SORT_DIRECTION_DESC

# utility functions
def is_valid_sort_field(field_name):
    return field_name in VALID_SORT_FIELDS

def is_valid_sort_direction(sort_direction):
    return sort_direction in [SORT_DIRECTION_ASC, SORT_DIRECTION_DESC]

def make_sort_instruction(sort_field, sort_direction):
    return '{0}:{1}'.format(sort_field, sort_direction)