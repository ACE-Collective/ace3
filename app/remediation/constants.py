from enum import Enum


R_PAGE_OFFSET = "r_page_offset"
R_PAGE_SIZE = "r_page_size"
R_SORT_FILTER = "r_sort_filter"
R_SORT_FILTER_DESC = "r_sort_filter_desc"
R_FILTERS = "r_filters"
R_SORT_FILTER_DESC = "r_sort_filter_desc"

R_FILTER_ID = "r_filter_id"
R_FILTER_REMEDIATOR = "r_filter_remediator"
R_FILTER_TYPE = "r_filter_type"
R_FILTER_VALUE = "r_filter_value"
R_FILTER_ANALYST = "r_filter_analyst"
R_FILTER_ACTION = "r_filter_action"
R_FILTER_STATUS = "r_filter_status"
R_FILTER_RESULT = "r_filter_result"

R_FILTER_ALL = [
    R_FILTER_ID,
    R_FILTER_REMEDIATOR,
    R_FILTER_TYPE,
    R_FILTER_VALUE,
    R_FILTER_ANALYST,
    R_FILTER_ACTION,
    R_FILTER_STATUS,
    R_FILTER_RESULT,
]

class RemediationSortFilter(Enum):
    ID = "id"
    REMEDIATOR = "remediator"
    TYPE = "type"
    VALUE = "value"
    ANALYST = "analyst"
    ACTION = "action"
    STATUS = "status"
    RESULT = "result"

R_DEFAULT_SORT_FILTER = RemediationSortFilter.ID

class SortFilterDirection(Enum):
    ASC = "asc"
    DESC = "desc"

R_DEFAULT_SORT_FILTER_DIRECTION = SortFilterDirection.DESC

RH_PAGE_OFFSET = "rh_page_offset"
RH_PAGE_SIZE = "rh_page_size"
RH_SORT_FILTER = "rh_sort_filter"
RH_SORT_FILTER_DESC = "rh_sort_filter_desc"
RH_CHECKED = "rh_checked"
RH_FILTERS = "rh_filters"
RH_SORT_FILTER_DESC = "rh_sort_filter_desc"

R_PAGE_OFFSET_START = "start"
R_PAGE_OFFSET_BACKWARD = "backward"
R_PAGE_OFFSET_FORWARD = "forward"
R_PAGE_OFFSET_END = "end"

R_PAGE_SIZE_DEFAULT = 50
RH_PAGE_SIZE_DEFAULT = 50