# vim: sw=4:ts=4:et:cc=120

from enum import Enum


FC_PAGE_OFFSET = "fc_page_offset"
FC_PAGE_SIZE = "fc_page_size"
FC_SORT_FILTER = "fc_sort_filter"
FC_SORT_FILTER_DESC = "fc_sort_filter_desc"
FC_FILTERS = "fc_filters"

FC_FILTER_ID = "fc_filter_id"
FC_FILTER_COLLECTOR = "fc_filter_collector"
FC_FILTER_TYPE = "fc_filter_type"
FC_FILTER_VALUE = "fc_filter_value"
FC_FILTER_STATUS = "fc_filter_status"
FC_FILTER_RESULT = "fc_filter_result"

FC_FILTER_ALL = [
    FC_FILTER_ID,
    FC_FILTER_COLLECTOR,
    FC_FILTER_TYPE,
    FC_FILTER_VALUE,
    FC_FILTER_STATUS,
    FC_FILTER_RESULT,
]


class FileCollectionSortFilter(Enum):
    ID = "id"
    COLLECTOR = "collector"
    TYPE = "type"
    VALUE = "value"
    STATUS = "status"
    RESULT = "result"


FC_DEFAULT_SORT_FILTER = FileCollectionSortFilter.ID


class SortFilterDirection(Enum):
    ASC = "asc"
    DESC = "desc"


FC_DEFAULT_SORT_FILTER_DIRECTION = SortFilterDirection.DESC

FCH_PAGE_OFFSET = "fch_page_offset"
FCH_PAGE_SIZE = "fch_page_size"
FCH_SORT_FILTER = "fch_sort_filter"
FCH_SORT_FILTER_DESC = "fch_sort_filter_desc"
FCH_CHECKED = "fch_checked"
FCH_FILTERS = "fch_filters"

FC_PAGE_OFFSET_START = "start"
FC_PAGE_OFFSET_BACKWARD = "backward"
FC_PAGE_OFFSET_FORWARD = "forward"
FC_PAGE_OFFSET_END = "end"

FC_PAGE_SIZE_DEFAULT = 50
FCH_PAGE_SIZE_DEFAULT = 50
