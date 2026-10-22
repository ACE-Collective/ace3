from app.analysis.views.manage import manage
from app.analysis.views.index import index
from app.analysis.views.navigation import redirect_to, set_page_size, set_page_offset
from app.analysis.views.edit.tag import add_tag, remove_tag
from app.analysis.views.edit.observable import add_observable
from app.analysis.views.edit.comment import add_comment, delete_comment
from app.analysis.views.edit.new import new_alert, new_alert_observable, file
from app.analysis.views.edit.disposition import set_disposition
from app.analysis.views.edit.review import review_disposition
from app.analysis.views.edit.filters import (
    set_sort_filter, reset_filters, set_filters, remove_filter, remove_filter_category,
    new_filter_option, select_filter, apply_temp_filter, revert_temp_filter,
)
from app.analysis.views.observables import observables
from app.analysis.views.prune import toggle_prune, toggle_prune_volatile
from app.analysis.views.edit.event import add_to_event, load_more_events
from app.analysis.views.search import search, search_similar
from app.analysis.views.misc import upload_file, analyze_alert
from app.analysis.views.image import image_full
from app.analysis.views.context_processor import generic_functions, add_header