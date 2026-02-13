from app.analysis.views.manage import manage
from app.analysis.views.index import index
from app.analysis.views.export import download_json, export_alerts_to_csv, download_file, get_alert_metadata, email_file, html_details
from app.analysis.views.navigation import redirect_to, set_page_size, set_page_offset
from app.analysis.views.edit.tag import add_tag, remove_tag
from app.analysis.views.edit.observable import add_observable
from app.analysis.views.edit.comment import add_comment, delete_comment
from app.analysis.views.edit.ownership import assign_ownership, set_owner
from app.analysis.views.edit.new import new_alert, new_alert_observable, file
from app.analysis.views.edit.disposition import set_disposition
from app.analysis.views.edit.filters import set_sort_filter, reset_filters, reset_filters_special, set_filters, add_filter, remove_filter, remove_filter_category, new_filter_option 
from app.analysis.views.edit.legacy import mark_suspect
from app.analysis.views.observables import observables
from app.analysis.views.prune import toggle_prune, toggle_prune_volatile
from app.analysis.views.edit.observable_action.whitelist import observable_action_whitelist, observable_action_un_whitelist
from app.analysis.views.edit.observable_action.detection import observable_action_set_for_detection, observable_action_adjust_expiration
from app.analysis.views.edit.observable_action.legacy import observable_action
from app.analysis.views.edit.event import add_to_event, load_more_events, get_analysis_event_name_candidate
from app.analysis.views.search import search
from app.analysis.views.misc import upload_file, analyze_alert
from app.analysis.views.archive import download_archive
from app.analysis.views.image import image, image_full
from app.analysis.views.remediation import remediation_targets
from app.analysis.views.context_processor import generic_functions, add_header