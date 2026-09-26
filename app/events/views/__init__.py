from app.events.views.index import index
from app.events.views.manage import manage, manage_event_details
from app.events.views.edit.alerts import remove_alerts
from app.events.views.edit.close import close_event
from app.events.views.edit.malware import new_malware_option
from app.events.views.edit.modal import edit_event_modal, edit_event
from app.events.views.edit.tag import add_tag
from app.events.views.edit.bulk import (
    bulk_add_tag,
    bulk_remove_tag,
    bulk_add_comment,
    bulk_set_disposition,
    bulk_review_disposition,
)
