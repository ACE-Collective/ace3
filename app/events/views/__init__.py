from app.events.views.export import send_event_to, export_events_to_csv
from app.events.views.index import index
from app.events.views.manage import manage, manage_event_details
from app.events.views.edit.alerts import remove_alerts
from app.events.views.edit.close import close_event
from app.events.views.edit.detection import set_observables_detection_status
from app.events.views.edit.malware import new_malware_option
from app.events.views.edit.modal import edit_event_modal, edit_event
from app.events.views.edit.tag import add_tag
