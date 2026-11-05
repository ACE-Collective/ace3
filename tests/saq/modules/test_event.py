import pytest

from saq.analysis import RootAnalysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_ALERT_ADDED_TO_EVENT, ANALYSIS_MODE_DISPOSITIONED, ANALYSIS_MODE_EVENT, DISPOSITION_DELIVERY, F_EMAIL_ADDRESS
from saq.database import ALERT, Alert, EventMapping, User, Workload, get_db, set_dispositions
from saq.modules.event import AlertAddedToEventAnalyzer
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


@pytest.mark.integration
def test_changing_to_event_analysis_mode(db_event):
    # Create a test alert with an email_address observable
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_EMAIL_ADDRESS, 'test@test.com')
    root.save()
    root.schedule()
    ALERT(root)

    # Add the alert to the event
    alert_id = get_db().query(Alert.id).filter(Alert.uuid == root.uuid).one().id
    event_mapping = EventMapping(event_id=db_event.id, alert_id=alert_id)
    get_db().add(event_mapping)
    get_db().commit()

    # Disposition the alert, which will set it to dispositioned analysis mode
    set_dispositions([root.uuid], DISPOSITION_DELIVERY, get_db().query(User).first().id)

    # Get the workload entries from the database
    workload_entries = get_db().query(Workload).all()

    # Because the original alert was not actually processed, it should have an entry in the workload table. There
    # should be a second workload entry for when the alert was dispositioned.
    assert len(workload_entries) == 2
    assert all(w.uuid == root.uuid for w in workload_entries)
    assert any(w.analysis_mode == 'test_single' for w in workload_entries)
    assert any(w.analysis_mode == ANALYSIS_MODE_DISPOSITIONED for w in workload_entries)

    # Prior to running the analysis module, the analysis mode should not be event
    assert root.analysis_mode != ANALYSIS_MODE_EVENT

    # Execute the analysis
    analyzer = AnalysisModuleAdapter(AlertAddedToEventAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_ALERT_ADDED_TO_EVENT)))
    analyzer.execute_post_analysis()

    # The analysis mode should now be event
    assert root.analysis_mode == ANALYSIS_MODE_EVENT

    # an alert in no event keeps its mode, though the table maps another alert to an event
    other_root = RootAnalysis(analysis_mode='test_single')
    assert other_root.uuid != root.uuid
    analyzer = AnalysisModuleAdapter(AlertAddedToEventAnalyzer(
        context=create_test_context(root=other_root),
        config=get_analysis_module_config(ANALYSIS_MODULE_ALERT_ADDED_TO_EVENT)))
    analyzer.execute_post_analysis()
    assert other_root.analysis_mode == 'test_single'
