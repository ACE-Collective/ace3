import uuid
import pytest
from saq.database import Remediation, Alert, Observable
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.email_archive import archive_email
from saq.environment import get_global_runtime_settings
from saq.observables import FQDNObservable, URLObservable
from saq.remediation import REMEDIATION_ACTION_REMOVE, REMEDIATION_ACTION_RESTORE, REMEDIATION_STATUS_COMPLETED, REMEDIATION_STATUS_IN_PROGRESS, RemediationDelay, RemediationError, RemediationFailure, RemediationIgnore, RemediationService, RemediationSuccess, RemediationTarget, Remediator, get_remediation_targets
from saq.util.time import local_time
from tests.saq.helpers import create_root_analysis

@pytest.mark.parametrize('processing, state, css, restore_key, history', [
    (False, 'new', '', None, []),
    (True, 'new', '', None,
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = None,
            ),
        ],
    ),
    (True, 'removing', 'warning', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True, user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_IN_PROGRESS,
            ),
        ],
    ),
    (True, 'removing', 'danger', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = False,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_IN_PROGRESS,
            ),
        ],
    ),
    (False, 'removed', 'success', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'remove failed', 'danger', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = False,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'restored', 'success', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
            Remediation(
                action = REMEDIATION_ACTION_RESTORE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = None,
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'restored', 'success', 'world',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
            Remediation(
                action = REMEDIATION_ACTION_RESTORE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'world',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
])
@pytest.mark.integration
def test_remediation_target(processing, state, css, restore_key, history):
    # add all remediation history
    for remediation in history:
        remediation.user_id = get_global_runtime_settings().automation_user_id
        get_db().add(remediation)
    get_db().commit()

    # instantiate a remediation target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')

    # validate target properties
    assert target.processing == processing
    assert target.state == state
    assert target.css_class == css
    assert target.last_restore_key == restore_key

@pytest.mark.integration
def test_remediation_target_id():
    # instantiate a target from the id of another and ensure they are the same target
    target1 = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    target2 = RemediationTarget(id=target1.id)
    assert target2.type == target1.type
    assert target2.value == target1.value
    assert target2.id == target1.id

@pytest.mark.integration
def test_remediation_target_queue():
    # fetch targets with Remediation service
    service = RemediationService()
    targets = service.get_targets()
    assert len(targets) == 0

    # queue a remediation of a target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    target.queue(REMEDIATION_ACTION_REMOVE, get_global_runtime_settings().automation_user_id)

    # fetch targets with Remediation service
    targets = service.get_targets()
    assert len(targets) == 1
    assert targets[0].type == target.type
    assert targets[0].key == target.value
    assert targets[0].restore_key is None
    assert targets[0].user_id == get_global_runtime_settings().automation_user_id
    assert targets[0].action == REMEDIATION_ACTION_REMOVE
    assert targets[0].status == REMEDIATION_STATUS_IN_PROGRESS
    assert targets[0].successful
    assert targets[0].lock == service.uuid
    assert targets[0].lock_time is not None

@pytest.mark.integration
def test_remediation_target_stop_remediation():
    # queue a target for removal
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    target.queue(REMEDIATION_ACTION_REMOVE, get_global_runtime_settings().automation_user_id)
    
    # reload target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    
    # make sure the target was queued
    assert len(target.history) == 1
    assert target.history[0].status == 'NEW'
    
    # stop all remediations for the target
    target.stop_remediation()
    
    # reload target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    assert target.history[0].status == 'COMPLETED'
    assert target.history[0].successful == False

class MockRemediator(Remediator):
    def __init__(self, config_section_name, result):        
        self.name = config_section_name
        self.config = {}
        self.result = result

    @property
    def type(self): 
        return 'email'

    def remove(self, target):
        return self.result

@pytest.mark.parametrize('result1, result2, status, success, restore_key', [
    (RemediationSuccess('hello', restore_key='test'), RemediationSuccess('world'), REMEDIATION_STATUS_COMPLETED, True, 'test'),
    (RemediationSuccess('hello'), RemediationSuccess('world'), REMEDIATION_STATUS_COMPLETED, True, None),
    (RemediationSuccess('hello'), RemediationDelay('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationSuccess('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationSuccess('hello'), RemediationFailure('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationSuccess('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, True, None),
    (RemediationDelay('hello'), RemediationDelay('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationDelay('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationDelay('hello'), RemediationFailure('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationDelay('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationError('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationError('hello'), RemediationFailure('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationError('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationFailure('hello'), RemediationFailure('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationFailure('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationIgnore('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, False, None),
])
@pytest.mark.integration
def test_remediation(result1, result2, status, success, restore_key):
    # setup a test remediation service
    service = RemediationService()
    service.remediators.append(MockRemediator('test1', result1))
    service.remediators.append(MockRemediator('test2', result2))

    # queue target
    RemediationTarget('email', '<test@test.com>|jdoe@site.com').queue(REMEDIATION_ACTION_REMOVE, get_global_runtime_settings().automation_user_id)

    # remediate target with remediation service
    target = service.get_targets()[0]
    service.remediate(target)

    # verify results
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    assert target.history[0].status == status
    assert target.history[0].successful == success
    assert target.history[0].restore_key == restore_key

TEST_MESSAGE_ID = "<test@test.com>"
TEST_RECIPIENTS = ["foo@company.com", "john@company.com", "jane@company.com"]

@pytest.fixture
def archived_email(tmpdir):
    email = tmpdir / "email"
    email.write_binary(b"test")

    return archive_email(str(email), TEST_MESSAGE_ID, TEST_RECIPIENTS, local_time())

# this is an integration test because I don't have a way to mock the email_archive database
@pytest.mark.integration
def test_message_id_remediation_targets(archived_email):
    from saq.observables import MessageIDObservable

    # add some remediation history
    history = Remediation(type='email', key="<test@test.com>|foo@company.com", action='remove', user_id=get_global_runtime_settings().automation_user_id)
    get_db().add(history)
    get_db().commit()

    # get remediation targets for MessageIDObservable
    message_id = MessageIDObservable("<test@test.com>")
    targets = message_id.remediation_targets
    assert len(targets) == 3
    target_strings = []
    for target in targets:
        target_strings.append(f"{target.type}|{target.value}")

    assert 'email|<test@test.com>|foo@company.com' in target_strings
    assert 'email|<test@test.com>|john@company.com' in target_strings
    assert 'email|<test@test.com>|jane@company.com' in target_strings


@pytest.mark.integration
def test_url_remediation_targets():
    observable = URLObservable(value="http://www.company.com")
    assert not observable.remediation_targets


@pytest.mark.integration
def test_fqdn_remediation_targets():
    observable = FQDNObservable(value="company.com")
    assert not observable.remediation_targets


# make sure an observable with a bad value does not trip up the get_remediation_targets function
@pytest.mark.integration
def test_alert_get_remediation_targets_bad_observable(monkeypatch):
    class MockAlert(Alert):
        def __init__(self):
            pass
        def get_observables(self):
            return [Observable(type='ipv4', md5='123', value=b'123')]

    alert = MockAlert()
    targets = alert.get_remediation_targets()

    assert targets == []

@pytest.mark.integration 
def test_get_remediation_targets_empty_list():
    """Test get_remediation_targets with empty alert_uuids list"""
    result = get_remediation_targets([])
    assert result == []


@pytest.mark.integration
def test_get_remediation_targets_nonexistent_alert():
    """Test get_remediation_targets with non-existent alert UUID"""
    result = get_remediation_targets(["nonexistent-uuid"])
    assert result == []


@pytest.mark.integration
def test_get_remediation_targets_single_alert_no_observables():
    """Test get_remediation_targets with alert that has no observables with remediation targets"""
    # Create a root analysis with no observables
    root = create_root_analysis()
    root.save()
    
    # Create alert from root analysis
    alert = ALERT(root)
    
    result = get_remediation_targets([alert.uuid])
    assert result == []


@pytest.mark.integration
def test_get_remediation_targets_single_alert_with_observables():
    """Test get_remediation_targets with alert containing observables with remediation targets"""
    from saq.observables import MessageIDObservable
    from saq.email_archive import archive_email
    import tempfile
    import os
    
    # Create a temporary email file and archive it
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        f.write(b"test email content")
        temp_email_path = f.name
    
    try:
        message_id = "<test@example.com>"
        recipients = ["user1@company.com", "user2@company.com"]
        archive_email(temp_email_path, message_id, recipients, local_time())
        
        # Create root analysis with MessageID observable
        root = create_root_analysis()
        
        # Add MessageID observable which has remediation targets
        observable = root.add_observable(MessageIDObservable(message_id))
        
        # Create alert from root analysis
        root.save()
        alert = ALERT(root)
        
        result = get_remediation_targets([alert.uuid])
        
        # Should return 2 remediation targets (one for each recipient)
        assert len(result) == 2
        assert all(isinstance(target, RemediationTarget) for target in result)
        assert all(target.type == "email" for target in result)
        
        # Check that targets contain expected email keys
        target_values = [target.value for target in result]
        expected_values = [f"{message_id}|{recipient}" for recipient in recipients]
        for expected in expected_values:
            assert expected in target_values
            
    finally:
        os.unlink(temp_email_path)


@pytest.mark.integration
def test_get_remediation_targets_multiple_alerts():
    """Test get_remediation_targets with multiple alerts"""
    from saq.observables import MessageIDObservable
    from saq.email_archive import archive_email
    import tempfile
    import os
    
    temp_files = []
    try:
        # Create first alert with MessageID observable
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"test email content 1")
            temp_files.append(f.name)
        
        message_id_1 = "<test1@example.com>"
        recipients_1 = ["user1@company.com"]
        archive_email(temp_files[0], message_id_1, recipients_1, local_time())
        
        root1 = create_root_analysis(uuid=str(uuid.uuid4()))

        observable1 = root1.add_observable(MessageIDObservable(message_id_1))
        root1.save()
        alert1 = ALERT(root1)
        
        # Create second alert with MessageID observable
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"test email content 2")
            temp_files.append(f.name)
        
        message_id_2 = "<test2@example.com>"
        recipients_2 = ["user2@company.com", "user3@company.com"]
        archive_email(temp_files[1], message_id_2, recipients_2, local_time())
        
        root2 = create_root_analysis(uuid=str(uuid.uuid4()))
        
        observable2 = root2.add_observable(MessageIDObservable(message_id_2))
        root2.save()
        alert2 = ALERT(root2)
        
        result = get_remediation_targets([alert1.uuid, alert2.uuid])
        
        # Should return 3 remediation targets total (1 from first alert, 2 from second)
        assert len(result) == 3
        assert all(isinstance(target, RemediationTarget) for target in result)
        assert all(target.type == "email" for target in result)
        
        # Check that all expected targets are present
        target_values = [target.value for target in result]
        expected_values = [
            f"{message_id_1}|{recipients_1[0]}",
            f"{message_id_2}|{recipients_2[0]}",
            f"{message_id_2}|{recipients_2[1]}"
        ]
        for expected in expected_values:
            assert expected in target_values
            
    finally:
        for temp_file in temp_files:
            os.unlink(temp_file)


@pytest.mark.integration 
def test_get_remediation_targets_deduplication():
    """Test that get_remediation_targets properly deduplicates targets with same type and value"""
    from saq.observables import MessageIDObservable
    from saq.email_archive import archive_email
    import tempfile
    import os
    
    temp_files = []
    try:
        # Create two identical MessageID observables in different alerts
        message_id = "<duplicate@example.com>"
        recipients = ["user@company.com"]
        
        for i in range(2):
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
                f.write(f"test email content {i}".encode())
                temp_files.append(f.name)
            
            archive_email(temp_files[i], message_id, recipients, local_time())
            
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            observable = root.add_observable(MessageIDObservable(message_id))
            root.save()
            alert = ALERT(root)
            
            if i == 0:
                alert_uuids = [alert.uuid]
            else:
                alert_uuids.append(alert.uuid)
        
        result = get_remediation_targets(alert_uuids)
        
        # Should return only 1 remediation target despite having 2 identical observables
        assert len(result) == 1
        assert result[0].type == "email"
        assert result[0].value == f"{message_id}|{recipients[0]}"
        
    finally:
        for temp_file in temp_files:
            os.unlink(temp_file)


@pytest.mark.integration
def test_get_remediation_targets_sorting():
    """Test that get_remediation_targets returns targets in sorted order"""
    from saq.observables import MessageIDObservable
    from saq.email_archive import archive_email
    import tempfile
    import os
    
    temp_files = []
    try:
        # Create multiple MessageID observables with different values to test sorting
        test_data = [
            ("<zzz@example.com>", ["zzz@company.com"]),
            ("<aaa@example.com>", ["aaa@company.com"]),
            ("<mmm@example.com>", ["mmm@company.com"])
        ]
        
        alert_uuids = []
        for i, (message_id, recipients) in enumerate(test_data):
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
                f.write(f"test email content {i}".encode())
                temp_files.append(f.name)
            
            archive_email(temp_files[i], message_id, recipients, local_time())
            
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            
            observable = root.add_observable(MessageIDObservable(message_id))
            root.save()
            alert = ALERT(root)
            alert_uuids.append(alert.uuid)
        
        result = get_remediation_targets(alert_uuids)
        
        # Should return 3 targets sorted by observable_id|type|value
        assert len(result) == 3
        
        # Extract the sort keys and verify they're in ascending order
        sort_keys = [f"{target.observable_database_id}|{target.type}|{target.value}" for target in result]
        assert sort_keys == sorted(sort_keys)
        
    finally:
        for temp_file in temp_files:
            os.unlink(temp_file)


@pytest.mark.integration
def test_get_remediation_targets_mixed_observable_types():
    """Test get_remediation_targets with mix of observables that have and don't have remediation targets"""
    from saq.observables import MessageIDObservable, FQDNObservable
    from saq.email_archive import archive_email
    import tempfile
    import os
    
    # Create a temporary email file and archive it
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        f.write(b"test email content")
        temp_email_path = f.name
    
    try:
        message_id = "<mixed@example.com>"
        recipients = ["user@company.com"]
        archive_email(temp_email_path, message_id, recipients, local_time())
        
        # Create root analysis with both MessageID (has targets) and FQDN (no targets) observables
        root = create_root_analysis()
        
        # Add MessageID observable (has remediation targets)
        message_observable = root.add_observable(MessageIDObservable(message_id))
        
        # Add FQDN observable (no remediation targets)
        fqdn_observable = root.add_observable(FQDNObservable("example.com"))
        
        root.save()
        alert = ALERT(root)
        
        result = get_remediation_targets([alert.uuid])
        
        # Should return only 1 target from MessageID observable, FQDN should be ignored
        assert len(result) == 1
        assert result[0].type == "email"
        assert result[0].value == f"{message_id}|{recipients[0]}"
        
    finally:
        os.unlink(temp_email_path)