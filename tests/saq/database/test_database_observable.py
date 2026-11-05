import pymysql
import pytest

from saq.constants import QUEUE_DEFAULT
from saq.database.pool import get_db, get_db_connection
from saq.database.database_observable import observable_is_interesting, observable_is_set_for_detection, upsert_observable
from saq.database.model import Observable as DBObservable, ObservableDetection
from saq.database.util.observable_detection import create_observable_detection
from saq.observables import create_observable


@pytest.fixture(autouse=True)
def clean_detections():
    get_db().query(ObservableDetection).delete()
    get_db().commit()
    yield
    get_db().query(ObservableDetection).delete()
    get_db().commit()


@pytest.mark.integration
def test_observable_is_set_for_detection_requires_a_matching_type():
    """A detection matches only when type and hash both match."""
    detected = create_observable("fqdn", "shared.example.com")
    create_observable_detection(detected.type, detected.value, None)

    other_type = create_observable("url_domain", "shared.example.com")
    assert other_type is not None
    assert detected.sha256_bytes == other_type.sha256_bytes

    assert observable_is_set_for_detection(detected) is True
    assert observable_is_set_for_detection(other_type) is False

def _store_observable(observable, is_interesting: bool):
    get_db().add(DBObservable(type=observable.type, sha256=observable.sha256_bytes,
                              value=observable.value.encode("utf8"), is_interesting=is_interesting))
    get_db().commit()


@pytest.mark.integration
def test_observable_is_interesting_false():
    observable = create_observable("ipv4", "192.168.1.1")
    _store_observable(observable, False)

    assert observable_is_interesting(observable) is False


@pytest.mark.integration
def test_observable_is_interesting_requires_a_matching_type():
    """Same hash under another type is another observable."""
    interesting = create_observable("fqdn", "shared.example.com")
    _store_observable(interesting, True)

    other_type = create_observable("url_domain", "shared.example.com")
    assert other_type is not None
    assert interesting.sha256_bytes == other_type.sha256_bytes

    assert observable_is_interesting(interesting) is True
    assert observable_is_interesting(other_type) is False


@pytest.mark.integration
def test_upsert_observable_new():
    """Test upserting a new observable that doesn't exist."""
    observable = create_observable("test", "upsert_test_new")
    assert observable is not None
    
    # Ensure it doesn't exist
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE type = %s AND sha256 = %s", 
                      (observable.type, observable.sha256_bytes))
        result = cursor.fetchone()
        assert result[0] == 0
    
    # Upsert the observable
    obs_id = upsert_observable(observable)
    assert obs_id is not None
    assert isinstance(obs_id, int)
    assert obs_id > 0
    
    # Verify it was inserted
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, type, value, sha256, for_detection FROM observables WHERE id = %s", (obs_id,))
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == obs_id
        assert result[1] == observable.type
        assert result[2].decode("utf-8") == observable.value
        assert result[3] == observable.sha256_bytes


@pytest.mark.integration
def test_upsert_observable_existing():
    """Test upserting an observable that already exists."""
    observable = create_observable("test", "upsert_test_existing")
    assert observable is not None
    
    # First insert manually
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO observables (`type`, `value`, `sha256`, `for_detection`) VALUES (%s, %s, %s, %s)",
                      (observable.type, observable.value, observable.sha256_bytes, True))
        db.commit()
        original_id = cursor.lastrowid
    
    # Upsert the same observable
    obs_id = upsert_observable(observable)
    assert obs_id == original_id
    
    # Verify no duplicate was created
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE type = %s AND sha256 = %s",
                      (observable.type, observable.sha256_bytes))
        result = cursor.fetchone()
        assert result[0] == 1


@pytest.mark.integration
def test_upsert_observable_same_value_different_type():
    """The same value under two types is two observables, though the two share a hash."""
    fqdn = create_observable("fqdn", "upsert.example.com")
    url_domain = create_observable("url_domain", "upsert.example.com")
    assert fqdn.sha256_bytes == url_domain.sha256_bytes

    assert upsert_observable(fqdn) != upsert_observable(url_domain)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM observables WHERE sha256 = %s", (fqdn.sha256_bytes,))
        assert cursor.fetchone()[0] == 2


@pytest.mark.integration
def test_upsert_observable_returns_the_row_another_writer_inserted_first(monkeypatch):
    """Another writer commits the observable between the upsert's SELECT and its INSERT: the INSERT
    hits the unique key, and the upsert returns the other writer's row."""
    observable = create_observable("test", "race_condition_test")
    other_id = []
    execute = pymysql.cursors.Cursor.execute

    def execute_then_race(self, query, args=None):
        result = execute(self, query, args)
        if query.startswith("SELECT id FROM observables") and not other_id:
            other_id.append(None)
            with get_db_connection() as other:
                cursor = other.cursor()
                execute(cursor, "INSERT INTO observables (`type`, `value`, `sha256`) VALUES (%s, %s, %s)",
                        (observable.type, observable.value, observable.sha256_bytes))
                other.commit()
                other_id[0] = cursor.lastrowid
        return result

    monkeypatch.setattr(pymysql.cursors.Cursor, "execute", execute_then_race)
    obs_id = upsert_observable(observable)
    monkeypatch.undo()

    assert other_id[0] is not None
    assert obs_id == other_id[0]


#
# Batched disposition history.
#
# get_observable_disposition_histories() is the batched form of
# get_observable_disposition_history(). The alert view reads the history twice per
# rendered observable node, so the per-observable form issued hundreds of 3-table
# aggregate joins for one page. The two must agree.
#

def _alert_with_observables(description: str, disposition: str, observables: list,
                            queue: str = QUEUE_DEFAULT):
    """Creates a dispositioned alert in the given queue carrying the given observables."""
    import uuid as uuid_module

    from saq.analysis.root import RootAnalysis
    from saq.constants import ANALYSIS_MODE_ANALYSIS
    from saq.database.model import Alert as DBAlert
    from saq.database.util.alert import ALERT
    from saq.util.uuid import storage_dir_from_uuid

    root_uuid = str(uuid_module.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        tool="tool",
        tool_instance="tool_instance",
        alert_type="alert_type",
        desc=description,
        storage_dir=storage_dir_from_uuid(root_uuid),
        queue=queue,
        analysis_mode=ANALYSIS_MODE_ANALYSIS)
    root.initialize_storage()
    for observable in observables:
        root.add_observable_by_spec(observable.type, observable.value)

    root.save()
    alert = ALERT(root)

    get_db().query(DBAlert).filter(DBAlert.uuid == root_uuid).update(
        {"disposition": disposition}, synchronize_session=False)
    get_db().commit()
    return alert


@pytest.mark.integration
def test_batched_disposition_history_matches_per_observable():
    from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE
    from saq.database.database_observable import (
        get_observable_disposition_histories,
        get_observable_disposition_history,
    )

    observable = create_observable("ipv4", "192.168.60.1")
    other = create_observable("ipv4", "192.168.60.2")

    _alert_with_observables("fp alert one", DISPOSITION_FALSE_POSITIVE, [observable])
    _alert_with_observables("fp alert two", DISPOSITION_FALSE_POSITIVE, [observable, other])
    _alert_with_observables("delivery alert", DISPOSITION_DELIVERY, [observable])

    batched = get_observable_disposition_histories([observable, other])

    for target in (observable, other):
        expected = get_observable_disposition_history(target)
        assert expected  # both observables appear in a dispositioned alert
        assert dict(batched[target.uuid].history) == dict(expected.history)

    assert dict(batched[observable.uuid].history) == {
        DISPOSITION_FALSE_POSITIVE: 2,
        DISPOSITION_DELIVERY: 1,
    }


@pytest.mark.integration
def test_batched_disposition_history_skips_whitelisted_and_unseen():
    from saq.constants import DISPOSITION_FALSE_POSITIVE
    from saq.database.database_observable import (
        get_observable_disposition_histories,
        get_observable_disposition_history,
    )

    whitelisted = create_observable("ipv4", "192.168.60.3")
    unseen = create_observable("ipv4", "192.168.60.4")

    _alert_with_observables("fp alert", DISPOSITION_FALSE_POSITIVE, [whitelisted])
    whitelisted.whitelist()

    batched = get_observable_disposition_histories([whitelisted, unseen])

    # whitelisted: the per-observable form returns None, the batched form omits it
    assert get_observable_disposition_history(whitelisted) is None
    assert whitelisted.uuid not in batched

    # never seen in a dispositioned alert: the per-observable form returns an empty
    # (falsy) history, the batched form omits it -- the view renders nothing for either
    assert not get_observable_disposition_history(unseen)
    assert unseen.uuid not in batched


@pytest.mark.integration
def test_batched_disposition_history_requires_a_matching_type():
    """A hash can be shared across observable types; the history must not leak between them."""
    from saq.constants import DISPOSITION_FALSE_POSITIVE
    from saq.database.database_observable import get_observable_disposition_histories

    seen = create_observable("fqdn", "history.example.com")
    other_type = create_observable("url_domain", "history.example.com")
    assert other_type is not None
    assert seen.sha256_bytes == other_type.sha256_bytes

    _alert_with_observables("fqdn fp alert", DISPOSITION_FALSE_POSITIVE, [seen])

    batched = get_observable_disposition_histories([seen, other_type])
    assert dict(batched[seen.uuid].history) == {DISPOSITION_FALSE_POSITIVE: 1}
    assert other_type.uuid not in batched


@pytest.mark.integration
def test_disposition_history_only_counts_the_default_queue():
    """The badge summarizes the default triage queue, not every queue.

    Alerts in other queues are a different population, so they must not be folded
    into the counts the alert page's analysis tree renders.
    """
    from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE
    from saq.database.database_observable import (
        get_observable_disposition_histories,
        get_observable_disposition_history,
    )

    both_queues = create_observable("ipv4", "192.168.60.5")
    external_only = create_observable("ipv4", "192.168.60.6")

    _alert_with_observables("default queue fp", DISPOSITION_FALSE_POSITIVE, [both_queues])
    _alert_with_observables(
        "external queue delivery", DISPOSITION_DELIVERY, [both_queues, external_only],
        queue="external")

    batched = get_observable_disposition_histories([both_queues, external_only])

    # seen in both queues: only the default-queue alert is counted
    expected = {DISPOSITION_FALSE_POSITIVE: 1}
    assert dict(batched[both_queues.uuid].history) == expected
    assert dict(get_observable_disposition_history(both_queues).history) == expected

    # seen only outside the default queue: absent from the batched form, falsy from the
    # per-observable form -- the same contract as an observable never seen at all
    assert external_only.uuid not in batched
    assert not get_observable_disposition_history(external_only)
