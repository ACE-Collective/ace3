import pytest
from datetime import datetime

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import MAX_DETECTION_VALUE_LENGTH
from saq.database.model import Observable as DBObservable, ObservableDetection as DBObservableDetection, User
from saq.database.pool import get_db
from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    ObservableDetectionSummary,
    create_observable_detection,
    delete_observable_detection,
    disable_observable_detection,
    enable_observable_detection,
    get_all_observable_detections,
    get_observable_detection,
    get_observable_detection_for,
    get_observable_detections,
    resolve_detection_identity,
    set_observable_detection_expiration,
    _match_observable,
)
from saq.database.util.sync import sync_observable
from saq.observables.generator import create_observable
from saq.observables.file import FileObservable
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission


@pytest.fixture
def test_user() -> User:
    """Create a test user for observable detection tests."""
    username = "detection_test_user"
    email = "detection_test@example.com"
    display_name = "Detection Test User"
    password = "testpass123"

    user = add_user(username, email, display_name, password)
    add_user_permission(user.id, "*", "*")
    yield user

    try:
        delete_user(username)
    except Exception:
        pass


@pytest.fixture
def test_observable():
    return Observable(type="ipv4", value="192.168.1.1")


@pytest.fixture
def test_observables():
    return [
        Observable(type="ipv4", value="192.168.1.1"),
        Observable(type="fqdn", value="example.com"),
        Observable(type="url", value="http://malicious.example.com/path"),
        Observable(type="file", value="malicious.exe"),
    ]


@pytest.fixture
def test_root_analysis(test_observables):
    root = RootAnalysis()
    for observable in test_observables:
        root.add_observable(observable)
    return root


@pytest.fixture(autouse=True)
def clean_detections():
    """Each test starts with an empty detection table."""
    get_db().query(DBObservableDetection).delete()
    get_db().commit()
    yield
    get_db().query(DBObservableDetection).delete()
    get_db().commit()


#
# resolve_detection_identity: validation and normalization
#


@pytest.mark.integration
def test_resolve_detection_identity_matches_the_real_observable_class():
    """The stored value and hash are exactly what the analysis engine will produce.

    This is what makes a detection actually fire: the analyzer looks observables up in redis under
    f"{type}:{value}" built from the in-memory observable, so anything that resolved differently
    here would produce a detection that silently never matches.
    """
    identity = resolve_detection_identity("ipv4", "1.2.3.4")
    engine_view = create_observable("ipv4", "1.2.3.4")

    assert identity.type == engine_view.type
    assert identity.value == engine_view.value
    assert identity.value_sha256 == engine_view.sha256_bytes


@pytest.mark.integration
def test_resolve_detection_identity_normalizes():
    """Types whose value setter normalizes are stored normalized."""
    identity = resolve_detection_identity("ipv4_conversation", " 1.2.3.4_5.6.7.8 ")
    assert identity.value == "1.2.3.4_5.6.7.8"


@pytest.mark.integration
def test_resolve_detection_identity_rejects_invalid_value_for_type():
    with pytest.raises(InvalidDetectionValue):
        resolve_detection_identity("ipv4", "notanip")


@pytest.mark.integration
def test_resolve_detection_identity_rejects_overlong_value():
    too_long = "https://example.com/" + ("x" * MAX_DETECTION_VALUE_LENGTH)
    with pytest.raises(InvalidDetectionValue):
        resolve_detection_identity("url", too_long)


@pytest.mark.integration
def test_resolve_detection_identity_file_uses_content_hash():
    """A file detection is keyed by unhex(value), not sha256(value).

    A FileObservable cannot be constructed without a file_path, and a detection has none -- it
    identifies content, not a location -- so this path must not go through create_observable.
    """
    identity = resolve_detection_identity("file", FILE_CONTENT_SHA256.upper())
    assert identity.type == "file"
    # lowercased to match hexdigest(), which is what the runtime redis key is built from
    assert identity.value == FILE_CONTENT_SHA256
    assert identity.value_sha256 == bytes.fromhex(FILE_CONTENT_SHA256)

    # and it agrees with a real FileObservable, which is how the alert view looks it up
    file_obs = FileObservable(value=FILE_CONTENT_SHA256, file_path="malicious.exe")
    assert identity.value_sha256 == file_obs.sha256_bytes


@pytest.mark.integration
@pytest.mark.parametrize("bad_value", ["not-a-hash", "abcd", ""])
def test_resolve_detection_identity_rejects_bad_file_value(bad_value):
    with pytest.raises(InvalidDetectionValue):
        resolve_detection_identity("file", bad_value)


#
# create / delete
#


@pytest.mark.integration
def test_create_detection_for_never_seen_observable(test_user):
    """The point of the separate table: a detection needs no observables index row."""
    detection = create_observable_detection(
        "fqdn", "never-seen.example.com", test_user.id, detection_context="added ahead of time")

    assert detection.id is not None
    assert detection.value == "never-seen.example.com"
    assert detection.created_by == test_user.id
    assert detection.detection_context == "added ahead of time"

    # nothing was written to the observables index
    assert get_db().query(DBObservable).filter(
        DBObservable.sha256 == detection.value_sha256).one_or_none() is None


@pytest.mark.integration
def test_create_detection_is_idempotent_on_type_and_value(test_user):
    first = create_observable_detection("ipv4", "1.2.3.4", test_user.id, detection_context="one")
    second = create_observable_detection("ipv4", "1.2.3.4", test_user.id, detection_context="two")

    assert first.id == second.id
    assert second.detection_context == "two"
    assert get_db().query(DBObservableDetection).count() == 1


@pytest.mark.integration
def test_create_detection_same_value_different_type_are_distinct(test_user):
    create_observable_detection("fqdn", "example.com", test_user.id)
    create_observable_detection("url_domain", "example.com", test_user.id)
    assert get_db().query(DBObservableDetection).count() == 2


@pytest.mark.integration
def test_create_detection_rejects_invalid_value(test_user):
    with pytest.raises(InvalidDetectionValue):
        create_observable_detection("ipv4", "notanip", test_user.id)


@pytest.mark.integration
def test_new_detection_gets_the_configured_per_type_default_expiration(test_user):
    """observable_expiration_mappings now means "how long a detection of this type lives".

    It used to be applied by ingest to every observable it indexed, whether or not anyone wanted a
    detection on it -- which is what made observables.expires_on mean two different things.
    """
    get_config().observable_expiration_mappings["ipv4"] = "01:00:00:00"
    try:
        detection = create_observable_detection("ipv4", "10.10.10.10", test_user.id)
        assert detection.expires_on is not None
    finally:
        del get_config().observable_expiration_mappings["ipv4"]


@pytest.mark.integration
def test_new_detection_of_an_unmapped_type_never_expires(test_user):
    """The default configuration maps nothing, so detections never expire unless told to."""
    detection = create_observable_detection("fqdn", "unmapped.example.com", test_user.id)
    assert detection.expires_on is None


@pytest.mark.integration
def test_explicit_expiration_beats_the_default(test_user):
    get_config().observable_expiration_mappings["ipv4"] = "01:00:00:00"
    try:
        explicit = datetime(2099, 6, 1, 0, 0, 0)
        detection = create_observable_detection(
            "ipv4", "10.10.10.11", test_user.id, expires_on=explicit)
        assert detection.expires_on == explicit
    finally:
        del get_config().observable_expiration_mappings["ipv4"]


@pytest.mark.integration
def test_re_enabling_does_not_reset_an_analyst_chosen_expiration(test_user, test_observable):
    """The per-type default applies on insert only."""
    get_config().observable_expiration_mappings[test_observable.type] = "01:00:00:00"
    try:
        detection = enable_observable_detection(test_observable, test_user.id, "enabled")
        chosen = datetime(2099, 6, 1, 0, 0, 0)
        set_observable_detection_expiration(detection.id, chosen, test_user.id)

        again = enable_observable_detection(test_observable, test_user.id, "enabled again")
        assert again.expires_on == chosen
    finally:
        del get_config().observable_expiration_mappings[test_observable.type]


@pytest.mark.integration
def test_delete_observable_detection(test_user):
    detection = create_observable_detection("ipv4", "5.5.5.5", test_user.id)
    assert delete_observable_detection(detection.id) is True
    assert get_db().query(DBObservableDetection).count() == 0
    assert delete_observable_detection(detection.id) is False


#
# enable / disable from an in-memory analysis Observable
#


@pytest.mark.integration
def test_enable_observable_detection_creates_no_observables_row(test_user, test_observable):
    """Enabling used to insert into `observables` as a side effect. That table is the ingest path's."""
    detection = enable_observable_detection(test_observable, test_user.id, "manually enabled")

    assert detection.type == test_observable.type
    assert detection.value == test_observable.value
    assert detection.value_sha256 == test_observable.sha256_bytes
    assert detection.modified_by == test_user.id
    assert detection.detection_context == "manually enabled"

    assert get_db().query(DBObservable).filter(
        DBObservable.sha256 == test_observable.sha256_bytes).one_or_none() is None


@pytest.mark.integration
def test_enable_observable_detection_existing(test_user, test_observable):
    enable_observable_detection(test_observable, test_user.id, "first")
    detection = enable_observable_detection(test_observable, test_user.id, "second")

    assert detection.detection_context == "second"
    assert get_db().query(DBObservableDetection).count() == 1


@pytest.mark.integration
def test_enable_observable_detection_unknown_user(test_observable):
    with pytest.raises(ValueError):
        enable_observable_detection(test_observable, 999999, "context")


@pytest.mark.integration
def test_disable_observable_detection_removes_the_row(test_user, test_observable):
    """A row is an active detection, so disabling deletes it."""
    enable_observable_detection(test_observable, test_user.id, "enabled")
    assert disable_observable_detection(test_observable, test_user.id, "disabled") is True
    assert get_observable_detection_for(test_observable) is None


@pytest.mark.integration
def test_disable_observable_detection_missing_is_a_noop(test_user, test_observable):
    assert disable_observable_detection(test_observable, test_user.id, "disabled") is False


#
# expiration
#


@pytest.mark.integration
def test_set_observable_detection_expiration(test_user, test_observable):
    # NOTE: the unittest config maps ipv4 to a 14 day default, so a new detection of this type
    # starts with an expiration rather than None
    detection = enable_observable_detection(test_observable, test_user.id, "enabled")

    expires = datetime(2099, 1, 1, 12, 0, 0)
    updated = set_observable_detection_expiration(detection.id, expires, test_user.id)
    assert updated.expires_on == expires

    cleared = set_observable_detection_expiration(detection.id, None, test_user.id)
    assert cleared.expires_on is None


@pytest.mark.integration
def test_set_observable_detection_expiration_unknown_id(test_user):
    assert set_observable_detection_expiration(999999, None, test_user.id) is None


@pytest.mark.integration
def test_get_observable_detection_by_type_and_hash(test_user, test_observable):
    enable_observable_detection(test_observable, test_user.id, "enabled")

    assert get_observable_detection(test_observable.type, test_observable.sha256_bytes) is not None
    # a matching hash under a different type is a different detection
    assert get_observable_detection("fqdn", test_observable.sha256_bytes) is None


#
# lookups used to render the alert view
#


@pytest.mark.integration
def test_get_observable_detections(test_user, test_observables):
    enable_observable_detection(test_observables[0], test_user.id, "context one")
    enable_observable_detection(test_observables[1], test_user.id, "context two")

    detections = get_observable_detections(test_observables)

    assert set(detections) == {test_observables[0].uuid, test_observables[1].uuid}
    assert detections[test_observables[0].uuid].for_detection is True
    assert detections[test_observables[0].uuid].detection_context == "context one"
    assert detections[test_observables[0].uuid].detection_modified_by == test_user.display_name


@pytest.mark.integration
def test_get_observable_detections_omits_observables_without_one(test_user, test_observables):
    enable_observable_detection(test_observables[0], test_user.id, "context")
    detections = get_observable_detections(test_observables)
    assert test_observables[1].uuid not in detections


@pytest.mark.integration
def test_get_observable_detections_empty_input():
    assert get_observable_detections([]) == {}


@pytest.mark.integration
def test_get_all_observable_detections(test_user, test_root_analysis, test_observables):
    enable_observable_detection(test_observables[0], test_user.id, "context")
    detections = get_all_observable_detections(test_root_analysis)
    assert test_observables[0].uuid in detections


@pytest.mark.integration
def test_match_observable(test_user, test_observables):
    detection = enable_observable_detection(test_observables[0], test_user.id, "context")

    assert _match_observable(test_observables, detection) is test_observables[0]

    detection.type = "does_not_match"
    assert _match_observable(test_observables, detection) is None


#
# file observables
#

# The sha256 hex of some file's contents. A FileObservable's *value* is this string; the file
# itself need not exist on disk for these tests.
FILE_CONTENT_SHA256 = "33699d5edadeda6a4d87091cb701215ac698a8292ec93196146e155cf9786166"


@pytest.mark.integration
def test_file_observable_sha256_bytes_matches_sha256_hash():
    """A FileObservable's sha256_bytes must be the raw bytes of its sha256_hash.

    This invariant holds for every other observable type. FileObservable overrides sha256_hash (to
    the file's content sha256) so it must also override sha256_bytes -- otherwise sha256_bytes is a
    hash-of-the-hash, which never matches the observables.sha256 column populated by sync.py via
    UNHEX(sha256_hash), and the detect-enabled / comments / interesting lookups silently miss files.
    """
    file_obs = FileObservable(value=FILE_CONTENT_SHA256, file_path="malicious.exe")
    assert file_obs.sha256_bytes == bytes.fromhex(file_obs.sha256_hash)
    assert file_obs.sha256_bytes == bytes.fromhex(FILE_CONTENT_SHA256)

    # the invariant also holds (unchanged) for a base observable
    base_obs = Observable(type="ipv4", value="192.168.1.1")
    assert base_obs.sha256_bytes == bytes.fromhex(base_obs.sha256_hash)


@pytest.mark.integration
def test_get_observable_detections_file_observable(test_user):
    """A FILE observable's detection is keyed by the file's content sha256.

    Regression for FILE observables never showing the "(detect enabled)" marker. Uses a real
    FileObservable, not the base-Observable "file" fixture, which is why the original tests did not
    catch this.
    """
    file_obs = FileObservable(value=FILE_CONTENT_SHA256, file_path="malicious.exe")

    detection = enable_observable_detection(file_obs, test_user.id, "file detection context")
    assert detection.value_sha256 == bytes.fromhex(FILE_CONTENT_SHA256)

    detections = get_observable_detections([file_obs])
    assert file_obs.uuid in detections
    assert detections[file_obs.uuid].for_detection is True
    assert detections[file_obs.uuid].detection_context == "file detection context"


@pytest.mark.integration
def test_file_detection_joins_to_the_observables_index(test_user):
    """The detection's hash matches what sync_observable writes, so the LEFT JOIN back lines up."""
    file_obs = FileObservable(value=FILE_CONTENT_SHA256, file_path="malicious.exe")

    db = get_db()
    existing = db.query(DBObservable).filter(
        DBObservable.sha256 == file_obs.sha256_bytes,
        DBObservable.type == file_obs.type,
    ).first()
    if existing:
        db.delete(existing)
        db.commit()

    try:
        # populate the observables table exactly as alert processing does
        synced = sync_observable(file_obs)
        db.commit()

        detection = enable_observable_detection(file_obs, test_user.id, "file detection context")
        assert synced.sha256 == detection.value_sha256
        assert synced.type == detection.type
    finally:
        row = db.query(DBObservable).filter(
            DBObservable.sha256 == file_obs.sha256_bytes,
            DBObservable.type == file_obs.type,
        ).first()
        if row:
            db.delete(row)
            db.commit()


@pytest.mark.integration
def test_observable_detection_summary_dataclass():
    summary = ObservableDetectionSummary(
        observable_uuid="test-uuid-123",
        for_detection=True,
        detection_modified_by="Test User",
        detection_context="test context",
    )

    assert summary.observable_uuid == "test-uuid-123"
    assert summary.for_detection is True
    assert summary.detection_modified_by == "Test User"
    assert summary.detection_context == "test context"
