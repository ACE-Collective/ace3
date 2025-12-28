import pytest
from flask import session, url_for

from app.remediation.constants import (
    R_DEFAULT_SORT_FILTER,
    R_DEFAULT_SORT_FILTER_DIRECTION,
    R_FILTER_ACTION,
    R_FILTER_ANALYST,
    R_FILTER_ID,
    R_FILTER_REMEDIATOR,
    R_FILTER_RESULT,
    R_FILTER_STATUS,
    R_FILTER_TYPE,
    R_FILTER_VALUE,
    R_PAGE_OFFSET,
    R_PAGE_OFFSET_BACKWARD,
    R_PAGE_OFFSET_END,
    R_PAGE_OFFSET_FORWARD,
    R_PAGE_OFFSET_START,
    R_PAGE_SIZE,
    R_PAGE_SIZE_DEFAULT,
    R_SORT_FILTER,
    R_SORT_FILTER_DESC,
    RemediationSortFilter,
    SortFilterDirection,
)
from app.remediation.views.remediations import (
    get_current_pagination_offset,
    get_current_pagination_size,
    get_current_sort_filter,
    get_current_sort_filter_direction,
    get_sort_filter_column_by_name,
    get_total_remediations_count,
    remediate_target,
)
from saq.database.model import Remediation, User
from saq.database.pool import get_db
from saq.remediation.target import (
    ObservableRemediationInterface,
    RemediationTarget,
    register_observable_remediation_interface,
    reset_observable_remediation_interface_registry,
)
from saq.remediation.types import RemediationAction, RemediationStatus

pytestmark = pytest.mark.integration


class TestSessionHelperFunctions:
    """Test session helper functions for pagination and sorting."""

    @pytest.mark.parametrize("session_key,session_value,func,expected", [
        (R_PAGE_OFFSET, None, get_current_pagination_offset, 0),
        (R_PAGE_OFFSET, 100, get_current_pagination_offset, 100),
        (R_PAGE_SIZE, None, get_current_pagination_size, R_PAGE_SIZE_DEFAULT),
        (R_PAGE_SIZE, 75, get_current_pagination_size, 75),
    ])
    def test_pagination_helpers(self, app, session_key, session_value, func, expected):
        """Test pagination helper functions with and without session values."""
        with app.test_request_context():
            if session_value is not None:
                session[session_key] = session_value
            result = func()
            assert result == expected

    @pytest.mark.parametrize("session_value,expected,should_update_session", [
        (None, R_DEFAULT_SORT_FILTER, False),
        (RemediationSortFilter.TYPE.value, RemediationSortFilter.TYPE, False),
        ("invalid_value", R_DEFAULT_SORT_FILTER, True),
    ])
    def test_get_current_sort_filter(self, app, session_value, expected, should_update_session):
        """Test getting sort filter with various session states."""
        with app.test_request_context():
            if session_value is not None:
                session[R_SORT_FILTER] = session_value
            sort_filter = get_current_sort_filter()
            assert sort_filter == expected
            if should_update_session:
                assert session[R_SORT_FILTER] == R_DEFAULT_SORT_FILTER.value

    @pytest.mark.parametrize("session_value,expected,should_update_session", [
        (None, R_DEFAULT_SORT_FILTER_DIRECTION, False),
        (SortFilterDirection.ASC.value, SortFilterDirection.ASC, False),
        ("invalid_direction", R_DEFAULT_SORT_FILTER_DIRECTION, True),
    ])
    def test_get_current_sort_filter_direction(self, app, session_value, expected, should_update_session):
        """Test getting sort filter direction with various session states."""
        with app.test_request_context():
            if session_value is not None:
                session[R_SORT_FILTER_DESC] = session_value
            direction = get_current_sort_filter_direction()
            assert direction == expected
            if should_update_session:
                assert session[R_SORT_FILTER_DESC] == R_DEFAULT_SORT_FILTER_DIRECTION.value


class TestGetSortFilterColumn:
    """Test the get_sort_filter_column_by_name function."""

    @pytest.mark.parametrize("sort_filter,expected_column", [
        (RemediationSortFilter.ID, Remediation.id),
        (RemediationSortFilter.REMEDIATOR, Remediation.name),
        (RemediationSortFilter.TYPE, Remediation.type),
        (RemediationSortFilter.ANALYST, Remediation.user_id),
        (RemediationSortFilter.ACTION, Remediation.action),
        (RemediationSortFilter.STATUS, Remediation.status),
        (RemediationSortFilter.RESULT, Remediation.result),
    ])
    def test_get_sort_filter_column(self, app, sort_filter, expected_column):
        """Test getting correct column for each sort filter type."""
        with app.test_request_context():
            column = get_sort_filter_column_by_name(sort_filter)
            assert column == expected_column


class TestGetTotalRemediationsCount:
    """Test the get_total_remediations_count function."""

    def test_get_total_remediations_count_empty(self, app):
        """Test getting total count when no remediations exist."""
        with app.test_request_context():
            count = get_total_remediations_count()
            assert count == 0

    def test_get_total_remediations_count_with_data(self, app, analyst):
        """Test getting total count with remediations in database."""
        with app.test_request_context():
            # add some test remediations
            for i in range(5):
                remediation = Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key=f"192.168.1.{i}",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                )
                get_db().add(remediation)
            get_db().commit()

            count = get_total_remediations_count()
            assert count == 5


class TestRemediateTarget:
    """Test the remediate_target function."""

    def test_remediate_target_with_no_interfaces(self, app, analyst):
        """Test remediate_target when no interfaces are registered."""
        with app.test_request_context():
            reset_observable_remediation_interface_registry()
            count = remediate_target("ipv4", "192.168.1.1")
            assert count == 0

    def test_remediate_target_with_interface(self, app, analyst, web_client):
        """Test remediate_target with a registered interface."""
        reset_observable_remediation_interface_registry()

        # create a mock interface that returns a remediation target
        class MockInterface(ObservableRemediationInterface):
            def get_remediation_targets(self, observable):
                return [
                    RemediationTarget(
                        remediator_name="test_remediator",
                        observable_type="ipv4",
                        observable_value="192.168.1.1",
                    )
                ]

        register_observable_remediation_interface("ipv4", MockInterface())

        with web_client.session_transaction() as sess:
            # ensure we're authenticated
            pass

        with web_client.application.test_request_context():
            from flask_login import login_user

            user = get_db().query(User).filter(User.id == analyst).first()
            login_user(user)
            count = remediate_target("ipv4", "192.168.1.1")
            assert count == 1

            # verify remediation was queued
            remediation = get_db().query(Remediation).filter(Remediation.key == "192.168.1.1").first()
            assert remediation is not None
            assert remediation.action == RemediationAction.REMOVE.value
            assert remediation.status == RemediationStatus.NEW.value

    def test_remediate_target_invalid_observable(self, app, analyst):
        """Test remediate_target with invalid observable type."""
        with app.test_request_context():
            reset_observable_remediation_interface_registry()
            count = remediate_target("invalid_type", "some_value")
            assert count == 0


#
# XXX these tests are only testing that the HTTP response code is good
# eventually these all turn into FastAPI calls and then we can validate the response data
#

class TestRemediationsRoute:
    """Test the /remediation/remediations route."""

    def test_remediations_post_empty_database(self, web_client):
        """Test POST to remediations route with empty database."""
        filter_values = {
            R_FILTER_ID: "",
            R_FILTER_REMEDIATOR: "",
            R_FILTER_TYPE: "",
            R_FILTER_VALUE: "",
            R_FILTER_ANALYST: "",
            R_FILTER_ACTION: "",
            R_FILTER_STATUS: "",
            R_FILTER_RESULT: "",
        }

        response = web_client.post(
            url_for("remediation.remediations"),
            json={"filter_values": filter_values},
            content_type="application/json",
        )

        assert response.status_code == 200
        # response should be rendered HTML template
        assert b"remediation/remediations.html" in response.data or response.data

    def test_remediations_post_with_data(self, web_client, analyst):
        """Test POST to remediations route with data in database."""
        # add test remediations
        for i in range(3):
            remediation = Remediation(
                type="ipv4",
                name="test_remediator",
                action=RemediationAction.REMOVE.value,
                key=f"192.168.1.{i}",
                user_id=analyst,
                status=RemediationStatus.NEW.value,
            )
            get_db().add(remediation)
        get_db().commit()

        filter_values = {
            R_FILTER_ID: "",
            R_FILTER_REMEDIATOR: "",
            R_FILTER_TYPE: "",
            R_FILTER_VALUE: "",
            R_FILTER_ANALYST: "",
            R_FILTER_ACTION: "",
            R_FILTER_STATUS: "",
            R_FILTER_RESULT: "",
        }

        response = web_client.post(
            url_for("remediation.remediations"),
            json={"filter_values": filter_values},
            content_type="application/json",
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("filter_key,setup_data,filter_value_getter", [
        # ID filter
        (
            R_FILTER_ID,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                )
            ],
            lambda remediations, analyst: str(remediations[0].id),
        ),
        # Type filter
        (
            R_FILTER_TYPE,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
                Remediation(
                    type="fqdn",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="example.com",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
            ],
            lambda remediations, analyst: "ipv4",
        ),
        # Analyst filter
        (
            R_FILTER_ANALYST,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                )
            ],
            lambda remediations, analyst: get_db().query(User).filter(User.id == analyst).first().display_name,
        ),
        # Remediator filter
        (
            R_FILTER_REMEDIATOR,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
                Remediation(
                    type="ipv4",
                    name="other_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.2",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
            ],
            lambda remediations, analyst: "test_remediator",
        ),
        # Value filter
        (
            R_FILTER_VALUE,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="10.0.0.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
            ],
            lambda remediations, analyst: "192.168.1.1",
        ),
        # Action filter
        (
            R_FILTER_ACTION,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.RESTORE.value,
                    key="192.168.1.2",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
            ],
            lambda remediations, analyst: RemediationAction.REMOVE.value,
        ),
        # Status filter
        (
            R_FILTER_STATUS,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.NEW.value,
                ),
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.2",
                    user_id=analyst,
                    status=RemediationStatus.IN_PROGRESS.value,
                ),
            ],
            lambda remediations, analyst: RemediationStatus.NEW.value,
        ),
        # Result filter
        (
            R_FILTER_RESULT,
            lambda analyst: [
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.1",
                    user_id=analyst,
                    status=RemediationStatus.COMPLETED.value,
                    result="SUCCESS",
                ),
                Remediation(
                    type="ipv4",
                    name="test_remediator",
                    action=RemediationAction.REMOVE.value,
                    key="192.168.1.2",
                    user_id=analyst,
                    status=RemediationStatus.COMPLETED.value,
                    result="FAILED",
                ),
            ],
            lambda remediations, analyst: "SUCCESS",
        ),
    ])
    def test_remediations_post_with_filters(self, web_client, analyst, filter_key, setup_data, filter_value_getter):
        """Test POST to remediations route with various filters."""
        # setup test data
        remediations = setup_data(analyst)
        get_db().add_all(remediations)
        get_db().commit()

        # get the filter value to use
        filter_value = filter_value_getter(remediations, analyst)

        # build filter_values dict with all filters empty except the one being tested
        filter_values = {
            R_FILTER_ID: "",
            R_FILTER_REMEDIATOR: "",
            R_FILTER_TYPE: "",
            R_FILTER_VALUE: "",
            R_FILTER_ANALYST: "",
            R_FILTER_ACTION: "",
            R_FILTER_STATUS: "",
            R_FILTER_RESULT: "",
        }
        filter_values[filter_key] = filter_value

        response = web_client.post(
            url_for("remediation.remediations"),
            json={"filter_values": filter_values},
            content_type="application/json",
        )

        assert response.status_code == 200

    def test_remediations_put_invalid_observable(self, web_client):
        """Test PUT to remediations route with invalid observable."""
        response = web_client.put(
            url_for("remediation.remediations"),
            json={"observable_type": "invalid_type", "observable_value": "some_value"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 0

    def test_remediations_put_with_interface(self, web_client, analyst):
        """Test PUT to remediations route with registered interface."""
        reset_observable_remediation_interface_registry()

        class MockInterface(ObservableRemediationInterface):
            def get_remediation_targets(self, observable):
                return [
                    RemediationTarget(
                        remediator_name="test_remediator",
                        observable_type="ipv4",
                        observable_value="192.168.1.1",
                    )
                ]

        register_observable_remediation_interface("ipv4", MockInterface())

        response = web_client.put(
            url_for("remediation.remediations"),
            json={"observable_type": "ipv4", "observable_value": "192.168.1.1"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 1

        # verify remediation was created
        remediation = get_db().query(Remediation).filter(Remediation.key == "192.168.1.1").first()
        assert remediation is not None

    def test_remediations_patch_cancel_action(self, web_client, analyst):
        """Test PATCH to remediations route with cancel action."""
        # create a remediation in progress
        remediation = Remediation(
            type="ipv4",
            name="test_remediator",
            action=RemediationAction.REMOVE.value,
            key="192.168.1.1",
            user_id=analyst,
            status=RemediationStatus.IN_PROGRESS.value,
        )
        get_db().add(remediation)
        get_db().commit()

        response = web_client.patch(
            url_for("remediation.remediations"),
            json={"remediation_ids": [remediation.id], "action": "cancel", "comment": "test cancel"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 1

    def test_remediations_patch_retry_action(self, web_client, analyst):
        """Test PATCH to remediations route with retry action."""
        # create a completed remediation
        remediation = Remediation(
            type="ipv4",
            name="test_remediator",
            action=RemediationAction.REMOVE.value,
            key="192.168.1.1",
            user_id=analyst,
            status=RemediationStatus.COMPLETED.value,
            result="SUCCESS",
        )
        get_db().add(remediation)
        get_db().commit()

        response = web_client.patch(
            url_for("remediation.remediations"),
            json={"remediation_ids": [remediation.id], "action": "retry"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 1

    def test_remediations_patch_restore_action(self, web_client, analyst):
        """Test PATCH to remediations route with restore action."""
        # create a completed removal remediation
        remediation = Remediation(
            type="ipv4",
            name="test_remediator",
            action=RemediationAction.REMOVE.value,
            key="192.168.1.1",
            user_id=analyst,
            status=RemediationStatus.COMPLETED.value,
            result="SUCCESS",
        )
        get_db().add(remediation)
        get_db().commit()

        response = web_client.patch(
            url_for("remediation.remediations"),
            json={"remediation_ids": [remediation.id], "action": "restore"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 1

        # verify a new RESTORE remediation was queued
        restore_remediation = (
            get_db()
            .query(Remediation)
            .filter(
                Remediation.action == RemediationAction.RESTORE.value,
                Remediation.type == "ipv4",
                Remediation.key == "192.168.1.1",
            )
            .first()
        )
        assert restore_remediation is not None
        assert restore_remediation.status == RemediationStatus.NEW.value

    def test_remediations_patch_restore_action_not_eligible(self, web_client, analyst):
        """Test PATCH restore action on remediation that doesn't meet criteria."""
        # create a remediation that is NOT eligible for restore (not COMPLETED)
        remediation = Remediation(
            type="ipv4",
            name="test_remediator",
            action=RemediationAction.REMOVE.value,
            key="192.168.1.1",
            user_id=analyst,
            status=RemediationStatus.IN_PROGRESS.value,
        )
        get_db().add(remediation)
        get_db().commit()

        response = web_client.patch(
            url_for("remediation.remediations"),
            json={"remediation_ids": [remediation.id], "action": "restore"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 0

        # verify no RESTORE remediation was created
        restore_count = (
            get_db()
            .query(Remediation)
            .filter(Remediation.action == RemediationAction.RESTORE.value)
            .count()
        )
        assert restore_count == 0

    def test_remediations_patch_invalid_action(self, web_client):
        """Test PATCH to remediations route with invalid action."""
        response = web_client.patch(
            url_for("remediation.remediations"),
            json={"remediation_ids": [1], "action": "invalid_action"},
            content_type="application/json",
        )

        assert response.status_code == 400

    def test_remediations_delete(self, web_client, analyst):
        """Test DELETE to remediations route."""
        # create a remediation
        remediation = Remediation(
            type="ipv4",
            name="test_remediator",
            action=RemediationAction.REMOVE.value,
            key="192.168.1.1",
            user_id=analyst,
            status=RemediationStatus.NEW.value,
        )
        get_db().add(remediation)
        get_db().commit()
        remediation_id = remediation.id

        response = web_client.delete(
            url_for("remediation.remediations"),
            json={"remediation_ids": [remediation_id]},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 1

        # verify remediation was deleted
        remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
        assert remediation is None

    def test_remediations_requires_permission(self, app):
        """Test that remediations route requires permission."""
        with app.test_client() as client:
            response = client.post(
                url_for("remediation.remediations"),
                json={"filter_values": {}},
                content_type="application/json",
            )
            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location


class TestRemediationsPageRoute:
    """Test the /remediation/remediations/page route."""

    def test_remediations_page_get_default_values(self, web_client):
        """Test GET request returns default pagination values."""
        response = web_client.get(url_for("remediation.remediations_page"))

        assert response.status_code == 200
        data = response.get_json()
        assert "offset" in data
        assert "size" in data
        assert "total" in data
        assert data["offset"] == 0
        assert data["size"] == R_PAGE_SIZE_DEFAULT
        assert data["total"] == 0

    def test_remediations_page_get_with_session_values(self, web_client):
        """Test GET request returns values from session."""
        with web_client.session_transaction() as sess:
            sess[R_PAGE_OFFSET] = 50
            sess[R_PAGE_SIZE] = 100

        response = web_client.get(url_for("remediation.remediations_page"))

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 50
        assert data["size"] == 100

    @pytest.mark.parametrize("requested_size,expected_size", [
        (75, 75),
        (0, 1),  # minimum bound
        (2000, 1000),  # maximum bound
    ])
    def test_remediations_page_post_set_size(self, web_client, requested_size, expected_size):
        """Test POST request to set page size with bounds enforcement."""
        response = web_client.post(
            url_for("remediation.remediations_page"),
            json={"size": requested_size},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["size"] == expected_size

    @pytest.mark.parametrize("direction,initial_offset,page_size,expected_offset", [
        (R_PAGE_OFFSET_START, 100, 50, 0),
        (R_PAGE_OFFSET_BACKWARD, 100, 50, 50),
        (R_PAGE_OFFSET_BACKWARD, 25, 50, 0),  # should not go below 0
    ])
    def test_remediations_page_post_direction_simple(
        self, web_client, direction, initial_offset, page_size, expected_offset
    ):
        """Test POST request with various pagination directions."""
        with web_client.session_transaction() as sess:
            sess[R_PAGE_OFFSET] = initial_offset
            sess[R_PAGE_SIZE] = page_size

        response = web_client.post(
            url_for("remediation.remediations_page"),
            json={"direction": direction},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == expected_offset

    def test_remediations_page_post_direction_forward(self, web_client, analyst):
        """Test POST request with forward direction."""
        # add some remediations to have a total count
        for i in range(200):
            remediation = Remediation(
                type="ipv4",
                name="test_remediator",
                action=RemediationAction.REMOVE.value,
                key=f"192.168.1.{i}",
                user_id=analyst,
                status=RemediationStatus.NEW.value,
            )
            get_db().add(remediation)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[R_PAGE_OFFSET] = 0
            sess[R_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.remediations_page"),
            json={"direction": R_PAGE_OFFSET_FORWARD},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 50

    def test_remediations_page_post_direction_end(self, web_client, analyst):
        """Test POST request with end direction."""
        # add remediations
        for i in range(200):
            remediation = Remediation(
                type="ipv4",
                name="test_remediator",
                action=RemediationAction.REMOVE.value,
                key=f"192.168.1.{i}",
                user_id=analyst,
                status=RemediationStatus.NEW.value,
            )
            get_db().add(remediation)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[R_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.remediations_page"),
            json={"direction": R_PAGE_OFFSET_END},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        # offset should be total - page_size
        assert data["offset"] == 150

    def test_remediations_page_requires_permission(self, app):
        """Test that remediations_page route requires permission."""
        with app.test_client() as client:
            response = client.get(url_for("remediation.remediations_page"))
            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location


class TestRemediationsSortRoute:
    """Test the /remediation/remediations/sort route."""

    def test_remediations_sort_post_direction(self, web_client):
        """Test POST request to set sort direction."""
        response = web_client.post(
            url_for("remediation.remediations_sort"),
            json={"sort_direction": SortFilterDirection.ASC.value},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # verify session was updated
        with web_client.session_transaction() as sess:
            assert sess[R_SORT_FILTER_DESC] == SortFilterDirection.ASC.value

    def test_remediations_sort_post_filter(self, web_client):
        """Test POST request to set sort filter."""
        response = web_client.post(
            url_for("remediation.remediations_sort"),
            json={"sort_filter": RemediationSortFilter.TYPE.value},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # verify session was updated
        with web_client.session_transaction() as sess:
            assert sess[R_SORT_FILTER] == RemediationSortFilter.TYPE.value

    def test_remediations_sort_post_both(self, web_client):
        """Test POST request to set both sort filter and direction."""
        response = web_client.post(
            url_for("remediation.remediations_sort"),
            json={
                "sort_filter": RemediationSortFilter.STATUS.value,
                "sort_direction": SortFilterDirection.ASC.value,
            },
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # verify session was updated
        with web_client.session_transaction() as sess:
            assert sess[R_SORT_FILTER] == RemediationSortFilter.STATUS.value
            assert sess[R_SORT_FILTER_DESC] == SortFilterDirection.ASC.value

    @pytest.mark.parametrize("json_data", [
        {"sort_direction": "invalid_direction"},
        {"sort_filter": "invalid_filter"},
    ])
    def test_remediations_sort_invalid_values(self, web_client, json_data):
        """Test POST request with invalid sort direction or filter."""
        response = web_client.post(
            url_for("remediation.remediations_sort"),
            json=json_data,
            content_type="application/json",
        )

        assert response.status_code == 400

    def test_remediations_sort_requires_permission(self, app):
        """Test that remediations_sort route requires permission."""
        with app.test_client() as client:
            response = client.post(
                url_for("remediation.remediations_sort"),
                json={"sort_direction": SortFilterDirection.ASC.value},
                content_type="application/json",
            )
            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location


class TestMassRemediateRoute:
    """Test the /remediation/mass_remediate route."""

    @pytest.mark.parametrize("observable_values,expected_count", [
        ("192.168.1.1", 1),
        ("192.168.1.1\n192.168.1.2\n192.168.1.3", 3),
        ("192.168.1.1\r\n192.168.1.2\r192.168.1.3", 3),  # mixed line endings
        ("192.168.1.1\n\n192.168.1.2\n   \n192.168.1.3", 3),  # with blank lines
    ])
    def test_mass_remediate_with_values(self, web_client, analyst, observable_values, expected_count):
        """Test mass remediate with various input formats."""
        reset_observable_remediation_interface_registry()

        class MockInterface(ObservableRemediationInterface):
            def get_remediation_targets(self, observable):
                return [
                    RemediationTarget(
                        remediator_name="test_remediator",
                        observable_type="ipv4",
                        observable_value=observable.value,
                    )
                ]

        register_observable_remediation_interface("ipv4", MockInterface())

        response = web_client.post(
            url_for("remediation.mass_remediate"),
            json={"observable_type": "ipv4", "observable_values": observable_values},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == expected_count

        # verify remediations were actually created in the database
        remediations = (
            get_db()
            .query(Remediation)
            .filter(
                Remediation.type == "ipv4",
                Remediation.action == RemediationAction.REMOVE.value,
                Remediation.name == "test_remediator",
            )
            .all()
        )
        assert len(remediations) == expected_count

        # verify all remediations are in NEW status
        for remediation in remediations:
            assert remediation.status == RemediationStatus.NEW.value
            assert remediation.user_id == analyst

    def test_mass_remediate_no_interfaces(self, web_client):
        """Test mass remediate with no interfaces registered."""
        reset_observable_remediation_interface_registry()

        response = web_client.post(
            url_for("remediation.mass_remediate"),
            json={"observable_type": "ipv4", "observable_values": "192.168.1.1"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 0

    def test_mass_remediate_requires_permission(self, app):
        """Test that mass_remediate route requires permission."""
        with app.test_client() as client:
            response = client.post(
                url_for("remediation.mass_remediate"),
                json={"observable_type": "ipv4", "observable_values": "192.168.1.1"},
                content_type="application/json",
            )
            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location
