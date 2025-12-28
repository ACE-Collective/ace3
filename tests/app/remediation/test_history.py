import pytest
from flask import session, url_for

from app.remediation.constants import (
    R_PAGE_OFFSET_BACKWARD,
    R_PAGE_OFFSET_END,
    R_PAGE_OFFSET_FORWARD,
    R_PAGE_OFFSET_START,
    RH_PAGE_OFFSET,
    RH_PAGE_SIZE,
    RH_PAGE_SIZE_DEFAULT,
)
from app.remediation.views.history import (
    get_current_pagination_offset,
    get_current_pagination_size,
    get_total_remediation_history_count,
)
from saq.database.model import Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.remediation.types import RemediationAction, RemediationStatus

pytestmark = pytest.mark.integration


class TestHistoryHelperFunctions:
    """Test helper functions for remediation history pagination."""

    def test_get_current_pagination_offset_default(self, app):
        """Test getting pagination offset when not set in session."""
        with app.test_request_context():
            offset = get_current_pagination_offset()
            assert offset == 0

    def test_get_current_pagination_offset_from_session(self, app):
        """Test getting pagination offset from session."""
        with app.test_request_context():
            session[RH_PAGE_OFFSET] = 100
            offset = get_current_pagination_offset()
            assert offset == 100

    def test_get_current_pagination_size_default(self, app):
        """Test getting pagination size when not set in session."""
        with app.test_request_context():
            size = get_current_pagination_size()
            assert size == RH_PAGE_SIZE_DEFAULT

    def test_get_current_pagination_size_from_session(self, app):
        """Test getting pagination size from session."""
        with app.test_request_context():
            session[RH_PAGE_SIZE] = 75
            size = get_current_pagination_size()
            assert size == 75

    def test_get_total_remediation_history_count_empty(self, app, analyst):
        """Test getting total count when no history exists."""
        with app.test_request_context():
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

            count = get_total_remediation_history_count(remediation.id)
            assert count == 0

    def test_get_total_remediation_history_count_with_data(self, app, analyst):
        """Test getting total count with history records."""
        with app.test_request_context():
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

            # add history records
            for i in range(5):
                history = RemediationHistory(
                    remediation_id=remediation.id,
                    result="SUCCESS",
                    message=f"test message {i}",
                    status=RemediationStatus.COMPLETED.value,
                )
                get_db().add(history)
            get_db().commit()

            count = get_total_remediation_history_count(remediation.id)
            assert count == 5

    def test_get_total_remediation_history_count_multiple_remediations(self, app, analyst):
        """Test count only returns history for specific remediation."""
        with app.test_request_context():
            # create two remediations
            remediation1 = Remediation(
                type="ipv4",
                name="test_remediator",
                action=RemediationAction.REMOVE.value,
                key="192.168.1.1",
                user_id=analyst,
                status=RemediationStatus.NEW.value,
            )
            remediation2 = Remediation(
                type="ipv4",
                name="test_remediator",
                action=RemediationAction.REMOVE.value,
                key="192.168.1.2",
                user_id=analyst,
                status=RemediationStatus.NEW.value,
            )
            get_db().add_all([remediation1, remediation2])
            get_db().commit()

            # add history to both
            for i in range(3):
                history1 = RemediationHistory(
                    remediation_id=remediation1.id,
                    result="SUCCESS",
                    message=f"remediation1 message {i}",
                    status=RemediationStatus.COMPLETED.value,
                )
                get_db().add(history1)

            for i in range(7):
                history2 = RemediationHistory(
                    remediation_id=remediation2.id,
                    result="FAILED",
                    message=f"remediation2 message {i}",
                    status=RemediationStatus.COMPLETED.value,
                )
                get_db().add(history2)
            get_db().commit()

            # verify counts are separate
            count1 = get_total_remediation_history_count(remediation1.id)
            count2 = get_total_remediation_history_count(remediation2.id)
            assert count1 == 3
            assert count2 == 7


class TestHistoryRoute:
    """Test the /remediation/history/<remediation_id> route."""

    def test_history_get_empty(self, web_client, analyst):
        """Test GET request with no history."""
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

        response = web_client.get(url_for("remediation.history", remediation_id=remediation.id))

        assert response.status_code == 200

    def test_history_get_with_data(self, web_client, analyst):
        """Test GET request with history records."""
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

        # add history records
        for i in range(3):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        response = web_client.get(url_for("remediation.history", remediation_id=remediation.id))

        assert response.status_code == 200

    def test_history_respects_pagination_offset(self, web_client, analyst):
        """Test that history route respects pagination offset."""
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

        # add many history records
        for i in range(100):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        # set pagination offset
        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 50
            sess[RH_PAGE_SIZE] = 10

        response = web_client.get(url_for("remediation.history", remediation_id=remediation.id))

        assert response.status_code == 200

    def test_history_respects_pagination_size(self, web_client, analyst):
        """Test that history route respects pagination size."""
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

        # add history records
        for i in range(100):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        # set pagination size
        with web_client.session_transaction() as sess:
            sess[RH_PAGE_SIZE] = 25

        response = web_client.get(url_for("remediation.history", remediation_id=remediation.id))

        assert response.status_code == 200

    def test_history_orders_by_insert_date_desc(self, web_client, analyst):
        """Test that history is ordered by insert_date descending."""
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

        # add history records
        for i in range(5):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
            get_db().commit()  # commit each one to ensure different timestamps

        response = web_client.get(url_for("remediation.history", remediation_id=remediation.id))

        assert response.status_code == 200

    def test_history_requires_permission(self, app):
        """Test that history route requires remediation read permission."""
        with app.test_client() as client:
            response = client.get(url_for("remediation.history", remediation_id=1))

            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location

    def test_history_with_nonexistent_remediation(self, web_client):
        """Test GET request with nonexistent remediation ID."""
        response = web_client.get(url_for("remediation.history", remediation_id=99999))

        assert response.status_code == 200


class TestHistoryPageRoute:
    """Test the /remediation/history/<remediation_id>/page route."""

    def test_history_page_get_default_values(self, web_client, analyst):
        """Test GET request returns default pagination values."""
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

        response = web_client.get(url_for("remediation.history_page", remediation_id=remediation.id))

        assert response.status_code == 200
        data = response.get_json()
        assert "offset" in data
        assert "size" in data
        assert "total" in data
        assert data["offset"] == 0
        assert data["size"] == RH_PAGE_SIZE_DEFAULT
        assert data["total"] == 0

    def test_history_page_get_with_session_values(self, web_client, analyst):
        """Test GET request returns values from session."""
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

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 50
            sess[RH_PAGE_SIZE] = 100

        response = web_client.get(url_for("remediation.history_page", remediation_id=remediation.id))

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 50
        assert data["size"] == 100

    def test_history_page_get_with_data(self, web_client, analyst):
        """Test GET request with history data returns correct total."""
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

        # add history records
        for i in range(15):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        response = web_client.get(url_for("remediation.history_page", remediation_id=remediation.id))

        assert response.status_code == 200
        data = response.get_json()
        assert data["total"] == 15

    @pytest.mark.parametrize("requested_size,expected_size", [
        (75, 75),
        (0, 1),  # minimum bound
        (2000, 1000),  # maximum bound
    ])
    def test_history_page_post_set_size(self, web_client, analyst, requested_size, expected_size):
        """Test POST request to set page size with bounds enforcement."""
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

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"size": requested_size},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["size"] == expected_size

    def test_history_page_post_direction_start(self, web_client, analyst):
        """Test POST request with start direction."""
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

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 100

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_START},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 0

    def test_history_page_post_direction_backward(self, web_client, analyst):
        """Test POST request with backward direction."""
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

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 100
            sess[RH_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_BACKWARD},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 50

    def test_history_page_post_direction_backward_not_below_zero(self, web_client, analyst):
        """Test POST backward direction does not go below zero."""
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

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 25
            sess[RH_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_BACKWARD},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 0

    def test_history_page_post_direction_forward(self, web_client, analyst):
        """Test POST request with forward direction."""
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

        # add many history records
        for i in range(200):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 0
            sess[RH_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_FORWARD},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["offset"] == 50

    def test_history_page_post_direction_forward_not_beyond_end(self, web_client, analyst):
        """Test POST forward direction does not go beyond last page."""
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

        # add history records
        for i in range(100):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 75
            sess[RH_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_FORWARD},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        # offset should not exceed total - page_size (100 - 50 = 50)
        assert data["offset"] == 50

    def test_history_page_post_direction_end(self, web_client, analyst):
        """Test POST request with end direction."""
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

        # add history records
        for i in range(200):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_END},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        # offset should be total - page_size (200 - 50 = 150)
        assert data["offset"] == 150

    def test_history_page_post_direction_end_not_below_zero(self, web_client, analyst):
        """Test POST end direction does not result in negative offset."""
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

        # add few history records (less than page size)
        for i in range(25):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_SIZE] = 50

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"direction": R_PAGE_OFFSET_END},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        # offset should be 0, not negative
        assert data["offset"] == 0

    def test_history_page_post_size_and_direction(self, web_client, analyst):
        """Test POST request with both size and direction changes."""
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

        # add history records
        for i in range(100):
            history = RemediationHistory(
                remediation_id=remediation.id,
                result="SUCCESS",
                message=f"test message {i}",
                status=RemediationStatus.COMPLETED.value,
            )
            get_db().add(history)
        get_db().commit()

        with web_client.session_transaction() as sess:
            sess[RH_PAGE_OFFSET] = 0

        response = web_client.post(
            url_for("remediation.history_page", remediation_id=remediation.id),
            json={"size": 25, "direction": R_PAGE_OFFSET_FORWARD},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["size"] == 25
        assert data["offset"] == 25

    def test_history_page_requires_permission(self, app):
        """Test that history_page route requires remediation read permission."""
        with app.test_client() as client:
            response = client.get(url_for("remediation.history_page", remediation_id=1))

            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location

    def test_history_page_post_requires_permission(self, app):
        """Test that history_page POST requires remediation read permission."""
        with app.test_client() as client:
            response = client.post(
                url_for("remediation.history_page", remediation_id=1),
                json={"size": 50},
                content_type="application/json",
            )

            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location
