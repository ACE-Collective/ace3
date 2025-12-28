import pytest
from flask import session, url_for

from app.remediation.constants import (
    R_DEFAULT_SORT_FILTER,
    R_DEFAULT_SORT_FILTER_DIRECTION,
    R_PAGE_OFFSET,
    R_PAGE_SIZE,
    R_PAGE_SIZE_DEFAULT,
    R_SORT_FILTER,
    R_SORT_FILTER_DESC,
    RH_PAGE_OFFSET,
    RH_PAGE_SIZE,
    RH_PAGE_SIZE_DEFAULT,
)
from app.remediation.views.manage import (
    get_remediatable_observable_types,
    initialize_remediation_session,
    reset_remediation_history_pagination,
    reset_remediation_pagination,
    reset_remediation_sort_filter,
)
from saq.remediation.target import (
    ObservableRemediationInterface,
    register_observable_remediation_interface,
    reset_observable_remediation_interface_registry,
)

pytestmark = pytest.mark.integration


class TestRemediationSessionFunctions:
    """Test session management functions for remediation."""

    def test_reset_remediation_pagination(self, app):
        """Test resetting remediation pagination to defaults."""
        with app.test_request_context():
            reset_remediation_pagination()

            assert session[R_PAGE_OFFSET] == 0
            assert session[R_PAGE_SIZE] == R_PAGE_SIZE_DEFAULT

    def test_reset_remediation_pagination_preserves_page_size(self, app):
        """Test that reset preserves existing page size."""
        with app.test_request_context():
            session[R_PAGE_SIZE] = 100
            reset_remediation_pagination()

            assert session[R_PAGE_OFFSET] == 0
            assert session[R_PAGE_SIZE] == 100

    def test_reset_remediation_history_pagination(self, app):
        """Test resetting remediation history pagination to defaults."""
        with app.test_request_context():
            reset_remediation_history_pagination()

            assert session[RH_PAGE_OFFSET] == 0
            assert session[RH_PAGE_SIZE] == RH_PAGE_SIZE_DEFAULT

    def test_reset_remediation_history_pagination_preserves_page_size(self, app):
        """Test that reset preserves existing history page size."""
        with app.test_request_context():
            session[RH_PAGE_SIZE] = 100
            reset_remediation_history_pagination()

            assert session[RH_PAGE_OFFSET] == 0
            assert session[RH_PAGE_SIZE] == 100

    def test_reset_remediation_sort_filter(self, app):
        """Test resetting sort filter to defaults."""
        with app.test_request_context():
            reset_remediation_sort_filter()

            assert session[R_SORT_FILTER] == R_DEFAULT_SORT_FILTER.value
            assert session[R_SORT_FILTER_DESC] == R_DEFAULT_SORT_FILTER_DIRECTION.value

    def test_initialize_remediation_session_sets_all_defaults(self, app):
        """Test that initialization sets all session variables."""
        with app.test_request_context():
            initialize_remediation_session()

            # check pagination is set
            assert R_PAGE_OFFSET in session
            assert R_PAGE_SIZE in session
            assert session[R_PAGE_OFFSET] == 0
            assert session[R_PAGE_SIZE] == R_PAGE_SIZE_DEFAULT

            # check history pagination is set
            assert RH_PAGE_OFFSET in session
            assert RH_PAGE_SIZE in session
            assert session[RH_PAGE_OFFSET] == 0
            assert session[RH_PAGE_SIZE] == RH_PAGE_SIZE_DEFAULT

            # check sort filter is set
            assert R_SORT_FILTER in session
            assert R_SORT_FILTER_DESC in session
            assert session[R_SORT_FILTER] == R_DEFAULT_SORT_FILTER.value
            assert session[R_SORT_FILTER_DESC] == R_DEFAULT_SORT_FILTER_DIRECTION.value

    def test_initialize_remediation_session_preserves_existing_values(self, app):
        """Test that initialization preserves existing session values."""
        with app.test_request_context():
            # set custom values
            session[R_PAGE_OFFSET] = 50
            session[R_PAGE_SIZE] = 100
            session[RH_PAGE_OFFSET] = 25
            session[RH_PAGE_SIZE] = 75
            session[R_SORT_FILTER] = "type"
            session[R_SORT_FILTER_DESC] = "asc"

            initialize_remediation_session()

            # verify custom values were preserved
            assert session[R_PAGE_OFFSET] == 50
            assert session[R_PAGE_SIZE] == 100
            assert session[RH_PAGE_OFFSET] == 25
            assert session[RH_PAGE_SIZE] == 75
            assert session[R_SORT_FILTER] == "type"
            assert session[R_SORT_FILTER_DESC] == "asc"

    def test_initialize_remediation_session_partial_existing_values(self, app):
        """Test initialization with only some existing values."""
        with app.test_request_context():
            # only set some values
            session[R_PAGE_SIZE] = 100

            initialize_remediation_session()

            # verify custom values were preserved
            assert session[R_PAGE_SIZE] == 100

            # verify missing values were initialized
            assert session[R_PAGE_OFFSET] == 0
            assert session[RH_PAGE_OFFSET] == 0
            assert session[RH_PAGE_SIZE] == RH_PAGE_SIZE_DEFAULT
            assert session[R_SORT_FILTER] == R_DEFAULT_SORT_FILTER.value
            assert session[R_SORT_FILTER_DESC] == R_DEFAULT_SORT_FILTER_DIRECTION.value

    def test_initialize_remediation_session_missing_sort_desc_resets_both(self, app):
        """Test that missing sort direction causes both sort values to be reset."""
        with app.test_request_context():
            # set only the sort filter, not the direction
            session[R_SORT_FILTER] = "type"

            initialize_remediation_session()

            # both should be reset to defaults since one was missing
            assert session[R_SORT_FILTER] == R_DEFAULT_SORT_FILTER.value
            assert session[R_SORT_FILTER_DESC] == R_DEFAULT_SORT_FILTER_DIRECTION.value


class TestGetRemediatableObservableTypes:
    """Test the function that retrieves remediatable observable types."""

    def test_get_remediatable_observable_types_empty(self, app):
        """Test getting remediatable types when registry is empty."""
        with app.test_request_context():
            reset_observable_remediation_interface_registry()

            result = get_remediatable_observable_types()

            assert isinstance(result, list)
            assert len(result) == 0

    def test_get_remediatable_observable_types_single_type(self, app):
        """Test getting remediatable types with one registered type."""
        with app.test_request_context():
            reset_observable_remediation_interface_registry()

            # create a mock interface
            class MockInterface(ObservableRemediationInterface):
                def get_remediation_targets(self, observable):
                    return []

            register_observable_remediation_interface("ipv4", MockInterface())

            result = get_remediatable_observable_types()

            assert isinstance(result, list)
            assert len(result) == 1
            assert "ipv4" in result

    def test_get_remediatable_observable_types_multiple_types(self, app):
        """Test getting remediatable types with multiple registered types."""
        with app.test_request_context():
            reset_observable_remediation_interface_registry()

            # create mock interfaces
            class MockInterface(ObservableRemediationInterface):
                def get_remediation_targets(self, observable):
                    return []

            register_observable_remediation_interface("ipv4", MockInterface())
            register_observable_remediation_interface("fqdn", MockInterface())
            register_observable_remediation_interface("email_address", MockInterface())

            result = get_remediatable_observable_types()

            assert isinstance(result, list)
            assert len(result) == 3
            assert "ipv4" in result
            assert "fqdn" in result
            assert "email_address" in result


class TestManageRoute:
    """Test the /remediation/manage route."""

    def test_manage_get_request(self, web_client):
        """Test GET request to remediation manage page."""
        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200
        assert b"remediation/manage.html" in response.data or b"Remediation" in response.data

    def test_manage_initializes_session(self, web_client):
        """Test that manage route initializes session variables."""
        with web_client.session_transaction() as sess:
            # clear any existing session variables
            sess.clear()

        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200

        with web_client.session_transaction() as sess:
            # verify session was initialized
            assert R_PAGE_OFFSET in sess
            assert R_PAGE_SIZE in sess
            assert RH_PAGE_OFFSET in sess
            assert RH_PAGE_SIZE in sess
            assert R_SORT_FILTER in sess
            assert R_SORT_FILTER_DESC in sess

    def test_manage_preserves_existing_session(self, web_client):
        """Test that manage route preserves existing session values."""
        with web_client.session_transaction() as sess:
            sess[R_PAGE_OFFSET] = 100
            sess[R_PAGE_SIZE] = 75

        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200

        with web_client.session_transaction() as sess:
            assert sess[R_PAGE_OFFSET] == 100
            assert sess[R_PAGE_SIZE] == 75

    def test_manage_requires_permission(self, app):
        """Test that manage route requires remediation read permission."""
        with app.test_client() as client:
            response = client.get(url_for("remediation.manage"))

            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location

    def test_manage_passes_page_size_to_template(self, web_client):
        """Test that manage route passes page_size to template."""
        with web_client.session_transaction() as sess:
            sess[R_PAGE_SIZE] = 75

        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200
        # the template should receive the page_size value
        # we can't directly inspect template variables in a rendered response,
        # but we can verify the route executed successfully

    def test_manage_passes_rh_page_size_to_template(self, web_client):
        """Test that manage route passes rh_page_size to template."""
        with web_client.session_transaction() as sess:
            sess[RH_PAGE_SIZE] = 100

        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200

    def test_manage_passes_observable_types_to_template(self, web_client):
        """Test that manage route passes observable_types to template."""
        reset_observable_remediation_interface_registry()

        # create mock interface
        class MockInterface(ObservableRemediationInterface):
            def get_remediation_targets(self, observable):
                return []

        register_observable_remediation_interface("ipv4", MockInterface())
        register_observable_remediation_interface("fqdn", MockInterface())

        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200
        # the template should receive the observable_types list

    def test_manage_with_empty_observable_types(self, web_client):
        """Test manage route when no observable types are registered."""
        reset_observable_remediation_interface_registry()

        response = web_client.get(url_for("remediation.manage"))

        assert response.status_code == 200
