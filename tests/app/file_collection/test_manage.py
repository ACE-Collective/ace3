# vim: sw=4:ts=4:et:cc=120

import pytest
from flask import session, url_for

from app.file_collection.constants import (
    FC_DEFAULT_SORT_FILTER,
    FC_DEFAULT_SORT_FILTER_DIRECTION,
    FC_PAGE_OFFSET,
    FC_PAGE_SIZE,
    FC_PAGE_SIZE_DEFAULT,
    FC_SORT_FILTER,
    FC_SORT_FILTER_DESC,
    FCH_PAGE_OFFSET,
    FCH_PAGE_SIZE,
    FCH_PAGE_SIZE_DEFAULT,
)
from app.file_collection.views.manage import (
    initialize_file_collection_session,
    reset_file_collection_history_pagination,
    reset_file_collection_pagination,
    reset_file_collection_sort_filter,
)

pytestmark = pytest.mark.integration


class TestFileCollectionSessionFunctions:
    """Test session management functions for file collection."""

    def test_reset_file_collection_pagination(self, app):
        """Test resetting file collection pagination to defaults."""
        with app.test_request_context():
            reset_file_collection_pagination()

            assert session[FC_PAGE_OFFSET] == 0
            assert session[FC_PAGE_SIZE] == FC_PAGE_SIZE_DEFAULT

    def test_reset_file_collection_pagination_preserves_page_size(self, app):
        """Test that reset preserves existing page size."""
        with app.test_request_context():
            session[FC_PAGE_SIZE] = 100
            reset_file_collection_pagination()

            assert session[FC_PAGE_OFFSET] == 0
            assert session[FC_PAGE_SIZE] == 100

    def test_reset_file_collection_history_pagination(self, app):
        """Test resetting file collection history pagination to defaults."""
        with app.test_request_context():
            reset_file_collection_history_pagination()

            assert session[FCH_PAGE_OFFSET] == 0
            assert session[FCH_PAGE_SIZE] == FCH_PAGE_SIZE_DEFAULT

    def test_reset_file_collection_history_pagination_preserves_page_size(self, app):
        """Test that reset preserves existing history page size."""
        with app.test_request_context():
            session[FCH_PAGE_SIZE] = 100
            reset_file_collection_history_pagination()

            assert session[FCH_PAGE_OFFSET] == 0
            assert session[FCH_PAGE_SIZE] == 100

    def test_reset_file_collection_sort_filter(self, app):
        """Test resetting sort filter to defaults."""
        with app.test_request_context():
            reset_file_collection_sort_filter()

            assert session[FC_SORT_FILTER] == FC_DEFAULT_SORT_FILTER.value
            assert session[FC_SORT_FILTER_DESC] == FC_DEFAULT_SORT_FILTER_DIRECTION.value

    def test_initialize_file_collection_session_sets_all_defaults(self, app):
        """Test that initialization sets all session variables."""
        with app.test_request_context():
            initialize_file_collection_session()

            # check pagination is set
            assert FC_PAGE_OFFSET in session
            assert FC_PAGE_SIZE in session
            assert session[FC_PAGE_OFFSET] == 0
            assert session[FC_PAGE_SIZE] == FC_PAGE_SIZE_DEFAULT

            # check history pagination is set
            assert FCH_PAGE_OFFSET in session
            assert FCH_PAGE_SIZE in session
            assert session[FCH_PAGE_OFFSET] == 0
            assert session[FCH_PAGE_SIZE] == FCH_PAGE_SIZE_DEFAULT

            # check sort filter is set
            assert FC_SORT_FILTER in session
            assert FC_SORT_FILTER_DESC in session
            assert session[FC_SORT_FILTER] == FC_DEFAULT_SORT_FILTER.value
            assert session[FC_SORT_FILTER_DESC] == FC_DEFAULT_SORT_FILTER_DIRECTION.value

    def test_initialize_file_collection_session_preserves_existing_values(self, app):
        """Test that initialization preserves existing session values."""
        with app.test_request_context():
            # set custom values
            session[FC_PAGE_OFFSET] = 50
            session[FC_PAGE_SIZE] = 100
            session[FCH_PAGE_OFFSET] = 25
            session[FCH_PAGE_SIZE] = 75
            session[FC_SORT_FILTER] = "type"
            session[FC_SORT_FILTER_DESC] = "asc"

            initialize_file_collection_session()

            # verify custom values were preserved
            assert session[FC_PAGE_OFFSET] == 50
            assert session[FC_PAGE_SIZE] == 100
            assert session[FCH_PAGE_OFFSET] == 25
            assert session[FCH_PAGE_SIZE] == 75
            assert session[FC_SORT_FILTER] == "type"
            assert session[FC_SORT_FILTER_DESC] == "asc"


class TestManageRoute:
    """Test the /file_collection/manage route."""

    def test_manage_requires_permission(self, app):
        """Test that manage route requires file_collection read permission."""
        with app.test_client() as client:
            response = client.get(url_for("file_collection.manage"))

            # should redirect to login due to missing permission
            assert response.status_code == 302
            assert "login" in response.location
