import pytest
from flask import url_for

from app.auth.views import get_remote_ipv4
from app.models import User
from saq.database import get_db
from saq.database.util.user_management import add_user, delete_user
from saq.constants import QUEUE_DEFAULT

pytestmark = pytest.mark.integration


@pytest.fixture
def test_user():
    """Create a test user for authentication tests."""
    user = add_user(
        username="testuser",
        email="testuser@localhost", 
        display_name="Test User",
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="Etc/UTC"
    )
    yield user
    delete_user("testuser")


@pytest.fixture  
def disabled_user():
    """Create a disabled test user."""
    user = add_user(
        username="disableduser",
        email="disableduser@localhost",
        display_name="Disabled User", 
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="Etc/UTC"
    )
    
    # Disable the user
    db_user = get_db().query(User).filter_by(username="disableduser").first()
    db_user.enabled = False
    get_db().commit()
    
    yield user
    delete_user("disableduser")


class TestGetRemoteIpv4:
    """Test the get_remote_ipv4 helper function."""
    
    def test_remote_addr_without_forwarded_for(self, app):
        """Test getting IP from REMOTE_ADDR when no X-Forwarded-For header."""
        with app.test_request_context(environ_base={'REMOTE_ADDR': '192.168.1.100'}):
            result = get_remote_ipv4()
            assert result == '192.168.1.100'
    
    def test_remote_addr_with_forwarded_for(self, app):
        """Test getting IP from X-Forwarded-For when header is present."""
        with app.test_request_context(environ_base={
            'REMOTE_ADDR': '192.168.1.100',
            'HTTP_X_FORWARDED_FOR': '10.0.0.50'
        }):
            result = get_remote_ipv4()
            assert result == '10.0.0.50'


class TestLogin:
    """Test the login view function."""
    
    def test_login_get_request(self, app):
        """Test GET request to login page returns form."""
        with app.test_client() as client:
            response = client.get(url_for('auth.login'))
            assert response.status_code == 200
            assert b'Username' in response.data
            assert b'Password' in response.data
    
    def test_login_valid_credentials(self, app, test_user):
        """Test successful login with valid credentials."""
        with app.test_client() as client:
            response = client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            # Should redirect after successful login
            assert response.status_code == 302
            assert 'username=testuser' in response.headers.get('Set-Cookie', '')
    
    def test_login_invalid_username(self, app):
        """Test login with non-existent username."""
        with app.test_client() as client:
            response = client.post(url_for('auth.login'), data={
                'username': 'nonexistentuser',
                'password': 'password123'
            })
            
            assert response.status_code == 200
            assert b'Invalid username or password' in response.data
    
    def test_login_invalid_password(self, app, test_user):
        """Test login with incorrect password."""
        with app.test_client() as client:
            response = client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'wrongpassword'
            })
            
            assert response.status_code == 200
            assert b'Invalid username or password' in response.data
    
    def test_login_disabled_user(self, app, disabled_user):
        """Test login attempt with disabled user account."""
        with app.test_client() as client:
            response = client.post(url_for('auth.login'), data={
                'username': 'disableduser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 200
            assert b'User is disabled' in response.data
    
    def test_login_remember_me(self, app, test_user):
        """Test login with remember me checkbox."""
        with app.test_client() as client:
            response = client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!',
                'remember_me': True
            })
            
            assert response.status_code == 302

            # Check that the remember me cookie is set
            # Flask-Login sets the cookie named 'remember_token'
            remember_cookie = None
            for cookie in response.headers.getlist('Set-Cookie'):
                if cookie.startswith('remember_token='):
                    remember_cookie = cookie
                    break

            assert remember_cookie is not None
    
    def test_login_with_next_parameter(self, app, test_user):
        """Test login redirect to next parameter."""
        with app.test_client() as client:
            next_url = url_for('main.index')
            response = client.post(url_for('auth.login', next=next_url), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 302
            assert response.location.endswith(next_url)
    
    def test_login_with_external_next_parameter_blocked(self, app, test_user):
        """Test that external redirects are blocked."""
        with app.test_client() as client:
            external_url = 'https://malicious-site.com'
            response = client.post(url_for('auth.login', next=external_url), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 302
            # Should redirect to main.index (/) instead of external URL
            assert 'malicious-site.com' not in response.location
            assert response.location.endswith('/')
    
    def test_login_with_javascript_url_blocked(self, app, test_user):
        """Test that javascript: URLs are blocked."""
        with app.test_client() as client:
            js_url = 'javascript:alert("xss")'
            response = client.post(url_for('auth.login', next=js_url), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 302
            # Should redirect to main.index (/) instead of javascript URL
            assert 'javascript:' not in response.location
            assert response.location.endswith('/')
    
    def test_login_with_data_url_blocked(self, app, test_user):
        """Test that data: URLs are blocked."""
        with app.test_client() as client:
            data_url = 'data:text/html,<script>alert("xss")</script>'
            response = client.post(url_for('auth.login', next=data_url), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 302
            # Should redirect to main.index (/) instead of data URL
            assert 'data:' not in response.location
            assert response.location.endswith('/')
    
    def test_login_with_invalid_url_blocked(self, app, test_user):
        """Test that invalid URLs are blocked."""
        with app.test_client() as client:
            invalid_url = 'not-a-valid-url'
            response = client.post(url_for('auth.login', next=invalid_url), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 302
            # Should redirect to main.index (/) instead of invalid URL
            assert response.location.endswith('/')
    
    def test_login_clears_storage_dir_session(self, app, test_user):
        """Test that login clears current_storage_dir from session."""
        with app.test_client() as client:
            # First set something in session
            with client.session_transaction() as sess:
                sess['current_storage_dir'] = '/some/path'
            
            response = client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            assert response.status_code == 302
            
            # Check that session key was removed
            with client.session_transaction() as sess:
                assert 'current_storage_dir' not in sess


class TestLogout:
    """Test the logout view function."""
    
    def test_logout_authenticated_user(self, app, test_user):
        """Test logout for authenticated user."""
        with app.test_client() as client:
            # First login
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            # Then logout (POST-only: GET must not be able to destroy a session)
            response = client.post(url_for('auth.logout'))
            
            assert response.status_code == 302
            assert response.location.endswith(url_for('main.index'))
    
    def test_logout_get_request_rejected(self, app, test_user):
        """GET on logout must not log anyone out -- it is not safe to expose a
        session-destroying action to prefetchers, link scanners, or <img> tags."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })

            response = client.get(url_for('auth.logout'))
            assert response.status_code == 405

            # still logged in: a protected page renders instead of redirecting to login
            response = client.get(url_for('auth.change_password'))
            assert response.status_code == 200

    def test_logout_unauthenticated_user(self, app):
        """Test logout redirect for unauthenticated user."""
        with app.test_client() as client:
            response = client.post(url_for('auth.logout'))
            
            # Should redirect to login page due to @login_required
            assert response.status_code == 302
            assert 'login' in response.location
    
    def test_logout_clears_cid_session(self, app, test_user):
        """Test that logout clears cid from session."""
        with app.test_client() as client:
            # First login
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            # Set cid in session
            with client.session_transaction() as sess:
                sess['cid'] = 'some_correlation_id'
            
            # Logout
            response = client.post(url_for('auth.logout'))
            
            assert response.status_code == 302
            
            # Check that cid was removed
            with client.session_transaction() as sess:
                assert 'cid' not in sess


class TestChangePassword:
    """Test the change_password view function."""
    
    def test_change_password_get_request(self, app, test_user):
        """Test GET request to change password page."""
        with app.test_client() as client:
            # Login first
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            response = client.get(url_for('auth.change_password'))
            
            assert response.status_code == 200
            assert b'Change Password' in response.data
            assert b'Minimum' in response.data  # From template requirements
            assert b'characters in length' in response.data
    
    def test_change_password_unauthenticated(self, app):
        """Test change password requires authentication."""
        with app.test_client() as client:
            response = client.get(url_for('auth.change_password'))
            
            # Should redirect to login
            assert response.status_code == 302
            assert 'login' in response.location
    
    def test_change_password_success(self, app, test_user):
        """Test successful password change."""
        with app.test_client() as client:
            # Login first
            client.post(url_for('auth.login'), data={
                'username': 'testuser', 
                'password': 'TestPass123!'
            })
            
            response = client.post(url_for('auth.change_password'), data={
                'current_password': 'TestPass123!',
                'new_password': 'NewPass456@',
                'confirm': 'NewPass456@'
            })
            
            # Should redirect to login after successful change (session invalidated)
            assert response.status_code == 302
            assert response.location.endswith(url_for('auth.login'))
    
    def test_change_password_wrong_current(self, app, test_user):
        """Test change password with incorrect current password."""
        with app.test_client() as client:
            # Login first
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            response = client.post(url_for('auth.change_password'), data={
                'current_password': 'WrongPassword',
                'new_password': 'NewPass456@',
                'confirm': 'NewPass456@'
            })
            
            assert response.status_code == 200
            # Check for the actual flash message text
            assert b'Current password is incorrect' in response.data
    
    def test_change_password_complexity_requirements(self, app, test_user):
        """Test password change validates complexity requirements."""
        with app.test_client() as client:
            # Login first
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            # Try with weak password
            response = client.post(url_for('auth.change_password'), data={
                'current_password': 'TestPass123!',
                'new_password': 'weak',
                'confirm': 'weak'
            })
            
            assert response.status_code == 200
            # Form validation should prevent submission
    
    def test_change_password_mismatch(self, app, test_user):
        """Test password change with mismatched new passwords.""" 
        with app.test_client() as client:
            # Login first
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            response = client.post(url_for('auth.change_password'), data={
                'current_password': 'TestPass123!',
                'new_password': 'NewPass456@',
                'confirm': 'DifferentPass789#'
            })
            
            assert response.status_code == 200
            # Form validation should prevent submission due to mismatch
    
    def test_change_password_includes_template_vars(self, app, test_user):
        """Test that change password template includes required variables."""
        with app.test_client() as client:
            # Login first
            client.post(url_for('auth.login'), data={
                'username': 'testuser',
                'password': 'TestPass123!'
            })
            
            response = client.get(url_for('auth.change_password'))
            
            assert response.status_code == 200
            # Check that special chars and min length are mentioned in page
            assert b'8' in response.data  # PASS_MIN_LENGTH

class TestOwnApiKey:
    """API keys are display-once and never recoverable, so there is no nav-bar action to re-copy
    one and no key is ever rendered into page HTML."""

    def test_no_copy_api_key_nav_item(self, app, test_user):
        """Regression: the retired 'Copy API Key' nav item fetched a recoverable key, which no
        longer exists."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'testuser', 'password': 'TestPass123!'
            })
            page = client.get(url_for('auth.change_password'))
            assert page.status_code == 200
            assert b'copy_api_key_link' not in page.data
            assert b'/api/v2/users/me/apikey' not in page.data

    def test_no_flask_apikey_route_exists(self, app):
        """New endpoints belong in aceapi_v2; nothing in the auth blueprint serves the key."""
        assert 'auth.get_own_api_key' not in app.view_functions
