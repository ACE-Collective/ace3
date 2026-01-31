import json
import pytest
from flask import url_for
from flask_login import login_user

from saq.database import get_db
from saq.database.model import AuthGroup, AuthGroupUser, AuthUserPermission, AuthGroupPermission, User
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.group import create_auth_group, add_user_to_auth_group, add_group_permission
from saq.permissions.user import add_user_permission
from saq.constants import QUEUE_DEFAULT

pytestmark = pytest.mark.integration


@pytest.fixture
def test_user():
    """Create a test user with edit permissions for authentication."""
    user = add_user(
        username="edituser",
        email="edituser@localhost", 
        display_name="Edit User",
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="UTC"
    )
    # Grant user edit permissions
    add_user_permission(user.id, "user", "edit")
    yield user
    delete_user("edituser")


@pytest.fixture
def test_group():
    """Create a test auth group."""
    group = create_auth_group("testgroup")
    yield group
    # Clean up group
    db = get_db()
    db.query(AuthGroupUser).filter(AuthGroupUser.group_id == group.id).delete()
    db.query(AuthGroupPermission).filter(AuthGroupPermission.group_id == group.id).delete()
    db.query(AuthGroup).filter(AuthGroup.id == group.id).delete()
    db.commit()


@pytest.fixture
def target_user():
    """Create a user to be edited/deleted in tests."""
    user = add_user(
        username="targetuser",
        email="targetuser@localhost",
        display_name="Target User", 
        password="TargetPass123!",
        queue=QUEUE_DEFAULT,
        timezone="America/New_York"
    )
    yield user
    try:
        delete_user("targetuser")
    except:
        pass  # User may have been deleted in test


class TestAddUser:
    """Test the add_user endpoint."""
    
    def test_add_user_success(self, app, test_user):
        """Test successfully adding a new user."""
        with app.test_client() as client:
            # Login as user with edit permissions
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            user_data = {
                "username": "newuser",
                "email": "newuser@localhost",
                "display_name": "New User",
                "password": "NewPass123!",
                "queue": "default",
                "timezone": "UTC",
                "permissions": [
                    {"major": "alert", "minor": "read", "effect": "ALLOW"}
                ],
                "groups": []
            }
            
            response = client.post(
                url_for('auth.add_user'),
                data=json.dumps(user_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] == 'User added successfully'
            
            # Verify user was created in database
            db = get_db()
            created_user = db.query(User).filter(User.username == "newuser").first()
            assert created_user is not None
            assert created_user.email == "newuser@localhost"
            assert created_user.display_name == "New User"
            assert created_user.queue == "default"
            assert created_user.timezone == "UTC"
            
            # Verify permission was added
            permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.user_id == created_user.id,
                AuthUserPermission.major == "alert",
                AuthUserPermission.minor == "read"
            ).first()
            assert permission is not None
            assert permission.effect == "ALLOW"
            
            # Clean up
            delete_user("newuser")
    
    def test_add_user_with_groups(self, app, test_user, test_group):
        """Test adding a user with group membership."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            user_data = {
                "username": "groupuser",
                "email": "groupuser@localhost", 
                "display_name": "Group User",
                "queue": "default",
                "timezone": "UTC",
                "permissions": [],
                "groups": [test_group.id]
            }
            
            response = client.post(
                url_for('auth.add_user'),
                data=json.dumps(user_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify user was added to group
            db = get_db()
            created_user = db.query(User).filter(User.username == "groupuser").first()
            group_membership = db.query(AuthGroupUser).filter(
                AuthGroupUser.user_id == created_user.id,
                AuthGroupUser.group_id == test_group.id
            ).first()
            assert group_membership is not None
            
            delete_user("groupuser")
    
    def test_add_user_no_password_generates_random(self, app, test_user):
        """Test that omitting password generates a random one."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            user_data = {
                "username": "nopassuser",
                "email": "nopassuser@localhost",
                "display_name": "No Pass User", 
                "queue": "default",
                "timezone": "UTC",
                "permissions": [],
                "groups": []
            }
            
            response = client.post(
                url_for('auth.add_user'),
                data=json.dumps(user_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify user was created with a password hash
            db = get_db()
            created_user = db.query(User).filter(User.username == "nopassuser").first()
            assert created_user is not None
            assert created_user.password_hash is not None
            assert len(created_user.password_hash) > 0
            
            delete_user("nopassuser")
    
    def test_add_user_requires_auth(self, app):
        """Test that adding user requires authentication."""
        with app.test_client() as client:
            user_data = {
                "username": "unauthorized",
                "email": "unauthorized@localhost",
                "display_name": "Unauthorized",
                "queue": "default", 
                "timezone": "UTC",
                "permissions": [],
                "groups": []
            }
            
            response = client.post(
                url_for('auth.add_user'),
                data=json.dumps(user_data),
                content_type='application/json'
            )
            
            # Should redirect to login
            assert response.status_code == 302
            assert 'login' in response.location


class TestEditUsers:
    """Test the edit_users endpoint."""
    
    def test_edit_single_user_all_fields(self, app, test_user, target_user):
        """Test editing all fields of a single user."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            edit_data = {
                str(target_user.id): {
                    "username": "editeduser",
                    "password": "NewPass456!",
                    "display_name": "Edited User",
                    "email": "edited@localhost",
                    "queue": "high",
                    "timezone": "America/Los_Angeles",
                    "enabled": False,
                    "permissions": [
                        {"major": "event", "minor": "write", "effect": "ALLOW"}
                    ],
                    "groups": []
                }
            }
            
            response = client.post(
                url_for('auth.edit_users'),
                data=json.dumps(edit_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] == 'Users updated successfully'
            
            # Verify changes in database
            db = get_db()
            db.refresh(target_user)
            assert target_user.username == "editeduser"
            assert target_user.display_name == "Edited User"
            assert target_user.email == "edited@localhost"
            assert target_user.queue == "high"
            assert target_user.timezone == "America/Los_Angeles"
            assert target_user.enabled == False
            
            # Verify password was changed
            from saq.database.model import verify_password_hash
            assert verify_password_hash("NewPass456!", target_user.password_hash)
            
            # Verify permissions were updated
            permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.user_id == target_user.id,
                AuthUserPermission.major == "event",
                AuthUserPermission.minor == "write"
            ).first()
            assert permission is not None
            assert permission.effect == "ALLOW"
    
    def test_edit_multiple_users_limited_fields(self, app, test_user, target_user):
        """Test editing multiple users (limited to certain fields)."""
        # Create a second user to edit
        user2 = add_user(
            username="targetuser2",
            email="targetuser2@localhost",
            display_name="Target User 2",
            password="Pass123!",
            queue=QUEUE_DEFAULT,
            timezone="UTC"
        )
        
        try:
            with app.test_client() as client:
                client.post(url_for('auth.login'), data={
                    'username': 'edituser',
                    'password': 'TestPass123!'
                })
                
                edit_data = {
                    str(target_user.id): {
                        "queue": "bulk",
                        "timezone": "Europe/London",
                        "enabled": False
                    },
                    str(user2.id): {
                        "queue": "bulk", 
                        "timezone": "Europe/London",
                        "enabled": False
                    }
                }
                
                response = client.post(
                    url_for('auth.edit_users'),
                    data=json.dumps(edit_data),
                    content_type='application/json'
                )
                
                assert response.status_code == 200
                
                # Verify changes for both users
                db = get_db()
                db.refresh(target_user)
                db.refresh(user2)
                
                assert target_user.queue == "bulk"
                assert target_user.timezone == "Europe/London"
                assert target_user.enabled == False
                
                assert user2.queue == "bulk"
                assert user2.timezone == "Europe/London"
                assert user2.enabled == False
                
                # Username/email should remain unchanged for multi-user edit
                assert target_user.username == "targetuser"
                assert user2.username == "targetuser2"
        finally:
            delete_user("targetuser2")
    
    def test_edit_user_with_groups(self, app, test_user, target_user, test_group):
        """Test editing user's group memberships."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            edit_data = {
                str(target_user.id): {
                    "groups": [test_group.id]
                }
            }
            
            response = client.post(
                url_for('auth.edit_users'),
                data=json.dumps(edit_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify group membership
            db = get_db()
            membership = db.query(AuthGroupUser).filter(
                AuthGroupUser.user_id == target_user.id,
                AuthGroupUser.group_id == test_group.id
            ).first()
            assert membership is not None
    
    def test_edit_user_not_found(self, app, test_user):
        """Test editing a non-existent user returns 404."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            edit_data = {
                "99999": {  # Non-existent user ID
                    "queue": "test"
                }
            }
            
            response = client.post(
                url_for('auth.edit_users'),
                data=json.dumps(edit_data),
                content_type='application/json'
            )
            
            assert response.status_code == 404
            data = response.get_json()
            assert 'User 99999 not found' in data['error']
    
    def test_edit_user_replaces_permissions(self, app, test_user, target_user):
        """Test that editing permissions replaces existing ones."""
        # Add initial permission
        add_user_permission(target_user.id, "initial", "permission")
        
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            edit_data = {
                str(target_user.id): {
                    "permissions": [
                        {"major": "new", "minor": "permission", "effect": "ALLOW"}
                    ]
                }
            }
            
            response = client.post(
                url_for('auth.edit_users'),
                data=json.dumps(edit_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify old permission is gone and new one exists
            db = get_db()
            old_permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.user_id == target_user.id,
                AuthUserPermission.major == "initial"
            ).first()
            assert old_permission is None
            
            new_permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.user_id == target_user.id,
                AuthUserPermission.major == "new"
            ).first()
            assert new_permission is not None


class TestAddPermission:
    """Test the add_permission endpoint."""
    
    def test_add_permission_to_users(self, app, test_user, target_user):
        """Test adding permissions to users."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            permission_data = {
                "major": "test",
                "minor": "permission",
                "effect": "ALLOW",
                "users": [target_user.id],
                "groups": []
            }
            
            response = client.post(
                url_for('auth.add_permission'),
                data=json.dumps(permission_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] == 'Permission added successfully'
            
            # Verify permission was added
            db = get_db()
            permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.user_id == target_user.id,
                AuthUserPermission.major == "test",
                AuthUserPermission.minor == "permission"
            ).first()
            assert permission is not None
            assert permission.effect == "ALLOW"
    
    def test_add_permission_to_groups(self, app, test_user, test_group):
        """Test adding permissions to groups."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            permission_data = {
                "major": "group",
                "minor": "test",
                "effect": "DENY",
                "users": [],
                "groups": [test_group.id]
            }
            
            response = client.post(
                url_for('auth.add_permission'),
                data=json.dumps(permission_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify group permission was added
            db = get_db()
            permission = db.query(AuthGroupPermission).filter(
                AuthGroupPermission.group_id == test_group.id,
                AuthGroupPermission.major == "group",
                AuthGroupPermission.minor == "test"
            ).first()
            assert permission is not None
            assert permission.effect == "DENY"
    
    def test_add_permission_to_both_users_and_groups(self, app, test_user, target_user, test_group):
        """Test adding permissions to both users and groups simultaneously."""
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            permission_data = {
                "major": "combined",
                "minor": "access",
                "effect": "ALLOW",
                "users": [target_user.id],
                "groups": [test_group.id]
            }
            
            response = client.post(
                url_for('auth.add_permission'),
                data=json.dumps(permission_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify both user and group permissions were added
            db = get_db()
            user_permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.user_id == target_user.id,
                AuthUserPermission.major == "combined"
            ).first()
            assert user_permission is not None
            
            group_permission = db.query(AuthGroupPermission).filter(
                AuthGroupPermission.group_id == test_group.id,
                AuthGroupPermission.major == "combined"
            ).first()
            assert group_permission is not None


class TestDeletePermission:
    """Test the delete_permission endpoint."""
    
    def test_delete_user_permissions(self, app, test_user, target_user):
        """Test deleting user permissions."""
        # Add a permission to delete
        add_user_permission(target_user.id, "delete", "me")
        
        db = get_db()
        permission = db.query(AuthUserPermission).filter(
            AuthUserPermission.user_id == target_user.id,
            AuthUserPermission.major == "delete"
        ).first()
        permission_id = permission.id
        
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            delete_data = {
                "users": [permission_id],
                "groups": []
            }
            
            response = client.post(
                url_for('auth.delete_permission'),
                data=json.dumps(delete_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] == 'Permission deleted successfully'
            
            # Verify permission was deleted
            deleted_permission = db.query(AuthUserPermission).filter(
                AuthUserPermission.id == permission_id
            ).first()
            assert deleted_permission is None
    
    def test_delete_group_permissions(self, app, test_user, test_group):
        """Test deleting group permissions."""
        # Add a group permission to delete
        add_group_permission(test_group.id, "delete", "group", "ALLOW")
        
        db = get_db()
        permission = db.query(AuthGroupPermission).filter(
            AuthGroupPermission.group_id == test_group.id,
            AuthGroupPermission.major == "delete"
        ).first()
        permission_id = permission.id
        
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            delete_data = {
                "users": [],
                "groups": [permission_id]
            }
            
            response = client.post(
                url_for('auth.delete_permission'),
                data=json.dumps(delete_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify group permission was deleted
            deleted_permission = db.query(AuthGroupPermission).filter(
                AuthGroupPermission.id == permission_id
            ).first()
            assert deleted_permission is None
    
    def test_delete_mixed_permissions(self, app, test_user, target_user, test_group):
        """Test deleting both user and group permissions simultaneously."""
        # Add permissions to delete
        add_user_permission(target_user.id, "user", "delete")
        add_group_permission(test_group.id, "group", "delete", "ALLOW")
        
        db = get_db()
        user_permission = db.query(AuthUserPermission).filter(
            AuthUserPermission.user_id == target_user.id,
            AuthUserPermission.major == "user"
        ).first()
        group_permission = db.query(AuthGroupPermission).filter(
            AuthGroupPermission.group_id == test_group.id,
            AuthGroupPermission.major == "group"
        ).first()
        
        # Store IDs before deletion
        user_permission_id = user_permission.id
        group_permission_id = group_permission.id
        
        with app.test_client() as client:
            client.post(url_for('auth.login'), data={
                'username': 'edituser',
                'password': 'TestPass123!'
            })
            
            delete_data = {
                "users": [user_permission_id],
                "groups": [group_permission_id]
            }
            
            response = client.post(
                url_for('auth.delete_permission'),
                data=json.dumps(delete_data),
                content_type='application/json'
            )
            
            assert response.status_code == 200
            
            # Verify both permissions were deleted
            assert db.query(AuthUserPermission).filter(
                AuthUserPermission.id == user_permission_id
            ).first() is None
            
            assert db.query(AuthGroupPermission).filter(
                AuthGroupPermission.id == group_permission_id
            ).first() is None


class TestEditEndpointsAuth:
    """Test authentication and authorization for edit endpoints."""
    
    def test_all_endpoints_require_auth(self, app):
        """Test that all edit endpoints require authentication."""
        endpoints = [
            ('auth.add_user', {}),
            ('auth.edit_users', {}),
            ('auth.add_permission', {}),
            ('auth.delete_permission', {})
        ]
        
        with app.test_client() as client:
            for endpoint, data in endpoints:
                response = client.post(
                    url_for(endpoint),
                    data=json.dumps(data),
                    content_type='application/json'
                )
                # Should redirect to login
                assert response.status_code == 302
                assert 'login' in response.location
    
    def test_endpoints_require_user_edit_permission(self, app):
        """Test that edit endpoints require 'user edit' permission."""
        # Create user without edit permissions
        user_no_perms = add_user(
            username="noperms",
            email="noperms@localhost",
            display_name="No Perms User",
            password="TestPass123!",
            queue=QUEUE_DEFAULT,
            timezone="UTC"
        )
        
        try:
            endpoints = [
                ('auth.add_user', {"username": "test"}),
                ('auth.edit_users', {"1": {"queue": "test"}}),
                ('auth.add_permission', {"major": "test", "minor": "test", "effect": "ALLOW", "users": [], "groups": []}),
                ('auth.delete_permission', {"users": [], "groups": []})
            ]
            
            with app.test_client() as client:
                # Login as user without permissions
                client.post(url_for('auth.login'), data={
                    'username': 'noperms',
                    'password': 'TestPass123!'
                })
                
                for endpoint, data in endpoints:
                    response = client.post(
                        url_for(endpoint),
                        data=json.dumps(data),
                        content_type='application/json'
                    )
                    # Should return 403 or redirect due to lack of permissions
                    assert response.status_code in [302, 403]
        finally:
            delete_user("noperms")