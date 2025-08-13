import pytest

from saq.database.model import (
    AuthGroup, 
    AuthGroupUser, 
    AuthUserPermission, 
    AuthGroupPermission,
    User
)
from saq.database.pool import get_db
from saq.permissions import (
    create_auth_group,
    delete_auth_group,
    add_user_to_auth_group,
    delete_user_from_auth_group,
    add_user_permission,
    delete_user_permission,
    add_group_permission,
    delete_group_permission,
    get_user_permissions,
    get_group_permissions,
    user_has_permission,
    UserPermission,
    GroupPermission,
)


def create_test_user(username="testuser", email="test@example.com", password="testpass"):
    """Helper function to create a test user."""
    session = get_db()
    
    # Check if user already exists
    existing = session.query(User).filter(User.username == username).first()
    if existing:
        return existing
    
    user = User()
    user.username = username
    user.email = email
    user.password = password
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.mark.integration
class TestAuthGroupManagement:
    
    def test_create_auth_group(self):
        """Test creating a new auth group."""
        group = create_auth_group("test_group")
        
        assert group.name == "test_group"
        assert group.id is not None
        
        # Verify it was saved to database
        session = get_db()
        db_group = session.query(AuthGroup).filter(AuthGroup.name == "test_group").first()
        assert db_group is not None
        assert db_group.id == group.id

    def test_create_auth_group_idempotent(self):
        """Test that creating an auth group with existing name is idempotent."""
        group1 = create_auth_group("duplicate_group")
        group2 = create_auth_group("duplicate_group")
        
        assert group1.id == group2.id
        assert group1.name == group2.name
        
        # Verify only one group exists in database
        session = get_db()
        count = session.query(AuthGroup).filter(AuthGroup.name == "duplicate_group").count()
        assert count == 1

    def test_delete_auth_group(self):
        """Test deleting an auth group."""
        group = create_auth_group("to_delete_group")
        group_id = group.id
        
        # Delete the group
        result = delete_auth_group(group_id)
        assert result is True
        
        # Verify it's gone from database
        session = get_db()
        db_group = session.query(AuthGroup).filter(AuthGroup.id == group_id).first()
        assert db_group is None

    def test_delete_nonexistent_auth_group(self):
        """Test deleting a non-existent auth group returns False."""
        result = delete_auth_group(99999)
        assert result is False

    def test_add_user_to_auth_group(self):
        """Test adding a user to an auth group."""
        group = create_auth_group("user_group")
        user = create_test_user("groupuser1", "groupuser1@example.com")
        
        result = add_user_to_auth_group(user.id, group.id)
        assert result is True
        
        # Verify mapping exists in database
        session = get_db()
        mapping = session.query(AuthGroupUser).filter(
            AuthGroupUser.user_id == user.id,
            AuthGroupUser.group_id == group.id
        ).first()
        assert mapping is not None

    def test_add_user_to_auth_group_idempotent(self):
        """Test that adding a user to the same group twice is idempotent."""
        group = create_auth_group("idempotent_group")
        user = create_test_user("groupuser2", "groupuser2@example.com")
        
        result1 = add_user_to_auth_group(user.id, group.id)
        result2 = add_user_to_auth_group(user.id, group.id)
        
        assert result1 is True
        assert result2 is True
        
        # Verify only one mapping exists
        session = get_db()
        count = session.query(AuthGroupUser).filter(
            AuthGroupUser.user_id == user.id,
            AuthGroupUser.group_id == group.id
        ).count()
        assert count == 1

    def test_delete_user_from_auth_group(self):
        """Test removing a user from an auth group."""
        group = create_auth_group("removal_group")
        user = create_test_user("groupuser3", "groupuser3@example.com")
        
        # First add user to group
        add_user_to_auth_group(user.id, group.id)
        
        # Then remove user
        result = delete_user_from_auth_group(user.id, group.id)
        assert result is True
        
        # Verify mapping is gone
        session = get_db()
        mapping = session.query(AuthGroupUser).filter(
            AuthGroupUser.user_id == user.id,
            AuthGroupUser.group_id == group.id
        ).first()
        assert mapping is None

    def test_delete_user_from_auth_group_nonexistent(self):
        """Test removing a user from a group they're not in returns False."""
        group = create_auth_group("empty_group")
        result = delete_user_from_auth_group(999, group.id)
        assert result is False


@pytest.mark.integration
class TestUserPermissionManagement:
    
    def test_add_user_permission(self):
        """Test adding a permission to a user."""
        user = create_test_user("permuser1", "permuser1@example.com")
        major = "analysis"
        minor = "read"
        
        perm = add_user_permission(user.id, major, minor)
        
        assert perm.user_id == user.id
        assert perm.major == major
        assert perm.minor == minor
        assert perm.effect == "ALLOW"
        assert perm.id is not None

    def test_add_user_permission_with_effect(self):
        """Test adding a permission with explicit effect."""
        user = create_test_user("permuser2", "permuser2@example.com")
        major = "analysis"
        minor = "delete"
        effect = "DENY"
        
        perm = add_user_permission(user.id, major, minor, effect=effect)
        
        assert perm.effect == "DENY"

    def test_add_user_permission_with_created_by(self):
        """Test adding a permission with created_by field."""
        user = create_test_user("permuser3", "permuser3@example.com")
        creator = create_test_user("creator1", "creator1@example.com")
        major = "system"
        minor = "admin"
        
        perm = add_user_permission(user.id, major, minor, created_by=creator.id)
        
        assert perm.created_by == creator.id

    def test_add_user_permission_normalizes_effect(self):
        """Test that effect is normalized to uppercase."""
        user = create_test_user("permuser4", "permuser4@example.com")
        major = "test"
        minor = "lowercase"
        
        perm = add_user_permission(user.id, major, minor, effect="allow")
        
        assert perm.effect == "ALLOW"

    def test_add_user_permission_idempotent(self):
        """Test that adding the same permission twice is idempotent."""
        user = create_test_user("permuser5", "permuser5@example.com")
        major = "duplicate"
        minor = "permission"
        
        perm1 = add_user_permission(user.id, major, minor)
        perm2 = add_user_permission(user.id, major, minor)
        
        assert perm1.id == perm2.id
        
        # Verify only one permission exists
        session = get_db()
        count = session.query(AuthUserPermission).filter(
            AuthUserPermission.user_id == user.id,
            AuthUserPermission.major == major,
            AuthUserPermission.minor == minor,
            AuthUserPermission.effect == "ALLOW"
        ).count()
        assert count == 1

    def test_delete_user_permission_by_id(self):
        """Test deleting a user permission by ID."""
        user = create_test_user("permuser6", "permuser6@example.com")
        perm = add_user_permission(user.id, "test", "delete_by_id")
        perm_id = perm.id
        
        deleted = delete_user_permission(user.id, perm_id)
        
        assert deleted is True
        
        # Verify permission is gone
        session = get_db()
        db_perm = session.query(AuthUserPermission).filter(
            AuthUserPermission.id == perm_id
        ).first()

        assert db_perm is None

    def test_delete_user_permission_nonexistent_permission_id(self):
        """Test deleting user permission with non-existent permission ID."""
        user = create_test_user("permuser7", "permuser7@example.com")
        
        deleted = delete_user_permission(user.id, 99999)
        
        assert deleted is False

    def test_delete_user_permission_wrong_user(self):
        """Test deleting user permission with wrong user ID."""
        user1 = create_test_user("permuser8a", "permuser8a@example.com")
        user2 = create_test_user("permuser8b", "permuser8b@example.com")
        
        perm = add_user_permission(user1.id, "test", "wrong_user")
        
        # Try to delete with wrong user ID
        deleted = delete_user_permission(user2.id, perm.id)
        
        assert deleted is False
        
        # Verify permission still exists
        session = get_db()
        db_perm = session.query(AuthUserPermission).filter(
            AuthUserPermission.id == perm.id
        ).first()

        assert db_perm is not None

    def test_delete_user_permission_with_correct_user(self):
        """Test deleting user permission with correct user ID succeeds."""
        user = create_test_user("permuser9", "permuser9@example.com")
        perm = add_user_permission(user.id, "test", "correct_user")
        perm_id = perm.id  # Store the ID before deletion
        
        deleted = delete_user_permission(user.id, perm_id)
        
        assert deleted is True
        
        # Verify permission is gone
        session = get_db()
        db_perm = session.query(AuthUserPermission).filter(
            AuthUserPermission.id == perm_id
        ).first()

        assert db_perm is None

    def test_delete_user_permission_nonexistent_user(self):
        """Test deleting permission with non-existent user returns False."""
        deleted = delete_user_permission(99999, 99999)
        assert deleted is False


@pytest.mark.integration
class TestGroupPermissionManagement:
    
    def test_add_group_permission(self):
        """Test adding a permission to a group."""
        group = create_auth_group("perm_group")
        major = "group_test"
        minor = "read"
        
        perm = add_group_permission(group.id, major, minor)
        
        assert perm.group_id == group.id
        assert perm.major == major
        assert perm.minor == minor
        assert perm.effect == "ALLOW"
        assert perm.id is not None

    def test_add_group_permission_with_effect(self):
        """Test adding a group permission with explicit effect."""
        group = create_auth_group("deny_group")
        major = "group_test"
        minor = "write"
        effect = "DENY"
        
        perm = add_group_permission(group.id, major, minor, effect=effect)
        
        assert perm.effect == "DENY"

    def test_add_group_permission_with_created_by(self):
        """Test adding a group permission with created_by field."""
        group = create_auth_group("created_group")
        creator = create_test_user("grouppermcreator", "grouppermcreator@example.com")
        major = "system"
        minor = "admin"
        
        perm = add_group_permission(group.id, major, minor, created_by=creator.id)
        
        assert perm.created_by == creator.id

    def test_add_group_permission_normalizes_effect(self):
        """Test that group permission effect is normalized to uppercase."""
        group = create_auth_group("normalize_group")
        major = "test"
        minor = "normalize"
        
        perm = add_group_permission(group.id, major, minor, effect="deny")
        
        assert perm.effect == "DENY"

    def test_add_group_permission_idempotent(self):
        """Test that adding the same group permission twice is idempotent."""
        group = create_auth_group("duplicate_perm_group")
        major = "duplicate"
        minor = "permission"
        
        perm1 = add_group_permission(group.id, major, minor)
        perm2 = add_group_permission(group.id, major, minor)
        
        assert perm1.id == perm2.id
        
        # Verify only one permission exists
        session = get_db()
        count = session.query(AuthGroupPermission).filter(
            AuthGroupPermission.group_id == group.id,
            AuthGroupPermission.major == major,
            AuthGroupPermission.minor == minor,
            AuthGroupPermission.effect == "ALLOW"
        ).count()
        assert count == 1

    def test_delete_group_permission_by_id(self):
        """Test deleting a group permission by ID."""
        group = create_auth_group("delete_perm_group")
        perm = add_group_permission(group.id, "test", "delete_by_id")
        perm_id = perm.id
        
        deleted_count = delete_group_permission(permission_id=perm_id)
        
        assert deleted_count == 1
        
        # Verify permission is gone
        session = get_db()
        db_perm = session.query(AuthGroupPermission).filter(
            AuthGroupPermission.id == perm_id
        ).first()
        assert db_perm is None

    def test_delete_group_permission_by_filter(self):
        """Test deleting group permissions by filter."""
        group = create_auth_group("filter_delete_group")
        major = "filter_test"
        minor = "delete"
        
        add_group_permission(group.id, major, minor)
        
        deleted_count = delete_group_permission(
            group_id=group.id, major=major, minor=minor
        )
        
        assert deleted_count == 1

    def test_delete_group_permission_by_filter_with_effect(self):
        """Test deleting group permissions by filter with specific effect."""
        group = create_auth_group("effect_delete_group")
        major = "effect_test"
        minor = "delete"
        
        add_group_permission(group.id, major, minor, effect="ALLOW")
        add_group_permission(group.id, major, minor, effect="DENY")
        
        # Delete only DENY permissions
        deleted_count = delete_group_permission(
            group_id=group.id, major=major, minor=minor, effect="DENY"
        )
        
        assert deleted_count == 1
        
        # Verify ALLOW permission still exists
        session = get_db()
        remaining = session.query(AuthGroupPermission).filter(
            AuthGroupPermission.group_id == group.id,
            AuthGroupPermission.major == major,
            AuthGroupPermission.minor == minor,
            AuthGroupPermission.effect == "ALLOW"
        ).count()
        assert remaining == 1

    def test_delete_group_permission_missing_params(self):
        """Test that missing required parameters raise ValueError."""
        with pytest.raises(ValueError):
            delete_group_permission(group_id=1, major="test")  # missing minor
        
        with pytest.raises(ValueError):
            delete_group_permission(group_id=1, minor="test")  # missing major
        
        with pytest.raises(ValueError):
            delete_group_permission(major="test", minor="test")  # missing group_id

    def test_delete_group_permission_nonexistent(self):
        """Test deleting non-existent group permission returns 0."""
        deleted_count = delete_group_permission(permission_id=99999)
        assert deleted_count == 0


@pytest.mark.integration
class TestPermissionQueries:
    
    def test_get_user_permissions_direct_only(self):
        """Test getting user permissions without group inheritance."""
        user = create_test_user("queryuser1", "queryuser1@example.com")
        
        # Add direct user permissions
        add_user_permission(user.id, "direct", "read", "ALLOW")
        add_user_permission(user.id, "direct", "write", "DENY")
        
        permissions = get_user_permissions(user.id, include_groups=False)
        
        assert len(permissions) == 2
        assert all(isinstance(p, UserPermission) for p in permissions)
        
        # Check for read permission
        read_perm = next((p for p in permissions if p.minor == 'read'), None)
        assert read_perm is not None
        assert read_perm.major == 'direct'
        assert read_perm.effect == 'ALLOW'
        assert read_perm.source == 'user'
        assert read_perm.group_id is None
        
        # Check for write permission
        write_perm = next((p for p in permissions if p.minor == 'write'), None)
        assert write_perm is not None
        assert write_perm.major == 'direct'
        assert write_perm.effect == 'DENY'
        assert write_perm.source == 'user'

    def test_get_user_permissions_with_groups(self):
        """Test getting user permissions with group inheritance."""
        user = create_test_user("queryuser2", "queryuser2@example.com")
        
        # Create group and add user to it
        group = create_auth_group("query_group")
        add_user_to_auth_group(user.id, group.id)
        
        # Add direct user permission
        add_user_permission(user.id, "direct", "read", "ALLOW")
        
        # Add group permission
        add_group_permission(group.id, "group", "execute", "ALLOW")
        
        permissions = get_user_permissions(user.id, include_groups=True)
        
        assert len(permissions) == 2
        
        # Check direct permission
        direct_perm = next((p for p in permissions if p.source == 'user'), None)
        assert direct_perm is not None
        assert isinstance(direct_perm, UserPermission)
        assert direct_perm.major == 'direct'
        assert direct_perm.minor == 'read'
        
        # Check group permission (note: source is now 'group:{group_name}')
        group_perm = next((p for p in permissions if p.source.startswith('group:')), None)
        assert group_perm is not None
        assert group_perm.major == 'group'
        assert group_perm.minor == 'execute'
        assert group_perm.group_id == group.id
        assert group_perm.source == 'group:query_group'

    def test_get_user_permissions_multiple_groups(self):
        """Test getting user permissions from multiple groups."""
        user = create_test_user("queryuser3", "queryuser3@example.com")
        
        # Create two groups
        group1 = create_auth_group("multi_group1")
        group2 = create_auth_group("multi_group2")
        
        # Add user to both groups
        add_user_to_auth_group(user.id, group1.id)
        add_user_to_auth_group(user.id, group2.id)
        
        # Add permissions to both groups
        add_group_permission(group1.id, "group1", "perm1", "ALLOW")
        add_group_permission(group2.id, "group2", "perm2", "ALLOW")
        
        permissions = get_user_permissions(user.id, include_groups=True)
        
        group_perms = [p for p in permissions if p.source.startswith('group:')]
        assert len(group_perms) == 2
        
        group_ids = {p.group_id for p in group_perms}
        assert group1.id in group_ids
        assert group2.id in group_ids

    def test_get_user_permissions_no_permissions(self):
        """Test getting permissions for user with no permissions."""
        user_id = 999  # User with no permissions
        
        permissions = get_user_permissions(user_id, include_groups=True)
        
        assert len(permissions) == 0

    def test_get_group_permissions(self):
        """Test getting all permissions for a group."""
        group = create_auth_group("test_group_perms")
        
        # Add multiple permissions to group
        add_group_permission(group.id, "group_test", "read", "ALLOW")
        add_group_permission(group.id, "group_test", "write", "DENY")
        add_group_permission(group.id, "admin", "delete", "ALLOW")
        
        permissions = get_group_permissions(group.id)
        
        assert len(permissions) == 3
        assert all(isinstance(p, GroupPermission) for p in permissions)
        
        # Check permissions structure
        for perm in permissions:
            assert hasattr(perm, 'major')
            assert hasattr(perm, 'minor')
            assert hasattr(perm, 'effect')
            assert perm.effect in ['ALLOW', 'DENY']

    def test_get_group_permissions_empty_group(self):
        """Test getting permissions for group with no permissions."""
        group = create_auth_group("empty_perm_group")
        
        permissions = get_group_permissions(group.id)
        
        assert len(permissions) == 0

    def test_user_has_permission_direct_allow(self):
        """Test user has permission via direct ALLOW."""
        user = create_test_user("hasuser1", "hasuser1@example.com")
        major = "test_has"
        minor = "permission"
        
        add_user_permission(user.id, major, minor, "ALLOW")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is True

    def test_user_has_permission_direct_deny(self):
        """Test user denied permission via direct DENY."""
        user = create_test_user("hasuser2", "hasuser2@example.com")
        major = "test_deny"
        minor = "permission"
        
        add_user_permission(user.id, major, minor, "DENY")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is False

    def test_user_has_permission_group_allow(self):
        """Test user has permission via group ALLOW."""
        user = create_test_user("hasuser3", "hasuser3@example.com")
        major = "group_allow"
        minor = "permission"
        
        group = create_auth_group("allow_group")
        add_user_to_auth_group(user.id, group.id)
        add_group_permission(group.id, major, minor, "ALLOW")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is True

    def test_user_has_permission_group_deny(self):
        """Test user denied permission via group DENY."""
        user = create_test_user("hasuser4", "hasuser4@example.com")
        major = "group_deny"
        minor = "permission"
        
        group = create_auth_group("deny_group")
        add_user_to_auth_group(user.id, group.id)
        add_group_permission(group.id, major, minor, "DENY")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is False

    def test_user_has_permission_deny_overrides_allow(self):
        """Test that DENY overrides ALLOW when both are present."""
        user = create_test_user("hasuser5", "hasuser5@example.com")
        major = "override_test"
        minor = "permission"
        
        # Add both ALLOW and DENY at user level
        add_user_permission(user.id, major, minor, "ALLOW")
        add_user_permission(user.id, major, minor, "DENY")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is False

    def test_user_has_permission_user_deny_overrides_group_allow(self):
        """Test that user DENY overrides group ALLOW."""
        user = create_test_user("hasuser6", "hasuser6@example.com")
        major = "mixed_test"
        minor = "permission"
        
        # Group allows
        group = create_auth_group("mixed_group")
        add_user_to_auth_group(user.id, group.id)
        add_group_permission(group.id, major, minor, "ALLOW")
        
        # User denies
        add_user_permission(user.id, major, minor, "DENY")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is False

    def test_user_has_permission_group_deny_overrides_user_allow(self):
        """Test that group DENY overrides user ALLOW."""
        user = create_test_user("hasuser7", "hasuser7@example.com")
        major = "mixed_test2"
        minor = "permission"
        
        # User allows
        add_user_permission(user.id, major, minor, "ALLOW")
        
        # Group denies
        group = create_auth_group("override_group")
        add_user_to_auth_group(user.id, group.id)
        add_group_permission(group.id, major, minor, "DENY")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is False

    def test_user_has_permission_multiple_groups_mixed(self):
        """Test permission with multiple groups having different effects."""
        user = create_test_user("hasuser8", "hasuser8@example.com")
        major = "multi_mixed"
        minor = "permission"
        
        # Group 1 allows
        group1 = create_auth_group("allow_multi_group")
        add_user_to_auth_group(user.id, group1.id)
        add_group_permission(group1.id, major, minor, "ALLOW")
        
        # Group 2 denies
        group2 = create_auth_group("deny_multi_group")
        add_user_to_auth_group(user.id, group2.id)
        add_group_permission(group2.id, major, minor, "DENY")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        # DENY should override ALLOW
        assert has_perm is False

    def test_user_has_permission_no_permission(self):
        """Test user has no permission when none are defined."""
        user_id = 999
        
        has_perm = user_has_permission(user_id, "nonexistent", "permission")
        
        assert has_perm is False

    def test_user_has_permission_multiple_allows(self):
        """Test user has permission with multiple ALLOW sources."""
        user = create_test_user("hasuser9", "hasuser9@example.com")
        major = "multi_allow"
        minor = "permission"
        
        # Direct user permission
        add_user_permission(user.id, major, minor, "ALLOW")
        
        # Group permission
        group = create_auth_group("multi_allow_group")
        add_user_to_auth_group(user.id, group.id)
        add_group_permission(group.id, major, minor, "ALLOW")
        
        has_perm = user_has_permission(user.id, major, minor)
        
        assert has_perm is True


@pytest.mark.integration
class TestWildcardPermissionMatching:
    """Test wildcard features of permission matching using fnmatch patterns."""
    
    def test_user_permission_wildcard_minor_star(self):
        """Test user permission with wildcard in minor component (test:*)."""
        user = create_test_user("wildcarduser1", "wildcarduser1@example.com")
        
        # Add permission with wildcard in minor component
        add_user_permission(user.id, "test", "*", "ALLOW")
        
        # Should match any minor component
        assert user_has_permission(user.id, "test", "blah") is True
        assert user_has_permission(user.id, "test", "something") is True
        assert user_has_permission(user.id, "test", "anything") is True
        
        # Should not match different major component
        assert user_has_permission(user.id, "other", "blah") is False

    def test_user_permission_wildcard_major_star(self):
        """Test user permission with wildcard in major component (*:read)."""
        user = create_test_user("wildcarduser2", "wildcarduser2@example.com")
        
        # Add permission with wildcard in major component
        add_user_permission(user.id, "*", "read", "ALLOW")
        
        # Should match any major component with read minor
        assert user_has_permission(user.id, "analysis", "read") is True
        assert user_has_permission(user.id, "system", "read") is True
        assert user_has_permission(user.id, "test", "read") is True
        
        # Should not match different minor component
        assert user_has_permission(user.id, "analysis", "write") is False

    def test_user_permission_wildcard_both_star(self):
        """Test user permission with wildcard in both components (*:*)."""
        user = create_test_user("wildcarduser3", "wildcarduser3@example.com")
        
        # Add permission with wildcard in both components
        add_user_permission(user.id, "*", "*", "ALLOW")
        
        # Should match any permission
        assert user_has_permission(user.id, "analysis", "read") is True
        assert user_has_permission(user.id, "system", "write") is True
        assert user_has_permission(user.id, "test", "execute") is True
        assert user_has_permission(user.id, "anything", "something") is True

    def test_group_permission_wildcard_minor_star(self):
        """Test group permission with wildcard in minor component."""
        user = create_test_user("wildcarduser4", "wildcarduser4@example.com")
        group = create_auth_group("wildcard_group")
        add_user_to_auth_group(user.id, group.id)
        
        # Add group permission with wildcard in minor component
        add_group_permission(group.id, "test", "*", "ALLOW")
        
        # Should match any minor component
        assert user_has_permission(user.id, "test", "blah") is True
        assert user_has_permission(user.id, "test", "something") is True
        assert user_has_permission(user.id, "test", "anything") is True
        
        # Should not match different major component
        assert user_has_permission(user.id, "other", "blah") is False

    def test_group_permission_wildcard_major_star(self):
        """Test group permission with wildcard in major component."""
        user = create_test_user("wildcarduser5", "wildcarduser5@example.com")
        group = create_auth_group("wildcard_major_group")
        add_user_to_auth_group(user.id, group.id)
        
        # Add group permission with wildcard in major component
        add_group_permission(group.id, "*", "delete", "ALLOW")
        
        # Should match any major component with delete minor
        assert user_has_permission(user.id, "analysis", "delete") is True
        assert user_has_permission(user.id, "system", "delete") is True
        assert user_has_permission(user.id, "test", "delete") is True
        
        # Should not match different minor component
        assert user_has_permission(user.id, "analysis", "read") is False

    def test_wildcard_permission_pattern_prefix(self):
        """Test wildcard permission with prefix pattern (test_*)."""
        user = create_test_user("wildcarduser6", "wildcarduser6@example.com")
        
        # Add permission with prefix pattern
        add_user_permission(user.id, "test_*", "read", "ALLOW")
        
        # Should match permissions starting with test_
        assert user_has_permission(user.id, "test_analysis", "read") is True
        assert user_has_permission(user.id, "test_system", "read") is True
        assert user_has_permission(user.id, "test_module", "read") is True
        
        # Should not match permissions not starting with test_
        assert user_has_permission(user.id, "analysis", "read") is False
        assert user_has_permission(user.id, "system", "read") is False

    def test_wildcard_permission_pattern_suffix(self):
        """Test wildcard permission with suffix pattern (*_test)."""
        user = create_test_user("wildcarduser7", "wildcarduser7@example.com")
        
        # Add permission with suffix pattern
        add_user_permission(user.id, "*_test", "execute", "ALLOW")
        
        # Should match permissions ending with _test
        assert user_has_permission(user.id, "analysis_test", "execute") is True
        assert user_has_permission(user.id, "system_test", "execute") is True
        assert user_has_permission(user.id, "module_test", "execute") is True
        
        # Should not match permissions not ending with _test
        assert user_has_permission(user.id, "analysis", "execute") is False
        assert user_has_permission(user.id, "test", "execute") is False

    def test_wildcard_permission_question_mark(self):
        """Test wildcard permission with single character wildcard (?)."""
        user = create_test_user("wildcarduser8", "wildcarduser8@example.com")
        
        # Add permission with single character wildcard
        add_user_permission(user.id, "test?", "read", "ALLOW")
        
        # Should match single character after test
        assert user_has_permission(user.id, "test1", "read") is True
        assert user_has_permission(user.id, "testA", "read") is True
        assert user_has_permission(user.id, "tests", "read") is True
        
        # Should not match multiple characters or exact match
        assert user_has_permission(user.id, "test", "read") is False
        assert user_has_permission(user.id, "test12", "read") is False

    def test_wildcard_permission_deny_overrides_wildcard_allow(self):
        """Test that specific DENY overrides wildcard ALLOW."""
        user = create_test_user("wildcarduser9", "wildcarduser9@example.com")
        
        # Add wildcard ALLOW permission
        add_user_permission(user.id, "*", "read", "ALLOW")
        
        # Add specific DENY permission
        add_user_permission(user.id, "secret", "read", "DENY")
        
        # Wildcard should allow most permissions
        assert user_has_permission(user.id, "analysis", "read") is True
        assert user_has_permission(user.id, "system", "read") is True
        
        # Specific deny should override wildcard allow
        assert user_has_permission(user.id, "secret", "read") is False

    def test_wildcard_permission_user_deny_overrides_group_wildcard_allow(self):
        """Test that user DENY overrides group wildcard ALLOW."""
        user = create_test_user("wildcarduser10", "wildcarduser10@example.com")
        group = create_auth_group("wildcard_deny_group")
        add_user_to_auth_group(user.id, group.id)
        
        # Add group wildcard ALLOW permission
        add_group_permission(group.id, "*", "*", "ALLOW")
        
        # Add user specific DENY permission
        add_user_permission(user.id, "admin", "delete", "DENY")
        
        # Group wildcard should allow most permissions
        assert user_has_permission(user.id, "analysis", "read") is True
        assert user_has_permission(user.id, "system", "write") is True
        
        # User deny should override group wildcard allow
        assert user_has_permission(user.id, "admin", "delete") is False

    def test_wildcard_permission_mixed_patterns(self):
        """Test multiple wildcard patterns with different effects."""
        user = create_test_user("wildcarduser11", "wildcarduser11@example.com")
        
        # Add broad wildcard ALLOW
        add_user_permission(user.id, "*", "*", "ALLOW")
        
        # Add more specific wildcard DENY
        add_user_permission(user.id, "admin_*", "*", "DENY")
        
        # Add very specific ALLOW to override the deny
        add_user_permission(user.id, "admin_safe", "read", "ALLOW")
        
        # Broad permissions should work
        assert user_has_permission(user.id, "analysis", "read") is True
        assert user_has_permission(user.id, "system", "write") is True
        
        # Admin permissions should be denied
        assert user_has_permission(user.id, "admin_dangerous", "delete") is False
        assert user_has_permission(user.id, "admin_config", "write") is False
        
        # Specific admin_safe read should still be denied (DENY overrides ALLOW)
        assert user_has_permission(user.id, "admin_safe", "read") is False

    def test_wildcard_permission_brackets_pattern(self):
        """Test wildcard permission with character class brackets."""
        user = create_test_user("wildcarduser12", "wildcarduser12@example.com")
        
        # Add permission with character class pattern
        add_user_permission(user.id, "test[0-9]", "read", "ALLOW")
        
        # Should match digits
        assert user_has_permission(user.id, "test0", "read") is True
        assert user_has_permission(user.id, "test5", "read") is True
        assert user_has_permission(user.id, "test9", "read") is True
        
        # Should not match letters or multiple characters
        assert user_has_permission(user.id, "testa", "read") is False
        assert user_has_permission(user.id, "test", "read") is False
        assert user_has_permission(user.id, "test10", "read") is False