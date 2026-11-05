import pytest

from saq.configuration.config import get_config
from saq.constants import QUEUE_DEFAULT
from saq.database.model import User
from saq.database.pool import get_db
from saq.database.util.user_management import (
    add_user,
    create_api_key,
    delete_user,
    list_api_keys,
    revoke_api_key,
)
from saq.util import is_uuid, sha256_str


@pytest.mark.integration
def test_add_user_success():
    """Test successfully adding a new user to the database."""
    username = "testuser123"
    email = "testuser123@example.com"
    display_name = "Test User"
    password = "testpassword123"
    queue = "test_queue"
    timezone = "America/New_York"
    
    # Add the user
    user = add_user(
        username=username,
        email=email,
        display_name=display_name,
        password=password,
        queue=queue,
        timezone=timezone
    )
    
    # Verify user was created and returned
    assert user is not None
    assert isinstance(user, User)
    assert user.username == username
    assert user.email == email
    assert user.display_name == display_name
    assert user.queue == queue
    assert user.timezone == timezone
    assert user.id is not None
    
    # Verify password was hashed correctly
    assert user.verify_password(password)
    assert not user.verify_password("wrong_password")
    assert user.password_hash is not None
    assert user.password_hash != password  # Password should be hashed

    # Verify user exists in database, read in a new transaction so an uncommitted insert fails
    user_id = user.id
    db = get_db()
    db.close()
    db_user = db.query(User).filter(User.username == username).first()
    assert db_user is not None
    assert db_user.id == user_id
    
    # Cleanup
    delete_user(username)


@pytest.mark.integration
def test_add_user_with_defaults():
    """Test adding a user with default queue and timezone values."""
    username = "defaultuser"
    email = "defaultuser@example.com"
    display_name = "Default User"
    password = "password123"
    
    # Add user without specifying queue and timezone (should use defaults), by position
    user = add_user(username, email, display_name, password)
    
    assert user.username == username
    assert user.email == email
    assert user.display_name == display_name
    assert user.queue == QUEUE_DEFAULT
    assert user.timezone == "UTC"
    assert user.verify_password(password)
    
    # Cleanup
    delete_user(username)


@pytest.mark.integration
def test_delete_user_success():
    """Test successfully deleting an existing user."""
    username = "deleteuser"
    email = "deleteuser@example.com"
    display_name = "Delete User"
    password = "deletepass"
    
    # First add a user
    user = add_user(username, email, display_name, password)
    user_id = user.id
    
    # Verify user exists
    db = get_db()
    assert db.query(User).filter(User.id == user_id).first() is not None
    
    # Delete the user
    result = delete_user(username)
    
    # Verify deletion was successful
    assert result is True
    
    # Verify user no longer exists in database, read in a new transaction so an uncommitted
    # delete fails
    db.close()
    assert db.query(User).filter(User.id == user_id).first() is None
    assert db.query(User).filter(User.username == username).first() is None


@pytest.mark.integration
def test_delete_user_nonexistent():
    """Test deleting a user that doesn't exist."""
    nonexistent_username = "nonexistentuser123"
    
    # Ensure user doesn't exist
    db = get_db()
    assert db.query(User).filter(User.username == nonexistent_username).first() is None
    
    # Try to delete nonexistent user
    result = delete_user(nonexistent_username)
    
    # Should return False
    assert result is False


@pytest.mark.integration
def test_add_user_duplicate_username():
    """Test adding a user with a username that already exists."""
    username = "duplicateuser"
    email1 = "user1@example.com"
    email2 = "user2@example.com"
    display_name = "Duplicate User"
    password = "password123"
    
    # Add first user
    user1 = add_user(username, email1, display_name, password)
    assert user1 is not None
    
    try:
        # Try to add second user with same username (should fail)
        with pytest.raises(Exception):  # Should raise database integrity error
            add_user(username, email2, display_name, password)

        get_db().rollback()

    finally:
        # Cleanup
        delete_user(username)


@pytest.mark.integration
def test_add_user_duplicate_email():
    """Test adding a user with an email that already exists."""
    username1 = "user1"
    username2 = "user2"
    email = "duplicate@example.com"
    display_name = "User"
    password = "password123"
    
    # Add first user
    user1 = add_user(username1, email, display_name, password)
    assert user1 is not None
    
    try:
        # Try to add second user with same email (should fail)
        with pytest.raises(Exception):  # Should raise database integrity error
            add_user(username2, email, display_name, password)

        get_db().rollback()

    finally:
        # Cleanup
        delete_user(username1)


def _key_by_plaintext(user_id: int, api_key: str):
    return next((k for k in list_api_keys(user_id) if k.key_hash == sha256_str(api_key)), None)


@pytest.mark.integration
def test_create_list_revoke_api_key():
    user_id = get_config().global_settings.automation_user_id
    other = add_user("api_key_other", "api_key_other@example.com", "Other", "password123")
    other_id = other.id
    other_key = create_api_key(other_id, "theirs", inherit=True)
    api_key = create_api_key(user_id, "test", inherit=True)
    assert is_uuid(api_key)

    # read in a new transaction, so an uncommitted key is not listed
    get_db().close()
    # only this user's keys are listed
    assert [k.name for k in list_api_keys(user_id)] == ["test"]
    key = _key_by_plaintext(user_id, api_key)
    assert key is not None
    assert key.name == "test"
    assert key.inherit_user_scope
    assert list(key.scope) == []

    assert revoke_api_key(key.id)
    get_db().close()
    assert _key_by_plaintext(user_id, api_key) is None
    assert _key_by_plaintext(other_id, other_key) is not None
    assert not revoke_api_key(-1)


@pytest.mark.integration
def test_scoped_api_key_stores_its_scope():
    user_id = get_config().global_settings.automation_user_id
    api_key = create_api_key(user_id, "ai", scope=[("ai", "read")])

    key = _key_by_plaintext(user_id, api_key)
    assert not key.inherit_user_scope
    assert [(s.major, s.minor, s.effect) for s in key.scope] == [("ai", "read", "ALLOW")]


@pytest.mark.integration
def test_create_api_key_requires_exactly_one_of_inherit_or_scope():
    user_id = get_config().global_settings.automation_user_id
    with pytest.raises(ValueError):
        create_api_key(user_id, "bad")  # neither inherit nor scope
    with pytest.raises(ValueError):
        create_api_key(user_id, "bad", inherit=True, scope=[("ai", "read")])  # both


@pytest.mark.integration
def test_create_api_key_rejects_a_non_uuid_key():
    with pytest.raises(ValueError):
        create_api_key(get_config().global_settings.automation_user_id, "test", inherit=True, api_key="invalid")
