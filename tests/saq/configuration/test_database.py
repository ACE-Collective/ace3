import pytest

from saq.configuration.database import delete_database_config_value, get_database_config_value, set_database_config_value
from saq.configuration.encryption import decrypt_password, delete_password, encrypt_password
from saq.crypto import set_encryption_password

@pytest.fixture(autouse=True, scope="function")
def setup():
    set_encryption_password('test')

@pytest.mark.integration
def test_crud_database_config_str():
    # test set
    set_database_config_value('test', 'test_value')
    assert get_database_config_value('test') == 'test_value'

    # test update
    set_database_config_value('test', 'test_value_2')
    assert get_database_config_value('test') == 'test_value_2'

    # test delete
    delete_database_config_value('test')
    assert get_database_config_value('test') is None

@pytest.mark.integration
def test_crud_database_config_int():
    # test set
    set_database_config_value('test', 1)
    assert get_database_config_value('test', int) == 1

    # test update
    set_database_config_value('test', 2)
    assert get_database_config_value('test', int) == 2

    # test delete
    delete_database_config_value('test')
    assert get_database_config_value('test', int) is None

@pytest.mark.integration
def test_crud_database_config_bytes():
    # test set
    set_database_config_value('test', b'test_value')
    assert get_database_config_value('test', bytes) == b'test_value'

    # test update
    set_database_config_value('test', b'test_value_2')
    assert get_database_config_value('test', bytes) == b'test_value_2'

    # test delete
    delete_database_config_value('test')
    assert get_database_config_value('test') is None

@pytest.mark.integration
def test_database_config_invalid_type():
    with pytest.raises(TypeError):
        set_database_config_value('test', 1.0) # float not supported

@pytest.mark.integration
def test_encrypt_decrypt_delete_password():
    encrypt_password('password', 'Hello, World!')
    assert decrypt_password('password') == 'Hello, World!'
    assert delete_password('password') == 1
    assert decrypt_password('password') is None
