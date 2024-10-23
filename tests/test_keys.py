import pytest
import keyring
from keyring.errors import PasswordDeleteError

from iscc_crypto.main import create_key, save_key


def safe_delete_key(name):
    """Helper to safely delete a key from keyring"""
    try:
        keyring.delete_password("iscc_crypto", name)
    except PasswordDeleteError:
        pass


@pytest.fixture
def test_key():
    """Create a test key with a unique name"""
    key = create_key(name="test_key_temp_12345")
    yield key
    # Clean up - remove test key from keyring
    safe_delete_key(key.name)


def test_save_key_success(test_key):
    """Test successful key saving"""
    name = save_key(test_key)
    assert name == test_key.name
    # Verify key was actually saved
    stored = keyring.get_password("iscc_crypto", name)
    assert stored is not None


def test_save_key_with_authority():
    """Test saving key with authority URL"""
    key = create_key(name="test_key_auth_12345", authority="https://example.com")
    try:
        name = save_key(key)
        assert name == key.name
        stored = keyring.get_password("iscc_crypto", name)
        assert stored is not None
    finally:
        safe_delete_key(key.name)


def test_save_key_keyring_error(monkeypatch):
    """Test handling of keyring errors"""

    def mock_set_password(*args):
        raise keyring.errors.PasswordSetError("Test error")

    monkeypatch.setattr(keyring, "set_password", mock_set_password)
    key = create_key(name="test_key_error_12345")
    with pytest.raises(keyring.errors.KeyringError):
        save_key(key)
