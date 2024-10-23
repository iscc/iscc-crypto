import pytest
from iscc_crypto.main import create_key


def test_create_key_default():
    """Test create_key with default parameters"""
    key = create_key()
    assert key.name == "default"
    assert key.authority is None
    assert key.private_key is not None
    assert key.public_key is not None
    # Verify Ed25519 key type
    assert key.private_key.get("kty") == "OKP"
    assert key.private_key.get("crv") == "Ed25519"


def test_create_key_with_name():
    """Test create_key with custom name"""
    key = create_key("test-key")
    assert key.name == "test-key"
    assert key.authority is None


def test_create_key_with_authority():
    """Test create_key with valid authority URL"""
    key = create_key("auth-key", "https://example.com")
    assert key.name == "auth-key"
    assert key.authority == "https://example.com"


def test_create_key_empty_name():
    """Test create_key with empty name raises ValueError"""
    with pytest.raises(ValueError, match="Key name must not be empty"):
        create_key("")


@pytest.mark.parametrize(
    "invalid_url",
    [
        "http://example.com",  # Non-HTTPS
        "https://example.com?query",  # With query
        "https://example.com#fragment",  # With fragment
        "https://example.com//path",  # Double slash
    ],
)
def test_create_key_invalid_authority(invalid_url):
    """Test create_key with various invalid authority URLs"""
    with pytest.raises(ValueError):
        create_key("test", invalid_url)


def test_create_key_unique():
    """Test that create_key generates unique keys"""
    key1 = create_key("key1")
    key2 = create_key("key2")
    assert key1.private_key.export() != key2.private_key.export()
    assert key1.public_key.export() != key2.public_key.export()


def test_public_private_key_pair():
    """Test that public key is derived from private key"""
    key = create_key()
    exported_public = key.public_key.export()
    derived_public = key.private_key.export_public()
    assert exported_public == derived_public
