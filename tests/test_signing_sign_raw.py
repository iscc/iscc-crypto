import base58
import pytest
from iscc_crypto.keys import key_generate
from iscc_crypto.signing import sign_raw


@pytest.fixture
def test_keypair():
    """Create a test keypair."""
    return key_generate()


def test_sign_raw_valid_signature(test_keypair):
    """Test that sign_raw produces a valid signature for simple payload."""
    payload = b"test message"
    signature = sign_raw(payload, test_keypair)
    # Check signature format
    assert signature.startswith("z")
    # Verify decoded signature length is 64 bytes (Ed25519 signature size)
    assert len(base58.b58decode(signature[1:])) == 64


def test_sign_raw_empty_payload(test_keypair):
    """Test signing empty payload."""
    payload = b""
    signature = sign_raw(payload, test_keypair)
    assert signature.startswith("z")
    # Verify decoded signature length is 64 bytes (Ed25519 signature size)
    assert len(base58.b58decode(signature[1:])) == 64


def test_sign_raw_large_payload(test_keypair):
    """Test signing a large payload."""
    payload = b"x" * 1000000  # 1MB of data
    signature = sign_raw(payload, test_keypair)
    assert signature.startswith("z")
    # Verify decoded signature length is 64 bytes (Ed25519 signature size)
    assert len(base58.b58decode(signature[1:])) == 64


def test_sign_raw_unicode_payload(test_keypair):
    """Test signing unicode string converted to bytes."""
    payload = "Hello 世界".encode("utf-8")
    signature = sign_raw(payload, test_keypair)
    assert signature.startswith("z")
    # Verify decoded signature length is 64 bytes (Ed25519 signature size)
    assert len(base58.b58decode(signature[1:])) == 64


def test_sign_raw_binary_payload(test_keypair):
    """Test signing binary data."""
    payload = bytes(range(256))  # All possible byte values
    signature = sign_raw(payload, test_keypair)
    assert signature.startswith("z")
    # Verify decoded signature length is 64 bytes (Ed25519 signature size)
    assert len(base58.b58decode(signature[1:])) == 64


def test_sign_raw_invalid_payload_type(test_keypair):
    """Test that signing non-bytes payload raises TypeError."""
    with pytest.raises(TypeError):
        sign_raw("string instead of bytes", test_keypair)


def test_sign_raw_none_payload(test_keypair):
    """Test that signing None payload raises TypeError."""
    with pytest.raises(TypeError):
        sign_raw(None, test_keypair)


def test_sign_raw_deterministic(test_keypair):
    """Test that signing same payload twice produces same signature."""
    payload = b"test message"
    sig1 = sign_raw(payload, test_keypair)
    sig2 = sign_raw(payload, test_keypair)
    assert sig1 == sig2


def test_sign_raw_different_messages(test_keypair):
    """Test that different messages produce different signatures."""
    sig1 = sign_raw(b"message1", test_keypair)
    sig2 = sign_raw(b"message2", test_keypair)
    assert sig1 != sig2
