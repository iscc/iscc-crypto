import base58
import pytest
from unittest.mock import patch
from iscc_crypto.keys import key_generate
from iscc_crypto.signing import sign_json
from iscc_crypto.verifying import verify_json, VerificationError


@pytest.fixture
def test_keypair():
    return key_generate()


@pytest.fixture
def signed_doc(test_keypair):
    doc = {"test": "value", "number": 123}
    return sign_json(doc, test_keypair)


def test_verify_json_valid_signature(signed_doc):
    """Test successful verification of a valid signature."""
    result = verify_json(signed_doc)
    assert result.is_valid is True
    assert result.message is None


def test_verify_json_missing_signature():
    """Test verification fails when signature field is missing."""
    doc = {"pubkey": "some_key"}
    with pytest.raises(VerificationError, match="Missing required field: signature"):
        verify_json(doc)


def test_verify_json_missing_pubkey():
    """Test verification fails when pubkey field is missing."""
    doc = {"signature": {"proof": "xyz"}}
    with pytest.raises(VerificationError, match="Missing required field: pubkey"):
        verify_json(doc)


def test_verify_json_invalid_signature_format():
    """Test verification fails with invalid signature format."""
    doc = {"signature": {"proof": "invalid", "pubkey": "zkey"}}
    with pytest.raises(VerificationError, match="Invalid signature format"):
        verify_json(doc)


def test_verify_json_invalid_pubkey_format():
    """Test verification fails with invalid pubkey format."""
    doc = {"signature": {"proof": "zsig", "pubkey": "invalid"}}
    with pytest.raises(VerificationError, match="Invalid pubkey format"):
        verify_json(doc)


def test_verify_json_invalid_public_key_prefix():
    """Test verification fails when public key has invalid prefix."""
    # Create a pubkey with an invalid prefix (not ED01)
    invalid_key = "z" + base58.b58encode(bytes.fromhex("0000") + bytes(32)).decode()
    doc = {"signature": {"proof": "zsig", "pubkey": invalid_key}}
    with pytest.raises(VerificationError, match="Invalid pubkey format: Invalid public key prefix"):
        verify_json(doc)


def test_verify_json_tampered_content(signed_doc):
    """Test verification fails when content is modified after signing."""
    signed_doc["test"] = "tampered"
    result = verify_json(signed_doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid signature for payload" in result.message


def test_verify_json_wrong_key(test_keypair):
    """Test verification fails with wrong key."""
    doc = {"test": "value"}
    signed = sign_json(doc, test_keypair)
    # Generate different keypair
    other_keypair = key_generate()
    signed["pubkey"] = other_keypair.public_key
    result = verify_json(signed, raise_on_error=False)
    assert result.is_valid is False


def test_verify_json_no_raise_mode(signed_doc):
    """Test non-raising mode returns VerificationResult."""
    signed_doc["test"] = "tampered"
    result = verify_json(signed_doc, raise_on_error=False)
    assert result.is_valid is False
    assert isinstance(result.message, str)


def test_verify_json_nested_structure(test_keypair):
    """Test verification works with nested JSON structures."""
    doc = {"nested": {"array": [1, 2, 3], "object": {"a": 1, "b": "test"}}}
    signed = sign_json(doc, test_keypair)
    result = verify_json(signed)
    assert result.is_valid is True


def test_verify_json_empty_object(test_keypair):
    """Test verification works with empty object."""
    doc = {}
    signed = sign_json(doc, test_keypair)
    result = verify_json(signed)
    assert result.is_valid is True


def test_verify_json_canonicalization_error(signed_doc):
    """Test verification fails when canonicalization raises an error."""
    with patch("jcs.canonicalize") as mock_canonicalize:
        mock_canonicalize.side_effect = Exception("Canonicalization failed")
        result = verify_json(signed_doc, raise_on_error=False)
        assert result.is_valid is False
        assert result.message == "Verification failed: Canonicalization failed"
