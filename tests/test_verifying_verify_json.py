import pytest
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
    doc = {"declarer": "some_key"}
    with pytest.raises(VerificationError, match="Missing required field: signature"):
        verify_json(doc)


def test_verify_json_missing_declarer():
    """Test verification fails when declarer field is missing."""
    doc = {"signature": "zsig"}
    with pytest.raises(VerificationError, match="Missing required field: declarer"):
        verify_json(doc)


def test_verify_json_invalid_signature_format():
    """Test verification fails with invalid signature format."""
    doc = {"signature": "invalid", "declarer": "zkey"}
    with pytest.raises(VerificationError, match="Invalid signature format"):
        verify_json(doc)


def test_verify_json_invalid_declarer_format():
    """Test verification fails with invalid declarer format."""
    doc = {"signature": "zsig", "declarer": "invalid"}
    with pytest.raises(VerificationError, match="Invalid declarer format"):
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
    signed["declarer"] = other_keypair.public_key
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
