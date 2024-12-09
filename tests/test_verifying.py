import pytest
from hashlib import sha256
import jcs
from iscc_crypto.verifying import verify_raw, verify_json, VerificationError
from iscc_crypto.keys import key_generate
from iscc_crypto.signing import sign_raw


def test_verify_raw():
    """Test verify_raw function with various scenarios"""
    # Setup test data
    keypair = key_generate()
    message = b"test message"
    valid_sig = sign_raw(message, keypair)
    invalid_sig = "invalid_sig"
    wrong_sig = sign_raw(b"different message", keypair)

    # Test valid signature
    result = verify_raw(message, valid_sig, keypair.pk_obj)
    assert result.is_valid is True
    assert result.message is None

    # Test invalid signature format (no 'z' prefix)
    result = verify_raw(message, "not_z_prefixed", keypair.pk_obj, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid signature format" in result.message

    with pytest.raises(VerificationError, match="Invalid signature format"):
        verify_raw(message, "not_z_prefixed", keypair.pk_obj)

    # Test invalid signature content
    result = verify_raw(message, "z" + invalid_sig, keypair.pk_obj, raise_on_error=False)
    assert result.is_valid is False
    assert "Signature verification failed" in result.message

    with pytest.raises(VerificationError, match="Signature verification failed"):
        verify_raw(message, "z" + invalid_sig, keypair.pk_obj)

    # Test wrong signature (valid format but wrong message)
    result = verify_raw(message, wrong_sig, keypair.pk_obj, raise_on_error=False)
    assert result.is_valid is False
    assert "Signature verification failed" in result.message

    with pytest.raises(VerificationError):
        verify_raw(message, wrong_sig, keypair.pk_obj)

    # Test with different key
    different_keypair = key_generate()
    result = verify_raw(message, valid_sig, different_keypair.pk_obj, raise_on_error=False)
    assert result.is_valid is False
    assert "Signature verification failed" in result.message


def test_verify_json():
    """Test verify_json function with various scenarios"""
    # Setup test data
    keypair = key_generate()
    test_doc = {"data": "test message"}

    # Create valid signed document
    signed_doc = {
        "data": "test message",
        "declarer": keypair.public_key,
        "signature": sign_raw(sha256(jcs.canonicalize(test_doc)).digest(), keypair),
    }

    # Test valid signature
    result = verify_json(signed_doc)
    assert result.is_valid is True
    assert result.message is None

    # Test missing signature field
    doc_no_sig = signed_doc.copy()
    del doc_no_sig["signature"]
    result = verify_json(doc_no_sig, raise_on_error=False)
    assert result.is_valid is False
    assert "Missing required field: signature" in result.message

    with pytest.raises(VerificationError, match="Missing required field: signature"):
        verify_json(doc_no_sig)

    # Test missing declarer field
    doc_no_declarer = signed_doc.copy()
    del doc_no_declarer["declarer"]
    result = verify_json(doc_no_declarer, raise_on_error=False)
    assert result.is_valid is False
    assert "Missing required field: declarer" in result.message

    with pytest.raises(VerificationError, match="Missing required field: declarer"):
        verify_json(doc_no_declarer)

    # Test invalid signature format
    doc_invalid_sig = signed_doc.copy()
    doc_invalid_sig["signature"] = "not_z_prefixed"
    result = verify_json(doc_invalid_sig, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid signature format" in result.message

    with pytest.raises(VerificationError, match="Invalid signature format"):
        verify_json(doc_invalid_sig)

    # Test invalid declarer format
    doc_invalid_declarer = signed_doc.copy()
    doc_invalid_declarer["declarer"] = "invalid_declarer"
    result = verify_json(doc_invalid_declarer, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid declarer format" in result.message

    with pytest.raises(VerificationError, match="Invalid declarer format"):
        verify_json(doc_invalid_declarer)

    # Test with different key
    different_keypair = key_generate()
    doc_wrong_key = signed_doc.copy()
    doc_wrong_key["declarer"] = different_keypair.public_key
    result = verify_json(doc_wrong_key, raise_on_error=False)
    assert result.is_valid is False
    assert "Signature verification failed" in result.message

    with pytest.raises(VerificationError, match="Verification failed"):
        verify_json(doc_wrong_key)
