import pytest
from iscc_crypto.verifying import verify_raw, VerificationError
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
