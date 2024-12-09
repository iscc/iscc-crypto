import base58
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from iscc_crypto.verifying import verify_raw, VerificationError
from iscc_crypto.keys import key_generate


@pytest.fixture
def keypair():
    # type: () -> tuple[bytes, str, ed25519.Ed25519PublicKey]
    """Create test keypair and sample payload"""
    kp = key_generate()
    payload = b"test message"
    signature = kp.sk_obj.sign(payload)
    sig_mb = "z" + base58.b58encode(signature).decode("utf-8")
    return payload, sig_mb, kp.pk_obj


def test_verify_raw_valid_signature(keypair):
    # type: (tuple) -> None
    """Test successful verification of valid signature"""
    payload, signature, pubkey = keypair
    result = verify_raw(payload, signature, pubkey)
    assert result.is_valid is True
    assert result.message is None


def test_verify_raw_invalid_signature(keypair):
    # type: (tuple) -> None
    """Test detection of tampered signature"""
    payload, signature, pubkey = keypair
    tampered_sig = signature[:-1] + "0"  # Change last character
    with pytest.raises(VerificationError):
        verify_raw(payload, tampered_sig, pubkey)


def test_verify_raw_modified_payload(keypair):
    # type: (tuple) -> None
    """Test detection of modified payload"""
    payload, signature, pubkey = keypair
    modified_payload = b"modified message"
    with pytest.raises(VerificationError):
        verify_raw(modified_payload, signature, pubkey)


def test_verify_raw_wrong_pubkey(keypair):
    # type: (tuple) -> None
    """Test verification with wrong public key"""
    payload, signature, _ = keypair
    wrong_keypair = key_generate()
    with pytest.raises(VerificationError):
        verify_raw(payload, signature, wrong_keypair.pk_obj)


def test_verify_raw_invalid_signature_format(keypair):
    # type: (tuple) -> None
    """Test handling of malformed signature string"""
    payload, _, pubkey = keypair
    invalid_sig = "not-a-valid-signature"
    with pytest.raises(VerificationError):
        verify_raw(payload, invalid_sig, pubkey)


def test_verify_raw_empty_payload(keypair):
    # type: (tuple) -> None
    """Test verification with empty payload"""
    _, signature, pubkey = keypair
    with pytest.raises(VerificationError):
        verify_raw(b"", signature, pubkey)


def test_verify_raw_no_raise_mode(keypair):
    # type: (tuple) -> None
    """Test non-raising mode returns VerificationResult with error message"""
    payload, signature, _ = keypair
    wrong_keypair = key_generate()
    # Tamper with signature to ensure verification fails
    bad_signature = signature[:-1] + ("1" if signature[-1] != "1" else "2")
    result = verify_raw(payload, bad_signature, wrong_keypair.pk_obj, raise_on_error=False)
    assert result.is_valid is False
    assert isinstance(result.message, str)
    assert len(result.message) > 0


def test_verify_raw_none_values():
    # type: () -> None
    """Test handling of None values"""
    with pytest.raises(VerificationError):
        verify_raw(None, None, None)  # type: ignore
