from iscc_crypto.keys import create_keypair
from iscc_crypto.signing import create_signature
from iscc_crypto.verifying import verify_signature


def test_valid_signature():
    """Test verification of a valid signature"""
    kp = create_keypair()
    payload = b"test data"
    sig = create_signature(payload, kp)
    assert verify_signature(payload, sig, kp.pk_obj) is True


def test_invalid_signature():
    """Test rejection of an invalid signature"""
    kp = create_keypair()
    payload = b"test data"
    sig = create_signature(payload, kp)
    wrong_payload = b"wrong data"
    assert verify_signature(wrong_payload, sig, kp.pk_obj) is False


def test_wrong_public_key():
    """Test rejection when using wrong public key"""
    kp1 = create_keypair()
    kp2 = create_keypair()
    payload = b"test data"
    sig = create_signature(payload, kp1)
    assert verify_signature(payload, sig, kp2.pk_obj) is False


def test_malformed_signature():
    """Test handling of malformed signatures"""
    kp = create_keypair()
    payload = b"test data"

    # Missing z-prefix
    sig = create_signature(payload, kp)[1:]
    assert verify_signature(payload, sig, kp.pk_obj) is False

    # Invalid base58
    assert verify_signature(payload, "z!!!invalid!!!", kp.pk_obj) is False


def test_empty_inputs():
    """Test handling of empty inputs"""
    kp = create_keypair()
    assert verify_signature(b"", "", kp.pk_obj) is False
    assert verify_signature(b"data", "", kp.pk_obj) is False
    assert verify_signature(b"", "z123", kp.pk_obj) is False
