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
    assert result.signature_valid is True
    assert result.identity_verified is None
    assert result.message is None


def test_verify_json_missing_signature():
    """Test verification fails when signature field is missing."""
    doc = {"pubkey": "some_key"}
    with pytest.raises(VerificationError, match="Missing required field: signature"):
        verify_json(doc)


def test_verify_json_missing_pubkey():
    """Test verification fails when pubkey field is missing."""
    doc = {"signature": {"proof": "xyz"}}
    with pytest.raises(VerificationError, match="Missing pubkey field"):
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
    assert result.signature_valid is False
    assert "Invalid signature for payload" in result.message


def test_verify_json_wrong_key(test_keypair):
    """Test verification fails with wrong key."""
    doc = {"test": "value"}
    signed = sign_json(doc, test_keypair)
    # Generate different keypair
    other_keypair = key_generate()
    signed["signature"]["pubkey"] = other_keypair.public_key
    result = verify_json(signed, raise_on_error=False)
    assert result.is_valid is False
    assert result.signature_valid is False


def test_verify_json_no_raise_mode(signed_doc):
    """Test non-raising mode returns VerificationResult."""
    signed_doc["test"] = "tampered"
    result = verify_json(signed_doc, raise_on_error=False)
    assert result.is_valid is False
    assert result.signature_valid is False
    assert isinstance(result.message, str)


def test_verify_json_nested_structure(test_keypair):
    """Test verification works with nested JSON structures."""
    doc = {"nested": {"array": [1, 2, 3], "object": {"a": 1, "b": "test"}}}
    signed = sign_json(doc, test_keypair)
    result = verify_json(signed)
    assert result.is_valid is True
    assert result.signature_valid is True


def test_verify_json_empty_object(test_keypair):
    """Test verification works with empty object."""
    doc = {}
    signed = sign_json(doc, test_keypair)
    result = verify_json(signed)
    assert result.is_valid is True
    assert result.signature_valid is True


def test_verify_json_canonicalization_error(signed_doc):
    """Test verification fails when canonicalization raises an error."""
    with patch("jcs.canonicalize") as mock_canonicalize:
        mock_canonicalize.side_effect = Exception("Canonicalization failed")
        result = verify_json(signed_doc, raise_on_error=False)
        assert result.is_valid is False
        assert result.signature_valid is False
        assert result.message == "Signature verification failed: Canonicalization failed"


def test_verify_json_with_identity_doc_success(test_keypair):
    """Test successful identity verification with matching identity document."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType

    # Create keypair with controller
    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="key-1",
    )

    # Sign document
    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    # Create matching identity document
    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#key-1",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": test_keypair.public_key,
            }
        ],
        "authentication": ["did:example:123456789abcdefghi#key-1"],
    }

    # Verify with identity document
    result = verify_json(signed, identity_doc)
    assert result.is_valid is True
    assert result.signature_valid is True
    assert result.identity_verified is True
    assert result.message is None


def test_verify_json_with_identity_doc_wrong_controller():
    """Test identity verification fails with wrong controller."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType

    test_keypair = key_generate()
    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="key-1",
    )

    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    # Identity document with different controller
    identity_doc = {
        "id": "did:example:different",
        "verificationMethod": [
            {
                "id": "did:example:different#key-1",
                "type": "Multikey",
                "controller": "did:example:different",
                "publicKeyMultibase": test_keypair.public_key,
            }
        ],
    }

    result = verify_json(signed, identity_doc, raise_on_error=False)
    assert result.is_valid is False
    assert result.signature_valid is True
    assert result.identity_verified is False
    assert "Key not authorized by controller" in result.message


def test_verify_json_with_identity_doc_wrong_pubkey():
    """Test identity verification fails with wrong public key."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType

    test_keypair = key_generate()
    other_keypair = key_generate()

    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="key-1",
    )

    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    # Identity document with different pubkey
    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#key-1",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": other_keypair.public_key,
            }
        ],
    }

    result = verify_json(signed, identity_doc, raise_on_error=False)
    assert result.is_valid is False
    assert result.signature_valid is True
    assert result.identity_verified is False


def test_verify_json_no_controller_no_identity_verification():
    """Test that signatures without controller skip identity verification."""
    from iscc_crypto.signing import SigType

    test_keypair = key_generate()
    doc = {"test": "value"}
    signed = sign_json(doc, test_keypair, SigType.SELF_VERIFYING)

    # Identity document provided but signature has no controller
    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#key-1",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": test_keypair.public_key,
            }
        ],
    }

    result = verify_json(signed, identity_doc)
    assert result.is_valid is True
    assert result.signature_valid is True
    assert result.identity_verified is None  # No identity verification attempted


def test_verify_json_identity_doc_no_verification_methods():
    """Test identity verification fails when identity doc has no verification methods."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType

    test_keypair = key_generate()
    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="key-1",
    )

    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    # Identity document with no verification methods
    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [],
    }

    result = verify_json(signed, identity_doc, raise_on_error=False)
    assert result.is_valid is False
    assert result.signature_valid is True
    assert result.identity_verified is False


def test_verify_json_keyid_matching():
    """Test identity verification with keyid matching."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType

    test_keypair = key_generate()
    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="specific-key",
    )

    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    # Identity document with multiple keys - should match specific one
    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#other-key",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": key_generate().public_key,  # Different key
            },
            {
                "id": "did:example:123456789abcdefghi#specific-key",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": test_keypair.public_key,  # Matching key
            },
        ],
    }

    result = verify_json(signed, identity_doc)
    assert result.is_valid is True
    assert result.signature_valid is True
    assert result.identity_verified is True


def test_verify_json_identity_verification_exception():
    """Test identity verification exception handling."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType

    test_keypair = key_generate()
    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="key-1",
    )

    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#key-1",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": test_keypair.public_key,
            }
        ],
    }

    # Mock _verify_identity to raise an exception
    with patch("iscc_crypto.verifying._verify_identity") as mock_verify:
        mock_verify.side_effect = Exception("Verification error")
        result = verify_json(signed, identity_doc, raise_on_error=False)
        assert result.is_valid is False
        assert result.signature_valid is True
        assert result.identity_verified is False
        assert "Identity verification failed: Verification error" in result.message


def test_verify_json_identity_verification_exception_raises():
    """Test identity verification exception handling with raise_on_error=True."""
    from iscc_crypto.keys import KeyPair
    from iscc_crypto.signing import SigType
    from unittest.mock import patch

    test_keypair = key_generate()
    keypair_with_controller = KeyPair(
        public_key=test_keypair.public_key,
        secret_key=test_keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id="key-1",
    )

    doc = {"test": "value"}
    signed = sign_json(doc, keypair_with_controller, SigType.IDENTITY_BOUND)

    identity_doc = {
        "id": "did:example:123456789abcdefghi",
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#key-1",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": test_keypair.public_key,
            }
        ],
    }

    # Mock _verify_identity to raise an exception
    with patch("iscc_crypto.verifying._verify_identity") as mock_verify:
        mock_verify.side_effect = Exception("Verification error")
        with pytest.raises(VerificationError, match="Identity verification failed: Verification error"):
            verify_json(signed, identity_doc, raise_on_error=True)


def test_verify_identity_missing_fields():
    """Test _verify_identity with missing pubkey or controller."""
    from iscc_crypto.verifying import _verify_identity

    identity_doc = {
        "verificationMethod": [
            {
                "id": "did:example:123456789abcdefghi#key-1",
                "type": "Multikey",
                "controller": "did:example:123456789abcdefghi",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            }
        ],
    }

    # Missing pubkey
    sig_obj_no_pubkey = {"controller": "did:example:123456789abcdefghi"}
    assert _verify_identity(sig_obj_no_pubkey, identity_doc) is False

    # Missing controller
    sig_obj_no_controller = {"pubkey": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}
    assert _verify_identity(sig_obj_no_controller, identity_doc) is False
