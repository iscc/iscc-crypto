import pytest
from iscc_crypto.verifying import verify_vc, VerificationError
from iscc_crypto.keys import key_generate
from iscc_crypto.signing import sign_vc


def test_verify_vc_valid_signature():
    # type: () -> None
    """Test successful verification of a valid VC signature."""
    keypair = key_generate()
    doc = {"test": "data"}
    signed = sign_vc(doc, keypair)
    result = verify_vc(signed)
    assert result.is_valid is True
    assert result.message is None


def test_verify_vc_missing_proof():
    # type: () -> None
    """Test verification fails with missing proof field."""
    doc = {"test": "data"}
    with pytest.raises(VerificationError, match="Missing required field: proof"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Missing required field: proof" in result.message


def test_verify_vc_invalid_proof_type():
    # type: () -> None
    """Test verification fails with wrong proof type."""
    doc = {
        "test": "data",
        "proof": {
            "type": "WrongType",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z123",
            "proofValue": "z123",
        },
    }
    with pytest.raises(VerificationError, match="Invalid proof type"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid proof type" in result.message


def test_verify_vc_invalid_cryptosuite():
    # type: () -> None
    """Test verification fails with wrong cryptosuite."""
    doc = {
        "test": "data",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "wrong-suite",
            "verificationMethod": "did:key:z123",
            "proofValue": "z123",
        },
    }
    with pytest.raises(VerificationError, match="Invalid cryptosuite"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid cryptosuite" in result.message


def test_verify_vc_invalid_proof_value():
    # type: () -> None
    """Test verification fails with invalid proof value format."""
    doc = {
        "test": "data",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z123",
            "proofValue": "123",  # Missing 'z' prefix
        },
    }
    with pytest.raises(VerificationError, match="Invalid proofValue format"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid proofValue format" in result.message


def test_verify_vc_invalid_verification_method():
    # type: () -> None
    """Test verification fails with invalid verification method format."""
    doc = {
        "test": "data",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "invalid:key:z123",
            "proofValue": "z123",
        },
    }
    with pytest.raises(VerificationError, match="Invalid verificationMethod"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid verificationMethod" in result.message


def test_verify_vc_tampered_data():
    # type: () -> None
    """Test verification fails with tampered document data."""
    keypair = key_generate()
    doc = {"test": "data"}
    signed = sign_vc(doc, keypair)
    signed["test"] = "tampered"
    with pytest.raises(VerificationError, match="Invalid signature"):
        verify_vc(signed)
    result = verify_vc(signed, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid signature" in result.message


def test_verify_vc_nested_data():
    # type: () -> None
    """Test verification works with nested document structure."""
    keypair = key_generate()
    doc = {
        "level1": {
            "level2": {
                "level3": "deep data",
                "array": [1, 2, {"key": "value"}],
            }
        }
    }
    signed = sign_vc(doc, keypair)
    result = verify_vc(signed)
    assert result.is_valid is True
    assert result.message is None


def test_verify_vc_empty_document():
    # type: () -> None
    """Test verification works with empty document."""
    keypair = key_generate()
    doc = {}
    signed = sign_vc(doc, keypair)
    result = verify_vc(signed)
    assert result.is_valid is True
    assert result.message is None


def test_verify_vc_invalid_public_key():
    # type: () -> None
    """Test verification fails with invalid public key in verificationMethod."""
    doc = {
        "test": "data",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:zinvalid",
            "proofValue": "z123",
        },
    }
    with pytest.raises(VerificationError, match="Invalid public key"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid public key" in result.message


def test_verify_vc_invalid_public_key_prefix():
    # type: () -> None
    """Test verification fails when public key has wrong prefix bytes."""
    # Create key with wrong prefix (FF01 instead of ED01)
    wrong_prefix_key = "z32UwqJGWrxF4QJgDoUwmK5hjW1bJXrXzpfUkNqUX8p1V"
    doc = {
        "test": "data",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": f"did:key:{wrong_prefix_key}",
            "proofValue": "z123",
        },
    }
    with pytest.raises(VerificationError, match="Invalid public key prefix"):
        verify_vc(doc)
    result = verify_vc(doc, raise_on_error=False)
    assert result.is_valid is False
    assert "Invalid public key prefix" in result.message
