import pytest
from iscc_crypto.signing import sign_vc
from iscc_crypto.keys import key_generate


def test_sign_vc_basic():
    # type: () -> None
    """Test basic VC signing with minimal input"""
    keypair = key_generate()
    vc = {"type": "VerifiableCredential"}
    signed = sign_vc(vc, keypair)
    assert "proof" in signed
    assert signed["proof"]["type"] == "DataIntegrityProof"
    assert signed["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert signed["proof"]["proofPurpose"] == "assertionMethod"
    assert signed["proof"]["verificationMethod"].startswith("did:key:")
    assert signed["proof"]["proofValue"].startswith("z")


def test_sign_vc_with_options():
    # type: () -> None
    """Test VC signing with custom proof options"""
    keypair = key_generate()
    vc = {"type": "VerifiableCredential"}
    options = {
        "type": "CustomProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2024-01-01",
    }
    signed = sign_vc(vc, keypair, options)
    assert signed["proof"]["type"] == "CustomProof"
    assert signed["proof"]["created"] == "2024-01-01"
    assert "proofValue" in signed["proof"]


def test_sign_vc_existing_proof():
    # type: () -> None
    """Test that signing fails if VC already has a proof"""
    keypair = key_generate()
    vc = {"type": "VerifiableCredential", "proof": {"type": "ExistingProof"}}
    with pytest.raises(ValueError, match="must not contain 'proof' field"):
        sign_vc(vc, keypair)


def test_sign_vc_preserves_input():
    # type: () -> None
    """Test that original input document is not modified"""
    keypair = key_generate()
    original = {"type": "VerifiableCredential", "id": "test"}
    original_copy = original.copy()
    signed = sign_vc(original, keypair)
    assert original == original_copy
    assert signed != original
    assert "proof" not in original


def test_sign_vc_nested_data():
    # type: () -> None
    """Test signing VC with nested data structures"""
    keypair = key_generate()
    vc = {
        "type": "VerifiableCredential",
        "issuer": {"id": "did:example:123", "name": "Test Issuer"},
        "credentialSubject": {"id": "did:example:456", "claims": ["a", "b", "c"]},
    }
    signed = sign_vc(vc, keypair)
    assert "proof" in signed
    assert signed["issuer"] == vc["issuer"]
    assert signed["credentialSubject"] == vc["credentialSubject"]


def test_sign_vc_empty_document():
    # type: () -> None
    """Test signing empty document"""
    keypair = key_generate()
    signed = sign_vc({}, keypair)
    assert len(signed) == 1
    assert "proof" in signed
    assert signed["proof"]["proofValue"].startswith("z")


def test_sign_vc_none_options():
    # type: () -> None
    """Test explicitly passing None as options"""
    keypair = key_generate()
    vc = {"type": "VerifiableCredential"}
    signed = sign_vc(vc, keypair, None)
    assert "proof" in signed
    assert signed["proof"]["type"] == "DataIntegrityProof"


def test_sign_vc_minimal_options():
    # type: () -> None
    """Test signing with minimal custom options"""
    keypair = key_generate()
    vc = {"type": "VerifiableCredential"}
    options = {"type": "MinimalProof"}
    signed = sign_vc(vc, keypair, options)
    assert signed["proof"]["type"] == "MinimalProof"
    assert "proofValue" in signed["proof"]
