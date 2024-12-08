import base58
import pytest
from iscc_crypto.keys import key_generate
from iscc_crypto.signing import sign_raw
from iscc_crypto.verifying import verify_raw, verify_vc, verify_json, VerificationError


def test_valid_signature():
    """Test verification of a valid signature"""
    kp = key_generate()
    payload = b"test data"
    sig = sign_raw(payload, kp)
    assert verify_raw(payload, sig, kp.pk_obj) is True


def test_invalid_signature():
    """Test rejection of an invalid signature"""
    kp = key_generate()
    payload = b"test data"
    sig = sign_raw(payload, kp)
    wrong_payload = b"wrong data"
    assert verify_raw(wrong_payload, sig, kp.pk_obj) is False


def test_wrong_public_key():
    """Test rejection when using wrong public key"""
    kp1 = key_generate()
    kp2 = key_generate()
    payload = b"test data"
    sig = sign_raw(payload, kp1)
    assert verify_raw(payload, sig, kp2.pk_obj) is False


def test_malformed_signature():
    """Test handling of malformed signatures"""
    kp = key_generate()
    payload = b"test data"

    # Missing z-prefix
    sig = sign_raw(payload, kp)[1:]
    assert verify_raw(payload, sig, kp.pk_obj) is False

    # Invalid base58
    assert verify_raw(payload, "z!!!invalid!!!", kp.pk_obj) is False


def test_empty_inputs():
    """Test handling of empty inputs"""
    kp = key_generate()
    assert verify_raw(b"", "", kp.pk_obj) is False
    assert verify_raw(b"data", "", kp.pk_obj) is False
    assert verify_raw(b"", "z123", kp.pk_obj) is False


def test_verify_json_valid():
    """Test verification of a valid JSON document with proof"""
    kp = key_generate()

    # Create a document with valid proof
    document = {
        "content": "test data",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2023-01-01T00:00:00Z",
            "verificationMethod": "key-1",
            "proofValue": "z123",  # Will be replaced with real signature
        },
    }

    # Create copy without proof for verification
    doc_without_proof = document.copy()
    del doc_without_proof["proof"]

    # Create proof options without proofValue
    proof_options = document["proof"].copy()
    del proof_options["proofValue"]

    # Create signature
    import jcs
    from hashlib import sha256

    doc_digest = sha256(jcs.canonicalize(doc_without_proof)).digest()
    options_digest = sha256(jcs.canonicalize(proof_options)).digest()
    verification_payload = options_digest + doc_digest

    from iscc_crypto.signing import sign_raw

    signature = sign_raw(verification_payload, kp)
    document["proof"]["proofValue"] = signature

    # Verify
    verified, extracted_doc = verify_vc(document, kp.pk_obj)
    assert verified is True
    assert extracted_doc == doc_without_proof


def test_verify_json_invalid_inputs():
    """Test verification with invalid inputs"""
    kp = key_generate()

    # Test non-dict input
    assert verify_vc("not a dict", kp.pk_obj) == (False, None)
    assert verify_vc(None, kp.pk_obj) == (False, None)

    # Test missing proof
    doc_no_proof = {"content": "test"}
    assert verify_vc(doc_no_proof, kp.pk_obj) == (False, None)

    # Test invalid proof type
    doc_invalid_proof = {"content": "test", "proof": "not a dict"}
    assert verify_vc(doc_invalid_proof, kp.pk_obj) == (False, None)


def test_verify_json_invalid_proof_properties():
    """Test verification with invalid proof properties"""
    kp = key_generate()

    # Base document
    doc = {
        "content": "test",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofValue": "z123",
        },
    }

    # Test wrong type
    wrong_type = doc.copy()
    wrong_type["proof"]["type"] = "WrongType"
    assert verify_vc(wrong_type, kp.pk_obj) == (False, None)

    # Test wrong cryptosuite
    wrong_suite = doc.copy()
    wrong_suite["proof"]["cryptosuite"] = "wrong-suite"
    assert verify_vc(wrong_suite, kp.pk_obj) == (False, None)

    # Test missing proofValue
    no_proof_value = doc.copy()
    del no_proof_value["proof"]["proofValue"]
    assert verify_vc(no_proof_value, kp.pk_obj) == (False, None)

    # Test invalid proofValue prefix
    wrong_prefix = doc.copy()
    wrong_prefix["proof"]["proofValue"] = "x123"  # Should start with 'z'
    assert verify_vc(wrong_prefix, kp.pk_obj) == (False, None)


def test_verify_json_tampered_document():
    """Test verification of a tampered document"""
    kp = key_generate()

    # Create original document with valid proof
    original = {
        "content": "original",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofValue": "z123",
        },
    }

    # Create valid signature
    doc_without_proof = original.copy()
    del doc_without_proof["proof"]
    proof_options = original["proof"].copy()
    del proof_options["proofValue"]

    import jcs
    from hashlib import sha256

    doc_digest = sha256(jcs.canonicalize(doc_without_proof)).digest()
    options_digest = sha256(jcs.canonicalize(proof_options)).digest()
    verification_payload = options_digest + doc_digest

    from iscc_crypto.signing import sign_raw

    signature = sign_raw(verification_payload, kp)
    original["proof"]["proofValue"] = signature

    # Verify original
    assert verify_vc(original, kp.pk_obj)[0] is True

    # Tamper with content
    tampered = original.copy()
    tampered["content"] = "tampered"
    assert verify_vc(tampered, kp.pk_obj)[0] is False


def test_verify_json():
    """Test verification of JSON documents with signatures"""
    from iscc_crypto.signing import sign_json

    # Generate test key pair
    kp = key_generate()

    # Test successful verification
    original = {"message": "test data"}
    signed = sign_json(original, kp)
    verified = verify_json(signed)
    assert verified == original

    # Test missing signature field
    doc_no_sig = {"message": "test", "declarer": signed["declarer"]}
    with pytest.raises(VerificationError, match="Missing required field: signature"):
        verify_json(doc_no_sig)

    # Test missing declarer field
    doc_no_declarer = {"message": "test", "signature": signed["signature"]}
    with pytest.raises(VerificationError, match="Missing required field: declarer"):
        verify_json(doc_no_declarer)

    # Test invalid signature format
    doc_bad_sig = signed.copy()
    doc_bad_sig["signature"] = "not-z-prefixed"
    with pytest.raises(VerificationError, match="Invalid signature format"):
        verify_json(doc_bad_sig)

    # Test invalid declarer format
    doc_bad_declarer = signed.copy()
    doc_bad_declarer["declarer"] = "invalid-key"
    with pytest.raises(VerificationError, match="Invalid declarer format"):
        verify_json(doc_bad_declarer)

    # Test invalid public key prefix
    doc_bad_prefix = signed.copy()
    # Create a z-base58 string without ED01 prefix
    doc_bad_prefix["declarer"] = "z" + base58.b58encode(b"wrong prefix" + b"\x00" * 20).decode()
    with pytest.raises(VerificationError, match="Invalid declarer format"):
        verify_json(doc_bad_prefix)

    # Test tampered content
    tampered = signed.copy()
    tampered["message"] = "modified"
    with pytest.raises(VerificationError, match="Invalid signature"):
        verify_json(tampered)
