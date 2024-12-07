from iscc_crypto.keys import create_keypair
from iscc_crypto.signing import create_signature
from iscc_crypto.verifying import verify_signature, verify_json


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


def test_verify_json_valid():
    """Test verification of a valid JSON document with proof"""
    kp = create_keypair()

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

    from iscc_crypto.signing import create_signature

    signature = create_signature(verification_payload, kp)
    document["proof"]["proofValue"] = signature

    # Verify
    verified, extracted_doc = verify_json(document, kp.pk_obj)
    assert verified is True
    assert extracted_doc == doc_without_proof


def test_verify_json_invalid_inputs():
    """Test verification with invalid inputs"""
    kp = create_keypair()

    # Test non-dict input
    assert verify_json("not a dict", kp.pk_obj) == (False, None)
    assert verify_json(None, kp.pk_obj) == (False, None)

    # Test missing proof
    doc_no_proof = {"content": "test"}
    assert verify_json(doc_no_proof, kp.pk_obj) == (False, None)

    # Test invalid proof type
    doc_invalid_proof = {"content": "test", "proof": "not a dict"}
    assert verify_json(doc_invalid_proof, kp.pk_obj) == (False, None)


def test_verify_json_invalid_proof_properties():
    """Test verification with invalid proof properties"""
    kp = create_keypair()

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
    assert verify_json(wrong_type, kp.pk_obj) == (False, None)

    # Test wrong cryptosuite
    wrong_suite = doc.copy()
    wrong_suite["proof"]["cryptosuite"] = "wrong-suite"
    assert verify_json(wrong_suite, kp.pk_obj) == (False, None)

    # Test missing proofValue
    no_proof_value = doc.copy()
    del no_proof_value["proof"]["proofValue"]
    assert verify_json(no_proof_value, kp.pk_obj) == (False, None)

    # Test invalid proofValue prefix
    wrong_prefix = doc.copy()
    wrong_prefix["proof"]["proofValue"] = "x123"  # Should start with 'z'
    assert verify_json(wrong_prefix, kp.pk_obj) == (False, None)


def test_verify_json_tampered_document():
    """Test verification of a tampered document"""
    kp = create_keypair()

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

    from iscc_crypto.signing import create_signature

    signature = create_signature(verification_payload, kp)
    original["proof"]["proofValue"] = signature

    # Verify original
    assert verify_json(original, kp.pk_obj)[0] is True

    # Tamper with content
    tampered = original.copy()
    tampered["content"] = "tampered"
    assert verify_json(tampered, kp.pk_obj)[0] is False
