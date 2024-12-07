import iscc_crypto as icr

TEST_KEY = icr.KeyPair(
    public_key="z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    secret_key="z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
)

TEST_CREDENTIAL = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2",
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
}

TEST_PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod",
}

EXPECTED_SIGNED_CREDENTIAL = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2",
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2023-02-24T23:36:38Z",
        "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        "proofPurpose": "assertionMethod",
        "proofValue": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn",
    },
}

EXPEXTED_SIGNATURE_PAYLOAD = bytes.fromhex(
    "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da859b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
)

EXPECTED_SIGNATURE = (
    "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
)

TEST_TIME = "2023-02-24T23:36:38Z"


def test_spec_vector_signing():
    """Test vectors from https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022"""
    payload = bytes.fromhex(
        "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da859b7cb6251b8991add1"
        "ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
    )
    assert icr.create_signature(payload, TEST_KEY) == EXPECTED_SIGNATURE


def test_spec_vector_object_signing():
    signed_credential = icr.sign_json(TEST_CREDENTIAL, TEST_KEY, TEST_TIME)
    assert signed_credential == EXPECTED_SIGNED_CREDENTIAL


def test_context_injection():
    # Test string context gets converted to array
    obj = {"@context": "https://example.com/context"}
    signed = icr.sign_json(obj, TEST_KEY)
    assert isinstance(signed["@context"], list)
    assert signed["@context"][0] == "https://example.com/context"
    assert "https://w3id.org/security/data-integrity/v2" in signed["@context"]

    # Test data integrity context not injected when v2 credentials present
    obj = {"@context": ["https://www.w3.org/ns/credentials/v2"]}
    signed = icr.sign_json(obj, TEST_KEY)
    assert len(signed["@context"]) == 1

    # Test data integrity context not duplicated
    obj = {"@context": ["https://w3id.org/security/data-integrity/v2"]}
    signed = icr.sign_json(obj, TEST_KEY)
    assert signed["@context"].count("https://w3id.org/security/data-integrity/v2") == 1


def test_input_not_modified():
    # Test original input dict not modified
    original = {"foo": "bar"}
    signed = icr.sign_json(original, TEST_KEY)
    assert "proof" in signed
    assert "proof" not in original
    assert original == {"foo": "bar"}


def test_created_timestamp():
    # Test custom created time
    signed = icr.sign_json({}, TEST_KEY, created="2024-01-01T00:00:00Z")
    assert signed["proof"]["created"] == "2024-01-01T00:00:00Z"

    # Test auto-generated timestamp format
    signed = icr.sign_json({}, TEST_KEY)
    created = signed["proof"]["created"]
    assert len(created) == 20  # Check ISO format length
    assert created.endswith("Z")  # Check UTC timezone marker


def test_proof_structure():
    signed = icr.sign_json({}, TEST_KEY)
    proof = signed["proof"]

    # Check required proof properties
    assert proof["type"] == "DataIntegrityProof"
    assert proof["cryptosuite"] == "eddsa-jcs-2022"
    assert proof["proofPurpose"] == "assertionMethod"
    assert "created" in proof
    assert "verificationMethod" in proof
    assert "proofValue" in proof

    # Check verification method format
    assert proof["verificationMethod"].startswith("did:key:")
    assert "#" in proof["verificationMethod"]


def test_create_signature_payload():
    # Create payload and verify it matches expected test vector
    payload = icr.create_signature_payload(TEST_CREDENTIAL, TEST_PROOF_OPTIONS)
    assert payload == EXPEXTED_SIGNATURE_PAYLOAD

    # Test with empty document and options
    empty_payload = icr.create_signature_payload({}, {})
    assert len(empty_payload) == 64  # Should still produce 64 bytes
