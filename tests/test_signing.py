import pytest
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

EXPECTED_SIGNATURE_PAYLOAD = bytes.fromhex(
    "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da859b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
)

EXPECTED_SIGNATURE = (
    "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
)

TEST_TIME = "2023-02-24T23:36:38Z"


def test_sign_raw():
    """Test vectors from https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022"""
    payload = bytes.fromhex(
        "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da859b7cb6251b8991add1"
        "ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
    )
    assert icr.sign_raw(payload, TEST_KEY) == EXPECTED_SIGNATURE


def test_sign_vc():
    signed_credential = icr.sign_vc(TEST_CREDENTIAL, TEST_KEY, TEST_PROOF_OPTIONS)
    assert signed_credential == EXPECTED_SIGNED_CREDENTIAL


def test_input_not_modified():
    # Test original input dict not modified
    original = {"foo": "bar"}
    signed = icr.sign_vc(original, TEST_KEY)
    assert "proof" in signed
    assert "proof" not in original
    assert original == {"foo": "bar"}


def test_create_signature_payload():
    """Test signature payload creation matches spec vector"""
    payload = icr.create_signature_payload(TEST_CREDENTIAL, TEST_PROOF_OPTIONS)
    assert payload == EXPECTED_SIGNATURE_PAYLOAD


def test_sign_json():
    """Test basic json signing functionality"""
    # Test basic signing
    obj = {"message": "hello"}
    signed = icr.sign_json(obj, TEST_KEY)
    assert "declarer" in signed
    assert "signature" in signed
    assert signed["message"] == "hello"
    assert signed["declarer"] == TEST_KEY.public_key

    # Test input validation
    with pytest.raises(ValueError):
        icr.sign_json({"declarer": "exists"}, TEST_KEY)
    with pytest.raises(ValueError):
        icr.sign_json({"signature": "exists"}, TEST_KEY)

    # Test deep copy with nested structure
    nested = {"data": {"nested": [1, 2, 3]}}
    signed = icr.sign_json(nested, TEST_KEY)
    signed["data"]["nested"][0] = 99
    assert nested["data"]["nested"][0] == 1  # Original unchanged

    # Test original input remains unchanged
    original = {"foo": "bar"}
    signed = icr.sign_json(original, TEST_KEY)
    assert original == {"foo": "bar"}
