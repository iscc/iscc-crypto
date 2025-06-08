import pytest


@pytest.fixture
def seckey_multibase():
    """Test Vector EDDSA-JCS-2022 private key"""
    return "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"


@pytest.fixture
def pubkey_multibase():
    """Test Vector EDDSA-JCS-2022 public key"""
    return "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"


@pytest.fixture
def did_key():
    """Test Vector DID-KEY"""
    return "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


@pytest.fixture
def did_key_doc():
    """Test Vector DID Document for DID-KEY"""
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "verificationMethod": [
            {
                "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "type": "Multikey",
                "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            }
        ],
        "authentication": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ],
        "assertionMethod": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ],
        "capabilityDelegation": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ],
        "capabilityInvocation": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ],
    }


@pytest.fixture
def did_web():
    """Test Vector DID-WEB"""
    return "did:web:identity.foundation"


@pytest.fixture
def did_web_doc():
    """Test Vector DID Document for DID-WEB"""
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/v2",
            "https://w3id.org/security/suites/secp256k1recovery-2020/v2",
            "https://w3id.org/security/suites/ed25519-2018/v1",
        ],
        "id": "did:web:identity.foundation",
        "verificationMethod": [
            {
                "id": "did:web:identity.foundation#04d63533b05fd69cd05843d41d5cf35ef1461f08ec8f80ea33bc5750751ca2b6a5fa5c1b7ec78d10cb785cac20bdf91a681ac0a7f47cccdf010b4b2a20f9db1e78",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:web:identity.foundation",
                "publicKeyHex": "04d63533b05fd69cd05843d41d5cf35ef1461f08ec8f80ea33bc5750751ca2b6a5fa5c1b7ec78d10cb785cac20bdf91a681ac0a7f47cccdf010b4b2a20f9db1e78",
            },
            {
                "id": "did:web:identity.foundation#6e6b416461e001f17961bbb0df763ed46cd9dcb64a2f37ade0f85579520de5f9",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:web:identity.foundation",
                "publicKeyBase58": "8S2hqHB2PjNSdDgsULTEqjXx2n3zF32fjGabbDJocGyv",
            },
        ],
        "authentication": [
            "did:web:identity.foundation#04d63533b05fd69cd05843d41d5cf35ef1461f08ec8f80ea33bc5750751ca2b6a5fa5c1b7ec78d10cb785cac20bdf91a681ac0a7f47cccdf010b4b2a20f9db1e78",
            "did:web:identity.foundation#6e6b416461e001f17961bbb0df763ed46cd9dcb64a2f37ade0f85579520de5f9",
        ],
        "assertionMethod": [
            "did:web:identity.foundation#04d63533b05fd69cd05843d41d5cf35ef1461f08ec8f80ea33bc5750751ca2b6a5fa5c1b7ec78d10cb785cac20bdf91a681ac0a7f47cccdf010b4b2a20f9db1e78",
            "did:web:identity.foundation#6e6b416461e001f17961bbb0df763ed46cd9dcb64a2f37ade0f85579520de5f9",
        ],
        "keyAgreement": [
            "did:web:identity.foundation#6e6b416461e001f17961bbb0df763ed46cd9dcb64a2f37ade0f85579520de5f9"
        ],
        "service": [],
    }
