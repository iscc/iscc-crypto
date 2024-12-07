import pytest
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from iscc_crypto import *


def test_create_keypair_basic():
    # type: () -> None
    """Test basic keypair creation without optional parameters."""
    kp = keypair_generate()
    assert kp.public_key.startswith("z")
    assert kp.secret_key.startswith("z")
    assert kp.controller is None
    assert kp.key_id is None
    # Decode and verify public key prefix
    pub_decoded = base58.b58decode(kp.public_key[1:])
    assert pub_decoded.startswith(PREFIX_PUBLIC_KEY)
    # Decode and verify secret key prefix
    sec_decoded = base58.b58decode(kp.secret_key[1:])
    assert sec_decoded.startswith(PREFIX_SECRET_KEY)


def test_create_keypair_with_metadata():
    # type: () -> None
    """Test keypair creation with controller and key_id."""
    controller = "did:web:example.com"
    key_id = "key-0"
    kp = keypair_generate(controller=controller, key_id=key_id)
    assert kp.controller == controller
    assert kp.key_id == key_id


def test_key_lengths():
    # type: () -> None
    """Test that generated keys have correct lengths."""
    kp = keypair_generate()
    # Public key should be Ed25519 (32 bytes) + prefix (2 bytes)
    pub_decoded = base58.b58decode(kp.public_key[1:])
    assert len(pub_decoded) == 34  # 32 + 2
    # Secret key should be Ed25519 (32 bytes) + prefix (2 bytes)
    sec_decoded = base58.b58decode(kp.secret_key[1:])
    assert len(sec_decoded) == 34  # 32 + 2


def test_unique_keys():
    # type: () -> None
    """Test that each keypair generation creates unique keys."""
    kp1 = keypair_generate()
    kp2 = keypair_generate()
    assert kp1.public_key != kp2.public_key
    assert kp1.secret_key != kp2.secret_key


def test_from_secret():
    # type: () -> None
    """Test creating a KeyPair from an existing secret key."""
    # First create a keypair to get a valid secret key
    original = keypair_generate()
    # Create new keypair from secret key
    restored = keypair_from_secret(original.secret_key)
    # Public key should match
    assert restored.public_key == original.public_key
    assert restored.secret_key == original.secret_key
    assert restored.controller is None
    assert restored.key_id is None


def test_from_secret_with_metadata():
    # type: () -> None
    """Test from_secret with controller and key_id."""
    original = keypair_generate()
    controller = "did:web:example.com"
    key_id = "key-1"
    restored = keypair_from_secret(original.secret_key, controller=controller, key_id=key_id)
    assert restored.public_key == original.public_key
    assert restored.controller == controller
    assert restored.key_id == key_id


def test_from_env(monkeypatch):
    # type: (object) -> None
    """Test loading KeyPair from environment variables."""
    # Create a keypair to get valid test data
    kp = keypair_generate()

    # Test with all environment variables
    monkeypatch.setenv("ISCC_CRYPTO_SECRET_KEY", kp.secret_key)
    monkeypatch.setenv("ISCC_CRYPTO_CONTROLLER", "did:web:test.com")
    monkeypatch.setenv("ISCC_CRYPTO_KEY_ID", "key-test")

    loaded = keypair_from_env()
    assert loaded.public_key == kp.public_key
    assert loaded.secret_key == kp.secret_key
    assert loaded.controller == "did:web:test.com"
    assert loaded.key_id == "key-test"

    # Test with only required secret key
    monkeypatch.delenv("ISCC_CRYPTO_CONTROLLER")
    monkeypatch.delenv("ISCC_CRYPTO_KEY_ID")

    loaded = keypair_from_env()
    assert loaded.public_key == kp.public_key
    assert loaded.secret_key == kp.secret_key
    assert loaded.controller is None
    assert loaded.key_id is None


def test_from_env_missing_key(monkeypatch):
    # type: (object) -> None
    """Test error handling for missing environment variables."""

    # Clear relevant environment variables
    monkeypatch.delenv("ISCC_CRYPTO_SECRET_KEY", raising=False)

    with pytest.raises(ValueError, match="ISCC_CRYPTO_SECRET_KEY.*required"):
        keypair_from_env()


def test_from_secret_invalid():
    # type: () -> None
    """Test error handling for invalid secret keys."""

    # Test invalid multibase prefix
    with pytest.raises(ValueError, match="must start with 'z'"):
        keypair_from_secret("invalid")

    # Test invalid base58 encoding
    with pytest.raises(ValueError, match="Invalid base58"):
        keypair_from_secret("z!!!!")

    # Test invalid key prefix
    invalid_bytes = b"wrong" + b"\x00" * 32
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid secret key prefix"):
        keypair_from_secret(invalid_key)

    # Test invalid key length
    invalid_bytes = PREFIX_SECRET_KEY + b"\x00" * 16  # Too short
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid secret key"):
        keypair_from_secret(invalid_key)


def test_spec_vector():
    """Test against test vectors https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022"""
    secure_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
    expected_public_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
    assert keypair_from_secret(secure_key).public_key == expected_public_key


def test_pk_obj():
    """Test public key object creation and caching."""
    kp = keypair_generate()
    # Test that pk_obj returns an Ed25519PublicKey instance
    assert isinstance(kp.pk_obj, Ed25519PublicKey)
    # Test caching by verifying we get the same object back
    assert kp.pk_obj is kp.pk_obj
    # Verify the public key object matches the encoded public key
    public_bytes = base58.b58decode(kp.public_key[1:])[2:]  # Skip multikey prefix
    assert (
        kp.pk_obj.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        == public_bytes
    )


def test_encode_secret_key():
    # type: () -> None
    """Test encoding of Ed25519 private key to multikey format."""
    # Create a keypair to get a valid private key
    kp = keypair_generate()
    # Get the raw private key object
    sk_obj = kp.sk_obj
    # Encode it using our function
    encoded = secret_key_encode(sk_obj)
    # Verify the encoding matches the original
    assert encoded == kp.secret_key
    # Verify it starts with multibase prefix
    assert encoded.startswith("z")
    # Decode and verify the key prefix
    decoded = base58.b58decode(encoded[1:])
    assert decoded.startswith(PREFIX_SECRET_KEY)
    # Verify the key length (32 bytes + 2 prefix bytes)
    assert len(decoded) == 34


def test_pubkey_from_doc():
    # type: () -> None
    """Test extracting public key from document with DataIntegrityProof."""
    # Create a test document with a valid proof
    kp = keypair_generate()
    doc = {
        "proof": {
            "type": "DataIntegrityProof",
            "verificationMethod": f"did:key:{kp.public_key}#{kp.public_key}",
        }
    }
    # Extract and verify the public key
    pk = public_key_from_doc(doc)
    assert isinstance(pk, Ed25519PublicKey)
    assert public_key_encode(pk) == kp.public_key


def test_pubkey_from_doc_invalid():
    # type: () -> None
    """Test error handling for invalid documents."""
    # Test invalid document type
    with pytest.raises(ValueError, match="must be a dictionary"):
        public_key_from_doc("not a dict")

    # Test missing proof
    with pytest.raises(ValueError, match="must be a dictionary"):
        public_key_from_doc({"no": "proof"})

    # Test invalid proof type
    with pytest.raises(ValueError, match="type must be DataIntegrityProof"):
        public_key_from_doc({"proof": {"type": "WrongType"}})

    # Test missing verificationMethod
    with pytest.raises(ValueError, match="must be a string"):
        public_key_from_doc({"proof": {"type": "DataIntegrityProof"}})

    # Test invalid verificationMethod format
    with pytest.raises(ValueError, match="must start with did:key:"):
        public_key_from_doc(
            {"proof": {"type": "DataIntegrityProof", "verificationMethod": "wrong:format"}}
        )

    # Test invalid public key format
    with pytest.raises(ValueError, match="must start with z"):
        public_key_from_doc(
            {
                "proof": {
                    "type": "DataIntegrityProof",
                    "verificationMethod": "did:key:wrongformat",
                }
            }
        )

    # Test invalid base58 encoding
    with pytest.raises(ValueError, match="Invalid base58 encoding"):
        public_key_from_doc(
            {
                "proof": {
                    "type": "DataIntegrityProof",
                    "verificationMethod": "did:key:z!!!invalid!!!",
                }
            }
        )

    # Test invalid public key prefix
    invalid_bytes = b"wrong" + b"\x00" * 32
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid public key prefix"):
        public_key_from_doc(
            {
                "proof": {
                    "type": "DataIntegrityProof",
                    "verificationMethod": f"did:key:{invalid_key}",
                }
            }
        )

    # Test invalid public key bytes
    invalid_bytes = PREFIX_PUBLIC_KEY + b"\x00" * 16  # Too short
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid public key bytes"):
        public_key_from_doc(
            {
                "proof": {
                    "type": "DataIntegrityProof",
                    "verificationMethod": f"did:key:{invalid_key}",
                }
            }
        )


def test_encode_public_key():
    # type: () -> None
    """Test encoding of Ed25519 public key to multikey format."""
    # Create a keypair to get a valid public key
    kp = keypair_generate()
    # Get the raw public key object
    pk_obj = kp.pk_obj
    # Encode it using our function
    encoded = public_key_encode(pk_obj)
    # Verify the encoding matches the original
    assert encoded == kp.public_key
    # Verify it starts with multibase prefix
    assert encoded.startswith("z")
    # Decode and verify the key prefix
    decoded = base58.b58decode(encoded[1:])
    assert decoded.startswith(PREFIX_PUBLIC_KEY)
    # Verify the key length (32 bytes + 2 prefix bytes)
    assert len(decoded) == 34
