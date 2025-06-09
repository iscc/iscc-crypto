import pytest
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from iscc_crypto import *


def test_create_keypair_basic():
    # type: () -> None
    """Test basic keypair creation without optional parameters."""
    kp = key_generate()
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
    kp = key_generate(controller=controller, key_id=key_id)
    assert kp.controller == controller
    assert kp.key_id == key_id


def test_key_lengths():
    # type: () -> None
    """Test that generated keys have correct lengths."""
    kp = key_generate()
    # Public key should be Ed25519 (32 bytes) + prefix (2 bytes)
    pub_decoded = base58.b58decode(kp.public_key[1:])
    assert len(pub_decoded) == 34  # 32 + 2
    # Secret key should be Ed25519 (32 bytes) + prefix (2 bytes)
    sec_decoded = base58.b58decode(kp.secret_key[1:])
    assert len(sec_decoded) == 34  # 32 + 2


def test_unique_keys():
    # type: () -> None
    """Test that each keypair generation creates unique keys."""
    kp1 = key_generate()
    kp2 = key_generate()
    assert kp1.public_key != kp2.public_key
    assert kp1.secret_key != kp2.secret_key


def test_from_secret():
    # type: () -> None
    """Test creating a KeyPair from an existing secret key."""
    # First create a keypair to get a valid secret key
    original = key_generate()
    # Create new keypair from secret key
    restored = key_from_secret(original.secret_key)
    # Public key should match
    assert restored.public_key == original.public_key
    assert restored.secret_key == original.secret_key
    assert restored.controller is None
    assert restored.key_id is None


def test_from_secret_with_metadata():
    # type: () -> None
    """Test from_secret with controller and key_id."""
    original = key_generate()
    controller = "did:web:example.com"
    key_id = "key-1"
    restored = key_from_secret(original.secret_key, controller=controller, key_id=key_id)
    assert restored.public_key == original.public_key
    assert restored.controller == controller
    assert restored.key_id == key_id


def test_from_env(monkeypatch):
    # type: (object) -> None
    """Test loading KeyPair from environment variables."""
    # Create a keypair to get valid test data
    kp = key_generate()

    # Test with all environment variables
    monkeypatch.setenv("ISCC_CRYPTO_SECRET_KEY", kp.secret_key)
    monkeypatch.setenv("ISCC_CRYPTO_CONTROLLER", "did:web:test.com")
    monkeypatch.setenv("ISCC_CRYPTO_KEY_ID", "key-test")

    loaded = key_from_env()
    assert loaded.public_key == kp.public_key
    assert loaded.secret_key == kp.secret_key
    assert loaded.controller == "did:web:test.com"
    assert loaded.key_id == "key-test"

    # Test with only required secret key
    monkeypatch.delenv("ISCC_CRYPTO_CONTROLLER")
    monkeypatch.delenv("ISCC_CRYPTO_KEY_ID")

    loaded = key_from_env()
    assert loaded.public_key == kp.public_key
    assert loaded.secret_key == kp.secret_key
    assert loaded.controller is None
    assert loaded.key_id is None


def test_from_env_missing_key(monkeypatch):
    # type: (object) -> None
    """Test error handling for missing environment variables and platform directory."""

    # Clear relevant environment variables
    monkeypatch.delenv("ISCC_CRYPTO_SECRET_KEY", raising=False)

    # Mock platformdirs to return a non-existent directory
    import platformdirs

    monkeypatch.setattr(platformdirs, "user_data_dir", lambda x: "/tmp/nonexistent")

    with pytest.raises(ValueError, match="No keypair found"):
        key_from_env()


def test_key_from_platform_missing(monkeypatch):
    # type: (object) -> None
    """Test error handling for missing platform directory."""
    import platformdirs

    monkeypatch.setattr(platformdirs, "user_data_dir", lambda x: "/tmp/nonexistent")

    with pytest.raises(ValueError, match="No keypair found"):
        key_from_platform()


def test_key_from_platform_success(tmp_path, monkeypatch):
    # type: (object, object) -> None
    """Test successful loading from platform directory."""
    import platformdirs
    import json

    # Create test keypair data
    test_dir = tmp_path / "iscc-crypto"
    test_dir.mkdir()
    keypair_file = test_dir / "keypair.json"

    keypair_data = {
        "public_key": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
        "secret_key": "z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA",
        "controller": "did:web:example.com",
        "key_id": "did:web:example.com#key-1",
    }

    with open(keypair_file, "w") as f:
        json.dump(keypair_data, f)

    # Mock platformdirs to return our test directory (which contains iscc-crypto subfolder)
    monkeypatch.setattr(platformdirs, "user_data_dir", lambda x: str(test_dir))

    # Test loading
    loaded = key_from_platform()
    assert loaded.public_key == keypair_data["public_key"]
    assert loaded.secret_key == keypair_data["secret_key"]
    assert loaded.controller == keypair_data["controller"]
    assert loaded.key_id == keypair_data["key_id"]


def test_key_from_platform_invalid_json(tmp_path, monkeypatch):
    # type: (object, object) -> None
    """Test error handling for invalid JSON in platform directory."""
    import platformdirs

    # Create test directory with invalid JSON
    test_dir = tmp_path / "iscc-crypto"
    test_dir.mkdir()
    keypair_file = test_dir / "keypair.json"

    with open(keypair_file, "w") as f:
        f.write("invalid json")

    # Mock platformdirs to return our test directory
    monkeypatch.setattr(platformdirs, "user_data_dir", lambda x: str(test_dir))

    with pytest.raises(ValueError, match="Invalid keypair file"):
        key_from_platform()


def test_from_secret_invalid():
    # type: () -> None
    """Test error handling for invalid secret keys."""

    # Test invalid multibase prefix
    with pytest.raises(ValueError, match="must start with 'z'"):
        key_from_secret("invalid")

    # Test invalid base58 encoding
    with pytest.raises(ValueError, match="Invalid base58"):
        key_from_secret("z!!!!")

    # Test invalid key prefix
    invalid_bytes = b"wrong" + b"\x00" * 32
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid secret key prefix"):
        key_from_secret(invalid_key)

    # Test invalid key length
    invalid_bytes = PREFIX_SECRET_KEY + b"\x00" * 16  # Too short
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid secret key"):
        key_from_secret(invalid_key)


def test_spec_vector(seckey_multibase, pubkey_multibase):
    """Test against test vectors https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022"""
    assert key_from_secret(seckey_multibase).public_key == pubkey_multibase


def test_pk_obj():
    """Test public key object creation and caching."""
    kp = key_generate()
    # Test that pk_obj returns an Ed25519PublicKey instance
    assert isinstance(kp.pk_obj, Ed25519PublicKey)
    # Test caching by verifying we get the same object back
    assert kp.pk_obj is kp.pk_obj
    # Verify the public key object matches the encoded public key
    public_bytes = base58.b58decode(kp.public_key[1:])[2:]  # Skip multikey prefix
    assert (
        kp.pk_obj.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        == public_bytes
    )


def test_encode_secret_key():
    # type: () -> None
    """Test encoding of Ed25519 private key to multikey format."""
    # Create a keypair to get a valid private key
    kp = key_generate()
    # Get the raw private key object
    sk_obj = kp.sk_obj
    # Encode it using our function
    encoded = seckey_encode(sk_obj)
    # Verify the encoding matches the original
    assert encoded == kp.secret_key
    # Verify it starts with multibase prefix
    assert encoded.startswith("z")
    # Decode and verify the key prefix
    decoded = base58.b58decode(encoded[1:])
    assert decoded.startswith(PREFIX_SECRET_KEY)
    # Verify the key length (32 bytes + 2 prefix bytes)
    assert len(decoded) == 34


def test_pubkey_decode():
    # type: () -> None
    """Test decoding of public key from multikey format."""
    # Create a keypair to get a valid public key
    kp = key_generate()
    # Decode the public key
    pk = pubkey_decode(kp.public_key)
    # Verify we get back an Ed25519PublicKey
    assert isinstance(pk, Ed25519PublicKey)
    # Verify the decoded key matches the original
    assert pubkey_encode(pk) == kp.public_key

    # Test error cases
    # Test missing z prefix
    with pytest.raises(ValueError, match="Invalid key format"):
        pubkey_decode("invalid")

    # Test invalid base58 encoding
    with pytest.raises(ValueError, match="Invalid character '!'"):
        pubkey_decode("z!!!!")

    # Test invalid key prefix
    invalid_bytes = b"wrong" + b"\x00" * 32
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid public key prefix"):
        pubkey_decode(invalid_key)

    # Test invalid key length
    invalid_bytes = PREFIX_PUBLIC_KEY + b"\x00" * 16  # Too short
    invalid_key = "z" + base58.b58encode(invalid_bytes).decode()
    with pytest.raises(ValueError, match="Invalid public key bytes: An Ed25519 public key is 32 bytes long"):
        pubkey_decode(invalid_key)


def test_pubkey_from_doc():
    # type: () -> None
    """Test extracting public key from document with DataIntegrityProof."""
    # Create a test document with a valid proof
    kp = key_generate()
    doc = {
        "proof": {
            "type": "DataIntegrityProof",
            "verificationMethod": f"did:key:{kp.public_key}#{kp.public_key}",
        }
    }
    # Extract and verify the public key
    pk = pubkey_from_proof(doc)
    assert isinstance(pk, Ed25519PublicKey)
    assert pubkey_encode(pk) == kp.public_key


def test_pubkey_from_doc_invalid():
    # type: () -> None
    """Test error handling for invalid documents."""
    # Test invalid document type
    with pytest.raises(ValueError, match="must be a dictionary"):
        pubkey_from_proof("not a dict")

    # Test missing proof
    with pytest.raises(ValueError, match="must be a dictionary"):
        pubkey_from_proof({"no": "proof"})

    # Test invalid proof type
    with pytest.raises(ValueError, match="type must be DataIntegrityProof"):
        pubkey_from_proof({"proof": {"type": "WrongType"}})

    # Test missing verificationMethod
    with pytest.raises(ValueError, match="must be a string"):
        pubkey_from_proof({"proof": {"type": "DataIntegrityProof"}})

    # Test invalid verificationMethod format
    with pytest.raises(ValueError, match="must start with did:key:"):
        pubkey_from_proof({"proof": {"type": "DataIntegrityProof", "verificationMethod": "wrong:format"}})

    # Test invalid public key format
    with pytest.raises(ValueError, match="must start with z"):
        pubkey_from_proof(
            {
                "proof": {
                    "type": "DataIntegrityProof",
                    "verificationMethod": "did:key:wrongformat",
                }
            }
        )

    # Test invalid base58 encoding
    with pytest.raises(ValueError, match="Invalid base58 encoding"):
        pubkey_from_proof(
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
        pubkey_from_proof(
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
        pubkey_from_proof(
            {
                "proof": {
                    "type": "DataIntegrityProof",
                    "verificationMethod": f"did:key:{invalid_key}",
                }
            }
        )


def test_keypair_pubkey_multikey():
    # type: () -> None
    """Test KeyPair.pubkey_multikey property."""
    # Test with all required fields
    kp = key_generate(controller="did:web:example.com", key_id="key-0")
    multikey = kp.pubkey_multikey
    assert multikey["id"] == "did:web:example.com#key-0"
    assert multikey["type"] == "Multikey"
    assert multikey["controller"] == "did:web:example.com"
    assert multikey["publicKeyMultibase"] == kp.public_key

    # Test error when missing required fields
    kp_incomplete = key_generate()
    with pytest.raises(ValueError, match="MultiKey requires Controller and key ID"):
        _ = kp_incomplete.pubkey_multikey


def test_keypair_controller_document():
    # type: () -> None
    """Test KeyPair.controller_document property."""
    # Test with all required fields
    kp = key_generate(controller="did:web:example.com", key_id="key-0")
    doc = kp.controller_document

    # Verify document structure
    assert doc["@context"] == "https://www.w3.org/ns/controller/v1"
    assert doc["id"] == "did:web:example.com"
    assert isinstance(doc["assertionMethod"], list)
    assert len(doc["assertionMethod"]) == 1

    # Verify assertionMethod contains the multikey
    multikey = doc["assertionMethod"][0]
    assert multikey["id"] == "did:web:example.com#key-0"
    assert multikey["type"] == "Multikey"
    assert multikey["controller"] == "did:web:example.com"
    assert multikey["publicKeyMultibase"] == kp.public_key


def test_encode_public_key():
    # type: () -> None
    """Test encoding of Ed25519 public key to multikey format."""
    # Create a keypair to get a valid public key
    kp = key_generate()
    # Get the raw public key object
    pk_obj = kp.pk_obj
    # Encode it using our function
    encoded = pubkey_encode(pk_obj)
    # Verify the encoding matches the original
    assert encoded == kp.public_key
    # Verify it starts with multibase prefix
    assert encoded.startswith("z")
    # Decode and verify the key prefix
    decoded = base58.b58decode(encoded[1:])
    assert decoded.startswith(PREFIX_PUBLIC_KEY)
    # Verify the key length (32 bytes + 2 prefix bytes)
    assert len(decoded) == 34
