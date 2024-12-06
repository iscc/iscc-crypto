import base58
from iscc_crypto.keys import create_keypair, PREFIX_PUBLIC_KEY, PREFIX_SECRET_KEY


def test_create_keypair_basic():
    # type: () -> None
    """Test basic keypair creation without optional parameters."""
    kp = create_keypair()
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
    kp = create_keypair(controller=controller, key_id=key_id)
    assert kp.controller == controller
    assert kp.key_id == key_id


def test_key_lengths():
    # type: () -> None
    """Test that generated keys have correct lengths."""
    kp = create_keypair()
    # Public key should be Ed25519 (32 bytes) + prefix (2 bytes)
    pub_decoded = base58.b58decode(kp.public_key[1:])
    assert len(pub_decoded) == 34  # 32 + 2
    # Secret key should be Ed25519 (32 bytes) + prefix (2 bytes)
    sec_decoded = base58.b58decode(kp.secret_key[1:])
    assert len(sec_decoded) == 34  # 32 + 2


def test_unique_keys():
    # type: () -> None
    """Test that each keypair generation creates unique keys."""
    kp1 = create_keypair()
    kp2 = create_keypair()
    assert kp1.public_key != kp2.public_key
    assert kp1.secret_key != kp2.secret_key
