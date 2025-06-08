import pytest
from iscc_crypto.signing import sign_json
from iscc_crypto.keys import key_generate


def test_sign_json_basic():
    # type: () -> None
    """Test basic JSON signing functionality"""
    keypair = key_generate()
    data = {"test": "value"}
    signed = sign_json(data, keypair)
    assert "signature" in signed
    assert signed["signature"]["pubkey"] == keypair.public_key
    assert signed["signature"]["proof"].startswith("z")
    assert signed["test"] == "value"


def test_sign_json_nested():
    # type: () -> None
    """Test signing nested JSON structures"""
    keypair = key_generate()
    data = {"a": 1, "b": {"c": [1, 2, 3], "d": {"e": None}}}
    signed = sign_json(data, keypair)
    assert signed["b"]["c"] == [1, 2, 3]
    assert signed["b"]["d"]["e"] is None
    assert "signature" in signed


def test_sign_json_empty():
    # type: () -> None
    """Test signing empty JSON object"""
    keypair = key_generate()
    data = {}
    signed = sign_json(data, keypair)
    assert len(signed) == 1
    assert "signature" in signed


def test_sign_json_special_chars():
    # type: () -> None
    """Test signing JSON with special characters"""
    keypair = key_generate()
    data = {"unicode": "üñîçødé", "symbols": "!@#$%^&*()", "whitespace": "\t\n\r"}
    signed = sign_json(data, keypair)
    assert signed["unicode"] == "üñîçødé"
    assert signed["symbols"] == "!@#$%^&*()"
    assert signed["whitespace"] == "\t\n\r"


def test_sign_json_existing_fields():
    # type: () -> None
    """Test that signing fails if reserved fields exist"""
    keypair = key_generate()
    with pytest.raises(ValueError, match="Input must not contain a 'signature' field"):
        sign_json({"signature": "test"}, keypair)


def test_sign_json_immutable():
    # type: () -> None
    """Test that original data is not modified"""
    keypair = key_generate()
    original = {"test": "value"}
    original_copy = original.copy()
    signed = sign_json(original, keypair)
    assert original == original_copy
    assert signed != original


def test_sign_json_deterministic():
    # type: () -> None
    """Test that signing is deterministic for same input and key"""
    keypair = key_generate()
    data = {"test": "value"}
    sig1 = sign_json(data, keypair)["signature"]
    sig2 = sign_json(data, keypair)["signature"]
    assert sig1 == sig2


def test_sign_json_with_controller():
    # type: () -> None
    """Test signing with keypair that has a controller"""
    from iscc_crypto.keys import KeyPair

    keypair = key_generate()
    keypair_with_controller = KeyPair(
        public_key=keypair.public_key,
        secret_key=keypair.secret_key,
        controller="did:example:123456789abcdefghi",
        key_id=keypair.key_id,
    )
    data = {"test": "value"}
    signed = sign_json(data, keypair_with_controller)
    assert "signature" in signed
    assert signed["signature"]["controller"] == "did:example:123456789abcdefghi"
    assert signed["signature"]["pubkey"] == keypair.public_key
    assert signed["signature"]["proof"].startswith("z")
