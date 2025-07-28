# -*- coding: utf-8 -*-
import pytest
from iscc_crypto.nonce import create_nonce, decode_node_id


def test_create_nonce_basic():
    # type: () -> None
    """Test basic nonce creation with valid node_id."""
    node_id = 123
    nonce = create_nonce(node_id)

    # Check nonce format
    assert isinstance(nonce, str)
    assert len(nonce) == 32  # 128 bits = 16 bytes = 32 hex chars

    # Verify it's valid hex
    int(nonce, 16)  # Should not raise

    # Check that node_id is embedded correctly
    decoded_id = decode_node_id(nonce)
    assert decoded_id == node_id


def test_create_nonce_boundary_values():
    # type: () -> None
    """Test nonce creation with boundary node_id values."""
    # Minimum valid node_id
    nonce_min = create_nonce(0)
    assert decode_node_id(nonce_min) == 0

    # Maximum valid node_id
    nonce_max = create_nonce(4095)
    assert decode_node_id(nonce_max) == 4095


def test_create_nonce_invalid_node_id():
    # type: () -> None
    """Test nonce creation with invalid node_id values."""
    # Below minimum
    with pytest.raises(ValueError, match="Node ID must be between 0 and 4095, got -1"):
        create_nonce(-1)

    # Above maximum
    with pytest.raises(ValueError, match="Node ID must be between 0 and 4095, got 4096"):
        create_nonce(4096)

    # Way above maximum
    with pytest.raises(ValueError, match="Node ID must be between 0 and 4095, got 10000"):
        create_nonce(10000)


def test_create_nonce_randomness():
    # type: () -> None
    """Test that nonces are random (different for same node_id)."""
    node_id = 42
    nonces = [create_nonce(node_id) for _ in range(10)]

    # All should have same node_id
    for nonce in nonces:
        assert decode_node_id(nonce) == node_id

    # But nonces should be unique due to randomness
    assert len(set(nonces)) == 10


def test_decode_node_id_valid():
    # type: () -> None
    """Test decoding node_id from valid nonces."""
    # Create nonces with known node_ids and verify decoding
    test_ids = [0, 1, 42, 255, 1000, 2047, 4095]

    for node_id in test_ids:
        nonce = create_nonce(node_id)
        decoded = decode_node_id(nonce)
        assert decoded == node_id


def test_decode_node_id_invalid_type():
    # type: () -> None
    """Test decode_node_id with invalid input types."""
    with pytest.raises(TypeError, match="Nonce must be a string"):
        decode_node_id(123)

    with pytest.raises(TypeError, match="Nonce must be a string"):
        decode_node_id(None)

    with pytest.raises(TypeError, match="Nonce must be a string"):
        decode_node_id(b"abc")


def test_decode_node_id_invalid_length():
    # type: () -> None
    """Test decode_node_id with invalid nonce lengths."""
    # Too short
    with pytest.raises(ValueError, match="Nonce must be 32 characters long, got 31"):
        decode_node_id("a" * 31)

    # Too long
    with pytest.raises(ValueError, match="Nonce must be 32 characters long, got 33"):
        decode_node_id("a" * 33)

    # Empty
    with pytest.raises(ValueError, match="Nonce must be 32 characters long, got 0"):
        decode_node_id("")


def test_decode_node_id_invalid_hex():
    # type: () -> None
    """Test decode_node_id with invalid hex strings."""
    # Non-hex characters
    with pytest.raises(ValueError, match="Nonce must be a valid hex string"):
        decode_node_id("g" * 32)  # 'g' is not a valid hex char

    with pytest.raises(ValueError, match="Nonce must be a valid hex string"):
        decode_node_id("0123456789abcdefGHIJKLMNOPQRSTUV")  # Mixed case invalid


def test_nonce_node_id_preservation():
    # type: () -> None
    """Test that the lower 116 bits are properly randomized."""
    # Create multiple nonces with same node_id
    node_id = 1234
    nonces = []

    for _ in range(5):
        nonce = create_nonce(node_id)
        nonces.append(nonce)

        # Verify node_id is preserved
        assert decode_node_id(nonce) == node_id

    # Extract the lower parts (excluding node_id bits) and verify they differ
    lower_parts = []
    for nonce in nonces:
        # Convert to int and mask out the node_id bits
        nonce_int = int(nonce, 16)
        lower_part = nonce_int & ((1 << 116) - 1)
        lower_parts.append(lower_part)

    # All lower parts should be different (statistically)
    assert len(set(lower_parts)) == len(lower_parts)


def test_nonce_bits_distribution():
    # type: () -> None
    """Test that node_id occupies exactly the first 12 bits."""
    # Test various node_ids to ensure proper bit positioning
    test_cases = [
        (0x000, "000"),  # All zeros
        (0xFFF, "fff"),  # All ones (4095)
        (0x123, "123"),  # Mixed
        (0xABC, "abc"),  # Mixed hex
    ]

    for node_id, expected_prefix in test_cases:
        nonce = create_nonce(node_id)
        # The first 3 hex chars represent 12 bits
        assert nonce[:3] == expected_prefix
        assert decode_node_id(nonce) == node_id
