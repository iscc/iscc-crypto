# -*- coding: utf-8 -*-
"""
Cryptographic nonce generation for ISCC notarization protocol.

This module provides secure nonce generation and decoding functionality for the ISCC notarization protocol. The
nonces are 128-bit values with an embedded 12-bit node identifier for routing and replay protection.
"""

import secrets


__all__ = ["create_nonce", "decode_node_id"]


def create_nonce(node_id):
    # type: (int) -> str
    """
    Create random nonce with embedded node identifier.

    Generates a 128-bit nonce value using a cryptographically secure random number generator.
    The first 12 bits of the nonce contain the node_id, while the remaining 116 bits are
    random. This design allows for both uniqueness (via randomness) and routing information
    (via node_id) in a single value.

    The nonce is used in the ISCC notarization protocol to prevent replay attacks and to
    route IsccNote objects to the appropriate notary node for processing.

    :param node_id: Node identifier to embed in the nonce. Must be an integer between 0 and 4095
                    (inclusive), as it needs to fit within 12 bits.
    :return: A 32-character lowercase hexadecimal string representing the 128-bit nonce.
             The first 3 hex characters (12 bits) contain the node_id.
    :raises ValueError: If node_id is not within the valid range of 0-4095.
    """
    if not 0 <= node_id <= 4095:
        raise ValueError(f"Node ID must be between 0 and 4095, got {node_id}")

    # Generate 128 bits (16 bytes) of secure random data
    random_bytes = secrets.token_bytes(16)

    # Convert to integer for bit manipulation
    random_int = int.from_bytes(random_bytes, byteorder="big")

    # Clear the first 12 bits
    random_int &= ~(0xFFF << 116)  # 128 - 12 = 116

    # Embed the node_id in the first 12 bits
    random_int |= node_id << 116

    # Convert back to bytes and then to hex
    nonce_bytes = random_int.to_bytes(16, byteorder="big")
    return nonce_bytes.hex()


def decode_node_id(nonce):
    # type: (str) -> int
    """
    Extract and return the 12-bit node identifier from a nonce string.

    Decodes the node_id that was embedded in the first 12 bits of the nonce during creation.
    This function is the inverse of the node_id embedding performed by create_nonce().

    The node_id is used by the ISCC notarization protocol to determine which notary node
    should process a particular IsccNote object, enabling efficient routing and load
    distribution across multiple notary nodes.

    :param nonce: A 32-character hexadecimal string representing a 128-bit nonce value.
                  Must be exactly 32 characters long and contain only valid hex characters
                  (0-9, a-f, A-F).
    :return: The node identifier (0-4095) extracted from the first 12 bits of the nonce.
    :raises TypeError: If nonce is not a string.
    :raises ValueError: If nonce is not exactly 32 characters long or contains invalid
                       hexadecimal characters.

    Example:
        >>> nonce = "07b4a5c6d7e8f9a0b1c2d3e4f5a6b7c8"
        >>> node_id = decode_node_id(nonce)
        >>> node_id
        123
    """
    # Validate nonce format
    if not isinstance(nonce, str):
        raise TypeError("Nonce must be a string")

    if len(nonce) != 32:
        raise ValueError(f"Nonce must be 32 characters long, got {len(nonce)}")

    try:
        # Convert hex string to bytes
        nonce_bytes = bytes.fromhex(nonce)
    except ValueError:
        raise ValueError("Nonce must be a valid hex string")

    # Convert to integer
    nonce_int = int.from_bytes(nonce_bytes, byteorder="big")

    # Extract the first 12 bits
    node_id = nonce_int >> 116  # 128 - 12 = 116

    return node_id
