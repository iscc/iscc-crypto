import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


__all__ = [
    "verify_signature",
]


def verify_signature(payload, signature, public_key):
    # type: (bytes, str, Ed25519PublicKey) -> bool
    """
    Verify an EdDSA signature over raw bytes. The signature must be encoded according to
    [RFC8032] with base-58-btc header and alphabet conformant with eddsa-jcs-2022.

    :param payload: Original signed bytes
    :param signature: Multibase encoded signature (z-base58-btc)
    :param public_key: Base58 encoded public key
    :return: True if signature is valid, False otherwise
    """
    try:
        raw_signature = base58.b58decode(signature[1:])
        public_key.verify(raw_signature, payload)
        return True
    except (ValueError, InvalidSignature):
        return False
