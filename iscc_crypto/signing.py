import base58
from cryptography.hazmat.primitives.asymmetric import ed25519
from iscc_crypto.keys import KeyPair


__all__ = [
    "sign_data",
]


def sign_data(payload, keypair):
    # type: (bytes, KeyPair) -> str
    """
    Sign a bytes payload conformant with eddsa-jcs-2022 cryptosuite.

    :param payload: Bytes to sign
    :param keypair: KeyPair containing the signing key
    :return: Multibase encoded signature (z-base58-btc)
    """
    # Decode secret key from multibase
    secret_bytes = base58.b58decode(keypair.secret_key[1:])

    # Create private key from bytes (skip multikey prefix)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_bytes[2:])

    # Sign the payload
    signature = private_key.sign(payload)

    # Encode signature in multibase format
    return "z" + base58.b58encode(signature).decode("utf-8")
