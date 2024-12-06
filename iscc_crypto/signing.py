import base58
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
    # Sign the payload using cached private key
    signature = keypair.sk_obj.sign(payload)

    # Encode signature in multibase format
    return "z" + base58.b58encode(signature).decode("utf-8")
