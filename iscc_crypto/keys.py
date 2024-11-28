"""Key Management"""

from time import time
from urllib.parse import urlparse
from jwcrypto import jwk
import keyring


def create_keypair(kid="default", issuer=None):
    # type: (str, str|None) -> dict
    """
    Create a new Ed25519 key pair for signing JSON data.

    Warning:
        The returned data includes sensitive key material. Handle with care!

    If an issuer URL is given, signature verification will check against
    <issuer>/.well-known/jwks.json as specified in docs/iscc-keys-format.md

    :param str kid: Key ID used for key storage and retrieval (must be unique within `issuer`)
    :param str issuer: HTTPS URL of the key issuing authority
    :return: Key object containing the Ed25519 key pair and metadata
    :raises ValueError: If name is empty or issuer URL is invalid
    """
    if not kid:
        raise ValueError("Key ID cannot be empty")

    if issuer:
        parsed = urlparse(issuer)
        if not all([parsed.scheme == "https", parsed.netloc]):
            raise ValueError("Authority must be a valid HTTPS URL")

    # Generate Ed25519 key pair
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519", kid=kid, use="sig")

    # Export as dict and add metadata
    key_data = key.export(private_key=True, as_dict=True)

    key_data["nbf"] = int(time())
    if issuer:
        key_data["iss"] = issuer

    return key_data


def store_keypair(keypair):
    # type: (dict) -> str
    """
    Store the key to the operating system keyring.

    The key is stored securely using the system's default keyring backend.

    :param dict keypair: Key object containing Ed25519 keypair and metadata
    :return: Name under which the key was stored
    :raises keyring.errors.KeyringError: If saving to keyring fails
    """


if __name__ == "__main__":
    from rich import print

    print(create_keypair("iscc", "https://iscc.ai/actor/random-house"))


# IGNORE THIS OUTCOMMENTED CODE:
# def get_key(name: Optional[str] = None) -> jwk.JWK:
#     """
#     Returns the key stored under `name`. If `name` is blank returns the default key.
#     If no key exists for `name` a new EC secp256k1 key is generated, stored and
#     returned.
#     """
#     name = name or "iscc"
#     user = getpass.getuser()
#     kr = keyring.get_keyring()
#     keydata = kr.get_password(service=name, username=user)
#     if keydata:
#         key = jwk.JWK(**json_decode(keydata))
#     else:
#         key = generate_key()
#         keydata = key.export(private_key=True, as_dict=False)
#         kr.set_password(service=name, username=user, password=keydata)
#     return key
#
#
# def generate_key():
#     """
#     Generate a new EC secp256k1 key
#     """
#     key = jwk.JWK.generate(kty="EC", crv="secp256k1")
#     log.info(f"Generated new key: {key.export(private_key=False)}")
#     return key
#
#
# if __name__ == "__main__":
#     k = get_key()
#     print("KEY:")
#     print(k)
#     print("PUBKEY DICT")
#     print(k.export_public(as_dict=True))
#     print("PUBKEY PEM")
#     print(k.export_to_pem(private_key=False, password=None))
#     print("PRIVATE KEY")
#     print(k.export_private())
