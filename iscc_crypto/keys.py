"""Key Management"""

from time import time
from urllib.parse import urlparse
from jwcrypto import jwk
import keyring
import json
from loguru import logger as log


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

    log.trace(f"Created key with kid: {kid}")
    return key_data


def store_keypair(keypair, overwrite=False):
    # type: (dict, bool) -> str
    """
    Store the key to the operating system keyring.

    The key is stored using the system's default keyring backend.

    :param dict keypair: Key object containing Ed25519 keypair and metadata
    :param bool overwrite: Allow overwriting existing key with same kid
    :return: Name under which the key was stored
    :raises keyring.errors.KeyringError: If saving to keyring fails
    :raises ValueError: If key exists and overwrite=False
    """

    if "kid" not in keypair:
        raise ValueError("Key ID (kid) missing from keypair")

    kid = keypair["kid"]

    # Check if key already exists
    existing = keyring.get_password(service_name="iscc", username=kid)
    if existing and not overwrite:
        raise ValueError(f"Key with ID '{kid}' already exists and overwrite=False")

    keydata = json.dumps(keypair)
    keyring.set_password(service_name="iscc", username=kid, password=keydata)
    log.trace(f"Stored key with kid: {kid}")
    return kid


def load_keypair(kid="default"):
    # type: (str) -> dict
    """
    Load a keypair from the operating system keyring.

    :param str kid: Key ID of the keypair to load (defaults to 'default')
    :return: Key object containing Ed25519 keypair and metadata
    :raises keyring.errors.KeyringError: If loading from keyring fails
    :raises ValueError: If key does not exist
    """
    keydata = keyring.get_password(service_name="iscc", username=kid)
    log.trace(f"Loaded key with kid: {kid}")
    if not keydata:
        raise ValueError(f"No key found with ID '{kid}'")

    try:
        return json.loads(keydata)
    except json.JSONDecodeError:
        raise ValueError(f"Invalid key data for ID '{kid}'")


def delete_keypair(kid):
    # type: (str) -> None
    """
    Delete a keypair from the operating system keyring.

    :param str kid: Key ID of the keypair to delete
    :raises keyring.errors.KeyringError: If deleting from keyring fails
    :raises ValueError: If key does not exist
    """
    if not keyring.get_password(service_name="iscc", username=kid):
        raise ValueError(f"No key found with ID '{kid}'")

    keyring.delete_password(service_name="iscc", username=kid)
    log.trace(f"Deleted key with kid: {kid}")


if __name__ == "__main__":
    from rich import print

    kp = create_keypair(kid="testkey", issuer="https://iscc.ai")
    print(kp)
    kid = store_keypair(kp, overwrite=False)
    print(f"Stored with kid: {kid}")
    lkp = load_keypair(kid)
    print(f"Loaded keypair {kid}:")
    print(lkp)
    delete_keypair(kid)
