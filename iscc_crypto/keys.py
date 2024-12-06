import base58
import msgspec
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


__all__ = [
    "PREFIX_PUBLIC_KEY",
    "PREFIX_SECRET_KEY",
    "KeyPair",
    "create_keypair",
    "from_secret",
    "from_env",
]


PREFIX_PUBLIC_KEY = bytes.fromhex("ED01")
PREFIX_SECRET_KEY = bytes.fromhex("8026")


class KeyPair(msgspec.Struct):
    """Combined public and secret key data structure."""

    public_key: str
    """The public key encoded as a multibase string."""

    secret_key: str
    """The private/secret key encoded as a multibase string."""

    controller: str | None = None
    """Optional URL for the controlling authority in DID Web format (did:web:example.com)."""

    key_id: str | None = None
    """Optional key identifier within the controller document (e.g. did:web:example.com#key-0)."""


def create_keypair(controller=None, key_id=None):
    # type: (str|None, str|None) -> KeyPair
    """
    Create a new Ed25519 key pair for signing in accordance with https://www.w3.org/TR/vc-di-eddsa/.

    WARNING:
        The returned data includes sensitive key material. Handle with care!

    :param str controller: HTTPS URL of the key issuing authority (DID Controller Document).
    :param str key_id: Key ID used for key storage and retrieval
    :return: Key object containing the Ed25519 key pair and metadata
    :raises ValueError: If name is empty or controler URL is invalid
    """
    # Generate the Ed25519 keypair
    secret_key = ed25519.Ed25519PrivateKey.generate()
    public_key = secret_key.public_key()

    # Get and encode the secret key
    secret_bytes = secret_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    prefixed_secret = PREFIX_SECRET_KEY + secret_bytes
    secret_multibase = "z" + base58.b58encode(prefixed_secret).decode("utf-8")

    # Get and encode the public key
    public_multibase = encode_public_key(public_key)

    return KeyPair(
        public_key=public_multibase,
        secret_key=secret_multibase,
        controller=controller,
        key_id=key_id,
    )


def from_secret(secret_key, controller=None, key_id=None):
    # type: (str, str|None, str|None) -> KeyPair
    """
    Create a KeyPair from an existing Ed25519 secret key in multikey format.

    :param str secret_key: The secret key in multikey format (z-base58 encoded)
    :param str controller: HTTPS URL of the key issuing authority (DID Controller Document)
    :param str key_id: Key ID used for key storage and retrieval
    :return: Key object containing the Ed25519 key pair and metadata
    :raises ValueError: If secret key is invalid
    """
    if not secret_key.startswith("z"):
        raise ValueError("Secret key must start with 'z' (base58btc multibase prefix)")

    # Decode the secret key
    try:
        secret_bytes = base58.b58decode(secret_key[1:])
    except Exception as e:
        raise ValueError(f"Invalid base58 encoding: {e}")

    if not secret_bytes.startswith(PREFIX_SECRET_KEY):
        raise ValueError("Invalid secret key prefix")

    # Create private key object
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_bytes[2:])
    except Exception as e:
        raise ValueError(f"Invalid secret key bytes: {e}")

    # Get and encode the public key
    public_multibase = encode_public_key(private_key.public_key())

    return KeyPair(
        public_key=public_multibase,
        secret_key=secret_key,
        controller=controller,
        key_id=key_id,
    )


def from_env():
    # type: () -> KeyPair
    """
    Create a KeyPair from environment variables.

    Loads the following environment variables:
    - ISCC_CRYPTO_SECRET_KEY: The secret key in multikey format
    - ISCC_CRYPTO_CONTROLLER: Optional controller URL
    - ISCC_CRYPTO_KEY_ID: Optional key identifier

    :return: KeyPair constructed from environment variables
    :raises ValueError: If ISCCCRYPTO__SECRET_KEY is missing or invalid
    """
    load_dotenv()
    secret_key = os.getenv("ISCC_CRYPTO_SECRET_KEY")
    if not secret_key:
        raise ValueError("ISCC_CRYPTO_SECRET_KEY environment variable is required")

    return from_secret(
        secret_key=secret_key,
        controller=os.getenv("ISCC_CRYPTO_CONTROLLER"),
        key_id=os.getenv("ISCC_CRYPTO_KEY_ID"),
    )


def encode_public_key(public_key):
    # type: (ed25519.Ed25519PublicKey) -> str
    """
    Encode a public key in multikey format.

    :param public_key: Ed25519 public key object
    :return: Multikey encoded public key string
    """
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    prefixed_public = PREFIX_PUBLIC_KEY + public_bytes
    return "z" + base58.b58encode(prefixed_public).decode("utf-8")
