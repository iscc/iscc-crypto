import base58
import os
from dataclasses import dataclass
from functools import cached_property
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


__all__ = [
    "PREFIX_PUBLIC_KEY",
    "PREFIX_SECRET_KEY",
    "KeyPair",
    "keypair_generate",
    "keypair_from_secret",
    "keypair_from_env",
    "encode_public_key",
    "encode_secret_key",
    "pubkey_from_doc",
]


PREFIX_PUBLIC_KEY = bytes.fromhex("ED01")
PREFIX_SECRET_KEY = bytes.fromhex("8026")


@dataclass(frozen=True)
class KeyPair:
    """Combined public and secret key data structure."""

    public_key: str
    """The public key encoded as a multibase string."""

    secret_key: str
    """The private/secret key encoded as a multibase string."""

    controller: str | None = None
    """Optional URL for the controlling authority in DID Web format (did:web:example.com)."""

    key_id: str | None = None
    """Optional key identifier within the controller document (e.g. did:web:example.com#key-0)."""

    @cached_property
    def sk_obj(self):
        # type: () -> ed25519.Ed25519PrivateKey
        """Get cached secret key object."""
        # Decode secret key from multibase and create private key object
        secret_bytes = base58.b58decode(self.secret_key[1:])[2:]  # Skip multikey prefix
        return ed25519.Ed25519PrivateKey.from_private_bytes(secret_bytes)

    @cached_property
    def pk_obj(self):
        # type: () -> ed25519.Ed25519PublicKey
        """Get cached public key object."""
        # Decode public key from multibase and create public key object
        public_bytes = base58.b58decode(self.public_key[1:])[2:]  # Skip multikey prefix
        return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)


def keypair_generate(controller=None, key_id=None):
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

    # Encode keys
    secret_multibase = encode_secret_key(secret_key)
    public_multibase = encode_public_key(public_key)

    return KeyPair(
        public_key=public_multibase,
        secret_key=secret_multibase,
        controller=controller,
        key_id=key_id,
    )


def keypair_from_secret(secret_key, controller=None, key_id=None):
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


def keypair_from_env():
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

    return keypair_from_secret(
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


def encode_secret_key(secret_key):
    # type: (ed25519.Ed25519PrivateKey) -> str
    """
    Encode a secret key in multikey format.

    :param secret_key: Ed25519 private key object
    :return: Multikey encoded secret key string
    """
    secret_bytes = secret_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    prefixed_secret = PREFIX_SECRET_KEY + secret_bytes
    return "z" + base58.b58encode(prefixed_secret).decode("utf-8")


def pubkey_from_doc(doc):
    # type: (dict) -> ed25519.Ed25519PublicKey
    """
    Extract Ed25519PublicKey from a document with DataIntegrityProof.

    :param doc: Document with DataIntegrityProof containing did:key verificationMethod
    :return: Ed25519PublicKey object
    :raises ValueError: If proof or verificationMethod is invalid
    """
    if not isinstance(doc, dict):
        raise ValueError("Document must be a dictionary")

    proof = doc.get("proof")
    if proof is None or not isinstance(proof, dict):
        raise ValueError("Proof must be a dictionary")

    if proof.get("type") != "DataIntegrityProof":
        raise ValueError("Proof type must be DataIntegrityProof")

    verification_method = proof.get("verificationMethod")
    if verification_method is None or not isinstance(verification_method, str):
        raise ValueError("verificationMethod must be a string")

    if not verification_method.startswith("did:key:"):
        raise ValueError("verificationMethod must start with did:key:")

    # Extract the public key part after did:key:
    pubkey_part = verification_method.split("#")[0].replace("did:key:", "")
    if not pubkey_part.startswith("z"):
        raise ValueError("Public key must start with z (base58btc multibase prefix)")

    try:
        pubkey_bytes = base58.b58decode(pubkey_part[1:])
    except Exception as e:
        raise ValueError(f"Invalid base58 encoding: {e}")

    if not pubkey_bytes.startswith(PREFIX_PUBLIC_KEY):
        raise ValueError("Invalid public key prefix")

    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes[2:])
    except Exception as e:
        raise ValueError(f"Invalid public key bytes: {e}")
