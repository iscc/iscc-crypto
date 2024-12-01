import jcs
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base58
import msgspec
from hashlib import sha256


class KeyPair(msgspec.Struct):
    """Combined public and secret key data structure."""

    public_key: str
    secret_key: str


def create_keypair():
    # type: () -> KeyPair
    """
    Generate an Ed25519 keypair for use with eddsa-jcs-2022 cryptosuite.
    Returns a tuple of (publicKeyMultibase, secretKeyMultibase) encoded in multibase format.

    The keys are encoded according to the Multikey specification:
    - A 0xed01 prefix for public key
    - A 0x80ed01 prefix for private key
    - Followed by the raw key bytes
    - The result is base58-btc encoded with 'z' prefix
    """
    # Generate the Ed25519 keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get the raw bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Add the Multikey prefixes
    prefixed_public = bytes.fromhex("ed01") + public_bytes
    prefixed_private = bytes.fromhex("8026") + private_bytes

    # Encode in base58-btc with 'z' prefix
    public_multibase = "z" + base58.b58encode(prefixed_public).decode("utf-8")
    private_multibase = "z" + base58.b58encode(prefixed_private).decode("utf-8")

    return KeyPair(public_key=public_multibase, secret_key=private_multibase)


def from_secret(secret_key):
    # type: (str) -> KeyPair
    """
    Create a KeyPair from an existing multibase-encoded secret key.

    :param secret_key: Multibase encoded secret key (z-base58-btc)
    :return: KeyPair with public and secret keys
    """
    # Remove multibase prefix and decode
    secret_bytes = base58.b58decode(secret_key[1:])

    # Remove multikey prefix and create private key
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_bytes[2:])
    public_key = private_key.public_key()

    # Get raw public key bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Add multikey prefixes and encode
    prefixed_public = bytes.fromhex("ed01") + public_bytes
    public_multibase = "z" + base58.b58encode(prefixed_public).decode("utf-8")

    return KeyPair(public_key=public_multibase, secret_key=secret_key)


def sign(payload, keypair):
    # type: (bytes, KeyPair) -> str
    """
    Sign a bytes payload using eddsa-jcs-2022 cryptosuite.

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


# Example usage:
if __name__ == "__main__":
    test_key = KeyPair(
        public_key="z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        secret_key="z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
    )
    print(f"Test Key: {test_key}")
    reconstructed = from_secret(test_key.secret_key)
    print(f"Reconstructed Key: {reconstructed}")
    assert test_key == reconstructed

    credential = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2",
        ],
        "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "name": "Alumni Credential",
        "description": "A minimum viable example of an Alumni Credential.",
        "issuer": "https://vc.example/issuers/5678",
        "validFrom": "2023-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
    }

    assert (
        sha256(jcs.canonicalize(credential)).hexdigest()
        == "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
    )

    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2023-02-24T23:36:38Z",
        "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        "proofPurpose": "assertionMethod",
    }

    assert (
        sha256(jcs.canonicalize(options)).hexdigest()
        == "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da8"
    )

    combined = "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da859b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"

    expected_signature = (
        "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
    )
    signature = sign(bytes.fromhex(combined), test_key)
    print(signature)
    assert signature == expected_signature
