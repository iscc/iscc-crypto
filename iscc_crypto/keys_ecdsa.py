"""
# ecdsa-jcs-2019 cryptosuite

## https://www.w3.org/TR/vc-di-ecdsa/:

[FIPS-186-5] includes the deterministic ECDSA algorithm which is also specified in [RFC6979].
All ECDSA signatures MUST use the deterministic variant of the algorithm defined in [FIPS-186-5].

## https://www.w3.org/TR/controller-document/:

### ECDSA 256-bit public key:

The Multikey encoding of a P-256 public key MUST start with the two-byte prefix 0x8024 (the varint
expression of 0x1200) followed by the 33-byte compressed public key data. The resulting 35-byte
value MUST then be encoded using the base-58-btc alphabet, according to Section 2.4 Multibase, and
then prepended with the base-58-btc Multibase header (z).

### ECDSA 256-bit secret key:

The Multikey encoding of a P-256 secret key MUST start with the two-byte prefix 0x8626 (the varint
expression of 0x1306) followed by the 32-byte secret key data. The resulting 34-byte value MUST
then be encoded using the base-58-btc alphabet, according to Section 2.4 Multibase, and then
prepended with the base-58-btc Multibase header (z).
"""

from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import serialization, hashes
import msgspec
import base58
import jcs


class KeyPair(msgspec.Struct):
    """Combined public and secret key data structure."""

    public_key: str
    secret_key: str


def create_keypair():
    # type: () -> KeyPair
    """
    Generate an ECDSA [FIPS-186-5] keypair for use with ecdsa-jcs-2019 cryptosuite.

    The keys are encoded according to the Multikey specification:
    - A 0x8024 prefix for public key
    - A 0x8626 prefix for private key
    - Followed by the raw key bytes
    - The result is base58-btc encoded with 'z' prefix
    """
    # Generate the ECDSA keypair using P-256 curve
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Get the raw bytes
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint
    )

    # Add the Multikey prefixes
    prefixed_public = bytes.fromhex("8024") + public_bytes
    prefixed_private = bytes.fromhex("8626") + private_bytes

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

    # Remove multikey prefix and create private key value
    private_value = int.from_bytes(secret_bytes[2:], "big")
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())
    public_key = private_key.public_key()

    # Get public key bytes in compressed format
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint
    )

    # Add multikey prefix and encode
    prefixed_public = bytes.fromhex("8024") + public_bytes
    public_multibase = "z" + base58.b58encode(prefixed_public).decode("utf-8")

    return KeyPair(public_key=public_multibase, secret_key=secret_key)


def sign(payload, keypair):
    # type: (bytes, KeyPair) -> str
    """
    Sign a bytes payload conformant with ecdsa-jcs-2019 cryptosuite.

    :param payload: Bytes to sign
    :param keypair: KeyPair containing the signing key
    :return: Multibase encoded signature (z-base58-btc)
    """
    # Decode secret key from multibase
    secret_bytes = base58.b58decode(keypair.secret_key[1:])

    # Create private key from bytes (skip multikey prefix)
    private_value = int.from_bytes(secret_bytes[2:], "big")
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())

    # Sign the payload using deterministic RFC6979 k-generation
    der_signature = private_key.sign(
        payload,
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
    )

    # Convert DER signature to IEEE P1363 format
    r, s = asym_utils.decode_dss_signature(der_signature)
    signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    # Encode signature in multibase format
    return "z" + base58.b58encode(signature).decode("utf-8")


if __name__ == "__main__":
    from rich import print
    from hashlib import sha256

    test_key = KeyPair(
        public_key="zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
        secret_key="z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN",
    )
    print(f"Test Key:")
    print(test_key)

    reconstructed = from_secret(test_key.secret_key)
    print(f"Reconstructed Key:")
    print(reconstructed)
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
        "cryptosuite": "ecdsa-jcs-2019",
        "created": "2023-02-24T23:36:38Z",
        "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
        "proofPurpose": "assertionMethod",
    }

    assert (
        sha256(jcs.canonicalize(options)).hexdigest()
        == "9c4b552d65fcb106b6b27ec2436d8ae81b319afc7aeaab7964b2938cd120cec3"
    )

    combined = "9c4b552d65fcb106b6b27ec2436d8ae81b319afc7aeaab7964b2938cd120cec359b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"

    expected_signature = (
        "zq6PrUMCtqY5obCSsrQxuFJdGffCDxvFuopdZiBPUBRTFEs1VVsBZi8YiEwVWgHYrXxoV93gBHqGDBtQLPFxpZxz"
    )

    signature = sign(bytes.fromhex(combined), test_key)
    print("Signature:")
    print(signature)
    assert signature == expected_signature
