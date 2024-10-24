"""Signing Large Media assets with data access proof"""

from typing import Tuple

import blake3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import smart_open


def generate_signing_key():
    # type: () -> Ed25519PrivateKey
    """
    Generate a random Ed25519 private key for signing.

    :return: Ed25519 private key instance
    """
    return ed25519.Ed25519PrivateKey.generate()


def sign_file(uri, private_key, chunk_size=2097152):
    # type: (str, Ed25519PrivateKey, int) -> Tuple[bytes, bytes]
    """
    Create data access proof signature for file using streaming.

    Following the approach from https://crypto.stackexchange.com/a/55156/55556
    Returns two signatures that prove both knowledge of the hash and access to the actual file:
    1. sig1 = Sign(H(M))  - Signature of the file hash
    2. sig2 = Sign(HMAC(sig1, M)) - Signature of HMAC using sig1 as key over the full file

    This solution:

    1. Makes two passes over the file (unavoidable for proving data access)
    2. Uses BLAKE3 which:
        - Is significantly faster than SHA256/SHA3
        - Has built-in keyed hashing (HMAC) capability
        - Supports streaming naturally
    3. Returns two signatures that together prove:
        - The signer knew the file hash (sig1)
        - The signer had access to the full file content (sig2)
        - The signatures are cryptographically linked through the HMAC

    :param uri: URI to file that should be signed
    :param private_key: Ed25519 private key for signing
    :param chunk_size: Size of chunks to read in bytes, defaults to 1MB
    :return: Tuple of (signature1, signature2) proving file access
    """

    # First pass - calculate BLAKE3 hash of file
    hasher = blake3.blake3()
    # with filepath.open("rb") as f:
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    file_hash = hasher.digest()

    # First signature - sign the file hash
    sig1 = private_key.sign(file_hash)

    # Second pass - calculate HMAC using first 32 bytes of sig1 as key
    hmac_hasher = blake3.blake3(key=sig1[:32])
    # with filepath.open("rb") as f:
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hmac_hasher.update(chunk)
    hmac_digest = hmac_hasher.digest()

    # Second signature - sign the HMAC
    sig2 = private_key.sign(hmac_digest)

    return sig1, sig2


def verify_file(uri, public_key, signatures, chunk_size=1024 * 1024):
    # type: (str|Path, Ed25519PublicKey, Tuple[bytes, bytes], int) -> bool
    """
    Verify data access proof signature for file.

    :param uri: Path to file to verify
    :param public_key: Ed25519 public key for verification
    :param signatures: Tuple of (signature1, signature2) from sign_file
    :param chunk_size: Size of chunks to read in bytes, defaults to 1MB
    :return: True if signatures are valid, raises InvalidSignature otherwise
    """
    sig1, sig2 = signatures

    # First pass - verify sig1 matches file hash
    hasher = blake3.blake3()
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    file_hash = hasher.digest()
    public_key.verify(sig1, file_hash)

    # Second pass - verify sig2 matches HMAC
    hmac_hasher = blake3.blake3(key=sig1[:32])
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hmac_hasher.update(chunk)
    hmac_digest = hmac_hasher.digest()
    public_key.verify(sig2, hmac_digest)

    return True


if __name__ == "__main__":
    fp = r"C:\Users\titusz\Downloads\Reor_0.2.23.exe"
    k = generate_signing_key()
    print("KEY")
    print(k)
    s1, s2 = sign_file(fp, k)
    print("SIG1")
    print(s1)
    print("SIG1 TYPE")
    print(type(s1))
    print("SIG1 LENGTH")
    print(len(s1))
    print("SIG2")
    print(s2)
    v = verify_file(fp, k.public_key(), (s1, s2))
    print("VERIFY")
    print(v)
