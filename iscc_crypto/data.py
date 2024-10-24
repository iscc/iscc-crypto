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


def sign_file(uri, private_key, chunk_size=2097152, with_proof=False):
    # type: (str, Ed25519PrivateKey, int, bool) -> bytes | Tuple[bytes, bytes]
    """
    Sign a file with an Ed25519 signature.

    :param uri: URI to file that should be signed
    :param private_key: Ed25519 private key for signing
    :param chunk_size: Size of chunks to read in bytes, defaults to 2MB
    :param with_proof: If True, also create and return data access proof signature
    :return: Single signature or tuple of (signature, proof_signature) if with_proof=True
    """
    # Calculate BLAKE3 hash of file
    hasher = blake3.blake3()
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    file_hash = hasher.digest()

    # Sign the file hash
    signature = private_key.sign(file_hash)

    if with_proof:
        proof_sig = prove_file_access(uri, private_key, signature, chunk_size)
        return signature, proof_sig
    return signature


def prove_file_access(uri, private_key, file_signature, chunk_size=2097152):
    # type: (str, Ed25519PrivateKey, bytes, int) -> bytes
    """
    Create a data access proof signature for a file.

    Uses the approach from https://crypto.stackexchange.com/a/55156/55556
    to prove actual access to file content by computing an HMAC over the
    entire file using the first signature as key.

    :param uri: URI to file to prove access to
    :param private_key: Ed25519 private key for signing
    :param file_signature: Original file signature to use as HMAC key
    :param chunk_size: Size of chunks to read in bytes, defaults to 2MB
    :return: Proof signature that demonstrates file access
    """
    # Calculate HMAC using first 32 bytes of file signature as key
    hmac_hasher = blake3.blake3(key=file_signature[:32])
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hmac_hasher.update(chunk)
    hmac_digest = hmac_hasher.digest()

    # Sign the HMAC digest as proof of file access
    return private_key.sign(hmac_digest)


def verify_file(uri, public_key, signature, proof_signature=None, chunk_size=2097152):
    # type: (str|Path, Ed25519PublicKey, bytes, bytes|None, int) -> bool
    """
    Verify file signature and optional access proof.

    :param uri: Path to file to verify
    :param public_key: Ed25519 public key for verification
    :param signature: File signature to verify
    :param proof_signature: Optional data access proof signature
    :param chunk_size: Size of chunks to read in bytes, defaults to 2MB
    :return: True if signatures are valid, raises InvalidSignature otherwise
    """
    # Verify file signature
    hasher = blake3.blake3()
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    file_hash = hasher.digest()
    public_key.verify(signature, file_hash)

    # Verify access proof if provided
    if proof_signature is not None:
        verify_file_access_proof(uri, public_key, signature, proof_signature, chunk_size)

    return True


def verify_file_access_proof(uri, public_key, file_signature, proof_signature, chunk_size=2097152):
    # type: (str|Path, Ed25519PublicKey, bytes, bytes, int) -> bool
    """
    Verify a data access proof signature.

    :param uri: Path to file to verify
    :param public_key: Ed25519 public key for verification
    :param file_signature: Original file signature used as HMAC key
    :param proof_signature: Access proof signature to verify
    :param chunk_size: Size of chunks to read in bytes, defaults to 2MB
    :return: True if proof is valid, raises InvalidSignature otherwise
    """
    # Verify HMAC signature
    hmac_hasher = blake3.blake3(key=file_signature[:32])
    with smart_open.open(uri, "rb", compression="disable") as f:
        while chunk := f.read(chunk_size):
            hmac_hasher.update(chunk)
    hmac_digest = hmac_hasher.digest()
    public_key.verify(proof_signature, hmac_digest)
    return True


if __name__ == "__main__":
    fp = r"C:\Users\titusz\Downloads\Reor_0.2.23.exe"
    k = generate_signing_key()
    print("KEY")
    print(k)
    s1, s2 = sign_file(fp, k, with_proof=True)
    print("SIG1")
    print(s1)
    print("SIG1 TYPE")
    print(type(s1))
    print("SIG1 LENGTH")
    print(len(s1))
    print("SIG2")
    print(s2)
    v = verify_file(fp, k.public_key(), s1, s2)
    print("VERIFY")
    print(v)
