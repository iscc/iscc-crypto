import base58
from copy import deepcopy
from hashlib import sha256
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from iscc_crypto.signing import create_signature_payload
from iscc_crypto.keys import PREFIX_PUBLIC_KEY
import jcs
from dataclasses import dataclass


__all__ = [
    "verify_vc",
    "verify_json",
    "verify_raw",
    "VerificationError",
    "VerificationResult",
]


@dataclass(frozen=True)
class VerificationResult:
    """Container for verification results"""

    is_valid: bool
    message: str | None = None


class VerificationError(Exception):
    """Raised when signature verification fails"""

    pass


def verify_raw(payload, signature, public_key, raise_on_error=True):
    # type: (bytes, str, Ed25519PublicKey, bool) -> VerificationResult
    """
    Verify an EdDSA signature over raw bytes. The signature must be encoded according to
    [RFC8032] with base-58-btc header and alphabet conformant with eddsa-jcs-2022.

    :param payload: Original signed bytes
    :param signature: Multibase encoded signature (z-base58-btc)
    :param public_key: Base58 encoded public key
    :param raise_on_error: Raise VerificationError on failure instead of returning result
    :return: VerificationResult with status and optional error message
    :raises VerificationError: If signature verification fails and raise_on_error=True
    """
    try:
        if not signature.startswith("z"):
            msg = "Invalid signature format - must start with 'z'"
            if raise_on_error:
                raise VerificationError(msg)
            return VerificationResult(is_valid=False, message=msg)

        raw_signature = base58.b58decode(signature[1:])
        public_key.verify(raw_signature, payload)
        return VerificationResult(is_valid=True)
    except (ValueError, InvalidSignature) as e:
        msg = f"Signature verification failed: {str(e)}"
        if raise_on_error:
            raise VerificationError(msg)
        return VerificationResult(is_valid=False, message=msg)


def verify_json(obj):
    # type: (dict) -> bool
    """
    Verify an EdDSA signature on a JSON object using JCS canonicalization.

    Verifies signatures created by sign_json(). The verification process:
    1. Extracts signature and declarer fields from the document
    2. Creates a canonicalized hash of the document without signature fields
    3. Verifies the signature using the public key from declarer field

    :param obj: JSON object with signature to verify
    :return: True if signature is valid
    :raises VerificationError: If signature verification fails
    """
    try:
        signature = obj["signature"]
        declarer = obj["declarer"]
    except KeyError as e:
        raise VerificationError(f"Missing required field: {e.args[0]}")

    if not signature.startswith("z"):
        raise VerificationError("Invalid signature format - must start with 'z'")

    try:
        raw_key = base58.b58decode(declarer[1:])  # Remove 'z' prefix
        if not raw_key.startswith(PREFIX_PUBLIC_KEY):
            raise ValueError("Invalid public key prefix")
        public_key = Ed25519PublicKey.from_public_bytes(raw_key[2:])  # Remove ED01 prefix
    except (ValueError, IndexError):
        raise VerificationError("Invalid declarer format")

    # Create copy without signature fields
    doc_without_sig = deepcopy(obj)
    del doc_without_sig["signature"]
    del doc_without_sig["declarer"]

    try:
        verification_payload = sha256(jcs.canonicalize(doc_without_sig)).digest()
        return verify_raw(verification_payload, signature, public_key)
    except Exception as e:
        raise VerificationError(f"Verification failed: {str(e)}")


def verify_vc(doc, public_key):
    # type: (dict, Ed25519PublicKey) -> tuple[bool, dict|None]
    """
    Verify a Data Integrity Proof on a JSON document using EdDSA and JCS canonicalization.

    Verifies proofs that follow the W3C VC Data Integrity spec (https://www.w3.org/TR/vc-di-eddsa).
    The verification process:
    1. Extracts and validates the proof from the document
    2. Canonicalizes both document and proof options using JCS
    3. Creates a composite hash of both canonicalized values
    4. Verifies the signature against the hash using the provided Ed25519 key

    :param doc: JSON document with proof to verify
    :param public_key: Ed25519PublicKey for verification
    :return: Tuple of (verified, document without proof) or (False, None) if invalid
    """
    if not isinstance(doc, dict):
        return False, None

    # Extract and validate proof
    proof = doc.get("proof")
    if not isinstance(proof, dict):
        return False, None

    # Validate proof properties
    if (
        proof.get("type") != "DataIntegrityProof"
        or proof.get("cryptosuite") != "eddsa-jcs-2022"
        or not isinstance(proof.get("proofValue"), str)
        or not proof["proofValue"].startswith("z")
    ):
        return False, None

    # Create copy without proof for verification
    doc_without_proof = deepcopy(doc)
    del doc_without_proof["proof"]

    # Create proof options without proofValue
    proof_options = deepcopy(proof)
    del proof_options["proofValue"]

    # Create verification payload and verify signature
    verification_payload = create_signature_payload(doc_without_proof, proof_options)
    if verify_raw(verification_payload, proof["proofValue"], public_key):
        return True, doc_without_proof
    return False, None
