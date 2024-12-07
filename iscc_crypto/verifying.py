import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from iscc_crypto.signing import create_signature_payload

__all__ = [
    "verify_signature",
    "verify_json",
]


def verify_json(document, public_key):
    # type: (dict, Ed25519PublicKey) -> tuple[bool, dict|None]
    """
    Verify a Data Integrity Proof on a JSON document using EdDSA and JCS canonicalization.

    Verifies proofs that follow the W3C VC Data Integrity spec (https://www.w3.org/TR/vc-di-eddsa).
    The verification process:
    1. Extracts and validates the proof from the document
    2. Canonicalizes both document and proof options using JCS
    3. Creates a composite hash of both canonicalized values
    4. Verifies the signature against the hash using the provided Ed25519 key

    :param document: JSON document with proof to verify
    :param public_key: Ed25519PublicKey for verification
    :return: Tuple of (verified, document without proof) or (False, None) if invalid
    """
    if not isinstance(document, dict):
        return False, None

    # Extract and validate proof
    proof = document.get("proof")
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
    doc_without_proof = document.copy()
    del doc_without_proof["proof"]

    # Create proof options without proofValue
    proof_options = proof.copy()
    del proof_options["proofValue"]

    # Create verification payload and verify signature
    verification_payload = create_signature_payload(doc_without_proof, proof_options)
    if verify_signature(verification_payload, proof["proofValue"], public_key):
        return True, doc_without_proof
    return False, None


def verify_signature(payload, signature, public_key):
    # type: (bytes, str, Ed25519PublicKey) -> bool
    """
    Verify an EdDSA signature over raw bytes. The signature must be encoded according to
    [RFC8032] with base-58-btc header and alphabet conformant with eddsa-jcs-2022.

    :param payload: Original signed bytes
    :param signature: Multibase encoded signature (z-base58-btc)
    :param public_key: Base58 encoded public key
    :return: True if signature is valid, False otherwise
    """
    try:
        raw_signature = base58.b58decode(signature[1:])
        public_key.verify(raw_signature, payload)
        return True
    except (ValueError, InvalidSignature):
        return False
