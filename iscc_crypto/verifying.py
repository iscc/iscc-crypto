import base58
from copy import deepcopy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from iscc_crypto.signing import create_signature_payload
from iscc_crypto.keys import PREFIX_PUBLIC_KEY, pubkey_decode
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
    :param public_key: Ed25519PublicKey for verification
    :param raise_on_error: Raise VerificationError on failure instead of returning result
    :return: VerificationResult with status and optional error message
    :raises VerificationError: If signature verification fails and raise_on_error=True
    """
    try:
        if not signature.startswith("z"):
            msg = "Invalid signature format - must start with 'z'"
            return raise_or_return(msg, raise_on_error)

        try:
            raw_signature = base58.b58decode(signature[1:])
        except Exception:
            msg = "Invalid base58 signature encoding"
            return raise_or_return(msg, raise_on_error)

        try:
            public_key.verify(raw_signature, payload)
            return VerificationResult(is_valid=True, message=None)
        except InvalidSignature:
            msg = "Invalid signature for payload"
            return raise_or_return(msg, raise_on_error)
    except Exception as e:
        msg = f"Verification failed: {str(e)}"
        return raise_or_return(msg, raise_on_error)


def verify_json(obj, raise_on_error=True):
    # type: (dict, bool) -> VerificationResult
    """
    Verify an EdDSA signature on a JSON object using JCS canonicalization.

    Verifies signatures created by sign_json(). The verification process:
    1. Extracts signature and declarer fields from the document
    2. Creates a canonicalized hash of the document without signature fields
    3. Verifies the signature using the public key from declarer field

    :param obj: JSON object with signature to verify
    :param raise_on_error: Raise VerificationError on failure instead of returning result
    :return: VerificationResult with status and optional error message
    :raises VerificationError: If signature verification fails and raise_on_error=True
    """
    # Extract required fields
    try:
        signature = obj["signature"]
        declarer = obj["declarer"]
    except KeyError as e:
        msg = f"Missing required field: {e.args[0]}"
        return raise_or_return(msg, raise_on_error)

    # Validate signature format
    if not signature.startswith("z"):
        msg = "Invalid signature format - must start with 'z'"
        return raise_or_return(msg, raise_on_error)

    # Parse and validate public key
    try:
        public_key = pubkey_decode(declarer)
    except ValueError as e:
        msg = f"Invalid declarer format: {str(e)}"
        return raise_or_return(msg, raise_on_error)

    # Create copy without signature fields
    doc_without_sig = deepcopy(obj)
    del doc_without_sig["signature"]
    del doc_without_sig["declarer"]

    # Verify signature
    try:
        verification_payload = jcs.canonicalize(doc_without_sig)
        return verify_raw(verification_payload, signature, public_key, raise_on_error)
    except Exception as e:
        msg = f"Verification failed: {str(e)}"
        return raise_or_return(msg, raise_on_error)


def verify_vc(doc, raise_on_error=True):
    # type: (dict, bool) -> VerificationResult
    """
    Verify a Data Integrity Proof on a JSON document using EdDSA and JCS canonicalization.

    Note:
        This function only supports offline verification for ISCC Notary credentials.
        It does NOT support generic verification of Verifiable Credentials.

    Verifies proofs that follow the W3C VC Data Integrity spec (https://www.w3.org/TR/vc-di-eddsa).
    The verification process:

    1. Extracts and validates the proof from the document
    2. Extracts the public key from the verificationMethod
    3. Canonicalizes both document and proof options using JCS
    4. Creates a composite hash of both canonicalized values
    5. Verifies the signature against the hash

    :param doc: JSON document with proof to verify
    :param raise_on_error: Raise VerificationError on failure instead of returning result
    :return: VerificationResult with status and optional error message
    :raises VerificationError: If signature verification fails and raise_on_error=True
    """
    try:
        # Extract required proof
        try:
            proof = doc["proof"]
        except KeyError as e:
            msg = "Missing required field: proof"
            return raise_or_return(msg, raise_on_error)

        # Validate proof properties
        if proof.get("type") != "DataIntegrityProof":
            msg = "Invalid proof type - must be DataIntegrityProof"
            return raise_or_return(msg, raise_on_error)

        if proof.get("cryptosuite") != "eddsa-jcs-2022":
            msg = "Invalid cryptosuite - must be eddsa-jcs-2022"
            return raise_or_return(msg, raise_on_error)

        proof_value = proof.get("proofValue")
        if not proof_value or not proof_value.startswith("z"):
            msg = "Invalid proofValue format - must start with 'z'"
            return raise_or_return(msg, raise_on_error)

        # Extract and validate verification method
        verification_method = proof.get("verificationMethod")
        if not verification_method or not verification_method.startswith("did:key:"):
            msg = "Invalid verificationMethod - must start with did:key:"
            return raise_or_return(msg, raise_on_error)

        # Extract public key from verification method
        try:
            pubkey_part = verification_method.split("#")[0].replace("did:key:", "")
            raw_key = base58.b58decode(pubkey_part[1:])
            if not raw_key.startswith(PREFIX_PUBLIC_KEY):
                raise ValueError("Invalid public key prefix")
            public_key = Ed25519PublicKey.from_public_bytes(raw_key[2:])
        except Exception as e:
            msg = f"Invalid public key in verificationMethod: {str(e)}"
            return raise_or_return(msg, raise_on_error)

        # Create copy without proof for verification
        doc_without_proof = deepcopy(doc)
        del doc_without_proof["proof"]

        # Create proof options without proofValue
        proof_options = deepcopy(proof)
        del proof_options["proofValue"]

        # Create verification payload and verify signature
        verification_payload = create_signature_payload(doc_without_proof, proof_options)
        return verify_raw(verification_payload, proof_value, public_key, raise_on_error)

    except Exception as e:
        msg = f"Verification failed: {str(e)}"
        return raise_or_return(msg, raise_on_error)


def raise_or_return(msg, raise_on_error):
    # type: (str, bool) -> VerificationResult
    """
    Helper function to handle verification errors consistently.

    :param msg: Error message
    :param raise_on_error: Whether to raise exception or return result
    :return: VerificationResult with is_valid=False and error message
    :raises VerificationError: If raise_on_error is True
    """
    if raise_on_error:
        raise VerificationError(msg)
    return VerificationResult(is_valid=False, message=msg)
