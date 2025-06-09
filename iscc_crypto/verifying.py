import base58
from copy import deepcopy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from iscc_crypto.signing import create_signature_payload
from iscc_crypto.keys import pubkey_decode
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
    """Container for verification results with separate integrity and identity validation"""

    signature_valid: bool
    identity_verified: bool | None = None
    message: str | None = None

    @property
    def is_valid(self) -> bool:
        """Overall validation status - both signature and identity (if checked) must be valid"""
        if self.identity_verified is None:
            return self.signature_valid
        return self.signature_valid and self.identity_verified


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
            return VerificationResult(signature_valid=True, message=None)
        except InvalidSignature:
            msg = "Invalid signature for payload"
            return raise_or_return(msg, raise_on_error)
    except Exception as e:
        msg = f"Verification failed: {str(e)}"
        return raise_or_return(msg, raise_on_error)


def verify_json(obj, identity_doc=None, raise_on_error=True):
    # type: (dict, dict|None, bool) -> VerificationResult
    """
    Verify an EdDSA signature on a JSON object using JCS canonicalization.

    - Verifies cryptographic signature (always)
    - Optionally verifies identity ownership (when identity_doc provided)

    The verification process:
    1. Extracts signature and pubkey fields from the document
    2. Creates a canonicalized hash of the document without the `proof` field
    3. Verifies the signature using the public key from pubkey field
    4. If identity_doc provided and signature has controller, verifies key ownership

    :param obj: JSON object with signature to verify
    :param identity_doc: Optional identity document (DID document or CID) for controller verification
    :param raise_on_error: Raise VerificationError on failure instead of returning result
    :return: VerificationResult with signature and identity verification status
    :raises VerificationError: If signature verification fails and raise_on_error=True
    """
    # Extract required fields
    try:
        signature = obj["signature"]["proof"]
    except KeyError as e:
        msg = f"Missing required field: {e.args[0]}"
        return raise_or_return(msg, raise_on_error)

    # Check if we have pubkey for offline verification
    pubkey = obj.get("signature", {}).get("pubkey")
    if not pubkey:
        msg = "Missing pubkey field - cannot verify signature offline"
        return raise_or_return(msg, raise_on_error)

    # Validate signature format
    if not signature.startswith("z"):
        msg = "Invalid signature format - must start with 'z'"
        return raise_or_return(msg, raise_on_error)

    # Parse and validate public key
    try:
        public_key = pubkey_decode(pubkey)
    except ValueError as e:
        msg = f"Invalid pubkey format: {str(e)}"
        return raise_or_return(msg, raise_on_error)

    # Create a copy without the proof property
    doc_without_sig = deepcopy(obj)
    del doc_without_sig["signature"]["proof"]

    # Verify cryptographic signature
    try:
        verification_payload = jcs.canonicalize(doc_without_sig)
        signature_result = verify_raw(verification_payload, signature, public_key, raise_on_error)

        if not signature_result.signature_valid:
            return signature_result

    except Exception as e:
        msg = f"Signature verification failed: {str(e)}"
        return raise_or_return(msg, raise_on_error)

    # If no identity document provided, return signature verification result
    if identity_doc is None:
        return VerificationResult(signature_valid=True, identity_verified=None, message=None)

    # Check if signature has controller for identity verification
    controller = obj.get("signature", {}).get("controller")
    if not controller:
        # No controller in signature, can't do identity verification
        return VerificationResult(signature_valid=True, identity_verified=None, message=None)

    # Perform identity verification
    try:
        identity_verified = _verify_identity(obj["signature"], identity_doc)
        return VerificationResult(
            signature_valid=True,
            identity_verified=identity_verified,
            message=None if identity_verified else "Key not authorized by controller",
        )
    except Exception as e:
        msg = f"Identity verification failed: {str(e)}"
        if raise_on_error:
            raise VerificationError(msg)
        return VerificationResult(signature_valid=True, identity_verified=False, message=msg)


def _verify_identity(signature_obj, identity_doc):
    # type: (dict, dict) -> bool
    """
    Verify that the signing key is authorized by the identity document.

    :param signature_obj: Signature object containing pubkey, controller, and optional keyid
    :param identity_doc: Identity document (DID document or CID) containing verification methods
    :return: True if key is authorized, False otherwise
    """
    pubkey = signature_obj.get("pubkey")
    controller = signature_obj.get("controller")
    keyid = signature_obj.get("keyid")

    if not pubkey or not controller:
        return False

    # Get verification methods from identity document
    verification_methods = identity_doc.get("verificationMethod", [])
    if not verification_methods:
        return False

    # Look for matching verification method
    for vm in verification_methods:
        # Check if controller matches
        if vm.get("controller") != controller:
            continue

        # If keyid is specified, check if it matches the verification method id
        if keyid:
            vm_id = vm.get("id", "")
            # Extract fragment after # for comparison
            vm_fragment = vm_id.split("#")[-1] if "#" in vm_id else vm_id
            if keyid != vm_fragment and keyid != vm_id:
                continue

        # Check if public key matches (only support publicKeyMultibase format)
        vm_pubkey = vm.get("publicKeyMultibase")
        if vm_pubkey == pubkey:
            return True

    return False


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
            public_key = pubkey_decode(pubkey_part)
        except ValueError as e:
            msg = f"Invalid public key in verificationMethod: {str(e)}"
            return raise_or_return(msg, raise_on_error)

        # Create copy without proof for verification
        doc_without_proof = deepcopy(doc)
        del doc_without_proof["proof"]

        # Create proof options without proofValue
        proof_options = deepcopy(proof)
        del proof_options["proofValue"]

        # Validate @context if present
        if "@context" in proof_options:
            try:
                doc_context = doc.get("@context", [])
                proof_context = proof_options["@context"]
                # Try list operations - will raise TypeError if not lists
                proof_len = len(proof_context)
                doc_prefix = doc_context[:proof_len]
                if doc_prefix != proof_context:
                    msg = "Document @context must start with all proof @context values in same order"
                    return raise_or_return(msg, raise_on_error)
            except (TypeError, AttributeError):
                msg = "Invalid @context format - must be lists"
                return raise_or_return(msg, raise_on_error)

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
    :return: VerificationResult with signature_valid=False and error message
    :raises VerificationError: If raise_on_error is True
    """
    if raise_on_error:
        raise VerificationError(msg)
    return VerificationResult(signature_valid=False, message=msg)
