from datetime import datetime, UTC
from hashlib import sha256
import base58
from iscc_crypto.keys import KeyPair
import jcs


__all__ = [
    "sign_json",
    "create_signature",
    "create_signature_payload",
]


def sign_json(result, keypair, created=None):
    # type: (dict, KeyPair, str|None) -> dict
    """
    Create a Data Integrity Proof for a JSON object using EdDSA and JCS canonicalization.

    Creates a proof that follows the W3C VC Data Integrity spec (https://www.w3.org/TR/vc-di-eddsa).
    The proof is added as a 'proof' property to a copy of the input object. The signing process:
    1. Optionally injects context for JSON-LD processing if @context exists
    2. Canonicalizes the input object and proof options using JCS
    3. Creates a composite hash of both canonicalized values
    4. Signs the hash with the provided Ed25519 key
    5. Encodes the signature in multibase format

    Context injection follows section 2.4.2 of the spec:
    - If @context exists and Data Integrity terms are used, injects data integrity context
    - Context injection may be skipped for non-JSON-LD processing
    - If no @context is present, no extensions to the spec are allowed

    :param result: JSON-compatible dictionary to be signed
    :param keypair: Ed25519 KeyPair for signing
    :param created: Optional ISO timestamp string (default: current UTC time)
    :return: Copy of input object with added 'proof' property containing the signature
    """
    # Make a copy to avoid modifying input
    result = result.copy()

    # Handle context injection per spec section 2.4.2
    if "@context" in result:
        # Convert string context to array
        if isinstance(result["@context"], str):
            result["@context"] = [result["@context"]]

        # Only inject if neither data integrity nor v2 credentials context present
        has_di_context = "https://w3id.org/security/data-integrity/v2" in result["@context"]
        has_vc_context = "https://www.w3.org/ns/credentials/v2" in result["@context"]

        if not (has_di_context or has_vc_context):
            # Context injection is optional for non-JSON-LD processing
            # We inject it since we're using Data Integrity terms (proof, proofValue)
            result["@context"].append("https://w3id.org/security/data-integrity/v2")

    # Create DID key URL for verification method
    did_key = f"did:key:{keypair.public_key}#{keypair.public_key}"

    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": created or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": did_key,
        "proofPurpose": "assertionMethod",
    }

    verification_payload = create_signature_payload(result, proof_options)
    signature = create_signature(verification_payload, keypair)

    proof_options["proofValue"] = signature
    result["proof"] = proof_options

    return result


def create_signature(payload, keypair):
    # type: (bytes, KeyPair) -> str
    """
    Create a detached EdDSA signature over raw bytes. The signature is produced according to
    [RFC8032] and encoded using the base-58-btc header and alphabet conformant with eddsa-jcs-2022.

    :param payload: Bytes to sign
    :param keypair: KeyPair containing the signing key
    :return: Multibase encoded signature (z-base58-btc)
    """
    # Sign the payload using cached private key
    signature = keypair.sk_obj.sign(payload)

    # Encode signature in multibase format
    return "z" + base58.b58encode(signature).decode("utf-8")


def create_signature_payload(document_data, proof_options):
    # type: (dict, dict) -> bytes
    """
    Create a signature payload from document data and proof options.

    :param document_data: Document data without proof
    :param proof_options: Proof options without proofValue
    :return: Signature payload bytes
    """
    doc_digest = sha256(jcs.canonicalize(document_data)).digest()
    options_digest = sha256(jcs.canonicalize(proof_options)).digest()
    return options_digest + doc_digest
