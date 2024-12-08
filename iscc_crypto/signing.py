from datetime import datetime, UTC
from hashlib import sha256
import base58
from iscc_crypto.keys import KeyPair
import jcs


__all__ = [
    "sign_doc",
    "sign_raw",
    "create_signature_payload",
]


def sign_doc(doc, keypair, options=None):
    # type: (dict, KeyPair, dict|None) -> dict
    """
    Create a Data Integrity Proof for a JSON object using EdDSA and JCS canonicalization.

    Creates a proof that follows the W3C VC Data Integrity spec (https://www.w3.org/TR/vc-di-eddsa).

    :param doc: JSON-compatible dictionary to be signed
    :param keypair: Ed25519 KeyPair for signing
    :param options: Optional custom proof options
    :return: Copy of input object with added 'proof' property containing the signature
    """
    # Make a copy to avoid modifying input
    signed = doc.copy()

    # Create DID key URL for verification method
    did_key = f"did:key:{keypair.public_key}#{keypair.public_key}"

    proof_options = options or {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": did_key,
    }

    verification_payload = create_signature_payload(signed, proof_options)
    signature = sign_raw(verification_payload, keypair)

    proof_options["proofValue"] = signature
    signed["proof"] = proof_options

    return signed


def sign_raw(payload, keypair):
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
    options_digest = sha256(jcs.canonicalize(proof_options)).digest()
    doc_digest = sha256(jcs.canonicalize(document_data)).digest()
    return options_digest + doc_digest
