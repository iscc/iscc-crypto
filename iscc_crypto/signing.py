from copy import deepcopy
from hashlib import sha256
import base58
from iscc_crypto.keys import KeyPair
import jcs


__all__ = [
    "sign_vc",
    "sign_json",
    "sign_raw",
    "create_signature_payload",
]


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


def sign_json(obj, keypair):
    # type: (dict, KeyPair) -> dict
    """
    Sign any JSON serializable object using EdDSA and JCS canonicalization.

    Creates a copy of the input object, adds the public key as 'declarer',
    and appends an EdDSA signature as 'signature' property.

    :param obj: JSON-compatible dictionary to be signed
    :param keypair: Ed25519 KeyPair for signing
    :return: Copy of input object with added 'declarer' and 'signature' properties
    """
    if "declarer" in obj or "signature" in obj:
        raise ValueError("Input must not contain 'declarer' or 'signature' fields")

    signed = deepcopy(obj)
    payload = jcs.canonicalize(signed)
    signature = sign_raw(payload, keypair)

    signed.update({"declarer": keypair.public_key, "signature": signature})
    return signed


def sign_vc(vc, keypair, options=None):
    # type: (dict, KeyPair, dict|None) -> dict
    """
    Sign a Verifiable Credential using a Data Integrity Proof with cryptosuite eddsa-jcs-2022.

    Creates a proof that follows the W3C VC Data Integrity spec (https://www.w3.org/TR/vc-di-eddsa).

    :param vc: JSON/VC-compatible dictionary to be signed
    :param keypair: Ed25519 KeyPair for signing
    :param options: Optional custom proof options
    :return: Copy of input object with added 'proof' property containing the signature
    :raises ValueError: If input already contains a 'proof' field
    """
    if "proof" in vc:
        raise ValueError("Input must not contain 'proof' field")

    # Make a copy to avoid modifying input
    signed = deepcopy(vc)

    # Create DID key URL for verification method
    did_key = f"did:key:{keypair.public_key}#{keypair.public_key}"

    if options:
        proof_options = deepcopy(options)
    else:
        # Copy @context if present
        if "@context" in signed:
            proof_options = {"@context": signed["@context"]}
        else:
            proof_options = {}
        proof_options.update(
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": did_key,
                "proofPurpose": "assertionMethod",
            }
        )

    verification_payload = create_signature_payload(signed, proof_options)
    signature = sign_raw(verification_payload, keypair)

    proof_options["proofValue"] = signature
    signed["proof"] = proof_options

    return signed


def create_signature_payload(doc, options):
    # type: (dict, dict) -> bytes
    """
    Create a signature payload from document data and proof options.

    :param doc: Document data without proof
    :param options: Proof options without proofValue
    :return: Signature payload bytes
    """
    doc_digest = sha256(jcs.canonicalize(doc)).digest()
    options_digest = sha256(jcs.canonicalize(options)).digest()
    return options_digest + doc_digest
