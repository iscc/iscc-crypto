from copy import deepcopy
from enum import Enum
from hashlib import sha256
import base58
from iscc_crypto.keys import KeyPair
import jcs


__all__ = [
    "SigType",
    "sign_vc",
    "sign_json",
    "sign_raw",
    "create_signature_payload",
    "ISCC_SIG_VERSION",
]


# Version string for ISCC signature format
ISCC_SIG_VERSION = "ISCC-SIG v1.0"


class SigType(Enum):
    """Signature type enumeration for different disclosure levels."""

    AUTO = "auto"  # (default) - Uses all available keypair data
    PROOF_ONLY = "proof_only"  # Only includes signature proof (requires out-of-band pubkey for verification)
    SELF_VERIFYING = "self_verifying"  # Includes the pubkey for standalone/offline verification
    IDENTITY_BOUND = "identity_bound"  # Includes controller for attribution and online verification


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


def sign_json(obj, keypair, sigtype=SigType.AUTO):
    # type: (dict, KeyPair, SigType) -> dict
    """
    Sign any JSON serializable object using EdDSA and JCS canonicalization.

    Creates a copy of the input object, adds a `signature` property containing signature data
    based on the specified signature type. The proof property will contain an EdDSA signature
    over the entire JSON object.

    :param obj: JSON-compatible dictionary to be signed
    :param keypair: Ed25519 KeyPair for signing
    :param sigtype: Type of signature to create (AUTO, PROOF_ONLY, SELF_VERIFYING, IDENTITY_BOUND)
    :return: Copy of the input object with added 'signature' property
    """
    if "signature" in obj:
        raise ValueError("Input must not contain a 'signature' field")

    signed = deepcopy(obj)
    signed["signature"] = {"version": ISCC_SIG_VERSION}

    # Determine what to include based on sigtype
    if sigtype == SigType.AUTO:
        # Include all available data from keypair
        if keypair.controller:
            signed["signature"]["controller"] = keypair.controller
        if keypair.key_id:
            signed["signature"]["keyid"] = keypair.key_id
        signed["signature"]["pubkey"] = keypair.public_key
    elif sigtype == SigType.PROOF_ONLY:
        # Only include proof (added after signing)
        pass
    elif sigtype == SigType.SELF_VERIFYING:
        # Include pubkey for verification
        signed["signature"]["pubkey"] = keypair.public_key
    elif sigtype == SigType.IDENTITY_BOUND:
        # Include controller and pubkey for full attribution
        if not keypair.controller:
            raise ValueError("IDENTITY_BOUND sigtype requires keypair with controller")
        signed["signature"]["controller"] = keypair.controller
        if keypair.key_id:
            signed["signature"]["keyid"] = keypair.key_id
        signed["signature"]["pubkey"] = keypair.public_key

    payload = jcs.canonicalize(signed)
    signature = sign_raw(payload, keypair)

    signed["signature"]["proof"] = signature
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
