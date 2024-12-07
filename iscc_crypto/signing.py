from datetime import datetime, UTC
from hashlib import sha256
import base58
from iscc_crypto.keys import KeyPair
import jcs


__all__ = [
    "sign_json",
    "create_signature",
]


def sign_json(obj, keypair, created=None):
    # type: (dict, KeyPair, str) -> dict
    """Sign object in conformance with https://www.w3.org/TR/vc-di-eddsa"""

    did_key = f"did:key:{keypair.public_key}#{keypair.public_key}"

    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": created or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": did_key,
        "proofPurpose": "assertionMethod",
    }

    payload_digest = sha256(jcs.canonicalize(obj)).digest()
    options_digest = sha256(jcs.canonicalize(proof_options)).digest()
    signature_payload = options_digest + payload_digest
    signature = create_signature(signature_payload, keypair)

    proof_options["proofValue"] = signature
    signed_json = obj.copy()
    signed_json["proof"] = proof_options

    return signed_json


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
