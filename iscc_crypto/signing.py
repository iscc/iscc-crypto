"""
Signing Module for JWS/CT (Clear Text JSON Signatures)

To ease implementation we start with a restricted subset from the JOSE Standards with an option to
expand as adoption grows.

To sign arbitrary JSON objects and make implementations easier and more robust we use the following
restricted subset from the [JOSE](https://datatracker.ietf.org/group/jose/documents/)
(JavaScript Object Signing and Encryption) framework of standards:

- JWS Serialization MUST use compact mode - RFC 7515
- JWS Signature algorithms is restricted to EdDSA with curve Ed25519 - RFC 8037
- JWS Signature payloads MUST be detached - RFC 7515
- JSON payloads MUST be serialized with JCS for signing - RFC 8785
- Signatures MUST be processed according to `JWS Clear Text JSON Signature Option` (JWS/CT)
- Signatures MUST be stored on the top-level `signatures` property of the signed JSON object
"""

from loguru import logger as log
import copy
import jcs
import json
import jwcrypto.jwk
import jwcrypto.jws


def sign_object(obj, keypair):
    # type: (dict, dict) -> dict
    """
    Create a JWS/CT signature on any JSON/JCS serializable object.

    Implements the JWS/CT (Clear Text) signature scheme that keeps JSON objects in clear text
    format while signing. Uses JCS canonicalization and supports multiple signatures.

    :param dict obj: JSON/JCS serializable dict to be signed
    :param dict keypair: Keypair for signing as dict
    :return: Signed object with 'signatures' array containing JWS strings
    """
    # Deep copy to avoid modifying input
    result = copy.deepcopy(obj)

    # Remove eventual existing signatures
    signatures = result.pop("signatures", [])

    # Create JWK from key
    jwk = jwcrypto.jwk.JWK.from_json(json.dumps(keypair))

    # Prepare JWS header
    header = {"alg": "EdDSA", "iss": keypair["iss"], "jwk": json.loads(jwk.export_public())}

    # Canonicalize payload
    payload: bytes = jcs.canonicalize(result, utf8=True)

    # Create JWS token in detached mode (no payload)
    jws = jwcrypto.jws.JWS(payload)
    jws.add_signature(jwk, protected=header)
    jws.detach_payload()

    # Get compact serialization
    jws_string = jws.serialize(compact=True)

    # Add back signatures
    result["signatures"] = signatures + [jws_string]
    return result


def verify_object(obj):
    # type: (dict) -> bool
    """
    Verify JWS/CT signatures on a JSON object.

    Verifies all signatures in the 'signatures' array against the canonicalized object
    (excluding the signatures array itself). Returns True only if all signatures are valid.

    :param obj: JSON object with JWS/CT signatures to verify
    :return: True if all signatures are valid, False otherwise
    """
    # Deep copy and remove signatures for canonicalization
    data = copy.deepcopy(obj)
    signatures = data.pop("signatures", None)
    if signatures is None or not isinstance(signatures, list):
        return False
    if not signatures:
        return False

    # Canonicalize payload
    payload: bytes = jcs.canonicalize(data, utf8=True)

    # Try to verify each signature
    for sig in signatures:
        try:
            # Parse JWS token
            jws = jwcrypto.jws.JWS()
            jws.deserialize(sig)

            # Get protected header
            protected = jws.objects["protected"]
            header = json.loads(protected)
            if "jwk" not in header:
                log.error("jwk not in header")
                return False
            jwk = jwcrypto.jwk.JWK(**header["jwk"])

            # Set payload and verify signature
            jws.objects["payload"] = payload
            jws.verify(jwk)
        except Exception as e:
            log.error(e)
            return False

    return True


if __name__ == "__main__":
    from rich import print
    from iscc_crypto.keys import create_keypair

    kp = create_keypair("testkey", "https://example.com")
    print(kp)
    obj = {"nonce": "b0e9c8760d0f2e8f76fb623d16238607a14f36298552e9780f229a6401914490"}
    sobj1 = sign_object(obj, kp)
    print(sobj1)
    sobj2 = sign_object(sobj1, kp)
    print(sobj2)
    print(verify_object(sobj1))
    print(verify_object(sobj2))
