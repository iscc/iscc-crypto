"""Signing Module for JWS/CT (Clear Text JSON Signatures)"""

import copy
import jcs
import json
import jwcrypto.jwk
import jwcrypto.jws


def sign_object(obj, key):
    # type: (dict, dict) -> dict
    """
    Create a JWS/CT signature on any JSON/JCS serializable object.

    Implements the JWS/CT (Clear Text) signature scheme that keeps JSON objects in clear text
    format while signing. Uses JCS canonicalization and supports multiple signatures.

    :param obj: JSON/JCS serializable dict to be signed
    :param key: Signing key as dict with 'private' and 'kid' fields
    :return: Signed object with 'signatures' array containing JWS strings
    """
    # Deep copy to avoid modifying input
    result = copy.deepcopy(obj)

    # Create JWK from key
    jwk = jwcrypto.jwk.JWK.from_json(json.dumps(key))

    # Prepare JWS header
    header = {"alg": "EdDSA", "iss": key["iss"], "jwk": json.loads(jwk.export_public())}

    # Canonicalize payload
    payload: bytes = jcs.canonicalize(result, utf8=True)

    # Create JWS token in detached mode (no payload)
    jws = jwcrypto.jws.JWS(payload)
    jws.add_signature(jwk, protected=header)
    jws.detach_payload()

    # Get compact serialization
    jws_string = jws.serialize(compact=True)

    # Add signature to signatures array
    if "signatures" not in result:
        result["signatures"] = []
    result["signatures"].append(jws_string)

    return result


if __name__ == "__main__":
    from rich import print
    from iscc_crypto.keys import create_keypair

    kp = create_keypair("testkey", "https://example.com")
    print(kp)
    obj = {"nonce": "b0e9c8760d0f2e8f76fb623d16238607a14f36298552e9780f229a6401914490"}
    sobj = sign_object(obj, kp)
    print(sobj)
    sobj = sign_object(obj, kp)
    print(sobj)
