# -*- coding: utf-8 -*-
import json
from jwcrypto.common import json_encode
import iscc_crypto
from typing import Dict
from jwcrypto import jws, jwk
import jcs

__all__ = [
    "sign",
    "verify",
]


def sign(metadata: Dict, key: jwk.JWK) -> Dict:
    """
    Sign metadata with JWS/CT
    """
    msg = metadata.copy()
    payload = jcs.canonicalize(msg)
    token = jws.JWS(payload)
    protected = json_encode({"alg": "ES256K"})
    header = json_encode({"kid": key.thumbprint()})
    token.add_signature(key, "ES256K", protected=protected, header=header)
    token.detach_payload()
    signature = {
        "signature": token.serialize(compact=True),
        "pubkey": key.export_public(as_dict=True)
    }
    msg["signature"] = signature
    return msg


def verify(metadata) -> bool:
    msg = metadata.copy()
    signature = msg.pop('signature')
    sig = jws.JWS()
    sig.deserialize(signature['signature'])
    sig.objects['payload'] = jcs.canonicalize(msg)
    print("\n######## Deserialized Signature:")
    pprint(sig.objects)
    key = jws.JWK(**signature['pubkey'])
    sig.verify(key)
    return True


if __name__ == '__main__':
    from pprint import pprint
    metadata = {
        "@context": "http://purl.org/iscc/context",
        "@type": "CreativeWork",
        "$schema": "http://purl.org/iscc/schema",
        "iscc": "ISCC:KID6X6GUH5F5G",
        "name": "The never ending story",
        "identifier": ["ISRC:AA6Q72000047", "ISBN:9783866801929"]
    }
    priv_key = iscc_crypto.get_key()
    signed = sign(metadata, priv_key)
    print(f'######## Metadata:')
    print(json.dumps(metadata, indent=2))
    print(f'\n######## Key:')
    pprint(priv_key)
    print(f'\n######## Signed Message:')
    print(json.dumps(signed, indent=2))
    print(f'\n######## Verify Message:')
    pprint(verify(signed))


