# -*- coding: utf-8 -*-
from typing import Optional

from jwcrypto.common import json_decode
from loguru import logger as log
import keyring
import getpass
from jwcrypto import jwk


def get_key(name: Optional[str] = None) -> jwk.JWK:
    """
    Returns the key stored under `name`. If `name` is blank returns the default key.
    If no key exists for `name` a new EC secp256k1 key is generated, stored and
    returned.
    """
    name = name or "iscc"
    user = getpass.getuser()
    kr = keyring.get_keyring()
    keydata = kr.get_password(service=name, username=user)
    if keydata:
        key = jwk.JWK(**json_decode(keydata))
    else:
        key = generate_key()
        keydata = key.export(private_key=True, as_dict=False)
        kr.set_password(service=name, username=user, password=keydata)
    return key


def generate_key():
    """
    Generate a new EC secp256k1 key
    """
    key = jwk.JWK.generate(kty="EC", crv="secp256k1")
    log.info(f"Generated new key: {key.export(private_key=False)}")
    return key


if __name__ == "__main__":
    k = get_key()
    print("KEY:")
    print(k)
    print("PUBKEY DICT")
    print(k.export_public(as_dict=True))
    print("PUBKEY PEM")
    print(k.export_to_pem(private_key=False, password=None))
    print("PRIVATE KEY")
    print(k.export_private())
