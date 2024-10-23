# -*- coding: utf-8 -*-
import json
from pprint import pprint
import didkit
from iscc_crypto import keys
import asyncio


async def main():
    key = didkit.generate_ed25519_key()
    print("Ed25519 KEY:")
    print(key)

    did = didkit.key_to_did("key", key)
    print("DID for key:")
    print(did)

    key = keys.get_key("test-key").export_private()
    print("\nSECP256k1 KEY:")
    print(key)
    did = didkit.key_to_did("ethr", key)
    print("DID for key ethr metdhod:")
    print(did)

    doc = await didkit.resolve_did(did, "{}")
    docdata = json.loads(doc)
    print(json.dumps(docdata, indent=2))

    print("\nDID key for pkh method:")
    did = didkit.key_to_did("pkh:eip155:1", key)
    print(did)
    doc = await didkit.resolve_did(did, "{}")
    pprint(json.loads(doc))


if __name__ == '__main__':
    asyncio.run(main())

