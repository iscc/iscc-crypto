# ISCC - Crypto

The `iscc-crypto` python package implements cryptography related functionalities within the ISCC
Framework.

## Key Architectural Components:

1. Key Management (create, save, load, export, import, set)
1. Signing Operations (sign, verify_signature)
1. Timestamping Operations (timestamp, verify_timestamp)
1. Uses established standards (JWS, JCS, JWT)
1. Web-domain based trust model
1. Distributed timestamping protocol

# Quick Start

Key storage is delegated to the keyring service of the operating system. Be sure to understand the
security properties of your systems keyring service. See
[Python Keyring Module](https://pypi.org/project/keyring/)

### Create a new key

```python
import iscc_crypto

# Will create a new key or return an existing key
key = iscc_crypto.get_key()
print(key)

metadata = {
  "@context": "http://purl.org/iscc/context",
  "@type": "CreativeWork",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KID6X6GUH5F5G",
  "name": "The never ending story",
}

signed_metadata = iscc_crypto.sign(metadata, key)
```
