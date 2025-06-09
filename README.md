# ISCC - Crypto

[![Tests](https://github.com/iscc/iscc-crypto/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/iscc/iscc-crypto/actions/workflows/test.yml)

`iscc-crypto` is the cryptographic signing and verification module for the [ISCC](https://iscc.codes)
(*International Standard Content Code*) Framework.

## Features

- Ed25519 key generation and management
- JSON canonicalization and signing
- W3C Verifiable Credentials Data Integrity proofs
- Multibase and multikey support
- Minimal external dependencies for core cryptographic operations

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install `iscc-crypto`:

```bash
pip install iscc-crypto
```

## Quick Start

```python
import iscc_crypto as ic

# Generate new Ed25519 keypair
keypair = ic.key_generate()
print(f"Public Key: {keypair.public_key}")
print(f"Secret Key: {keypair.secret_key}")

# Sign a JSON document
doc = {"hello": "world"}
signed = ic.sign_json(doc, keypair)
print(f"Signed Doc: {signed}")

# Verify signature
verified = ic.verify_json(signed)
print(f"Verified Doc: {verified}")

# Create W3C Data Integrity Proof
vc = {"type": "VerifiableCredential", "issuer": "did:web:example.com"}
signed_vc = ic.sign_vc(vc, keypair)
print(f"Signed VC: {signed_vc}")

# Verify W3C Data Integrity Proof
result = ic.verify_vc(signed_vc)
print(f"VC Verified: {result.is_valid}")
```

## Documentation

Documentation is published at <https://crypto.iscc.codes>

## Development

**Requirements**

- [Python 3.10](https://www.python.org/) or higher
- [Poetry](https://python-poetry.org/) for dependency management

**Development Setup**

```shell
git clone https://github.com/iscc/iscc-crypto.git
cd iscc-crypto
poetry install
```

**Testing**

Run the test suite:

```shell
poetry run pytest
```

## Maintainers

[@titusz](https://github.com/titusz)

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss your plans. Please
make sure to update tests as appropriate.

You may also want to join our developer chat on Telegram at <https://t.me/iscc_dev>.

## License

`iscc-crypto` is licensed under the Apache License, Version 2.0
