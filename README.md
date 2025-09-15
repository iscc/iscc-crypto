# ISCC - Crypto

[![Tests](https://github.com/iscc/iscc-crypto/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/iscc/iscc-crypto/actions/workflows/test.yml)

`iscc-crypto` is the cryptographic signing and verification module for the [ISCC](https://iscc.codes)
(*International Standard Content Code*) Framework.

> [!CAUTION]
> **This is a proof of concept.** All releases with version numbers below v1.0.0 may break backward
> compatibility. The algorithms and code of this repository are experimental and not part of the official
> [ISO 24138:2024](https://www.iso.org/standard/77899.html) standard. **This library has not undergone a formal
> security audit by independent third parties.** While we strive to follow best practices and have implemented
> various security measures, the absence of an audit means there may be undiscovered vulnerabilities.
> **Therefore, this library should not be used in production environments where strong security guarantees are
> critical.**

## Features

- Ed25519 key generation and management
- JSON canonicalization and signing
- W3C Verifiable Credentials Data Integrity proofs
- Multibase and multikey support
- Cryptographic nonce generation with embedded node identifier
- Command-line interface for key generation and identity management
- Minimal external dependencies for core cryptographic operations

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install `iscc-crypto`:

```bash
pip install iscc-crypto
```

## Quick Start

```pycon
>>> import json
>>> import iscc_crypto as icr

>>> keypair = icr.key_from_secret("z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA")

>>> # Sign a JSON document
>>> doc = {"title": "My Document", "content": "Important data"}
>>> signed_doc = icr.sign_json(doc, keypair)

>>> # Show the signed document structure
>>> print(json.dumps(signed_doc, indent=2))
{
  "title": "My Document",
  "content": "Important data",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "pubkey": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
    "proof": "z5xCgXk6tGJTVcvrcvVok5XgLn5Mefo49ztwwW8QCmjoySH4ZEkri4XoY2JjiyaD7yD4Na7eoGPqmhPoeM2uvBmF8"
  }
}

>>> # Verify the signed document
>>> icr.verify_json(signed_doc)
VerificationResult(signature_valid=True, identity_verified=None, message=None)
```

## Documentation

Documentation is published at <https://crypto.iscc.codes>

## Development

**Requirements**

- [Python 3.10](https://www.python.org/) or higher
- [UV](https://docs.astral.sh/uv/) for dependency management

**Development Setup**

```shell
git clone https://github.com/iscc/iscc-crypto.git
cd iscc-crypto
uv sync
```

**Testing**

Run the test suite:

```shell
uv run pytest
```

## Maintainers

[@titusz](https://github.com/titusz)

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss your plans. Please
make sure to update tests as appropriate.

You may also want to join our developer chat on Telegram at <https://t.me/iscc_dev>.

## Funding

This work was supported through the Open Science Clusters’ Action for Research and Society (OSCARS) European
project under grant agreement Nº101129751.

See:
[BIO-CODES](https://oscars-project.eu/projects/bio-codes-enhancing-ai-readiness-bioimaging-data-content-based-identifiers)
project (Enhancing AI-Readiness of Bioimaging Data with Content-Based Identifiers).

## License

`iscc-crypto` is licensed under the Apache License, Version 2.0
