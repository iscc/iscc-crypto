# ISCC-CRYPTO Usage Guide

## Overview

ISCC-CRYPTO is a Python package for cryptographic operations related to ISCC (International Standard
Content Code). It provides Ed25519 key management and signing capabilities for verifiable
credentials following W3C standards.

## Installation

```bash
pip install iscc-crypto
```

## Key Management

### Generate New Keys

```python
from iscc_crypto import key_generate

# Generate a simple Ed25519 keypair without controller info
keypair = key_generate()
print(keypair.public_key)    # z-base58 encoded public key
print(keypair.secret_key)    # z-base58 encoded secret key


# Generate a new Ed25519 keypair with controller and key ID
keypair = key_generate(
    controller="https://example.com",
    key_id="key-1"
)
print(keypair.controller)    # https://example.com
print(keypair.key_id)       # key-1

# Access the controller document
print(keypair.controller_document)  # W3C controller document
```

### Load Existing Keys

```python
from iscc_crypto import key_from_secret

# Load keypair without controller info
keypair = key_from_secret("z...")

# Load keypair from existing secret key with controller info
keypair = key_from_secret(
    secret_key="z...",  # z-base58 encoded secret key
    controller="https://example.com",
    key_id="key-1"
)
```

### Load Keys from Environment

```python
from iscc_crypto import key_from_env

# Load keypair from environment variables:
# - ISCC_CRYPTO_SECRET_KEY: Required z-base58 encoded secret key
# - ISCC_CRYPTO_CONTROLLER: Optional controller URL
# - ISCC_CRYPTO_KEY_ID: Optional key identifier
keypair = key_from_env()
```

## Signing Operations

### Sign Raw Data

```python
from iscc_crypto import sign_raw

# Sign raw bytes
signature = sign_raw(b"data to sign", keypair)
```

### Sign JSON Data

```python
from iscc_crypto import sign_json

# Sign JSON object
data = {"key": "value"}
signed = sign_json(data, keypair)
```

### Sign Verifiable Credentials

```python
from iscc_crypto import sign_vc

# Sign a verifiable credential
vc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"]
}
signed_vc = sign_vc(vc, keypair)
```

## Verification

All verification functions return a `VerificationResult` object with two fields:

- `is_valid`: Boolean indicating if verification succeeded
- `message`: Optional error message if verification failed

By default, verification functions raise a `VerificationError` on failure. Pass
`raise_on_error=False` to get a `VerificationResult` instead.

### Verify Raw Signatures

```python
from iscc_crypto import verify_raw

# Verify raw signature (raises VerificationError on failure)
result = verify_raw(payload, signature, keypair.pk_obj)
print(result.is_valid)  # True

# Get VerificationResult instead of raising
result = verify_raw(payload, signature, keypair.pk_obj, raise_on_error=False)
if not result.is_valid:
    print(f"Verification failed: {result.message}")
```

### Verify JSON Signatures

```python
from iscc_crypto import verify_json

# Verify signed JSON
result = verify_json(signed_data, raise_on_error=False)
if result.is_valid:
    print("Signature valid")
else:
    print(f"Invalid signature: {result.message}")
```

### Verify Credentials

```python
from iscc_crypto import verify_vc

# Verify signed credential
result = verify_vc(signed_credential, raise_on_error=False)
if not result.is_valid:
    print(f"Verification failed: {result.message}")
```

## Important Notes

- All public/secret keys use z-base58 multibase encoding
- Signatures follow the EdDSA-JCS-2022 cryptosuite specification
- Verification methods support both error raising and result objects
- Key generation supports optional controller URLs and key IDs
- All signing operations create copies and don't modify input data
