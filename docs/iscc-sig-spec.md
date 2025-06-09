# ISCC Signature Specification

This specification defines a simple JSON signature format for ISCC metadata using EdDSA signatures and JSON
Canonicalization Scheme (JCS).

## Overview

ISCC Signatures add a `signature` object to any JSON document, providing cryptographic integrity and optional
identity attribution. The signature is computed over the entire JSON object using JCS canonicalization.

## Signature Format

```json
{
  "your": "data",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "controller": "<optional-identity-uri>",
    "keyid": "<optional-key-identifier>",
    "pubkey": "<optional-multibase-public-key>",
    "proof": "<multibase-signature>"
  }
}
```

### Fields

- **version** (required): Must be `"ISCC-SIG v1.0"`
- **controller** (optional): URI identifying the key controller (e.g., DID or CID)
- **keyid** (optional): Specific key identifier within the controller document
- **pubkey** (optional): Ed25519 public key in multibase format (z-base58-btc with ED01 prefix)
- **proof** (required): EdDSA signature in multibase format (z-base58-btc)

## Signature Types

### PROOF_ONLY

Minimal signature containing only version and proof. Requires out-of-band public key for verification.

### SELF_VERIFYING

Includes the public key for standalone verification without external dependencies.

### IDENTITY_BOUND

Includes controller URI and public key for full attribution and identity verification.

### AUTO (default)

Includes all available fields from the signing keypair.

## Signing Process

1. Ensure input JSON has no existing `signature` field
2. Create a copy and add `signature` object with:
   - `version`: "ISCC-SIG v1.0"
   - Optional fields based on signature type
3. Canonicalize the entire object using JCS
4. Sign the canonical bytes with Ed25519
5. Encode signature as multibase (z-base58-btc)
6. Add signature to `signature.proof` field

## Verification Process

1. Extract and validate `signature` object:
   - Check `version` equals "ISCC-SIG v1.0"
   - Extract `proof` field
2. Obtain public key from:
   - `signature.pubkey` field (if present)
   - External parameter (if provided)
3. Create copy without `signature.proof` field
4. Canonicalize using JCS
5. Verify EdDSA signature against canonical bytes

## Identity Verification (Optional)

When an identity document is provided:

1. Check if `signature.controller` exists
2. Verify the public key is authorized in the identity document's `verificationMethod` array
3. Match verification methods by:
   - Same controller URI AND
   - Same public key value (publicKeyMultibase)
   - If `keyid` is provided: also match against verification method's id
   - If `keyid` is absent: the public key itself acts as the identifier

## Implementation Requirements

- **Cryptography**: Ed25519 signatures per RFC 8032
- **Canonicalization**: JSON Canonicalization Scheme (RFC 8785)
- **Encoding**: Multibase z-base58-btc for keys and signatures
- **Public Keys**: 34-byte format with 2-byte ED01 prefix + 32-byte key
- **Signatures**: 64-byte Ed25519 signatures

## Example

```json
{
  "@context": "https://www.w3.org/ns/credentials/v2",
  "type": "VerifiableCredential",
  "issuer": "did:iscc:miagqfbqktdum3tse4qc",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "controller": "did:iscc:miagqfbqktdum3tse4qc",
    "pubkey": "z287jyNKkPBN5ixd7XKDn7KCVN6ktVFbp1A7fjvW3gWAEQwJy",
    "proof": "z5rG9VguGDRinEPG6fG1M9aJLBE5BJMVMsSaK65XKMxBfRJQBqNZfKnH8tFDBtjJSkPBJvahPJUqDdDjmdEQJgWpQ"
  }
}
```
