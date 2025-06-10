# ISCC Signature Specification

This specification defines a simple JSON signature format for ISCC metadata using EdDSA signatures and JSON
Canonicalization Scheme (JCS).

## Why a Custom Signature Format?

The ISCC framework requires a signature format that balances simplicity, flexibility, and standards compliance:

- **Simplicity**: Unlike complex standards like JSON-LD signatures or JWT, ISCC signatures are straightforward
  JSON objects that developers can implement without extensive cryptographic libraries
- **Flexibility**: The format supports three verification modes (proof-only, self-verifying, identity-bound)
  allowing use cases from simple integrity checks to full identity verification
- **Minimal Dependencies**: Uses only Ed25519 and JCS, avoiding heavyweight dependencies like JSON-LD processors
  or JWT libraries
- **Identity Agnostic**: Works with any identity system (DIDs, CIDs, URLs) without requiring specific identity
  infrastructure
- **Backward Compatible**: The simple structure ensures long-term stability and easy migration paths

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

## ISCC Signature Example

### Keypair Information

- **Public Key**: `z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx`
- **Secret Key**: `z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA`
- **Controller**: `did:web:crypto.iscc.codes:alice`

### Controlled Identity Document

Must be published at http://crypto.iscc.codes/alice/did.json:

```json
{
  "id": "did:web:crypto.iscc.codes:alice",
  "verificationMethod": [
    {
      "id": "did:web:crypto.iscc.codes:alice#z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
      "type": "Multikey",
      "controller": "did:web:crypto.iscc.codes:alice",
      "publicKeyMultibase": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
    }
  ],
  "authentication": [
    "did:web:crypto.iscc.codes:alice#z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
  ],
  "assertionMethod": [
    "did:web:crypto.iscc.codes:alice#z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
  ],
  "capabilityDelegation": [
    "did:web:crypto.iscc.codes:alice#z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
  ],
  "capabilityInvocation": [
    "did:web:crypto.iscc.codes:alice#z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
  ]
}
```

### Document to be Signed

```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*"
}
```

### Example: IDENTITY_BOUND Signature

Includes controller URI and public key for full attribution.

```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "controller": "did:web:crypto.iscc.codes:alice",
    "pubkey": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
    "proof": "z3fVSTAfmNZTp1unwoXsyQa9sUx7gAxaZVavBLEPA5muup5ukxbCrirS8jcuhKzvQ3kp6UCJz2RA5wkZhYZ49o5wr"
  }
}
```
