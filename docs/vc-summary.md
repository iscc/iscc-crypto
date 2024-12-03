# Verifiable Credentials Data Model - Timestamping Relevance

## Core Concepts

A **verifiable credential** contains:
- Claims made by an issuer about a subject
- Metadata about the credential itself
- A cryptographic proof that makes the credential tamper-evident

## Required Properties

- `@context` - Must include `https://www.w3.org/ns/credentials/v2` as first item
- `type` - Must include `VerifiableCredential` as first type
- `issuer` - URL or object with `id` property identifying the issuer
- `credentialSubject` - Contains the actual claims about the subject(s)

## Optional Properties

- `id` - URL uniquely identifying the credential
- `validFrom` - ISO datetime when the credential becomes valid
- `validUntil` - ISO datetime when the credential ceases to be valid
- `credentialStatus` - Information about current status (e.g., revocation)

## Securing Mechanisms

Two classes of securing mechanisms are supported:
1. Embedded proofs - included in the credential data
2. Enveloping proofs - wrap the credential data

The Data Integrity proof format uses an embedded proof like:
```json
{
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:example:123#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQp...FPP2oumHKtz"
  }
}
```

## Media Types

- `application/vc` - For verifiable credentials
- `application/vp` - For verifiable presentations

## Ecosystem Compatibility

A digital credential format is compatible with the VC ecosystem if:
1. It can be transformed into a conforming VC document
2. The transformation preserves @context values
3. The result uses at least one securing mechanism
4. It has a registered media type

## Relevance for ISCC Timestamping

The ISCC Timestamping Protocol could:
1. Use VC data model for timestamp responses
2. Leverage existing securing mechanisms
3. Benefit from standardized status checking
4. Enable integration with VC ecosystem tools

Key differences to consider:
- ISCC focuses on content timestamping vs identity credentials
- ISCC uses specialized timestamp format vs generic VC claims
- ISCC has specific server-id requirements not in VC model

# Data Integrity - Timestamping Relevance

## Core Concepts

A **data integrity proof** provides:
- Information about the proof mechanism
- Parameters required for verification
- The proof value itself

## Required Properties for DataIntegrityProof

- `type` - Must be "DataIntegrityProof"
- `cryptosuite` - Identifier for the cryptographic suite
- `proofValue` - Base-encoded binary data for verification

## Optional Properties

- `id` - URL uniquely identifying the proof
- `created` - ISO datetime when proof was created
- `expires` - ISO datetime when proof expires
- `verificationMethod` - URL pointing to verification key
- `proofPurpose` - Intended use of the proof
- `domain` - Security domain(s) where proof is valid
- `challenge` - One-time value to prevent replay attacks
- `nonce` - Random value to increase privacy

## Cryptographic Suites

A conforming cryptographic suite must specify:
- Transformation algorithms (if any)
- Hashing algorithms and parameters
- Proof serialization algorithms
- Proof verification algorithms

## Securing Data

Two common transformation approaches:
1. JSON Canonicalization (JCS) - For pure JSON data
2. RDF Dataset Canonicalization - For JSON-LD with semantic meaning

## Relevance for ISCC Timestamping

The Data Integrity specification provides:
1. Well-defined proof formats and verification
2. Standardized cryptographic suite requirements
3. Flexible transformation options
4. Built-in replay attack prevention

Key considerations:
- ISCC timestamps could use DataIntegrityProof format
- Cryptographic suites need to support microsecond precision
- Server-id could be encoded in verificationMethod
- Domain/challenge useful for timestamp security
