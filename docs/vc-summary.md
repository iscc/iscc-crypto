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
1. Enveloping proofs - wrap the credential data

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
1. The transformation preserves @context values
1. The result uses at least one securing mechanism
1. It has a registered media type

## Relevance for ISCC Timestamping

The ISCC Timestamping Protocol could:

1. Use VC data model for timestamp responses
1. Leverage existing securing mechanisms
1. Benefit from standardized status checking
1. Enable integration with VC ecosystem tools

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
1. RDF Dataset Canonicalization - For JSON-LD with semantic meaning

## Relevance for ISCC Timestamping

The Data Integrity specification provides:

1. Well-defined proof formats and verification
1. Standardized cryptographic suite requirements
1. Flexible transformation options
1. Built-in replay attack prevention

Key considerations:

- ISCC timestamps could use DataIntegrityProof format
- Cryptographic suites need to support microsecond precision
- Server-id could be encoded in verificationMethod
- Domain/challenge useful for timestamp security

# EdDSA-JCS-2022 Cryptosuite - Timestamping Relevance

## Core Features

The `eddsa-jcs-2022` cryptosuite provides:

- Ed25519 signatures (EdDSA with edwards25519 curve)
- JSON Canonicalization Scheme (JCS) for data normalization
- Base58-btc encoding for signatures and keys
- Strong unforgeability (SUF-CMA)

## Key Format

Uses Multikey format:

- Public key prefix: `0xed01`
- Base58-btc encoded with `z` prefix
- 32-byte public key data
- Example: `z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2`

## Proof Generation

1. Canonicalize document using JCS
1. Hash canonicalized document (SHA-256)
1. Hash proof configuration (SHA-256)
1. Concatenate hashes
1. Sign with Ed25519
1. Base58-btc encode signature

## Security Properties

- SUF-CMA (strong unforgeability under chosen message attacks)
- BS (binding signatures)
- SBS (strongly binding signatures)
- Protection against key substitution attacks

## Relevance for ISCC Timestamping

The cryptosuite provides:

1. Fast and secure signatures
1. Deterministic canonicalization
1. Compact key and signature encoding
1. Proven security properties

Key considerations:

- JCS ensures stable hashing of timestamp data
- Ed25519 performance suits high-volume timestamping
- Security properties match timestamping needs
- Base58-btc encoding aligns with ISCC practices

# Controller Document - Timestamping Relevance

## Core Concepts

A **controller document** provides:

- Cryptographic material for verification
- Service endpoints for interaction
- Verification relationships and methods
- Controller delegation capabilities

## Required Properties

- `id` - URL uniquely identifying the document/controller
- `type` - For verification methods (e.g., "JsonWebKey", "Multikey")
- `controller` - URL identifying the controller of verification methods

## Verification Methods

Two supported key formats:

1. JsonWebKey - Standard JWK format
1. Multikey - Compact multiformat encoding
   - Same format as used in ISCC protocol
   - Supports Ed25519, ECDSA, BLS12-381

## Verification Relationships

Defines how verification methods may be used:

- `authentication` - For proving control
- `assertionMethod` - For making claims
- `capabilityInvocation` - For invoking capabilities
- `capabilityDelegation` - For delegating control

## Relevance for ISCC Timestamping

The Controller Document specification provides:

1. Standard way to publish notary public keys
1. Well-defined key formats and relationships
1. Service endpoint discovery mechanism
1. Delegation capabilities for distributed notaries

Key considerations:

- Could standardize ISCC notary key publication
- Multikey format already aligns with ISCC
- Service endpoints useful for notary discovery
- Verification relationships map to timestamp use cases

# DID Core - Timestamping Relevance

## Core Concepts

A **Decentralized Identifier (DID)** provides:
- Globally unique identification without central authority
- Cryptographically verifiable control
- Resolution to DID documents containing verification methods
- Service endpoint discovery

## DID Syntax

Three-part structure:
1. `did:` - URI scheme identifier
2. Method name - Identifies DID method
3. Method-specific identifier - Unique within method

Example: `did:example:123456789abcdefghi`

## DID Documents

Required Properties:
- `id` - The DID itself
- `@context` - JSON-LD context definitions

Optional Properties:
- `verificationMethod` - List of verification methods
- `service` - List of service endpoints
- `controller` - DIDs of authorized controllers

## Verification Methods

Standard key representation formats:
1. `publicKeyJwk` - JSON Web Key format
2. `publicKeyMultibase` - Multibase/Multicodec format
   - Same format as ISCC protocol uses
   - Supports Ed25519, ECDSA, etc.

## Service Endpoints

Enables discovery of:
- Authentication services
- Authorization services
- Interaction endpoints
- Additional metadata

## Relevance for ISCC Timestamping

The DID Core specification provides:
1. Decentralized identifier system for notaries
2. Standard key and service discovery
3. Flexible verification methods
4. Method-specific customization

Key considerations:
- Could use DIDs to identify ISCC notaries
- DID methods could map to notary networks
- Service endpoints enable notary discovery
- Verification methods align with ISCC needs

# DID Method Key - Timestamping Relevance

## Core Features

The `did:key` method provides:
- Purely generative DIDs from public keys
- No registry or blockchain required
- Deterministic DID Document generation
- Support for multiple key types

## Key Format

Uses Multibase/Multicodec encoding:
- Base58-btc encoded with `z` prefix
- Multicodec identifier for key type
- Raw public key bytes
- Example: `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`

## Supported Key Types

Common cryptographic suites:
- Ed25519 (starts with `z6Mk`)
- X25519 (starts with `z6LS`)
- Secp256k1 (starts with `zQ3s`)
- P-256 (starts with `zDn`)

## Document Generation

Automatic expansion to DID Document:
- Verification methods from public key
- Standard verification relationships
- Key agreement capabilities
- No external resolution needed

## Relevance for ISCC Timestamping

The did:key method provides:
1. Registry-free notary identification
2. Deterministic key verification
3. Compact key representation
4. Fast resolution performance

Key considerations:
- Could identify notaries via did:key
- Format aligns with ISCC multibase usage
- Ed25519 support matches ISCC needs
- No blockchain dependency required

# DID Method Web - Timestamping Relevance

## Core Features

The `did:web` method provides:
- DNS and HTTPS based DID resolution
- No blockchain/special infrastructure needed
- Leverages existing web security (TLS)
- Domain reputation as trust anchor

## DID Format

Uses domain names and paths:
- Basic: `did:web:example.com`
- With path: `did:web:example.com:user:alice`
- With port: `did:web:example.com%3A3000`
- Resolves to: `https://{domain}/.well-known/did.json`

## Security Features

Required security measures:
- HTTPS with strong TLS configuration
- Domain name validation
- DNS security (DNSSEC recommended)
- Cross-Origin Resource Sharing (CORS)

## Document Resolution

Simple HTTPS-based process:
1. Convert DID to HTTPS URL
2. Fetch DID document via GET request
3. Verify domain/certificate match
4. Parse JSON-LD document

## Relevance for ISCC Timestamping

The did:web method provides:
1. Simple web-based notary identification
2. Built on existing web infrastructure
3. Domain reputation for trust
4. Easy key rotation/management

Key considerations:
- Could identify notaries via did:web
- Leverages existing DNS/TLS security
- Simple to deploy and maintain
- Domain reputation aids trust
