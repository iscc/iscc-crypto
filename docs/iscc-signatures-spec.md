# ISCC Signatures — Cryptographic signatures for International Standard Content Code metadata

## Foreword

This document has been prepared by Technical Committee ISO/TC 46, Information and documentation,
Subcommittee SC 9, Identification and description.

## Introduction

The first edition of ISO 24138:2024 specifies the syntax, structure, and initial algorithms for the
International Standard Content Code (ISCC). An ISCC is a deterministic data descriptor that applies
to a specific digital asset. Anyone can generate an ISCC using the open-source reference
implementation or any other application conforming to the provisions of ISO 24138:2024.

However, an ISCC aplies only to the digital asset itself. It makes no assumptions about any
associated actors or metadata. Additionally, ISO 24138:2024 does not define any methods for the
interoperable discovery of actors or metadata associated with a digital asset.

This document defines the use of digital signatures to associate ISCC metadata with an actor,
enabling verifiable attribution, integrity protection, and progressive disclosure of signer
identity.

## 1 Scope

This document specifies cryptographic signature methods for ISCC metadata documents. It covers:

1. JSON-based metadata signature format;
2. EdDSA signature generation using Ed25519 elliptic curve;
3. JSON Canonicalization Scheme (JCS) for deterministic document serialization;
4. Progressive disclosure mechanisms for signer identity;
5. Verification methods for signed ISCC metadata;
6. Integration with W3C Decentralized Identifiers (DIDs) and Verifiable Credentials.

This document does not specify:

- key management systems or policies;
- user interface requirements for signature presentation;
- business logic for signature validation workflows.

## 2 Normative references

The following documents are referred to in the text in such a way that some or all of their content
constitutes requirements of this document. For dated references, only the edition cited applies. For
undated references, the latest edition of the referenced document (including any amendments)
applies.

ISO 24138:2024, Information and documentation — International Standard Content Code (ISCC)

RFC 8037, JSON Web Signature (JWS)

RFC 8785, JSON Canonicalization Scheme (JCS)

RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)

W3C Recommendation, Decentralized Identifiers (DIDs) v1.0

W3C Recommendation, Verifiable Credentials Data Model v2.0

W3C Working Draft, Verifiable Credential Data Integrity 1.0

## 3 Terms and definitions

For the purposes of this document, the following terms and definitions apply.

### 3.1

**controller** entity that has authority over a cryptographic key and is responsible for managing
the associated digital credential

Note 1 to entry: Controllers are identified by dereferenceable URIs such as did:web or HTTP(S) URLs.

### 3.2

**digital signature** cryptographic mechanism that provides data integrity, authentication, and
non-repudiation for digital documents

### 3.3

**JSON Canonicalization Scheme** **JCS** deterministic transformation of JSON data into a canonical
form suitable for cryptographic operations

### 3.4

**keypair** combination of a private key and its corresponding public key used for asymmetric
cryptography

### 3.5

**multibase** encoding scheme that provides a self-describing base encoding prefix

### 3.6

**progressive disclosure** approach that allows signers to reveal identity information incrementally
from anonymous to pseudonymous to fully public

### 3.7

**proof** cryptographic evidence that demonstrates the integrity and authenticity of a signed
document

### 3.8

**verification method** cryptographic key or procedure used to verify digital signatures or proofs

## 4 Signature structure and format

### 4.1 General requirements

ISCC metadata signatures shall use JSON as the base document format with embedded signature
properties.

The signature properties shall be contained within a top-level property named "signature" in the
JSON object being signed.

### 4.2 Signature properties

#### 4.2.1 Required properties

The signature shall contain the following required property:

**proof**: multibase-encoded Ed25519 signature using z-base58btc encoding

#### 4.2.2 Optional properties

The signature may contain the following optional properties:

**pubkey**: public key of the signer in multibase format for offline verification

**controller**: URI identifying the entity controlling the signing key

**keyid**: identifier of the specific key within the controller's key set

### 4.3 Progressive disclosure levels

#### 4.3.1 Anonymous signatures

Signatures containing only the proof property provide privacy-preserving verification requiring
out-of-band public key distribution.

#### 4.3.2 Pseudonymous signatures

Signatures containing proof and pubkey properties enable non-interactive verification while
maintaining pseudonymity.

#### 4.3.3 Public signatures

Signatures containing proof, pubkey, and controller properties enable full identity verification and
key ownership validation.

## 5 Cryptographic algorithms

### 5.1 Signature algorithm

#### 5.1.1 EdDSA with Ed25519

All signatures shall use the EdDSA signature algorithm with the Ed25519 elliptic curve as specified
in RFC 8032.

#### 5.1.2 Key generation

Ed25519 keypairs shall be generated using cryptographically secure random number generators.

### 5.2 Document canonicalization

#### 5.2.1 JSON Canonicalization Scheme

All JSON documents shall be canonicalized using JCS as specified in RFC 8785 before signature
generation.

#### 5.2.2 Protected field inclusion

The canonicalization process shall include the following fields, when present, before hashing:

1. pubkey field;
2. controller field;
3. keyid field.

The canonicalization process shall exclude only the proof field from the document before hashing.

NOTE This ensures that pubkey, controller, and keyid fields are cryptographically protected by the
signature.

## 6 Verification procedures

### 6.1 Basic signature verification

#### 6.1.1 Document reconstruction

The verifier shall reconstruct the original document by removing signature fields and applying JCS
canonicalization.

#### 6.1.2 Cryptographic verification

The verifier shall validate the EdDSA signature using the provided or resolved public key.

### 6.2 Identity verification

#### 6.2.1 Controller resolution

When a controller URI is present, the verifier should resolve the controller document to validate
key ownership.

#### 6.2.2 Key binding verification

The verifier shall confirm that the signing key is authorized by the controller document.

## 7 Integration with decentralized identifiers

### 7.1 DID method support

#### 7.1.1 did:key method

Signatures may reference did:key identifiers for self-contained public key verification.

#### 7.1.2 did:web method

Signatures may reference did:web identifiers for web-based identity resolution.

### 7.2 Verification method resolution

The verifier shall resolve DID documents and extract appropriate verification methods for signature
validation.

## Annex A (informative) Implementation examples

### A.1 Basic JSON signature

[Example of simple JSON document with embedded signature]

### A.2 Verifiable Credential integration

[Example showing integration with W3C Verifiable Credentials]

### A.3 Progressive disclosure scenarios

[Examples demonstrating anonymous, pseudonymous, and public signature modes]

## Annex B (normative) Multibase encoding specifications

### B.1 Public key encoding

Public keys shall use the multibase format with z-base58btc encoding and the 0xed01 prefix.

### B.2 Signature encoding

Signatures shall use the multibase format with z-base58btc encoding.

## Annex C (informative) Security considerations

### C.1 Key management

[Guidelines for secure key generation, storage, and rotation]

### C.2 Privacy implications

[Discussion of privacy trade-offs in progressive disclosure]

### C.3 Attack vectors

[Analysis of potential cryptographic and implementation attacks]

## Bibliography

[1] FIPS 186-5, Digital Signature Standard (DSS)

[2] RFC 7517, JSON Web Key (JWK)

[3] W3C Working Draft, Data Integrity EdDSA Cryptosuites v1.0

______________________________________________________________________

# DRAFTING NOTES — DO NOT EDIT BELOW THIS LINE

______________________________________________________________________

- We use JSON

- We canonicalize with JCS

- We use Ed25519 Signatures

- We protect pubkey and controller properties with the signature

- Signature properties are:

  - proof: The actual digital signature in the form of a Multibase encoded Ed25519 signature (
    z-base58-btc) - (Required)
  - pubkey: The public key of the signer for offline integrity verification (Optional)
  - controller: The entity (person, organization, or system) who has authority over the
    cryptographic key used to create the signature and is responsible for managing this digital
    credential represented by a dereferencable URI did:web or URL to a controlled identifier
    document (Optional). If `pubkey` is set but `controller` is not set we implicitly derive a
    `did:key` as `controller`.
  - keyid: The id of the key in the controller document (optional). If not set, but `controller` is
    set we assume the keyid is the `pubkey` itself

- Concept: Property Set Implications — Progressive Disclosure — Three Levels and their implications:

  - Anonymous
    - Providing only `proof` is anonymous (privacy preserving). For signature verification the
      signer musst provide the `pubkey` to the verifier separately
  - Pseudonymous
    - Providing `proof` and `pubkey` is pseudonymous depending on publicly linkable knowledge about
      the `pubkey` but allows non-interactive integrity verification by the recipient.
  - Public
    - Providing `proof`, `pubkey` and `controller` is public and allows the recipient to verify the
      signature, establish the identity of the signer, and confirm that the public key belongs to
      the claimed controller by dereferencing the controller URI to retrieve and validate the
      controlled identifier document.

- Signed JSON objects by themselves are of no value to end users. We should also define UI/UX
  guidelines and clearly communicate options, features, privacy, and security interactions and
  implications regarding:

  - Key Generation
  - Key Managment
  - Metadata Document Signing
  - Signature presentation to the user
  - Signature interperation by the user

______________________________________________________________________

# INSTRUCTIONS TO CLAUDE WHILE WORKING ON THIS DOKUMENT

______________________________________________________________________

When working on this document, make sure you consult and cross-refernce relevant existing starndards
using deepwiki:

- **ISCC ISO 24138:2024 Specification**: See deepwiki at iscc/iscc-ieps
- **Verifiable Credentials Data Model v2.0**: See deepwiki at w3c/vc-data-model
- **Controlled Identifiers v1.0**: See deepwiki at w3c/cid
- **Decentralized Identifiers (DIDs) v1.0**: See deepwiki at w3c/did
- **Verifiable Credential Data Integrity 1.0**: See deebwiki at w3c/vc-data-integrity
- **Data Integrity EdDSA Cryptosuites v1.0**: See deepwiki at w3c/vc-di-eddsa
- **did:web Method Specifiction**: See deepwiki at w3c-ccg/did-method-web
- **The did:key Method v0.7**: See deepwiki at w3c-ccg/did-key-spec
