# ISCC Timestamping Protocol

## 1. Introduction

The ISCC Timestamping Protocol defines a standardized way to create verifiable timestamps and
declarations for digital content using W3C Verifiable Credentials. It enables content creators,
rights holders, and other parties to establish verifiable proofs of existence, ISCC-ID ownership,
and content declarations at specific points in time.

### 1.1 Purpose and Scope

This protocol specification defines:

- A microsecond-precise timestamping mechanism
- Methods for establishing content existence and ISCC-ID ownership
- Procedures for declaring ISCC-CODES
- Integration with the Verifiable Credentials ecosystem
- Security and cryptographic requirements
- API endpoints and data formats

### 1.2 Key Features

The protocol provides:

- High-precision distributed timestamping (microsecond resolution)
- Cryptographically verifiable timestamps and declarations
- Support for ownerless and owned timestamps
- Content binding through ISCC-CODEs and datahashes
- Integration with decentralized identity systems
- Standardized credential formats and proofs
- Offline verification capabilities

### 1.3 Verifiable Credentials Integration

The protocol leverages the W3C Verifiable Credentials Data Model to:

- Express timestamps as cryptographically verifiable claims
- Enable integration with existing VC infrastructure
- Provide standardized verification methods
- Support credential presentation and exchange
- Enable selective disclosure of timestamp metadata

### 1.4 Terminology

- **ISCC-ID**: A 64-bit identifier combining timestamp and server-id
- **Datahash**: A blake3 multihash over arbitrary data
- **ISCC-CODE**: A content-derived fingerprint following the ISCC specification
- **Notary**: A timestamping server that issues credentials
- **Requester**: An entity requesting timestamps or making declarations
- **DID**: Decentralized Identifier as specified by the W3C DID Core specification

## 2. Core Components

### 2.1 ISCC Identifier (ISCC-ID)

The ISCC-ID is a 64-bit timestamp that includes a server identifier to ensure global uniqueness and
chronological ordering. Each ISCC-ID represents a specific microsecond in time and the identity of
the notary server that issued it.

#### 2.1.1 Structure

The 64-bit identifier consists of:

- **Timestamp** (52 bits): Microseconds since Unix epoch (1970-01-01T00:00:00Z)
- **Server ID** (12 bits): Unique identifier of the issuing notary server

This structure enables:

- Timestamp precision to the microsecond
- Support for up to 4,096 unique notary servers
- Chronological sorting of identifiers
- Operation until year 2112

The self-describing header format allows for seamless protocol evolution by supporting new MAINTYPE,
SUBTYPE, VERSION, and LENGTH values. This ensures backward compatibility while enabling future
extensions if timestamp range or server capacity needs to be expanded.

#### 2.1.2 Canonical Format

The canonical string representation of an ISCC-ID uses the following format:

```
ISCC:MAIWFBMUTUVMPUAA
```

Components:

- Protocol prefix: `ISCC:`
- Base32-encoded concatenation of:
  - Header (16 bits):
    - MAINTYPE = `0110` (ISCC-ID)
    - SUBTYPE = `0000` (None)
    - VERSION = `0001` (V1)
    - LENGTH = `0001` (64-bit)
  - Payload (64 bits):
    - 52-bit timestamp
    - 12-bit server-id

#### 2.1.3 Capacity and Limitations

The ISCC-ID format provides:

- Maximum timestamp: Year 2112 (52-bit microseconds)
- Maximum servers: 4,096 (12-bit server-id)
- Theoretical throughput: ~4 billion timestamps per second across all servers
- Per-server throughput: Up to 1 million timestamps per second

#### 2.1.4 Server ID Registry

Server IDs are managed through a permissionless smart contract that maps 12-bit server IDs to notary
service endpoint URLs. The registry:

- Allows registration of new server IDs
- Maps server IDs to service endpoints
- Provides endpoint discovery
- Ensures unique server identification

The smart contract maintains an immutable record of server registrations and endpoint updates,
enabling transparent and decentralized operation of the timestamping network.

### 2.2 Verifiable Credentials

The ISCC Timestamping Protocol uses the W3C Verifiable Credentials Data Model to express timestamps
and declarations as cryptographically verifiable claims. This enables seamless integration with
existing VC ecosystem tools and infrastructure.

#### 2.2.1 Credential Types

The protocol defines three mutually exclusive credential types that MUST be included in the `type`
field after `VerifiableCredential`:

1. `IsccTimestamp` - For ownerless timestamps

   - Only requires datahash
   - No requester signature
   - Simple proof of existence at point in time

1. `IsccOwnership` - For owned but unbound timestamps

   - Requires requester signature
   - No content bindings
   - Establishes control over ISCC-ID

1. `IsccDeclaration` - For owned and content-bound timestamps

   - Requires requester signature
   - Binds ISCC-CODE and/or datahash (at least one MUST be present)
   - May include optional metadata bindings
   - Establishes both ISCC-ID ownership and content binding

#### 2.2.2 Required Properties

All ISCC credentials MUST include:

- `@context` - With `https://www.w3.org/ns/credentials/v2` as first item
- `type` - Must include `VerifiableCredential` and the specific ISCC type
- `issuer` - The `did:web` of the issuing ISCC Notary server
- `credentialSubject` - Contains the ISCC-specific claims

#### 2.2.3 Credential Subject Properties

The credential subject structure varies by type:

1. For `IsccTimestamp` (ownerless):

   ```json
   {
     "credentialSubject": {
       "id": "iscc:MAIWFBMUTUVMPUAA",
       "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF"
     }
   }
   ```

   - Simple assertion of existence
   - No owner/controller reference
   - ISCC-ID and datahash are the subject of the claim

1. For `IsccOwnership`:

   ```json
   {
     "credentialSubject": {
       "id": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
       "controlsIsccId": "iscc:MAIWFBMUTUVMPUAA"
     }
   }
   ```

   - Subject is the requester (identified by DID)
   - Credential attests control over ISCC-ID
   - Clear ownership relationship

1. For `IsccDeclaration`:

   ```json
   {
     "credentialSubject": {
       "id": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
       "controlsIsccId": "iscc:MAIWFBMUTUVMPUAA",
       "declares": {
         "isccCode": "ISCC:KACT4EBWK27737D2...",
         "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF"
       }
     }
   }
   ```

   - Subject is the requester (identified by DID)
   - Combines ownership with content binding
   - Structured declaration data

#### 2.2.4 Context Definition

The protocol defines a JSON-LD context that includes:

- ISCC-specific term definitions
- Cryptographic primitive mappings
- Verification method types
- Proof format specifications

This context MUST be included in all ISCC credentials to ensure proper semantic interpretation of
the claims.

### 2.3 Cryptographic Primitives

- Hash algorithms and encodings
- Signature schemes
- Key formats and management
- Proof formats and validation

## 3. Protocol Operations

### 3.1 Data Timestamping

- Request format and parameters
- Response structure
- Credential issuance
- Verification procedures

### 3.2 ISCC-ID Acquisition

- Request requirements
- Authorization process
- Response format
- Ownership attestation

### 3.3 ISCC-CODE Declaration

- Declaration request format
- Validation rules
- Response structure
- Metadata binding

## 4. Security Architecture

### 4.1 Notary Infrastructure

- Server identification (DIDs)
- Key management
- Trust establishment
- Service discovery

### 4.2 Proof Generation

- Data Integrity proofs
- Timestamp proofs
- Signature creation
- Canonicalization

### 4.3 Verification

- Proof validation
- Chain of trust
- Status checking
- Revocation handling

## 5. Data Formats

### 5.1 Request Messages

- Common fields
- Operation-specific parameters
- Validation rules
- Error handling

### 5.2 Response Messages

- Credential structure
- Proof formats
- Status codes
- Error responses

### 5.3 Credential Types

- IsccTimestamp
- IsccDeclaration
- Extension points
- Versioning

## 6. Implementation Guidelines

### 6.1 Best Practices

- Security considerations
- Performance optimization
- Error handling
- Rate limiting

### 6.2 Integration Patterns

- VC ecosystem integration
- Wallet compatibility
- Service implementation
- Client libraries

## 7. Protocol Extensions

### 7.1 Optional Features

- Metadata support
- Authority delegation
- Batch operations
- Custom proofs

### 7.2 Future Compatibility

- Version handling
- Feature negotiation
- Migration support
- Backward compatibility

## 8. Reference Implementation

- API specifications
- Example code
- Test vectors
- Conformance requirements

## Appendices

### A. JSON Schema Definitions

- Request schemas
- Response schemas
- Credential schemas
- Error schemas

### B. Example Messages

- Basic timestamps
- Code declarations
- Error cases
- Complex scenarios

### C. Security Considerations

- Threat model
- Attack vectors
- Mitigation strategies
- Best practices

### D. References

- Normative references
- Informative references
- Related specifications
- Tools and libraries
