# ISCC Timestamping Protocol

## 1. Introduction

- Purpose and scope of the protocol
- Key features and benefits
- Relationship to VC ecosystem
- Terminology and conventions

## 2. Core Components

### 2.1 ISCC Identifier (ISCC-ID)

- 64-bit identifier structure
- 52-bit microsecond timestamp component
- 12-bit server-id component
- Encoding format and rules
- Theoretical capacity and limitations

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
