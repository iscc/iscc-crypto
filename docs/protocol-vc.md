# ISCC Timestamping Protocol - VC Edition

## Overview

This specification defines how to represent ISCC Timestamps as Verifiable Credentials, enabling
integration with the broader VC ecosystem while maintaining the unique features of ISCC
Timestamping.

## Core Concepts

### ISCC-ID Structure

- 64-bit identifier (unchanged from core spec)
  - 52-bit microsecond timestamp
  - 12-bit server-id
- Theoretical capacity of ~4 billion timestamps/second
- Valid until year 2112

### Verifiable Credentials Integration

- Timestamps expressed as VCs
- Data Integrity proofs for tamper-evidence
- Standard VC properties for ecosystem compatibility
- ISCC-specific credential types and contexts

## Credential Format

### Required Properties

- `@context`
  - `https://www.w3.org/ns/credentials/v2`
  - ISCC-specific context URL
- `type`
  - `VerifiableCredential`
  - `IsccTimestamp`
- `issuer` - Timestamping server DID
- `credentialSubject`
  - ISCC timestamp data
  - Datahash binding

### Optional Properties

- `id` - ISCC-ID as URI
- `validFrom` - Timestamp creation time
- `credentialStatus` - Revocation information

## Securing Mechanisms

### Data Integrity Proofs

- EdDSA with JSON Canonicalization (JCS)
- Multikey format for keys
- Base58-btc encoding
- Microsecond precision support

### Proof Format

```json
{
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "[timestamp]",
    "verificationMethod": "[notary-did]#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "[signature]"
  }
}
```

## Notary Identification

### DID Methods

- `did:web` for DNS-based trust
- `did:key` for self-contained keys
- Maps to existing server-id registry

### Controller Documents

- Public key publication
- Service endpoint discovery
- Verification relationship definitions

## API Endpoints

### Data Timestamping

- Request/response formats
- VC representation
- Backward compatibility

### ISCC-ID Acquisition

- Credential issuance flow
- Ownership attestation
- Access control

### ISCC-CODE Declaration

- Code registration process
- Metadata binding
- Verification procedures

## Security Considerations

### Timestamp Integrity

- Proof verification
- Server authentication
- Replay protection

### Key Management

- Notary key rotation
- Credential status checking
- Trust establishment

## Examples

### Basic Timestamp

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://iscc.codes/credentials/v1"
  ],
  "type": ["VerifiableCredential", "IsccTimestamp"],
  "issuer": "did:web:notary.iscc.codes",
  "validFrom": "2024-01-01T12:00:00.123456Z",
  "credentialSubject": {
    "iscc_id": "ISCC:MAIWFBMUTUVMPUAA",
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2024-01-01T12:00:00.123456Z",
    "verificationMethod": "did:web:notary.iscc.codes#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4ER..."
  }
}
```

### Code Declaration

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://iscc.codes/credentials/v1"
  ],
  "type": ["VerifiableCredential", "IsccDeclaration"],
  "issuer": "did:web:notary.iscc.codes",
  "validFrom": "2024-01-01T12:00:00.123456Z",
  "credentialSubject": {
    "iscc_id": "ISCC:MAIWFBMUTUVMPUAA",
    "iscc_code": "ISCC:KACT4EBWK27737D2AYCJRAL5Z36G76RFRMO4554RU26HZ4ORJGIVHDI",
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2024-01-01T12:00:00.123456Z",
    "verificationMethod": "did:web:notary.iscc.codes#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4ER..."
  }
}
```

## Implementation Guidance

### Migration Path

- Backward compatibility support
- Gradual VC adoption
- Legacy format handling

### Ecosystem Integration

- VC wallet compatibility
- Verification library support
- Standard tooling usage

## References

1. W3C Verifiable Credentials Data Model
1. W3C Decentralized Identifiers (DIDs)
1. W3C Data Integrity
1. ISCC Timestamping Protocol
