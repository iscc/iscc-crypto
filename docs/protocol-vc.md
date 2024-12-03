# ISCC Timestamping Protocol - VC Integration

## Overview

This specification defines how the ISCC Timestamping Protocol integrates with the W3C Verifiable
Credentials (VC) ecosystem while maintaining backward compatibility with the core ISCC timestamping
features.

## Core Concepts

The protocol combines:

- ISCC-ID as unique timestamp identifier
- VC Data Model for credential representation
- Data Integrity proofs for verification
- Controller Documents for notary key discovery

## Timestamp Credential Format

A timestamp credential MUST be a valid Verifiable Credential with:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/iscc/v1"
  ],
  "type": ["VerifiableCredential", "TimestampCredential"],
  "issuer": "did:web:notary.example.com",
  "validFrom": "2024-01-01T12:00:00Z",
  "credentialSubject": {
    "id": "ISCC:MAIWFBMUTUVMPUAA",
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2024-01-01T12:00:00Z",
    "verificationMethod": "did:web:notary.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQp...FPP2oumHKtz"
  }
}
```

## Notary Identification

ISCC Notaries MUST be identified by either:

- `did:web` - For web-based notaries using DNS/TLS trust
- `did:key` - For permissionless notaries using cryptographic trust

The notary's DID document MUST be resolvable and contain:

- Ed25519 verification keys in Multikey format
- Service endpoints for timestamp requests
- Verification relationships for timestamp signing

## Timestamp Request

Request for creating a verifiable timestamp:

```json
{
  "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF",
  "challenge": "953749e57c4bc3e031bfbba408c5e72b8a89a0e4fd1b4409d26e3688a441195e"
}
```

## Timestamp Response

The response MUST be a valid Verifiable Credential as shown in the Timestamp Credential Format
section.

## Verification Process

1. Resolve notary DID document
1. Verify proof cryptosuite (eddsa-jcs-2022)
1. Validate proof against verification method
1. Check timestamp in ISCC-ID matches validFrom
1. Verify notary server-id authorization

## Security Considerations

- Notaries MUST use Ed25519 keys with strong entropy
- DIDs SHOULD use DNSSEC or blockchain anchoring
- Clients MUST verify full proof chain
- Timestamps MUST be microsecond precise
- Server-ids MUST be registered and authorized

## Privacy Considerations

- Datahashes provide content privacy
- Challenge prevents correlation
- did:key enables anonymous notaries
- No PII in credentials

## Ecosystem Compatibility

The protocol enables:

1. Standard VC verification tools
1. Integration with VC wallets
1. Semantic interoperability
1. Proof format reuse

While maintaining ISCC features:

1. Microsecond precision
1. Server-id uniqueness
1. Content timestamping
1. Distributed verification
