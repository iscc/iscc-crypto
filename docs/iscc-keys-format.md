# ISCC Keys Format Specification

This document specifies the format for publishing authorized public keys via the `.well-known/iscc-keys.json`
endpoint. The format enables domains to act as lightweight roots of trust by publishing their authorized public
keys in a standardized way.

## Overview

The `iscc-keys.json` file MUST be served via HTTPS from the `.well-known` directory of a domain. For example:
`https://example.com/.well-known/iscc-keys.json`

The file MUST contain a JSON object with two top-level properties:
- `keys`: An array of authorized public key objects
- `meta`: An object with metadata about the keys file

## Format

```json
{
  "keys": [
    {
      "kid": "2024-primary",
      "pubkey": "<Ed25519-public-key-as-base64>",
      "name": "ISCC Foundation Primary Key",
      "created": "2024-01-01T00:00:00Z",
      "expires": "2025-01-01T00:00:00Z",
      "revoked": "2024-06-01T00:00:00Z",
      "status": "active"
    }
  ],
  "meta": {
    "last_updated": "2024-01-15T14:30:00Z",
    "next_update": "2024-01-16T14:30:00Z",
    "max_age": 86400,
    "version": "1.0"
  }
}
```

## Key Object Properties

| Property  | Required | Type     | Description |
|-----------|----------|----------|-------------|
| kid       | Yes      | string   | Key identifier - unique within the domain |
| pubkey    | Yes      | string   | Ed25519 public key in base64 format |
| name      | No       | string   | Human readable name for the key |
| created   | Yes      | string   | ISO 8601 UTC timestamp of key creation |
| expires   | No       | string   | ISO 8601 UTC timestamp of key expiration |
| revoked   | No       | string   | ISO 8601 UTC timestamp of key revocation |
| status    | Yes      | string   | Key status: "active", "expired", or "revoked" |

## Meta Object Properties

| Property      | Required | Type     | Description |
|---------------|----------|----------|-------------|
| last_updated  | Yes      | string   | ISO 8601 UTC timestamp of last file update |
| next_update   | No       | string   | ISO 8601 UTC timestamp when to check again |
| max_age       | Yes      | integer  | Cache lifetime in seconds |
| version       | Yes      | string   | Format version, currently "1.0" |

## Security Considerations

1. The file MUST be served over HTTPS only
2. Implement appropriate rate limiting to prevent DoS attacks
3. Set correct `Cache-Control` headers matching the `max_age` value
4. Keep expired/revoked keys listed for a reasonable time to verify old signatures
5. Use appropriate CORS headers if cross-origin access is required
6. Serve with correct `Content-Type: application/json` header

## Implementation Notes

- All timestamps MUST be in UTC and formatted according to ISO 8601
- The `kid` SHOULD be unique within the domain and SHOULD NOT be reused
- Keys with `status` other than "active" MUST NOT be used for new signatures
- Clients SHOULD respect the `max_age` cache duration
- Clients SHOULD verify that the domain serving the keys matches the authority claim
