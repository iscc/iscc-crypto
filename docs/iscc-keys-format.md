# ISCC Keys Format Specification

This document specifies the format for publishing authorized public keys via the
`.well-known/iscc-keys.json` endpoint. The format enables domains to act as lightweight roots of
trust by publishing their authorized public keys in a standardized way.

## Overview

The `iscc-keys.json` file MUST be served via HTTPS from the `.well-known` directory at any path
level of a domain. The file MUST NOT be served from paths containing query parameters or fragments.
For example:

Valid paths:

- Root level: `https://example.com/.well-known/iscc-keys.json`
- User level: `https://example.com/users/peter/.well-known/iscc-keys.json`
- Department level: `https://example.com/departments/sales/.well-known/iscc-keys.json`

Invalid paths:

- With query: `https://example.com/users/peter/.well-known/iscc-keys.json?v=1`
- With fragment: `https://example.com/.well-known/iscc-keys.json#latest`
- Double slashes: `https://example.com//users/peter/.well-known/iscc-keys.json`
- Relative paths: `https://example.com/users/../.well-known/iscc-keys.json`

This allows domains to delegate different signing authorities to different paths. Each path can
maintain its own set of authorized keys independently. Path components MUST be normalized (no
relative paths) and MUST NOT contain double slashes.

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

| Property | Required | Type   | Description                                                                                                                                                                |
| -------- | -------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| kid      | Yes      | string | Key identifier - unique within the domain                                                                                                                                  |
| pubkey   | Yes      | string | Ed25519 public key in base64 format                                                                                                                                        |
| name     | No       | string | Human readable name for the key                                                                                                                                            |
| created  | No       | string | ISO 8601 UTC timestamp of key creation                                                                                                                                     |
| expires  | No       | string | ISO 8601 UTC timestamp of key expiration                                                                                                                                   |
| revoked  | No       | string | ISO 8601 UTC timestamp of key revocation                                                                                                                                   |
| status   | No       | string | Key status: "active", "expired", or "revoked". Defaults to "active" if not present. Once a key is marked as "revoked" or "expired" it MUST NOT be changed back to "active" |

## Meta Object Properties

| Property     | Required | Type    | Description                                |
| ------------ | -------- | ------- | ------------------------------------------ |
| last_updated | No       | string  | ISO 8601 UTC timestamp of last file update |
| next_update  | No       | string  | ISO 8601 UTC timestamp when to check again |
| max_age      | No       | integer | Cache lifetime in seconds                  |
| version      | Yes      | string  | Format version, currently "1.0"            |

## Security Considerations

1. The file MUST be served over HTTPS only
1. Implement appropriate rate limiting to prevent DoS attacks
1. Set correct `Cache-Control` headers matching the `max_age` value
1. Keep expired/revoked keys listed for a reasonable time to verify old signatures
1. Use appropriate CORS headers if cross-origin access is required
1. Serve with correct `Content-Type: application/json` header
1. Path-specific keys MUST be served from a `.well-known` directory at that exact path
1. Implementations MUST NOT fall back to parent paths when checking authorities

## Error Handling

Clients MUST reject the keys file if:

- It is not served over HTTPS
- It contains invalid JSON
- Required fields are missing
- Timestamps are not valid ISO 8601 UTC format
- The `version` field indicates an unsupported version
- The file is served with invalid path components
- Any `pubkey` field contains invalid base64 or invalid Ed25519 key data

## Implementation Notes

- All timestamps MUST be in UTC and formatted according to ISO 8601 (e.g., "2024-01-01T00:00:00Z")
- The `kid` SHOULD be unique within the path and SHOULD NOT be reused
- Keys with `status` other than "active" MUST NOT be used for new signatures
- Clients SHOULD respect the `max_age` cache duration
- Clients SHOULD verify that the domain and path serving the keys exactly matches the authority
  claim
- When verifying an authority URL like `https://example.com/users/peter`, clients MUST check for
  `.well-known/iscc-keys.json` at exactly that path level
