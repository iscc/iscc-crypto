# ISCC-TID - Distributed, Globally Unique, and Owned Timestamps

This specification defines a scalable distributed timestamping protocol with the following
properties:

- Built on top of JWS/JWT standards
- Up to 4096 independent timestamp-servers
- Each server can issue up to 1M unique timestamps per seccond (microseconds since epoch)
- High performance timestamping of large scale data
- Timestamps are globaly unique accross servers
- Timestamps are identifiers owned by timestamp requesters
- Timestamp owners can cryptographically prove timestamp ownership
- Timestamps can be stored using 64-bit / 8-bytes
- Timestamps support total ordering accross servers
- Timestamps preserve order in numerical (integer) and lexical (base32hex) sorting

## Overview

Clients may request a timestamp to:

- Prove the existence of some data at time x
- Acquire provable ownership of a globally unique Identifier bound to the timestamped data

**NOTE**: The same data can be timestamped multiple times by different parties.

## ISCC-TID

An ISCC Time-ID (ISCC-TID) is constructed from the concatenation of:

- 1. The prefix `ISCC:`
- 2. The character `0` indicating the ISCC is base32hex encoded Time-ID
- 3. Base32hex encoded concatenation of:
  - a) 52-Bit integer timestamp (microseconds since epoch)
  - b) 12-Bit integer server-id

## Timestamp Request

Timestamping requests are JWT tokens using the following claim names:

- `ver`: Protocol version
- `iss`: Public key of the timestamp requester
- `sub`: Blake3 256-bit hash of data to be timestamped

Request are wrapped in the following JSON structure:

```json
{
    "type": "timestamp-request",
    "jwt": "<jwt-token>"
}
```

## Timestamp Response

Timestamp responses are JWT tokens using the following claim names:

- `ver`: Protocol version
- `jti`: ISCC-TID
- `iss`: Public key of the timestamp server
- `sub`: Blake3 256-bit hash the timestamped data
- `azp`: Public key of the timestamp reqester (owner of the ISCC-TID)

# NOTES

1. Transport Protocol:

- required transport protocol is https
- timestamp servers expose a single endpoint at the root or a custom path
- timestamp requests by clients use the HTTP POST method

2. Request/Response Format:

- Content type for requests/responses is application/json
- Request size must not exeed 1kb
- HTTP status codes to be defined

3. JWT Details:

- Version "1.0" of the protocol only supports alg EdDSA crv Ed25519
- Version "1.0" requires no headers outside off the standard JWT headers
- Claim formats/encodings:
  - ver: string exactly "1.0" for v1
  - iss: string hex encoded public key
  - sub: string hex encoded blake3 hash
  - jti: string See ISCC-TID spec
  - azp: string hex encoded public key
- Additional optional claims are not allowed

4. Validation Rules

- Requests must
  - have a valid signature verified against the public key of the requester (`iss`)
- Responses must
  - have a valid signature verified against the public key of the timestamp server (`iss`)
- Server should respond with an error it data is invalid
- Clients should dispose of invalid responses
- Timestamps must be microseconds since epoch
- Timestamp servers must issue monotonically increasing timestamps and handle clock synchronization
  by blocking until a timestamp higher than the last issued timestamp is available
- Timestamps signed by expired times-server key are invalid

5. Security:

- CORS policies should allow third party requests
- Keys are expired accoring to iscc-keys-format spec
- Replay attacks are handled by monotonic unique timestamp issuance?

6. Chaching

- responses should not be cacheable
- timestamps are valid indefinitely

7. Server Requirements

- A list of server IDs will be maintained on github
- If a server goes offline clients can use other servers from the server registry on github
- timeservers are required to use a trustworthy source of time
- Server must regularly synchronize their clock such that accuracy is ± 0.1 seconds
- Reference implementation is at https://github.com/iscc/iscc-crypto
-
