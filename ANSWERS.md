1. Key Management:

- We use Ed25519 Signatures
- Besides the cryptographic material we store name and authority properties on the Key class
- We use the system default keyring backend
- authority URLs format spec at docs/iscc-keys-format.md

2. Signing:

- We only support Ed25519 signing?
- Signtures will be added as an object under the `signature` propetry with fields:
  - authority - url authority (optional)
  - pubkey - hex encoded public key
  - signature - JWS Detached signature
- We do not enforce any size limits on the input JSON data
- JCS canonicalization handles nested objects deterministically

3. Timestamping:

- The protocol for communication with the timestamp servers will be a REST API
- The timestemping request will body could be:

```json
{
    "payload": "571dae63146ee0fa4a393d9d502cef2e6692c5638aca646996b1171ae0609662",
    "signature": "<signatur over the payload by the requester>"
}
```

- The timestamping response body could be:

```json
{
    "tid": "ISCC:AAAWN77F727NXSUS",
    "signature": "<signature over the verified request object confirming unique tid asignment>"
}
```

- Timestamp server signatures are verified the same as other signatures in the framework
- The default timestamp server will be https://time.iscc.id
- Retry logic for timestamp server requests will be the responsibility of the user

4. Trust & Security:

- Details about how authority URL validation works are at docs/iscc-keys-format.md?
- There is no maximum age for signatures/timestamps?
- A public list of trusted timestamp servers will be maintained
- Certificate/key revocation is handled according to docs/iscc-keys-format.md?

5. Error Handling:

- Define and raise custom exceptions for specific error cases:
  - InvalidKeyError - for key validation/format issues
  - SignatureError - for signature validation failures
  - TimestampError - for timestamp validation/server issues
  - AuthorityError - for authority URL validation problems
- Error messages should be specific but not expose sensitive data
- Network errors should be caught and wrapped in appropriate custom exceptions
- Automatic retries for server requests are the responsibility of callers
- Log all errors with sufficient context for debugging

6. Performance:

- Should there be caching for authority URL validations?
- Should there be parallel processing for timestamp verification?
- Should there be limits on JSON data size?
