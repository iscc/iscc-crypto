1. Key Management:

- We use Ed25519 Signatures

- Besides the cryptographic material we store name and authority properties on the Key class

- We use the system default keyring backend

- How should key authority URLs be validated and what's the expected format of
  .well-known/iscc-keys.json?

2. Signing:

- Which signing algorithm(s) should be supported (RS256, ES256, EdDSA)?
- What's the exact format of the signature object that will be added to the JSON?
- Should there be size limits for the input JSON data?
- How should nested objects be handled during JCS canonicalization?

3. Timestamping:

- What's the protocol for communicating with timestamp servers?
- What's the format of the timestamp request/response?
- How are timestamp server signatures verified?
- Should there be a default timestamp server?
- Should there be retry logic for timestamp server requests?

4. Trust & Security:

- How should authority URL validation work in detail?
- Should there be a maximum age for signatures/timestamps?
- Should there be a list of trusted timestamp servers?
- How should certificate/key revocation be handled?

5. Error Handling:

- What specific error types should be defined?
- How detailed should error messages be?
- How should network errors be handled?

6. Performance:

- Should there be caching for authority URL validations?
- Should there be parallel processing for timestamp verification?
- Should there be limits on JSON data size?
