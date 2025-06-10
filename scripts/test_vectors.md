# ISCC Signature Test Vectors

## Keypair Information
Public Key: z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx
Secret Key: z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA

## Original Document
```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "image": "https://picsum.photos/200/300.jpg"
}
```

## Example 1: PROOF_ONLY Signature
Minimal signature containing only version and proof.
```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "image": "https://picsum.photos/200/300.jpg",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "proof": "z3hneqf6kXRg9rv7G2M5BHrw9G8jnBSAMnKTz1GuLST17GToNnvZWbEN6WuWqY9eVqauUMkydMioFr2MBDHBDt4ar"
  }
}
```

## Example 2: SELF_VERIFYING Signature
Includes the public key for standalone verification.
```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "image": "https://picsum.photos/200/300.jpg",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "pubkey": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
    "proof": "z5ESGSCt6Hw19CAa2k1vRZtsNewjKqqeTG6RbBmkvsNDfF6UPxCjBjDHJqZtSmGWuzE3AfF9cj1495MWYa64gWG2Y"
  }
}
```

## Example 3: IDENTITY_BOUND Signature
Includes controller URI and public key for full attribution.
```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "image": "https://picsum.photos/200/300.jpg",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "controller": "did:iscc:kacypxw445ftynj3cysxhafjma2huwulunrfe3blhrscxyh2m5aegqy",
    "pubkey": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
    "proof": "z2qRdsqT5c7T1JgzZvN4BEyQp1bt5369FkPKnviLAV8puvSDxqoitTCihugb6n6yh2WcgxZaVmkhjihw3AqbmBMzw"
  }
}
```

## Example 4: AUTO Signature
Includes all available fields from the signing keypair.
```json
{
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "image": "https://picsum.photos/200/300.jpg",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "controller": "did:iscc:kacypxw445ftynj3cysxhafjma2huwulunrfe3blhrscxyh2m5aegqy",
    "keyid": "key-1",
    "pubkey": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
    "proof": "z34fNkeMmTzNoxrVQ6faH8yZ7PvtMuLQUT2xQQoubmTi6TdHputRXjXLHhEnh1UZ5tGSeDNUACpcnvNTxmw3eMKUu"
  }
}
```

## Canonicalized Document (for verification)
The document after JCS canonicalization (without proof field):
```
{"$schema":"http://purl.org/iscc/schema","@context":"http://purl.org/iscc/context","@type":"VideoObject","description":"a 1984 fantasy film co-written and directed by *Wolfgang Petersen*","image":"https://picsum.photos/200/300.jpg","iscc":"ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY","name":"The Never Ending Story","signature":{"controller":"did:iscc:kacypxw445ftynj3cysxhafjma2huwulunrfe3blhrscxyh2m5aegqy","keyid":"key-1","pubkey":"z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx","version":"ISCC-SIG v1.0"}}
```

## Raw Signature Example
Direct signing of raw bytes:
Message (hex): 48656c6c6f204953434320576f726c6421
Message (utf8): Hello ISCC World!
Signature: z2RbHNur6LCowVV7T2m8d8rdEvgMnYpb54166JyA17QZog1tPj7xHrif5hTJBp6fSbnEwdWaaY7rnA5z9nrKzpHT2

## Verification Examples

### Verify SELF_VERIFYING signature:
Valid: True
Message: None

### Verify PROOF_ONLY signature (with external pubkey):
Valid: True
Message: None

### Verify raw signature:
Valid: True
Message: None
