# Getting Started with ISCC-CRYPTO

This tutorial will guide you through the fundamental operations of cryptographic signing and verification. By
the end of this tutorial, you'll be able to:

- Generate your first cryptographic keypair
- Sign a JSON document
- Verify a signed document
- Understand the signature format used by ISCC-CRYPTO

## Prerequisites

Before starting, ensure you have:

- [x] Python 3.10 or higher installed
- [x] Basic familiarity with Python and command line

## Installation

Install ISCC-Crypto using your preferred package manager:

=== "uv"

    ```bash
    uv add iscc-crypto
    ```

=== "pip"

    ```bash
    pip install iscc-crypto
    ```

=== "poetry"

    ```bash
    poetry add iscc-crypto
    ```

## Setting Up Your First Keypair

Let's start by generating a cryptographic keypair. A keypair consists of a public key (for verification) and a
secret key (for signing).

### Step 1: Import the Library

!!! info "Getting Started"

    Create a new Python file called `tutorial.py` and follow along with each step.

Create a new Python file called `tutorial.py` and import the necessary functions:

```python
from iscc_crypto import key_generate
```

### Step 2: Generate a Keypair

Generate your first keypair:

```python
# Generate a new keypair
keypair = key_generate()

print(f"Public key: {keypair.public_key}")
print(f"Secret key: {keypair.secret_key}")
```

Run the script:

```bash
python tutorial.py
```

You should see output similar to:

```
Public key: z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
Secret key: z3u2SqkHt13R6Y1AQPXnG7q3aBrJnxvbTdKDG8L6Wppzs...
```

!!! warning "Keep Your Secret Key Safe"

    The secret key is used to create signatures. ==Never share it or commit it to version control!==

## Signing Your First JSON Document

Now let's sign a JSON document using your keypair.

### Step 3: Create a Document to Sign

Add the following to your `tutorial.py`:

```python
from iscc_crypto import sign_json

# Create a sample document
document = {"name": "Alice", "message": "Hello, ISCC-Crypto!", "timestamp": "2024-01-15T10:00:00Z"}

# Sign the document
signed_document = sign_json(document, keypair)

print("\nSigned document:")
print(signed_document)
```

Run the updated script. You'll see the document now includes a signature:

```json
{
  "name": "Alice",
  "message": "Hello, ISCC-Crypto!",
  "timestamp": "2024-01-15T10:00:00Z",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "pubkey": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "proof": "z2kSw1VwHDepdegj6Rw8bMD8N2o56VhkdZ2qh8MHP5cHDk..."
  }
}
```

## Verifying a Signature

Let's verify that the signature is valid.

### Step 4: Verify the Signed Document

Add verification to your script:

```python
from iscc_crypto import verify_json

# Verify the signed document
result = verify_json(signed_document)

print(f"\nVerification result: {result.is_valid}")
print(f"Signature valid: {result.signature_valid}")
print(f"Message: {result.message}")
```

The verification process:

1. **Extract** the signature and public key
2. **Remove** the signature from the document
3. **Verify** that the signature matches the document content

## Understanding the Signature Format

ISCC-Crypto uses a standardized signature format that's both human-readable and machine-verifiable.

### Step 5: Examine the Signature Structure

Let's look more closely at what happens during signing:

```python
import json

# Pretty print the signed document
print("\nDetailed signature structure:")
print(json.dumps(signed_document, indent=2))

# Extract just the signature component
signature_data = signed_document["signature"]
print(f"\nPublic key length: {len(signature_data['pubkey'])}")
print(f"Signature proof length: {len(signature_data['proof'])}")
print(f"Version: {signature_data['version']}")
```

Key points about the signature format:

- ==**Multikey Encoding**==: Both keys and proofs use z-base58btc encoding for compactness
- ==**Structured Signature**==: The signature object contains version info, public key, and cryptographic proof
- ==**JSON Canonicalization**==: Documents are normalized before signing to ensure consistent results
- ==**Version Control**==: Each signature includes a version field ("ISCC-SIG v1.0")

### Step 6: Try Modifying the Document

To understand signature verification, let's see what happens when we modify a signed document:

```python
# Create a copy and modify it
tampered_document = signed_document.copy()
tampered_document["message"] = "Modified message!"

# Try to verify the tampered document
tampered_result = verify_json(tampered_document, raise_on_error=False)

print(f"\nTampered document verification: {tampered_result.is_valid}")
print(f"Signature valid: {tampered_result.signature_valid}")
print(f"Error message: {tampered_result.message}")
```

You'll see that verification fails when the document is modified!

## Complete Example

Here's the complete tutorial script:

```python
from iscc_crypto import key_generate, sign_json, verify_json
import json

# Generate a keypair
keypair = key_generate()
print(f"Public key: {keypair.public_key}")
print(f"Secret key: {keypair.secret_key[:50]}...")  # Show only part of secret key

# Create and sign a document
document = {"name": "Alice", "message": "Hello, ISCC-Crypto!", "timestamp": "2024-01-15T10:00:00Z"}

signed_document = sign_json(document, keypair)
print("\nSigned document:")
print(json.dumps(signed_document, indent=2))

# Verify the signature
result = verify_json(signed_document)
print(f"\nVerification result: {result.is_valid}")
print(f"Message: {result.message}")

# Try tampering with the document
tampered_document = signed_document.copy()
tampered_document["message"] = "Modified message!"
tampered_result = verify_json(tampered_document, raise_on_error=False)
print(f"\nTampered document verification: {tampered_result.is_valid}")
print(f"Error message: {tampered_result.message}")
```

## What You've Learned

Congratulations! You've successfully:

- [x] Generated a cryptographic keypair using Ed25519
- [x] Signed a JSON document with your secret key
- [x] Verified a signature using the embedded public key
- [x] Explored how signatures protect document integrity

## Next Steps

Now that you understand the basics, you can:

- Learn about [W3C Verifiable Credentials] for more advanced use cases
- Explore [key management strategies] for production environments
- Read about [cryptographic concepts] to understand the underlying technology

## Exercises

To reinforce your learning, try these exercises:

1. **Multiple Documents**: Create and sign several different JSON documents with the same keypair
2. **Key Rotation**: Generate two different keypairs and sign the same document with each
3. **Nested Objects**: Try signing more complex JSON structures with nested objects and arrays
4. **Error Handling**: Experiment with invalid inputs to understand error messages

!!! tip "Pro Tip"

    When working with real applications, store your keypairs securely using environment variables or secure key
    management systems. ==Never hardcode secret keys in your source code!==
