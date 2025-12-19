# Command Line Interface Tutorial

Learn to use ISCC-CRYPTO from the command line: set up your cryptographic identity, generate keypairs, and
sign/verify JSON documents.

## Prerequisites

- Python 3.10+
- [uv package manager](https://docs.astral.sh/uv/getting-started/installation/)

## Installation

```bash
uv tool install iscc-crypto
```

Verify:

```bash
iscc-crypto --version
# iscc-crypto X.Y.Z
```

!!! tip "Tool Management"

    Update: `uv tool upgrade iscc-crypto` | Uninstall: `uv tool uninstall iscc-crypto`

## Setting Up Your Identity

Before signing documents, create your cryptographic identity:

```bash
iscc-crypto setup
```

This interactive command will:

1. Ask about web server access
2. Let you choose web-based or standalone identity
3. Generate a secure keypair
4. Save your identity to your system's app folder

!!! warning "Backup Your Keys"

    Check `backup-instructions.txt` in your configuration directory after setup!

!!! info "setup vs keygen"

    - **setup**: Stores keypair in your config directory as your default identity
    - **keygen**: Outputs keypair to console for programmatic use (not stored)

## Generating Keypairs

The `keygen` command generates keypairs without storing them.

### Standalone Keypair

```bash
iscc-crypto keygen
```

```json
{
  "public_key": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "secret_key": "z3u2SqkHt13R6Y1AQPXnG7q3aBrJnxvbTdKDG8L6Wppzs..."
}
```

### Domain-Bound Identity

```bash
iscc-crypto keygen example.com
```

Outputs a DID document (stdout) and keypair info (stderr):

```json
{
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "id": "did:web:example.com#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "type": "Multikey",
      "controller": "did:web:example.com",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
  ],
  ...
}
```

### Path-Based Identities

```bash
iscc-crypto keygen example.com/alice           # Individual
iscc-crypto keygen example.com/engineering     # Department
iscc-crypto keygen -k mykey example.com        # Custom key ID
```

## Signing Documents

Sign JSON files using your stored identity (from `setup`):

```bash
iscc-crypto sign document.json
```

Output:

```
✅ Signed JSON saved to: document.signed.json
   Controller: did:web:example.com
   Public key: z6MkhaXgBZDvot...
   Signature: z2kSw1VwHDepde...
```

The signed file contains:

```json
{
  "name": "Alice",
  "message": "Hello",
  "signature": {
    "version": "ISCC-SIG v1.0",
    "controller": "did:web:example.com",
    "pubkey": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "proof": "z2kSw1VwHDepdegj6Rw8bMD8N2o56VhkdZ2qh8MHP5cHDk..."
  }
}
```

### Signature Types

```bash
iscc-crypto sign document.json --type <TYPE>
```

| Type             | Description                               |
| ---------------- | ----------------------------------------- |
| `auto`           | Chooses based on keypair config (default) |
| `self_verifying` | Includes public key only                  |
| `identity_bound` | Includes controller reference             |
| `proof_only`     | Minimal, requires external key for verify |

## Verifying Signatures

```bash
iscc-crypto verify document.signed.json
```

Output:

```
🔍 Resolving identity: did:web:example.com
✅ Identity document resolved
✅ Signature integrity: Valid
✅ Identity verification: Valid
✅ Overall verification: PASSED
```

Skip identity resolution (verify signature only):

```bash
iscc-crypto verify document.signed.json --skip-identity
```

## Validating Identity Documents

```bash
iscc-crypto validate-identity did:web:example.com
iscc-crypto validate-identity https://example.com/.well-known/did.json
```

## Viewing Your Identity

```bash
iscc-crypto info
```

```
🔐 Your ISCC Crypto Identity
📁 Location: <platform-specific-path>
🔑 Public key: z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
🌐 Controller: did:web:example.com
📤 Publish to: https://example.com/.well-known/did.json
```

## Configuration Directory

Identity files are stored in platform-specific locations:

| Platform | Path                                         |
| -------- | -------------------------------------------- |
| Linux    | `~/.local/share/iscc-crypto/`                |
| macOS    | `~/Library/Application Support/iscc-crypto/` |
| Windows  | `%LOCALAPPDATA%\iscc-crypto\`                |

Contents:

- `keypair.json` - Your keys (restricted permissions)
- `did.json` - Your DID document (if web-based)
- `backup-instructions.txt` - Security guidance

## Publishing Your Identity

For web-based identities:

1. Copy `did.json` from your config directory
2. Upload to `https://yourdomain.com/.well-known/did.json`
3. Verify: `curl https://yourdomain.com/.well-known/did.json`

## Advanced Usage

### Batch Signing

```bash
for file in *.json; do
  [[ ! "$file" =~ \.signed\.json$ ]] && iscc-crypto sign "$file"
done
```

### CI/CD Integration

```yaml
- name: Setup ISCC Crypto
  run: |
    uv tool install iscc-crypto
    mkdir -p ~/.local/share/iscc-crypto
    echo '${{ secrets.KEYPAIR_JSON }}' > ~/.local/share/iscc-crypto/keypair.json

- name: Sign artifacts
  run: |
    iscc-crypto sign release-manifest.json
    iscc-crypto verify release-manifest.signed.json
```

### Programmatic Key Extraction

```bash
# Extract public key
PUBLIC_KEY=$(iscc-crypto keygen | jq -r '.public_key')

# Generate and save DID document (keypair to stderr)
iscc-crypto keygen example.com > did.json 2> keypair-info.txt
```

## Command Reference

| Command             | Purpose                    | Key Options               |
| ------------------- | -------------------------- | ------------------------- |
| `setup`             | Interactive identity setup | Interactive prompts       |
| `keygen`            | Generate keypair           | `[domain]`, `-k/--key-id` |
| `sign`              | Sign JSON document         | `-t/--type`               |
| `verify`            | Verify signed JSON         | `--skip-identity`         |
| `validate-identity` | Validate DID document      | `<identifier>`            |
| `info`              | Show current identity      | —                         |

## Troubleshooting

**"No identity configured"**: Run `iscc-crypto setup` first.

**Command not found**: Add uv's tool directory to PATH:

```bash
uv tool dir  # Shows path to add
```

**Invalid key format**: Keys must use multibase z-base58btc format:

- Public keys: `z6Mk...`
- Secret keys: `z3u2...`

**Verification fails**:

- Document modified after signing
- Identity document not published/accessible
- Network issues

Try `--skip-identity` to verify signature integrity only.
