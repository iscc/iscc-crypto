"""ISCC Crypto CLI - Command line interface for cryptographic identity management."""

import json
import stat
from pathlib import Path
import click
import platformdirs
from iscc_crypto.keys import key_generate, KeyPair, key_from_secret
from iscc_crypto.resolve import resolve, build_did_web_url
from iscc_crypto.signing import sign_json, SigType
from iscc_crypto.verifying import verify_json
from iscc_crypto import __version__


APP_NAME = "iscc-crypto"


def get_config_dir():
    # type: () -> Path
    """Get platform-specific configuration directory."""
    return Path(platformdirs.user_data_dir(APP_NAME))


def load_keypair():
    # type: () -> KeyPair | None
    """Load keypair from configuration directory."""
    config_dir = get_config_dir()
    keypair_file = config_dir / "keypair.json"

    if not keypair_file.exists():
        return None

    try:
        with open(keypair_file) as f:
            data = json.load(f)

        # Reconstruct KeyPair from saved data
        keypair = key_from_secret(
            data["secret_key"], controller=data.get("controller"), key_id=data.get("key_id")
        )
        return keypair
    except Exception:  # pragma: no cover
        return None


def save_files(keypair, identity_doc, config_dir):
    # type: (KeyPair, dict | None, Path) -> None
    """Save keypair and optionally identity document with proper permissions."""
    config_dir.mkdir(parents=True, exist_ok=True)

    # Save keypair with restricted permissions
    keypair_file = config_dir / "keypair.json"
    keypair_data = {
        "public_key": keypair.public_key,
        "secret_key": keypair.secret_key,
        "controller": keypair.controller,
        "key_id": keypair.key_id,
    }

    with open(keypair_file, "w") as f:
        json.dump(keypair_data, f, indent=2)

    # Set restrictive permissions on keypair file (owner read/write only)
    try:
        keypair_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, NotImplementedError):
        # Windows doesn't support Unix-style permissions, skip silently
        pass

    # Save identity document as did.json (ready for upload) if provided
    if identity_doc is not None:
        identity_file = config_dir / "did.json"
        with open(identity_file, "w") as f:
            json.dump(identity_doc, f, indent=2)

    # Create simple backup instructions
    backup_file = config_dir / "backup-instructions.txt"
    backup_text = """BACKUP INSTRUCTIONS
==================

CRITICAL: Back up your secret key immediately!

Your keypair is saved in: {}

Backup options:
1. Copy keypair.json to a secure USB drive
2. Print the secret key and store in a safe
3. Use a password manager to store the secret key

Secret key: {}

⚠️  Keep your secret key private and secure!
⚠️  Anyone with your secret key can impersonate you!
""".format(keypair_file, keypair.secret_key)

    with open(backup_file, "w", encoding="utf-8") as f:
        f.write(backup_text)


@click.group(invoke_without_command=True, context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(__version__, "-v", "--version", message="iscc-crypto %(version)s")
@click.pass_context
def main(ctx):
    # type: (click.Context) -> None
    """ISCC-CRYPTO - Cryptographic operations for content identification."""
    if ctx.invoked_subcommand is None:
        click.echo(f"iscc-crypto v{__version__}\n")
        click.echo(ctx.get_help())


@main.command()
def setup():
    # type: () -> None
    """Guided setup for your cryptographic identity."""
    click.echo("🔐 ISCC Crypto Identity Setup")
    click.echo("Create your cryptographic identity for content signing.\n")

    # Check if identity already exists
    config_dir = get_config_dir()
    keypair_file = config_dir / "keypair.json"

    if keypair_file.exists():
        if not click.confirm("⚠️  Identity already exists. Overwrite?", default=False):
            click.echo("Setup cancelled.")
            return

    # Ask about web server access
    has_webserver = click.confirm("Do you have access to a web server where you can publish files?")

    domain = None
    if has_webserver:
        click.echo("\nChoose your identity type:")
        click.echo("[1] Web-based identity - Publish your identity document online (recommended)")
        click.echo("[2] Standalone identity - Self-contained cryptographic identity")

        choice = click.prompt("Selection", type=click.Choice(["1", "2"]))

        if choice == "1":
            domain = click.prompt("\nDomain name (e.g., example.com)")
            # Clean up domain (remove protocol, trailing slashes)
            domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    else:
        click.echo("Creating standalone identity...")

    # Generate keypair
    click.echo("\n⏳ Generating keypair...")
    keypair = key_generate()

    # Create identity document
    if domain:
        identity_id = f"did:web:{domain}"
        upload_url = f"https://{domain}/.well-known/did.json"

        # Update keypair with controller info
        keypair = KeyPair(
            public_key=keypair.public_key,
            secret_key=keypair.secret_key,
            controller=identity_id,
            key_id="iscc",
        )
        identity_doc = keypair.controller_document
    else:
        identity_doc = None
        identity_id = "standalone"

    # Save files
    save_files(keypair, identity_doc, config_dir)

    # Success message
    click.echo("✓ Generated keypair")
    if domain:
        click.echo("✓ Created identity document")
    click.echo(f"✓ Saved to: {config_dir}")

    if domain:
        click.echo(f"\n🌐 Your identity: {identity_id}")
        click.echo(f"\n📤 Upload did.json to: {upload_url}")
        click.echo("\nQuick publishing options:")
        click.echo("• GitHub Pages: Upload to /.well-known/did.json")
        click.echo("• Netlify: Drag & drop, configure /_redirects")
        click.echo("• Web hosting: Upload via FTP/SFTP")
        click.echo(f"\nTest with: curl {upload_url}")
    else:
        click.echo(f"\n✓ Your standalone keypair is ready to use")
        click.echo("  Use it for signing content and credentials")

    click.echo(f"\n📋 Check backup-instructions.txt for security guidance")


@main.command("validate-identity")
@click.argument("identifier")
def validate_identity(identifier):
    # type: (str) -> None
    """Validate an identity document (DID URI or document URL)."""
    click.echo(f"🔍 Validating identity: {identifier}")

    try:
        # Use the resolve function which handles all URI types and validation
        doc = resolve(identifier)

        # If we get here, the document passed validation
        click.echo("✅ Valid identity document")

        # Show basic info
        if "id" in doc:
            click.echo(f"   ID: {doc['id']}")

        # Show verification methods if present
        methods = doc.get("verificationMethod", [])
        if methods:
            click.echo(f"   Verification methods: {len(methods)}")
            for method in methods:
                if "publicKeyMultibase" in method:
                    key = method["publicKeyMultibase"]
                    click.echo(f"   Public key: {key[:20]}...")

    except Exception as e:
        click.echo(f"❌ Validation failed: {e}")


@main.command()
@click.argument("domain", required=False)
@click.option("-k", "--key-id", help="Custom key identifier (defaults to public key)")
def keygen(domain, key_id):
    # type: (str | None, str | None) -> None
    """Generate a new keypair (optionally for a domain).

    Examples:
      iscc-crypto keygen                          # Standalone keypair
      iscc-crypto keygen example.com              # Organization identity
      iscc-crypto keygen example.com/alice        # Individual identity
      iscc-crypto keygen example.com/users/alice  # Nested path identity
      iscc-crypto keygen -k mykey example.com     # With custom key ID
    """
    import sys

    # Generate keypair
    if domain:
        # Clean up domain (remove protocol, trailing slashes)
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

        # Convert path separators to did:web format (: instead of /)
        # example.com/alice becomes did:web:example.com:alice
        controller = f"did:web:{domain.replace('/', ':')}"
        keypair = key_generate(controller=controller, key_id=key_id)

        # Use the resolve module's URL builder to get the correct publish URL
        publish_url = build_did_web_url(controller)

        # Output keys as text to stderr (not JSON to prevent copy/paste mistakes)
        click.echo("# Generated keypair (KEEP SECRET!):", err=True)
        click.echo(f"# Public Key:  {keypair.public_key}", err=True)
        click.echo(f"# Secret Key:  {keypair.secret_key}", err=True)
        if keypair.key_id:
            click.echo(f"# Key ID:      {keypair.key_id}", err=True)
        click.echo("#", err=True)
        click.echo("# Controller Document for publication:", err=True)
        click.echo(f"# Publish to: {publish_url}", err=True)
        click.echo("#", err=True)

        # Output only the controller document as JSON to stdout
        click.echo(json.dumps(keypair.controller_document, indent=2))
    else:
        keypair = key_generate(key_id=key_id)
        # For standalone keys, still output as JSON since there's no risk
        output = {
            "public_key": keypair.public_key,
            "secret_key": keypair.secret_key,
        }
        if keypair.key_id:
            output["key_id"] = keypair.key_id
        click.echo(json.dumps(output, indent=2))


@main.command()
@click.argument("json_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-t",
    "--type",
    type=click.Choice(["auto", "proof_only", "self_verifying", "identity_bound"]),
    default="auto",
    help="Signature type (default: auto)",
)
def sign(json_file, type):
    # type: (Path, str) -> None
    """Sign a JSON file with your configured identity.

    The signed file will be saved as <filename>.signed.json in the same directory.
    """
    # Check if identity exists
    keypair = load_keypair()
    if not keypair:
        click.echo("❌ No identity configured. Run 'iscc-crypto setup' first.")
        return

    # Load the JSON file
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f"❌ Invalid JSON file: {e}")
        return
    except Exception as e:  # pragma: no cover
        click.echo(f"❌ Error reading file: {e}")
        return

    # Map string type to SigType enum
    sigtype_map = {
        "auto": SigType.AUTO,
        "proof_only": SigType.PROOF_ONLY,
        "self_verifying": SigType.SELF_VERIFYING,
        "identity_bound": SigType.IDENTITY_BOUND,
    }
    sigtype = sigtype_map[type]

    # Sign the JSON
    try:
        signed_data = sign_json(data, keypair, sigtype)
    except ValueError as e:
        click.echo(f"❌ Signing failed: {e}")
        return
    except Exception as e:  # pragma: no cover
        click.echo(f"❌ Unexpected error during signing: {e}")
        return

    # Create output filename
    output_file = json_file.parent / f"{json_file.stem}.signed.json"

    # Save the signed JSON
    try:
        with open(output_file, "w", encoding="utf-8", newline="\n") as f:
            json.dump(signed_data, f, indent=2)
        click.echo(f"✅ Signed JSON saved to: {output_file}")

        # Show signature info
        sig = signed_data.get("signature", {})
        if "controller" in sig:
            click.echo(f"   Controller: {sig['controller']}")
        if "pubkey" in sig:
            click.echo(f"   Public key: {sig['pubkey'][:20]}...")
        if "proof" in sig:
            click.echo(f"   Signature: {sig['proof'][:20]}...")

    except Exception as e:  # pragma: no cover
        click.echo(f"❌ Error saving signed file: {e}")
        return


@main.command()
@click.argument("json_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--skip-identity",
    is_flag=True,
    help="Skip identity verification (only check signature integrity)",
)
def verify(json_file, skip_identity):
    # type: (Path, bool) -> None
    """Verify a signed JSON file.

    Performs both integrity verification (signature check) and identity verification
    (resolves and validates the controller's identity document if present).
    """
    # Load the JSON file
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f"❌ Invalid JSON file: {e}")
        return
    except Exception as e:  # pragma: no cover
        click.echo(f"❌ Error reading file: {e}")
        return

    # Check if file has a signature
    if "signature" not in data:
        click.echo("❌ No signature found in JSON file")
        return

    # Get controller if present for identity verification
    sig = data.get("signature", {})
    controller = sig.get("controller")
    identity_doc = None

    # Resolve identity document if controller is present and identity check not skipped
    if controller and not skip_identity:
        click.echo(f"🔍 Resolving identity: {controller}")
        try:
            identity_doc = resolve(controller)
            click.echo("✅ Identity document resolved")
        except Exception as e:
            click.echo(f"⚠️  Could not resolve identity: {e}")
            # Continue with signature verification only

    # Verify the signature with optional identity verification
    try:
        result = verify_json(data, identity_doc=identity_doc, raise_on_error=False)

        # Report integrity verification result
        if result.signature_valid:
            click.echo("✅ Signature integrity: Valid")
        else:
            click.echo(f"❌ Signature integrity: Invalid - {result.message}")
            return  # Don't continue if signature is invalid

        # Report identity verification result if applicable
        if controller:
            if skip_identity:
                click.echo("⏭️  Identity verification: Skipped")
            elif result.identity_verified is None:
                click.echo("❓ Identity verification: Not performed (no identity document)")
            elif result.identity_verified:
                click.echo("✅ Identity verification: Valid")
            else:
                click.echo(f"❌ Identity verification: Invalid - {result.message}")

        # Show signature details
        click.echo("\n📋 Signature details:")
        if controller:
            click.echo(f"   Controller: {controller}")
        if "pubkey" in sig:
            click.echo(f"   Public key: {sig['pubkey'][:20]}...")
        if "proof" in sig:
            click.echo(f"   Signature: {sig['proof'][:20]}...")

        # Overall result
        if result.is_valid:
            click.echo("\n✅ Overall verification: PASSED")
        else:
            click.echo("\n❌ Overall verification: FAILED")

    except Exception as e:  # pragma: no cover
        click.echo(f"❌ Verification error: {e}")
        return


@main.command()
def info():
    # type: () -> None
    """Show information about your current identity."""
    config_dir = get_config_dir()
    keypair_file = config_dir / "keypair.json"
    identity_file = config_dir / "did.json"

    if not keypair_file.exists():
        click.echo("❌ No identity found. Run 'iscc-crypto setup' first.")
        return

    try:
        with open(keypair_file) as f:
            keypair_data = json.load(f)

        click.echo("🔐 Your ISCC Crypto Identity")
        click.echo(f"📁 Location: {config_dir}")
        click.echo(f"🔑 Public key: {keypair_data['public_key']}")

        if keypair_data.get("controller"):
            click.echo(f"🌐 Controller: {keypair_data['controller']}")

        if identity_file.exists():
            with open(identity_file) as f:
                identity_doc = json.load(f)

            if "id" in identity_doc and identity_doc["id"].startswith("did:web:"):
                domain = identity_doc["id"].replace("did:web:", "")
                click.echo(f"📤 Publish to: https://{domain}/.well-known/did.json")

    except Exception as e:
        click.echo(f"❌ Error reading identity: {e}")


if __name__ == "__main__":  # pragma: no cover
    main()
