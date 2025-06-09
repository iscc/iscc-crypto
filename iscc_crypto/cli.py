"""ISCC Crypto CLI - Command line interface for cryptographic identity management."""

import asyncio
import json
import stat
from pathlib import Path
import click
import platformdirs
from iscc_crypto.keys import key_generate, KeyPair
from iscc_crypto.resolve import resolve_url, NiquestsHttpClient


APP_NAME = "iscc-crypto"


def get_config_dir():
    # type: () -> Path
    """Get platform-specific configuration directory."""
    return Path(platformdirs.user_data_dir(APP_NAME))


def create_web_identity_doc(domain, public_key):
    # type: (str, str) -> dict
    """Create DID Web identity document."""
    did_id = f"did:web:{domain}"
    key_id = f"{did_id}#key-1"

    return {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did_id,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did_id,
                "publicKeyMultibase": public_key,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def create_standalone_identity_doc(public_key):
    # type: (str) -> dict
    """Create standalone CID identity document."""
    return {
        "@context": "https://w3id.org/cid/v1",
        "verificationMethod": [
            {"id": "#key-1", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": public_key}
        ],
    }


def save_files(keypair, identity_doc, config_dir):
    # type: (KeyPair, dict, Path) -> None
    """Save keypair and identity document with proper permissions."""
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

    # Save identity document as did.json (ready for upload)
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


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    # type: (click.Context) -> None
    """ISCC Crypto - Cryptographic operations for content identification."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
def setup():
    # type: () -> None
    """Set up your cryptographic identity."""
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
        identity_doc = create_web_identity_doc(domain, keypair.public_key)
        identity_id = f"did:web:{domain}"
        upload_url = f"https://{domain}/.well-known/did.json"

        # Update keypair with controller info
        keypair = KeyPair(
            public_key=keypair.public_key,
            secret_key=keypair.secret_key,
            controller=identity_id,
            key_id=f"{identity_id}#key-1",
        )
    else:
        identity_doc = create_standalone_identity_doc(keypair.public_key)
        identity_id = "standalone"

    # Save files
    save_files(keypair, identity_doc, config_dir)

    # Success message
    click.echo("✓ Generated keypair")
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
        click.echo(f"\n✓ Your standalone identity is ready to use")
        click.echo("  No publishing required - identity is self-contained")

    click.echo(f"\n📋 Check backup-instructions.txt for security guidance")


@main.command()
@click.argument("identifier")
def verify(identifier):
    # type: (str) -> None
    """Verify an identity (DID URL or document URL)."""
    click.echo(f"🔍 Verifying: {identifier}")

    try:
        if identifier.startswith("did:web:"):
            # Convert DID Web to URL
            domain = identifier.replace("did:web:", "")
            url = f"https://{domain}/.well-known/did.json"
        elif identifier.startswith("http"):
            url = identifier
        else:
            click.echo("❌ Invalid identifier. Use DID Web (did:web:example.com) or URL")
            return

        # Fetch and validate document
        click.echo(f"📥 Fetching: {url}")

        async def fetch_doc():
            http_client = NiquestsHttpClient()
            return await resolve_url(url, http_client)

        doc = asyncio.run(fetch_doc())

        if "@context" in doc and "verificationMethod" in doc:
            click.echo("✅ Valid identity document")

            # Show basic info
            if "id" in doc:
                click.echo(f"   ID: {doc['id']}")

            methods = doc.get("verificationMethod", [])
            click.echo(f"   Verification methods: {len(methods)}")

            for method in methods:
                if "publicKeyMultibase" in method:
                    key = method["publicKeyMultibase"]
                    click.echo(f"   Public key: {key[:20]}...")
        else:
            click.echo("❌ Invalid document format")

    except Exception as e:
        click.echo(f"❌ Verification failed: {e}")


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
