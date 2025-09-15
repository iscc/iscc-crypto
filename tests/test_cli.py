"""Tests for CLI functionality."""

import json
import pytest
from click.testing import CliRunner
from pathlib import Path

from iscc_crypto.cli import main, get_config_dir


def test_main_help():
    # type: () -> None
    """Test main command shows help."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, [])

    assert result.exit_code == 0
    assert "ISCC-CRYPTO" in result.output
    assert "Commands:" in result.output


def test_info_no_identity():
    # type: () -> None
    """Test info command when no identity exists."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            result = runner.invoke(main, ["info"])
            assert result.exit_code == 0
            assert "No identity found" in result.output
        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_setup_standalone_identity():
    # type: () -> None
    """Test setup command for standalone identity."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Simulate user input: no web server
            result = runner.invoke(main, ["setup"], input="n\n")

            assert result.exit_code == 0
            assert "Generated keypair" in result.output
            assert "standalone keypair" in result.output

            # Check files were created
            assert Path("keypair.json").exists()
            assert not Path("did.json").exists()  # No identity document for standalone
            assert Path("backup-instructions.txt").exists()

            # Verify file contents
            with open("keypair.json") as f:
                keypair_data = json.load(f)
            assert "public_key" in keypair_data
            assert "secret_key" in keypair_data
            assert keypair_data.get("controller") is None

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_setup_web_identity():
    # type: () -> None
    """Test setup command for web identity."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Simulate user input: has web server, choose web identity, domain
            result = runner.invoke(main, ["setup"], input="y\n1\nexample.com\n")

            assert result.exit_code == 0
            assert "Generated keypair" in result.output
            assert "did:web:example.com" in result.output
            assert "Upload did.json" in result.output

            # Check files were created
            assert Path("keypair.json").exists()
            assert Path("did.json").exists()

            # Verify DID Web document structure (controller_document format)
            with open("did.json") as f:
                identity_doc = json.load(f)
            assert identity_doc["id"] == "did:web:example.com"
            assert "@context" not in identity_doc  # Plain JSON, not JSON-LD
            assert "verificationMethod" in identity_doc
            assert identity_doc["verificationMethod"][0]["type"] == "Multikey"
            assert identity_doc["verificationMethod"][0]["id"] == "did:web:example.com#iscc"
            assert "authentication" in identity_doc
            assert "assertionMethod" in identity_doc
            assert "capabilityDelegation" in identity_doc
            assert "capabilityInvocation" in identity_doc

            # Verify keypair has controller info
            with open("keypair.json") as f:
                keypair_data = json.load(f)
            assert keypair_data["controller"] == "did:web:example.com"
            assert keypair_data["key_id"] == "iscc"

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_verify_invalid_identifier():
    # type: () -> None
    """Test validate-identity command with invalid identifier."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["validate-identity", "invalid-identifier"])

    assert result.exit_code == 0
    assert "Validation failed" in result.output


def test_setup_overwrite_cancelled():
    # type: () -> None
    """Test setup cancellation when identity exists."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Create existing keypair file
            Path("keypair.json").touch()

            # Simulate user input: don't overwrite
            result = runner.invoke(main, ["setup"], input="n\n")

            assert result.exit_code == 0
            assert "Setup cancelled" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_setup_standalone_no_webserver():
    # type: () -> None
    """Test setup when user has no webserver but chooses standalone."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Simulate user input: has webserver, choose standalone
            result = runner.invoke(main, ["setup"], input="y\n2\n")

            assert result.exit_code == 0
            assert "Generated keypair" in result.output
            assert "standalone keypair" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_info_with_web_identity():
    # type: () -> None
    """Test info command with web identity."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Create test files
            keypair_data = {
                "public_key": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
                "secret_key": "z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA",
                "controller": "did:web:example.com",
                "key_id": "iscc",
            }

            identity_doc = {"id": "did:web:example.com", "@context": "https://www.w3.org/ns/did/v1"}

            with open("keypair.json", "w") as f:
                json.dump(keypair_data, f)

            with open("did.json", "w") as f:
                json.dump(identity_doc, f)

            result = runner.invoke(main, ["info"])

            assert result.exit_code == 0
            assert "ISCC Crypto Identity" in result.output
            assert "did:web:example.com" in result.output
            assert "Publish to:" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_info_with_invalid_keypair():
    # type: () -> None
    """Test info command with corrupted keypair file."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Create invalid keypair file
            with open("keypair.json", "w") as f:
                f.write("invalid json")

            result = runner.invoke(main, ["info"])

            assert result.exit_code == 0
            assert "Error reading identity" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_verify_network_error():
    # type: () -> None
    """Test validate-identity command with network error."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["validate-identity", "did:web:nonexistent.example"])

    assert result.exit_code == 0
    assert "Validation failed" in result.output


def test_get_config_dir():
    # type: () -> None
    """Test get_config_dir function."""
    config_dir = get_config_dir()
    assert "iscc-crypto" in str(config_dir)


def test_verify_success_mock():
    # type: () -> None
    """Test validate-identity command with successful verification (mocked)."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    # Mock the resolve function to return a valid document
    import iscc_crypto.cli

    original_resolve = iscc_crypto.cli.resolve

    def mock_resolve(uri, http_client=None):
        # Return a valid DID document
        return {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#iscc",
                    "publicKeyMultibase": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
                }
            ],
        }

    iscc_crypto.cli.resolve = mock_resolve

    try:
        result = runner.invoke(main, ["validate-identity", "did:web:example.com"])

        assert result.exit_code == 0
        assert "Valid identity document" in result.output
        assert "ID: did:web:example.com" in result.output
        assert "Verification methods: 1" in result.output
        assert "Public key: z6MkpFpVngrAUTSY6Pag..." in result.output

    finally:
        iscc_crypto.cli.resolve = original_resolve


def test_verify_invalid_format_mock():
    # type: () -> None
    """Test validate-identity command with invalid document format (mocked)."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    # Mock the resolve function to raise validation error
    import iscc_crypto.cli
    from iscc_crypto.resolve import ResolutionError

    original_resolve = iscc_crypto.cli.resolve

    def mock_resolve(uri, http_client=None):
        # Raise validation error as would happen with invalid document
        raise ResolutionError("Document 'id' 'invalid' does not match requested DID 'did:web:example.com'")

    iscc_crypto.cli.resolve = mock_resolve

    try:
        result = runner.invoke(main, ["validate-identity", "did:web:example.com"])

        assert result.exit_code == 0
        assert "Validation failed" in result.output

    finally:
        iscc_crypto.cli.resolve = original_resolve


def test_verify_http_url():
    # type: () -> None
    """Test validate-identity command with HTTP URL."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["validate-identity", "https://example.com/.well-known/did.json"])

    assert result.exit_code == 0
    assert "Validation failed" in result.output  # Will fail due to network error


def test_save_files_chmod_oserror():
    # type: () -> None
    """Test save_files function when chmod fails with OSError (e.g., Windows)."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli
        from unittest.mock import patch

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Mock Path.chmod to raise OSError (simulates Windows behavior)
            with patch("pathlib.Path.chmod", side_effect=OSError("Permission denied")):
                # Simulate user input: no web server (standalone identity)
                result = runner.invoke(main, ["setup"], input="n\n")

                assert result.exit_code == 0
                assert "Generated keypair" in result.output
                assert "standalone keypair" in result.output

                # Check files were created despite chmod failure
                assert Path("keypair.json").exists()
                assert not Path("did.json").exists()  # No identity document for standalone
                assert Path("backup-instructions.txt").exists()

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_save_files_chmod_notimplementederror():
    # type: () -> None
    """Test save_files function when chmod fails with NotImplementedError."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli
        from unittest.mock import patch

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Mock Path.chmod to raise NotImplementedError
            with patch("pathlib.Path.chmod", side_effect=NotImplementedError("chmod not supported")):
                # Simulate user input: no web server (standalone identity)
                result = runner.invoke(main, ["setup"], input="n\n")

                assert result.exit_code == 0
                assert "Generated keypair" in result.output
                assert "standalone keypair" in result.output

                # Check files were created despite chmod failure
                assert Path("keypair.json").exists()
                assert not Path("did.json").exists()  # No identity document for standalone
                assert Path("backup-instructions.txt").exists()

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_keygen_without_domain():
    # type: () -> None
    """Test keygen command without domain."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen"])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert "public_key" in output
    assert "secret_key" in output
    assert output["public_key"].startswith("z")
    assert output["secret_key"].startswith("z")
    # No controller or controller_document when no domain
    assert "controller" not in output
    assert "controller_document" not in output


def test_keygen_with_domain():
    # type: () -> None
    """Test keygen command with domain."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen", "example.com"])

    assert result.exit_code == 0

    # Check that stderr contains keypair info
    assert "# Generated keypair (KEEP SECRET!):" in result.output
    assert "# Public Key:" in result.output
    assert "# Secret Key:" in result.output
    assert "# Controller Document for publication:" in result.output
    assert "# Publish to: https://example.com/.well-known/did.json" in result.output

    # Extract JSON from output (skip the comment lines)
    output_lines = result.output.strip().split("\n")
    json_lines = [line for line in output_lines if not line.startswith("#")]
    json_str = "\n".join(json_lines)
    doc = json.loads(json_str)

    # Should only contain controller document, not keypair
    assert "keypair" not in doc
    assert "secret_key" not in doc
    assert "public_key" not in doc

    # Check controller document structure
    assert doc["id"] == "did:web:example.com"
    assert "verificationMethod" in doc
    assert len(doc["verificationMethod"]) == 1

    # Extract public key from the output comments for verification
    pubkey_line = [line for line in output_lines if line.startswith("# Public Key:")][0]
    pubkey = pubkey_line.split(":", 1)[1].strip()

    # Check verification method uses public key as ID
    vm = doc["verificationMethod"][0]
    assert vm["type"] == "Multikey"
    assert vm["controller"] == "did:web:example.com"
    assert vm["publicKeyMultibase"] == pubkey
    # ID should be controller#public_key since key_id is None
    assert vm["id"] == f"did:web:example.com#{pubkey}"

    # Check all verification relationships
    assert "authentication" in doc
    assert "assertionMethod" in doc
    assert "capabilityDelegation" in doc
    assert "capabilityInvocation" in doc


def test_keygen_with_protocol_in_domain():
    # type: () -> None
    """Test keygen command strips protocol from domain."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen", "https://example.com/"])

    assert result.exit_code == 0

    # Extract JSON from output (skip the comment lines)
    output_lines = result.output.strip().split("\n")
    json_lines = [line for line in output_lines if not line.startswith("#")]
    json_str = "\n".join(json_lines)
    doc = json.loads(json_str)

    # Check domain was cleaned in controller document
    assert doc["id"] == "did:web:example.com"

    # Check output shows clean URL
    assert "# Publish to: https://example.com/.well-known/did.json" in result.output


def test_keygen_with_individual_identity():
    # type: () -> None
    """Test keygen command with individual identity path."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen", "example.com/alice"])

    assert result.exit_code == 0

    # Check output contains correct information
    assert "# Generated keypair (KEEP SECRET!):" in result.output
    assert "# Publish to: https://example.com/alice/did.json" in result.output

    # Extract JSON from output
    output_lines = result.output.strip().split("\n")
    json_lines = [line for line in output_lines if not line.startswith("#")]
    json_str = "\n".join(json_lines)
    doc = json.loads(json_str)

    # Check controller document
    assert doc["id"] == "did:web:example.com:alice"
    assert doc["verificationMethod"][0]["controller"] == "did:web:example.com:alice"


def test_keygen_with_nested_path():
    # type: () -> None
    """Test keygen command with nested path identity."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen", "example.com/users/alice"])

    assert result.exit_code == 0

    # Check output contains correct information
    assert "# Publish to: https://example.com/users/alice/did.json" in result.output

    # Extract JSON from output
    output_lines = result.output.strip().split("\n")
    json_lines = [line for line in output_lines if not line.startswith("#")]
    json_str = "\n".join(json_lines)
    doc = json.loads(json_str)

    # Check controller document
    assert doc["id"] == "did:web:example.com:users:alice"
    assert doc["verificationMethod"][0]["controller"] == "did:web:example.com:users:alice"


def test_keygen_with_custom_key_id():
    # type: () -> None
    """Test keygen command with custom key ID."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen", "-k", "mykey", "example.com"])

    assert result.exit_code == 0

    # Check that output shows custom key ID
    assert "# Key ID:      mykey" in result.output

    # Extract JSON from output
    output_lines = result.output.strip().split("\n")
    json_lines = [line for line in output_lines if not line.startswith("#")]
    json_str = "\n".join(json_lines)
    doc = json.loads(json_str)

    # Check verification method uses custom key ID
    vm = doc["verificationMethod"][0]
    assert vm["id"] == "did:web:example.com#mykey"

    # Check all verification relationships use custom key ID
    assert doc["authentication"] == ["did:web:example.com#mykey"]
    assert doc["assertionMethod"] == ["did:web:example.com#mykey"]
    assert doc["capabilityDelegation"] == ["did:web:example.com#mykey"]
    assert doc["capabilityInvocation"] == ["did:web:example.com#mykey"]


def test_keygen_standalone_with_key_id():
    # type: () -> None
    """Test keygen command without domain but with key ID."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["keygen", "-k", "mykey"])

    assert result.exit_code == 0
    output = json.loads(result.output)

    # Check output includes key_id
    assert "key_id" in output
    assert output["key_id"] == "mykey"
    assert "public_key" in output
    assert "secret_key" in output


def test_sign_no_identity():
    # type: () -> None
    """Test sign command when no identity exists."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Create a test JSON file
            test_json = {"test": "data", "value": 123}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            result = runner.invoke(main, ["sign", "test.json"])

            assert result.exit_code == 0
            assert "No identity configured" in result.output
            assert not Path("test.signed.json").exists()

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_with_identity():
    # type: () -> None
    """Test sign command with configured identity."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup identity first
            result = runner.invoke(main, ["setup"], input="n\n")
            assert result.exit_code == 0

            # Create a test JSON file
            test_json = {"test": "data", "value": 123}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Sign the file
            result = runner.invoke(main, ["sign", "test.json"])

            assert result.exit_code == 0
            assert "Signed JSON saved to" in result.output
            assert Path("test.signed.json").exists()

            # Verify signed file structure
            with open("test.signed.json") as f:
                signed_data = json.load(f)

            assert "test" in signed_data
            assert signed_data["test"] == "data"
            assert "signature" in signed_data
            assert "version" in signed_data["signature"]
            assert "pubkey" in signed_data["signature"]
            assert "proof" in signed_data["signature"]

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_with_web_identity():
    # type: () -> None
    """Test sign command with web identity."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup web identity
            result = runner.invoke(main, ["setup"], input="y\n1\nexample.com\n")
            assert result.exit_code == 0

            # Create a test JSON file
            test_json = {"message": "Hello world"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Sign the file
            result = runner.invoke(main, ["sign", "test.json"])

            assert result.exit_code == 0
            assert "Signed JSON saved to" in result.output
            assert "Controller: did:web:example.com" in result.output
            assert Path("test.signed.json").exists()

            # Verify signed file has controller
            with open("test.signed.json") as f:
                signed_data = json.load(f)

            assert signed_data["signature"]["controller"] == "did:web:example.com"
            assert signed_data["signature"]["keyid"] == "iscc"

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_invalid_json():
    # type: () -> None
    """Test sign command with invalid JSON file."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup identity
            result = runner.invoke(main, ["setup"], input="n\n")
            assert result.exit_code == 0

            # Create invalid JSON file
            with open("invalid.json", "w") as f:
                f.write("not valid json {")

            # Try to sign
            result = runner.invoke(main, ["sign", "invalid.json"])

            assert result.exit_code == 0
            assert "Invalid JSON file" in result.output
            assert not Path("invalid.signed.json").exists()

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_file_not_found():
    # type: () -> None
    """Test sign command with non-existent file."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    result = runner.invoke(main, ["sign", "nonexistent.json"])

    assert result.exit_code != 0


def test_sign_with_signature_type():
    # type: () -> None
    """Test sign command with different signature types."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup identity
            result = runner.invoke(main, ["setup"], input="n\n")
            assert result.exit_code == 0

            # Create test JSON
            test_json = {"data": "test"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Test self_verifying type
            result = runner.invoke(main, ["sign", "test.json", "-t", "self_verifying"])
            assert result.exit_code == 0

            with open("test.signed.json") as f:
                signed_data = json.load(f)
            assert "pubkey" in signed_data["signature"]
            assert "controller" not in signed_data["signature"]

            # Test proof_only type
            result = runner.invoke(main, ["sign", "test.json", "-t", "proof_only"])
            assert result.exit_code == 0

            with open("test.signed.json") as f:
                signed_data = json.load(f)
            assert "proof" in signed_data["signature"]
            assert "pubkey" not in signed_data["signature"]

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_already_signed():
    # type: () -> None
    """Test sign command with already signed JSON."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup identity
            result = runner.invoke(main, ["setup"], input="n\n")
            assert result.exit_code == 0

            # Create already signed JSON
            signed_json = {"data": "test", "signature": {"proof": "existing"}}
            with open("signed.json", "w") as f:
                json.dump(signed_json, f)

            # Try to sign
            result = runner.invoke(main, ["sign", "signed.json"])

            assert result.exit_code == 0
            assert "Signing failed" in result.output
            assert "Input must not contain a 'signature' field" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_with_identity_bound_type():
    # type: () -> None
    """Test sign command with identity_bound signature type."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup web identity for identity_bound signature
            result = runner.invoke(main, ["setup"], input="y\n1\nexample.com\n")
            assert result.exit_code == 0

            # Create test JSON
            test_json = {"data": "test"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Test identity_bound type
            result = runner.invoke(main, ["sign", "test.json", "-t", "identity_bound"])
            assert result.exit_code == 0
            assert "Signed JSON saved to" in result.output

            with open("test.signed.json") as f:
                signed_data = json.load(f)
            assert "controller" in signed_data["signature"]
            assert "keyid" in signed_data["signature"]
            assert signed_data["signature"]["controller"] == "did:web:example.com"

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_corrupted_keypair():
    # type: () -> None
    """Test sign command with corrupted keypair that causes load_keypair to fail."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Create a keypair.json with invalid secret key
            invalid_keypair = {
                "public_key": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
                "secret_key": "invalid_secret_key",  # This will cause key_from_secret to fail
                "controller": None,
                "key_id": None,
            }
            with open("keypair.json", "w") as f:
                json.dump(invalid_keypair, f)

            # Create test JSON
            test_json = {"data": "test"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Try to sign with corrupted keypair
            result = runner.invoke(main, ["sign", "test.json"])

            assert result.exit_code == 0
            assert "No identity configured" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_load_keypair_with_missing_secret_key():
    # type: () -> None
    """Test load_keypair when secret_key is missing from keypair.json."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Create a keypair.json missing secret_key
            invalid_keypair = {
                "public_key": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
                # Missing secret_key will cause KeyError
            }
            with open("keypair.json", "w") as f:
                json.dump(invalid_keypair, f)

            # Create test JSON
            test_json = {"data": "test"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Try to sign with incomplete keypair
            result = runner.invoke(main, ["sign", "test.json"])

            assert result.exit_code == 0
            assert "No identity configured" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_main_entry_point():
    # type: () -> None
    """Test main entry point when called directly."""
    import iscc_crypto.cli

    # Test the if __name__ == '__main__' condition
    if __name__ != "__main__":
        # This tests the module structure
        assert hasattr(iscc_crypto.cli, "main")
        assert callable(iscc_crypto.cli.main)


def test_sign_with_auto_type():
    # type: () -> None
    """Test sign command with auto signature type."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup standalone identity
            result = runner.invoke(main, ["setup"], input="n\n")
            assert result.exit_code == 0

            # Create test JSON
            test_json = {"data": "test"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Test auto type (default)
            result = runner.invoke(main, ["sign", "test.json", "-t", "auto"])
            assert result.exit_code == 0
            assert "Signed JSON saved to" in result.output

            with open("test.signed.json") as f:
                signed_data = json.load(f)
            assert "signature" in signed_data
            # Auto should choose self_verifying for standalone identity
            assert "pubkey" in signed_data["signature"]

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_sign_output_shows_partial_keys():
    # type: () -> None
    """Test that sign command output shows partial keys and signature."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    with runner.isolated_filesystem():
        # Mock get_config_dir to return current directory
        import iscc_crypto.cli

        original_get_config_dir = iscc_crypto.cli.get_config_dir
        iscc_crypto.cli.get_config_dir = lambda: Path(".")

        try:
            # Setup standalone identity
            result = runner.invoke(main, ["setup"], input="n\n")
            assert result.exit_code == 0

            # Create test JSON
            test_json = {"data": "test"}
            with open("test.json", "w") as f:
                json.dump(test_json, f)

            # Sign and check output
            result = runner.invoke(main, ["sign", "test.json"])
            assert result.exit_code == 0

            # Check that it shows truncated public key and signature
            assert "Public key:" in result.output
            assert "..." in result.output  # Shows truncated key
            assert "Signature:" in result.output

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_main_version_option():
    # type: () -> None
    """Test main command with version option."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["--version"])

    assert result.exit_code == 0
    assert "iscc-crypto" in result.output


def test_main_help_option():
    # type: () -> None
    """Test main command with help option."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "ISCC-CRYPTO" in result.output
    assert "Commands:" in result.output
