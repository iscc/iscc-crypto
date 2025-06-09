"""Tests for CLI functionality."""

import json
import pytest
from click.testing import CliRunner
from pathlib import Path

from iscc_crypto.cli import main, get_config_dir, create_web_identity_doc, create_standalone_identity_doc


def test_main_help():
    # type: () -> None
    """Test main command shows help."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, [])

    assert result.exit_code == 0
    assert "ISCC Crypto" in result.output
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


def test_create_web_identity_doc():
    # type: () -> None
    """Test web identity document creation."""
    public_key = "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
    domain = "example.com"

    doc = create_web_identity_doc(domain, public_key)

    assert doc["@context"] == "https://www.w3.org/ns/did/v1"
    assert doc["id"] == "did:web:example.com"
    assert len(doc["verificationMethod"]) == 1
    assert doc["verificationMethod"][0]["publicKeyMultibase"] == public_key
    assert doc["authentication"] == ["did:web:example.com#key-1"]
    assert doc["assertionMethod"] == ["did:web:example.com#key-1"]


def test_create_standalone_identity_doc():
    # type: () -> None
    """Test standalone identity document creation."""
    public_key = "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"

    doc = create_standalone_identity_doc(public_key)

    assert doc["@context"] == "https://w3id.org/cid/v1"
    assert len(doc["verificationMethod"]) == 1
    assert doc["verificationMethod"][0]["publicKeyMultibase"] == public_key
    assert doc["verificationMethod"][0]["id"] == "#key-1"


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
            assert "standalone identity" in result.output

            # Check files were created
            assert Path("keypair.json").exists()
            assert Path("did.json").exists()
            assert Path("backup-instructions.txt").exists()

            # Verify file contents
            with open("keypair.json") as f:
                keypair_data = json.load(f)
            assert "public_key" in keypair_data
            assert "secret_key" in keypair_data

            with open("did.json") as f:
                identity_doc = json.load(f)
            assert "@context" in identity_doc
            assert "verificationMethod" in identity_doc

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

            # Verify DID Web document
            with open("did.json") as f:
                identity_doc = json.load(f)
            assert identity_doc["id"] == "did:web:example.com"

            # Verify keypair has controller info
            with open("keypair.json") as f:
                keypair_data = json.load(f)
            assert keypair_data["controller"] == "did:web:example.com"

        finally:
            iscc_crypto.cli.get_config_dir = original_get_config_dir


def test_verify_invalid_identifier():
    # type: () -> None
    """Test verify command with invalid identifier."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["verify", "invalid-identifier"])

    assert result.exit_code == 0
    assert "Invalid identifier" in result.output


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
            assert "standalone identity" in result.output

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
                "key_id": "did:web:example.com#key-1",
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
    """Test verify command with network error."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["verify", "did:web:nonexistent.example"])

    assert result.exit_code == 0
    assert "Verification failed" in result.output


def test_get_config_dir():
    # type: () -> None
    """Test get_config_dir function."""
    config_dir = get_config_dir()
    assert "iscc-crypto" in str(config_dir)


def test_verify_success_mock():
    # type: () -> None
    """Test verify command with successful verification (mocked)."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    # Mock the async function to return a valid document
    import iscc_crypto.cli
    import asyncio

    original_asyncio_run = asyncio.run

    def mock_asyncio_run(coro):
        # Return a valid DID document
        return {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "publicKeyMultibase": "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx",
                }
            ],
        }

    iscc_crypto.cli.asyncio.run = mock_asyncio_run

    try:
        result = runner.invoke(main, ["verify", "did:web:example.com"])

        assert result.exit_code == 0
        assert "Valid identity document" in result.output
        assert "ID: did:web:example.com" in result.output
        assert "Verification methods: 1" in result.output
        assert "Public key: z6MkpFpVngrAUTSY6Pag..." in result.output

    finally:
        iscc_crypto.cli.asyncio.run = original_asyncio_run


def test_verify_invalid_format_mock():
    # type: () -> None
    """Test verify command with invalid document format (mocked)."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})

    # Mock the async function to return an invalid document
    import iscc_crypto.cli
    import asyncio

    original_asyncio_run = asyncio.run

    def mock_asyncio_run(coro):
        # Return an invalid document (missing required fields)
        return {"invalid": "document"}

    iscc_crypto.cli.asyncio.run = mock_asyncio_run

    try:
        result = runner.invoke(main, ["verify", "did:web:example.com"])

        assert result.exit_code == 0
        assert "Invalid document format" in result.output

    finally:
        iscc_crypto.cli.asyncio.run = original_asyncio_run


def test_verify_http_url():
    # type: () -> None
    """Test verify command with HTTP URL."""
    runner = CliRunner(env={"PYTHONIOENCODING": "utf-8"})
    result = runner.invoke(main, ["verify", "https://example.com/.well-known/did.json"])

    assert result.exit_code == 0
    assert "Verification failed" in result.output  # Will fail due to network error


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
                assert "standalone identity" in result.output

                # Check files were created despite chmod failure
                assert Path("keypair.json").exists()
                assert Path("did.json").exists()
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
                assert "standalone identity" in result.output

                # Check files were created despite chmod failure
                assert Path("keypair.json").exists()
                assert Path("did.json").exists()
                assert Path("backup-instructions.txt").exists()

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
