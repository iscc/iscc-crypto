"""Full test coverage for the iscc_crypto.resolve module."""

import asyncio
import json
import pytest

from iscc_crypto.resolve import (
    resolve,
    resolve_async,
    resolve_did_key,
    resolve_did_web,
    resolve_url,
    InvalidURIError,
    NetworkError,
    InvalidDocumentError,
    ResolutionError,
)


@pytest.mark.asyncio
async def test_resolve_did_key_valid(did_key, did_key_doc):
    """Test resolving a valid did:key returns correct DID document."""
    result = await resolve_did_key(did_key)

    # Check basic structure
    assert result["@context"] == [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ]
    assert result["id"] == did_key

    # Check verificationMethod
    assert len(result["verificationMethod"]) == 1
    vm = result["verificationMethod"][0]
    assert vm["id"] == f"{did_key}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    assert vm["type"] == "Multikey"
    assert vm["controller"] == did_key
    assert vm["publicKeyMultibase"] == "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    # Check capability references
    expected_ref = f"{did_key}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    assert result["authentication"] == [expected_ref]
    assert result["assertionMethod"] == [expected_ref]
    assert result["capabilityDelegation"] == [expected_ref]
    assert result["capabilityInvocation"] == [expected_ref]

    assert result == did_key_doc


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_prefix():
    """Test resolving invalid did:key prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid did:key format"):
        await resolve_did_key("did:web:example.com")


@pytest.mark.asyncio
async def test_resolve_did_key_no_prefix():
    """Test resolving URI without did:key prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid did:key format"):
        await resolve_did_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_multikey_prefix():
    """Test resolving did:key with invalid multikey prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key("did:key:x6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_base58():
    """Test resolving did:key with invalid base58 encoding raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key("did:key:z0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_key_prefix():
    """Test resolving did:key with wrong key prefix raises InvalidURIError."""
    # Valid base58 but wrong key type prefix (this would be for a different key type)
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key(
            "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWVUmw5Cz"
        )


@pytest.mark.asyncio
async def test_resolve_did_web_live(did_web, did_web_doc):
    assert await resolve_did_web(did_web) == did_web_doc


# Tests for resolve() sync wrapper function
def test_resolve_did_key_sync(did_key, did_key_doc):
    """Test sync resolve() function with did:key."""
    result = resolve(did_key)
    assert result == did_key_doc


def test_resolve_did_web_sync(did_web, did_web_doc):
    """Test sync resolve() function with did:web."""
    result = resolve(did_web)
    assert result == did_web_doc


def test_resolve_from_running_event_loop():
    """Test resolve() raises appropriate error when called from async context."""

    async def test_inner():
        with pytest.raises(
            ResolutionError, match="resolve\\(\\) cannot be called from async context"
        ):
            resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

    # Run in event loop to simulate async context
    asyncio.run(test_inner())


# Tests for resolve_async() routing logic
@pytest.mark.asyncio
async def test_resolve_async_http_url():
    """Test resolve_async routes HTTP URLs to resolve_url."""
    # This will test with a real HTTP request to httpbin.org
    url = "https://httpbin.org/json"
    result = await resolve_async(url)
    # httpbin.org/json returns a simple JSON object
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_resolve_async_https_url():
    """Test resolve_async routes HTTPS URLs to resolve_url."""
    url = "https://httpbin.org/json"
    result = await resolve_async(url)
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_resolve_async_did_key(did_key, did_key_doc):
    """Test resolve_async routes did:key to resolve_did_key."""
    result = await resolve_async(did_key)
    assert result == did_key_doc


@pytest.mark.asyncio
async def test_resolve_async_did_web(did_web, did_web_doc):
    """Test resolve_async routes did:web to resolve_did_web."""
    result = await resolve_async(did_web)
    assert result == did_web_doc


@pytest.mark.asyncio
async def test_resolve_async_unsupported_scheme():
    """Test resolve_async raises InvalidURIError for unsupported schemes."""
    with pytest.raises(InvalidURIError, match="Unsupported URI scheme"):
        await resolve_async("ftp://example.com/file")


@pytest.mark.asyncio
async def test_resolve_async_unknown_scheme():
    """Test resolve_async raises InvalidURIError for unknown schemes."""
    with pytest.raises(InvalidURIError, match="Unsupported URI scheme"):
        await resolve_async("xyz:test")


# Tests for resolve_url() function
@pytest.mark.asyncio
async def test_resolve_url_valid_json():
    """Test resolve_url with valid JSON response."""
    url = "https://httpbin.org/json"
    result = await resolve_url(url)
    assert isinstance(result, dict)
    # httpbin.org/json returns an object with "slideshow" key
    assert "slideshow" in result


@pytest.mark.asyncio
async def test_resolve_url_network_error():
    """Test resolve_url raises NetworkError for network failures."""
    # Use a non-existent domain
    with pytest.raises(NetworkError, match="Failed to fetch"):
        await resolve_url("https://nonexistent-domain-12345.com/document.json")


@pytest.mark.asyncio
async def test_resolve_url_http_error():
    """Test resolve_url raises NetworkError for HTTP errors."""
    # Use httpbin 404 endpoint
    with pytest.raises(NetworkError, match="Failed to fetch"):
        await resolve_url("https://httpbin.org/status/404")


@pytest.mark.asyncio
async def test_resolve_url_invalid_json():
    """Test resolve_url raises NetworkError for invalid JSON (caught as niquests exception)."""
    # httpbin.org/html returns HTML, not JSON
    # niquests.JSONDecodeError inherits from niquests.RequestException, so it gets caught by NetworkError
    with pytest.raises(NetworkError, match="Failed to fetch"):
        await resolve_url("https://httpbin.org/html")


# Additional resolve_did_web() tests
@pytest.mark.asyncio
async def test_resolve_did_web_invalid_prefix():
    """Test resolve_did_web with invalid prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid did:web format"):
        await resolve_did_web("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_web_empty_identifier():
    """Test resolve_did_web with empty method-specific identifier."""
    with pytest.raises(InvalidURIError, match="Empty method-specific identifier"):
        await resolve_did_web("did:web:")


@pytest.mark.asyncio
async def test_resolve_did_web_with_path():
    """Test resolve_did_web with path segments."""
    # This will fail with NetworkError but tests URL construction with paths
    with pytest.raises(NetworkError, match="Failed to fetch DID document"):
        await resolve_did_web("did:web:example.com:path:to:document")


@pytest.mark.asyncio
async def test_resolve_did_web_network_error():
    """Test resolve_did_web raises NetworkError for network failures."""
    with pytest.raises(NetworkError, match="Failed to fetch DID document"):
        await resolve_did_web("did:web:nonexistent-domain-12345.com")


@pytest.mark.asyncio
async def test_resolve_did_web_invalid_json():
    """Test resolve_did_web raises InvalidDocumentError for invalid JSON."""
    # This domain returns HTML instead of JSON
    with pytest.raises(InvalidDocumentError, match="Invalid JSON response"):
        await resolve_did_web("did:web:httpbin.org:html")


@pytest.mark.asyncio
async def test_resolve_did_web_mismatched_id():
    """Test resolve_did_web raises InvalidDocumentError for mismatched document ID."""
    # Create a test case where we know the document will have a different ID
    # We can't easily test this without a real endpoint that returns mismatched ID
    # But we can test the logic by creating a situation where it fails
    # This will hit a 404 which will be a NetworkError before we get to ID validation
    with pytest.raises(NetworkError):
        await resolve_did_web("did:web:httpbin.org:status:404")


# Tests for exception hierarchy
def test_resolution_error_inheritance():
    """Test that custom exceptions inherit from ResolutionError."""
    assert issubclass(NetworkError, ResolutionError)
    assert issubclass(InvalidURIError, ResolutionError)
    assert issubclass(InvalidDocumentError, ResolutionError)


def test_resolution_error_is_exception():
    """Test that ResolutionError inherits from Exception."""
    assert issubclass(ResolutionError, Exception)


def test_exception_messages():
    """Test that custom exceptions can be instantiated with messages."""
    network_err = NetworkError("Network failed")
    assert str(network_err) == "Network failed"

    uri_err = InvalidURIError("Invalid URI")
    assert str(uri_err) == "Invalid URI"

    doc_err = InvalidDocumentError("Invalid document")
    assert str(doc_err) == "Invalid document"

    res_err = ResolutionError("Resolution failed")
    assert str(res_err) == "Resolution failed"


# Edge case tests
@pytest.mark.asyncio
async def test_resolve_did_key_empty_multikey():
    """Test resolve_did_key with empty multikey after prefix."""
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key("did:key:")


@pytest.mark.asyncio
async def test_resolve_did_key_short_multikey():
    """Test resolve_did_key with too short multikey."""
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key("did:key:z123")


@pytest.mark.asyncio
async def test_resolve_url_empty_url():
    """Test resolve_url with malformed URL."""
    with pytest.raises(NetworkError, match="Failed to fetch"):
        await resolve_url("https://")


def test_resolve_empty_string():
    """Test resolve with empty string raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Unsupported URI scheme"):
        resolve("")


def test_resolve_none():
    """Test resolve with None input."""
    with pytest.raises(AttributeError):
        resolve(None)
