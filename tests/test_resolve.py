"""Full test coverage for the iscc_crypto.resolve module."""

import asyncio
import pytest

from iscc_crypto.resolve import (
    resolve,
    resolve_async,
    resolve_did_key,
    resolve_did_web,
    resolve_url,
    validate_cid,
    build_did_web_url,
    validate_did_doc,
    NetworkError,
    ResolutionError,
    NiquestsHttpClient,
)


class MockHttpClient:
    """Mock HTTP client for testing without network dependencies."""

    def __init__(self, responses=None):
        # type: (dict[str, dict] | None) -> None
        self.responses = responses or {}

    async def get_json(self, url):
        # type: (str) -> dict
        """Return mock response or raise appropriate errors."""
        if url in self.responses:
            response = self.responses[url]
            if "error" in response:
                error_type = response["error"]
                message = response.get("message", "Mock error")
                if error_type == "NetworkError":
                    from iscc_crypto.resolve import NetworkError

                    raise NetworkError(message)
                elif error_type == "ResolutionError":
                    from iscc_crypto.resolve import ResolutionError

                    raise ResolutionError(message)
            return response

        # Default: raise NetworkError for unknown URLs
        from iscc_crypto.resolve import NetworkError

        raise NetworkError(f"Failed to fetch {url}: Mock 404")


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
    """Test resolving invalid did:key prefix raises ResolutionError."""
    with pytest.raises(ResolutionError, match="Invalid did:key format"):
        await resolve_did_key("did:web:example.com")


@pytest.mark.asyncio
async def test_resolve_did_key_no_prefix():
    """Test resolving URI without did:key prefix raises ResolutionError."""
    with pytest.raises(ResolutionError, match="Invalid did:key format"):
        await resolve_did_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_multikey_prefix():
    """Test resolving did:key with invalid multikey prefix raises ValueError."""
    with pytest.raises(ValueError, match="Invalid key format"):
        await resolve_did_key("did:key:x6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_base58():
    """Test resolving did:key with invalid base58 encoding raises ValueError."""
    with pytest.raises(ValueError, match="Invalid character"):
        await resolve_did_key("did:key:z0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_key_prefix():
    """Test resolving did:key with wrong key prefix raises ValueError."""
    # Valid base58 but wrong key type prefix (this would be for a different key type)
    with pytest.raises(ValueError, match="Invalid public key prefix"):
        await resolve_did_key("did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWVUmw5Cz")


@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_did_web_live(did_web, did_web_doc):
    http_client = NiquestsHttpClient()
    assert await resolve_did_web(did_web, http_client) == did_web_doc


# Tests for resolve() sync wrapper function
def test_resolve_did_key_sync(did_key, did_key_doc):
    """Test sync resolve() function with did:key."""
    result = resolve(did_key)
    assert result == did_key_doc


@pytest.mark.network
def test_resolve_did_web_sync(did_web, did_web_doc):
    """Test sync resolve() function with did:web."""
    result = resolve(did_web)
    assert result == did_web_doc


def test_resolve_from_running_event_loop():
    """Test resolve() raises appropriate error when called from async context."""

    async def test_inner():
        with pytest.raises(ResolutionError, match="resolve\\(\\) cannot be called from async context"):
            resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

    # Run in event loop to simulate async context
    asyncio.run(test_inner())


# Tests for resolve_async() routing logic
@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_async_http_url():
    """Test resolve_async routes HTTP/HTTPS URLs to resolve_url."""
    # httpbin.org/json returns JSON without 'id' property, should fail CID validation
    url = "https://httpbin.org/json"
    with pytest.raises(
        ResolutionError,
        match="Retrieved document must contain an 'id' property",
    ):
        await resolve_async(url)


@pytest.mark.asyncio
async def test_resolve_async_did_key(did_key, did_key_doc):
    """Test resolve_async routes did:key to resolve_did_key."""
    result = await resolve_async(did_key)
    assert result == did_key_doc


@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_async_did_web(did_web, did_web_doc):
    """Test resolve_async routes did:web to resolve_did_web."""
    result = await resolve_async(did_web)
    assert result == did_web_doc


@pytest.mark.asyncio
async def test_resolve_async_unsupported_scheme():
    """Test resolve_async raises ResolutionError for unsupported schemes."""
    with pytest.raises(ResolutionError, match="Unsupported URI scheme"):
        await resolve_async("ftp://example.com/file")


@pytest.mark.asyncio
async def test_resolve_async_unknown_scheme():
    """Test resolve_async raises ResolutionError for unknown schemes."""
    with pytest.raises(ResolutionError, match="Unsupported URI scheme"):
        await resolve_async("xyz:test")


# Tests for resolve_url() function
@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_url_invalid_cid():
    """Test resolve_url with JSON that lacks required 'id' property."""
    # httpbin.org/json returns valid JSON but lacks required 'id' property for CID
    url = "https://httpbin.org/json"
    http_client = NiquestsHttpClient()
    with pytest.raises(
        ResolutionError,
        match="Retrieved document must contain an 'id' property",
    ):
        await resolve_url(url, http_client)


@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_url_network_error():
    """Test resolve_url raises NetworkError for network failures."""
    # Use a non-existent domain
    http_client = NiquestsHttpClient()
    with pytest.raises(NetworkError, match="Failed to fetch"):
        await resolve_url("https://nonexistent-domain-12345.com/document.json", http_client)


@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_url_http_error():
    """Test resolve_url raises NetworkError for HTTP errors."""
    # Use httpbin 404 endpoint
    http_client = NiquestsHttpClient()
    with pytest.raises(NetworkError, match="Failed to fetch"):
        await resolve_url("https://httpbin.org/status/404", http_client)


@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_url_invalid_json():
    """Test resolve_url raises ResolutionError for invalid JSON."""
    # httpbin.org/html returns HTML, not JSON
    http_client = NiquestsHttpClient()
    with pytest.raises(ResolutionError, match="Invalid JSON response"):
        await resolve_url("https://httpbin.org/html", http_client)


@pytest.mark.asyncio
async def test_resolve_url_non_string_id():
    """Test that resolve_url validates 'id' property is a string."""
    mock_client = MockHttpClient({"https://example.com/doc.json": {"id": 12345, "name": "Test"}})

    with pytest.raises(ResolutionError, match="Document 'id' property must be a string"):
        await resolve_url("https://example.com/doc.json", mock_client)


@pytest.mark.asyncio
async def test_resolve_url_mismatched_id():
    """Test that resolve_url validates 'id' matches the canonical URL."""
    mock_client = MockHttpClient(
        {"https://example.com/doc.json": {"id": "https://different.com/doc.json", "name": "Test"}}
    )

    with pytest.raises(
        ResolutionError,
        match="Document 'id' 'https://different.com/doc.json' does not match canonical URL 'https://example.com/doc.json'",
    ):
        await resolve_url("https://example.com/doc.json", mock_client)


# Tests for validate_cid() function
def test_validate_cid_valid_document():
    """Test validate_cid with valid CID document."""
    document = {"id": "https://example.com/doc.json", "name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    # Should not raise any exception
    validate_cid(document, canonical_url)


def test_validate_cid_missing_id_property():
    """Test validate_cid raises error when document lacks 'id' property."""
    document = {"name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(
        ResolutionError,
        match="Retrieved document must contain an 'id' property",
    ):
        validate_cid(document, canonical_url)


def test_validate_cid_non_dict_document():
    """Test validate_cid raises error when document is not a dict."""
    document = "not a dict"
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(
        ResolutionError,
        match="Retrieved document must contain an 'id' property",
    ):
        validate_cid(document, canonical_url)


def test_validate_cid_list_document():
    """Test validate_cid raises error when document is a list."""
    document = [{"id": "https://example.com/doc.json"}]
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(
        ResolutionError,
        match="Retrieved document must contain an 'id' property",
    ):
        validate_cid(document, canonical_url)


def test_validate_cid_none_document():
    """Test validate_cid raises error when document is None."""
    document = None
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(
        ResolutionError,
        match="Retrieved document must contain an 'id' property",
    ):
        validate_cid(document, canonical_url)


def test_validate_cid_non_string_id():
    """Test validate_cid raises error when 'id' property is not a string."""
    document = {"id": 12345, "name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(ResolutionError, match="Document 'id' property must be a string"):
        validate_cid(document, canonical_url)


def test_validate_cid_none_id():
    """Test validate_cid raises error when 'id' property is None."""
    document = {"id": None, "name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(ResolutionError, match="Document 'id' property must be a string"):
        validate_cid(document, canonical_url)


def test_validate_cid_list_id():
    """Test validate_cid raises error when 'id' property is a list."""
    document = {"id": ["https://example.com/doc.json"], "name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(ResolutionError, match="Document 'id' property must be a string"):
        validate_cid(document, canonical_url)


def test_validate_cid_mismatched_id():
    """Test validate_cid raises error when document ID doesn't match canonical URL."""
    document = {"id": "https://different.com/doc.json", "name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(
        ResolutionError,
        match="Document 'id' 'https://different.com/doc.json' does not match canonical URL 'https://example.com/doc.json'",
    ):
        validate_cid(document, canonical_url)


def test_validate_cid_empty_id():
    """Test validate_cid raises error when document ID is empty string."""
    document = {"id": "", "name": "Test Document"}
    canonical_url = "https://example.com/doc.json"

    with pytest.raises(
        ResolutionError,
        match="Document 'id' '' does not match canonical URL 'https://example.com/doc.json'",
    ):
        validate_cid(document, canonical_url)


def test_validate_cid_complex_valid_document():
    """Test validate_cid with complex valid document structure."""
    document = {
        "id": "https://example.com/complex-doc.json",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": "https://example.com/complex-doc.json#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "https://example.com/complex-doc.json",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            }
        ],
        "authentication": ["https://example.com/complex-doc.json#key1"],
    }
    canonical_url = "https://example.com/complex-doc.json"

    # Should not raise any exception
    validate_cid(document, canonical_url)


# Tests for build_did_web_url() function
def test_build_did_web_url_simple_domain():
    """Test build_did_web_url with simple domain."""
    did_web = "did:web:example.com"
    expected_url = "https://example.com/.well-known/did.json"

    result = build_did_web_url(did_web)
    assert result == expected_url


def test_build_did_web_url_domain_with_path():
    """Test build_did_web_url with domain and path."""
    did_web = "did:web:example.com:path:to:document"
    expected_url = "https://example.com/path/to/document/did.json"

    result = build_did_web_url(did_web)
    assert result == expected_url


def test_build_did_web_url_domain_with_port():
    """Test build_did_web_url with domain and port."""
    did_web = "did:web:example.com%3A8080"
    expected_url = "https://example.com:8080/.well-known/did.json"

    result = build_did_web_url(did_web)
    assert result == expected_url


def test_build_did_web_url_domain_with_port_and_path():
    """Test build_did_web_url with domain, port, and path."""
    did_web = "did:web:example.com%3A8080:user:alice"
    expected_url = "https://example.com:8080/user/alice/did.json"

    result = build_did_web_url(did_web)
    assert result == expected_url


def test_build_did_web_url_subdomain():
    """Test build_did_web_url with subdomain."""
    did_web = "did:web:identity.example.com"
    expected_url = "https://identity.example.com/.well-known/did.json"

    result = build_did_web_url(did_web)
    assert result == expected_url


def test_build_did_web_url_complex_path():
    """Test build_did_web_url with complex path structure."""
    did_web = "did:web:example.com:users:alice:credentials"
    expected_url = "https://example.com/users/alice/credentials/did.json"

    result = build_did_web_url(did_web)
    assert result == expected_url


def test_build_did_web_url_invalid_prefix():
    """Test build_did_web_url raises error for invalid prefix."""
    with pytest.raises(ResolutionError, match="Invalid did:web format"):
        build_did_web_url("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def test_build_did_web_url_empty_identifier():
    """Test build_did_web_url raises error for empty method-specific identifier."""
    with pytest.raises(ResolutionError, match="Empty method-specific identifier"):
        build_did_web_url("did:web:")


def test_build_did_web_url_no_prefix():
    """Test build_did_web_url raises error when missing did:web prefix."""
    with pytest.raises(ResolutionError, match="Invalid did:web format"):
        build_did_web_url("example.com")


def test_build_did_web_url_wrong_scheme():
    """Test build_did_web_url raises error for wrong DID method."""
    with pytest.raises(ResolutionError, match="Invalid did:web format"):
        build_did_web_url("did:example:123456")


# Tests for validate_did_document() function
def test_validate_did_document_valid():
    """Test validate_did_document with matching document ID."""
    did_document = {
        "id": "did:web:example.com",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [],
    }
    expected_did = "did:web:example.com"

    # Should not raise any exception
    validate_did_doc(did_document, expected_did)


def test_validate_did_document_mismatched_id():
    """Test validate_did_document raises error for mismatched document ID."""
    did_document = {"id": "did:web:different.com", "@context": ["https://www.w3.org/ns/did/v1"]}
    expected_did = "did:web:example.com"

    with pytest.raises(
        ResolutionError,
        match="DID document ID 'did:web:different.com' does not match requested DID 'did:web:example.com'",
    ):
        validate_did_doc(did_document, expected_did)


def test_validate_did_document_missing_id():
    """Test validate_did_document raises error when document lacks 'id' property."""
    did_document = {"@context": ["https://www.w3.org/ns/did/v1"], "verificationMethod": []}
    expected_did = "did:web:example.com"

    with pytest.raises(
        ResolutionError,
        match="DID document ID 'None' does not match requested DID 'did:web:example.com'",
    ):
        validate_did_doc(did_document, expected_did)


def test_validate_did_document_none_id():
    """Test validate_did_document raises error when document ID is None."""
    did_document = {"id": None, "@context": ["https://www.w3.org/ns/did/v1"]}
    expected_did = "did:web:example.com"

    with pytest.raises(
        ResolutionError,
        match="DID document ID 'None' does not match requested DID 'did:web:example.com'",
    ):
        validate_did_doc(did_document, expected_did)


def test_validate_did_document_empty_id():
    """Test validate_did_document raises error when document ID is empty string."""
    did_document = {"id": "", "@context": ["https://www.w3.org/ns/did/v1"]}
    expected_did = "did:web:example.com"

    with pytest.raises(
        ResolutionError,
        match="DID document ID '' does not match requested DID 'did:web:example.com'",
    ):
        validate_did_doc(did_document, expected_did)


def test_validate_did_document_non_string_id():
    """Test validate_did_document raises error when document ID is not a string."""
    did_document = {"id": 12345, "@context": ["https://www.w3.org/ns/did/v1"]}
    expected_did = "did:web:example.com"

    with pytest.raises(
        ResolutionError,
        match="DID document ID '12345' does not match requested DID 'did:web:example.com'",
    ):
        validate_did_doc(did_document, expected_did)


def test_validate_did_document_complex_valid():
    """Test validate_did_document with complex valid DID document."""
    did_document = {
        "id": "did:web:example.com:users:alice",
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "verificationMethod": [
            {
                "id": "did:web:example.com:users:alice#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com:users:alice",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            }
        ],
        "authentication": ["did:web:example.com:users:alice#key1"],
    }
    expected_did = "did:web:example.com:users:alice"

    # Should not raise any exception
    validate_did_doc(did_document, expected_did)


# Unit tests using mock HTTP client
@pytest.mark.asyncio
async def test_resolve_async_uses_default_http_client():
    """Test resolve_async uses NiquestsHttpClient by default."""
    # Test the default http_client path - this will fail with NetworkError (wrapped)
    with pytest.raises(NetworkError):
        await resolve_async("https://nonexistent-url-for-testing.com/doc.json")


@pytest.mark.asyncio
async def test_resolve_async_did_web_with_default_client():
    """Test resolve_async did:web path with default client."""
    # Test did:web path in resolve_async with default client - fails with NetworkError (wrapped)
    with pytest.raises(NetworkError):
        await resolve_async("did:web:nonexistent-domain-12345.com")


@pytest.mark.asyncio
async def test_resolve_url_success_with_mock():
    """Test resolve_url with valid CID document."""
    mock_client = MockHttpClient(
        {"https://example.com/doc.json": {"id": "https://example.com/doc.json", "name": "Test Document"}}
    )

    result = await resolve_url("https://example.com/doc.json", mock_client)
    assert result["id"] == "https://example.com/doc.json"
    assert result["name"] == "Test Document"


@pytest.mark.asyncio
async def test_resolve_did_web_success_with_mock():
    """Test resolve_did_web with valid DID document."""
    mock_client = MockHttpClient(
        {
            "https://example.com/.well-known/did.json": {
                "id": "did:web:example.com",
                "@context": ["https://www.w3.org/ns/did/v1"],
            }
        }
    )

    result = await resolve_did_web("did:web:example.com", mock_client)
    assert result["id"] == "did:web:example.com"


@pytest.mark.asyncio
async def test_resolve_did_web_invalid_json_with_mock():
    """Test resolve_did_web with invalid JSON response."""
    mock_client = MockHttpClient(
        {
            "https://example.com/.well-known/did.json": {
                "error": "ResolutionError",
                "message": "Invalid JSON response from https://example.com/.well-known/did.json: mock error",
            }
        }
    )

    with pytest.raises(ResolutionError, match="Invalid JSON response"):
        await resolve_did_web("did:web:example.com", mock_client)


@pytest.mark.asyncio
async def test_resolve_did_web_network_error_with_mock():
    """Test resolve_did_web with network error."""
    mock_client = MockHttpClient(
        {
            "https://example.com/.well-known/did.json": {
                "error": "NetworkError",
                "message": "Failed to fetch DID document from https://example.com/.well-known/did.json: mock network error",
            }
        }
    )

    with pytest.raises(NetworkError, match="Failed to fetch DID document from"):
        await resolve_did_web("did:web:example.com", mock_client)


@pytest.mark.asyncio
async def test_niquests_http_client_json_decode_error():
    """Test NiquestsHttpClient propagates JSON decode errors."""
    from iscc_crypto.resolve import NiquestsHttpClient
    import niquests

    client = NiquestsHttpClient()

    # Mock niquests to raise JSONDecodeError
    original_aget = niquests.aget

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise niquests.JSONDecodeError("Invalid JSON", "", 0)

    async def mock_aget(url, **kwargs):
        return MockResponse()

    niquests.aget = mock_aget

    try:
        with pytest.raises(ResolutionError, match="Invalid JSON response"):
            await client.get_json("https://example.com/test.json")
    finally:
        niquests.aget = original_aget


@pytest.mark.asyncio
async def test_niquests_http_client_request_error():
    """Test NiquestsHttpClient propagates request errors."""
    from iscc_crypto.resolve import NiquestsHttpClient
    import niquests

    client = NiquestsHttpClient()

    # Mock niquests to raise RequestException
    original_aget = niquests.aget

    async def mock_aget(url, **kwargs):
        raise niquests.RequestException("Network error")

    niquests.aget = mock_aget

    try:
        with pytest.raises(niquests.RequestException):
            await client.get_json("https://example.com/different-url.json")
    finally:
        niquests.aget = original_aget


@pytest.mark.asyncio
async def test_http_client_protocol_method():
    """Test HttpClient protocol ellipsis method."""
    from iscc_crypto.resolve import HttpClient

    # Create an instance that calls the protocol method directly
    class DirectProtocolCaller:
        pass

    caller = DirectProtocolCaller()

    # This should return None because the protocol method has ... (ellipsis)
    result = await HttpClient.get_json(caller, "https://example.com/test.json")
    assert result is None


# Additional resolve_did_web() tests
@pytest.mark.asyncio
async def test_resolve_did_web_invalid_prefix():
    """Test resolve_did_web with invalid prefix raises ResolutionError."""
    mock_client = MockHttpClient()
    with pytest.raises(ResolutionError, match="Invalid did:web format"):
        await resolve_did_web("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", mock_client)


@pytest.mark.asyncio
async def test_resolve_did_web_empty_identifier():
    """Test resolve_did_web with empty method-specific identifier."""
    mock_client = MockHttpClient()
    with pytest.raises(ResolutionError, match="Empty method-specific identifier"):
        await resolve_did_web("did:web:", mock_client)


@pytest.mark.asyncio
@pytest.mark.network
async def test_resolve_did_web_network_error():
    """Test resolve_did_web raises NetworkError for network failures."""
    http_client = NiquestsHttpClient()
    with pytest.raises(NetworkError, match="Failed to fetch DID document"):
        await resolve_did_web("did:web:nonexistent-domain-12345.com", http_client)


# Tests for exception hierarchy
def test_resolution_error_inheritance():
    """Test that custom exceptions inherit from ResolutionError."""
    assert issubclass(NetworkError, ResolutionError)


def test_resolution_error_is_exception():
    """Test that ResolutionError inherits from Exception."""
    assert issubclass(ResolutionError, Exception)


def test_exception_messages():
    """Test that custom exceptions can be instantiated with messages."""
    network_err = NetworkError("Network failed")
    assert str(network_err) == "Network failed"

    res_err = ResolutionError("Resolution failed")
    assert str(res_err) == "Resolution failed"


# Edge case tests
@pytest.mark.asyncio
async def test_resolve_did_key_empty_multikey():
    """Test resolve_did_key with empty multikey after prefix."""
    with pytest.raises(ValueError, match="Invalid key format"):
        await resolve_did_key("did:key:")


@pytest.mark.asyncio
async def test_resolve_did_key_short_multikey():
    """Test resolve_did_key with too short multikey."""
    with pytest.raises(ValueError, match="Invalid public key prefix"):
        await resolve_did_key("did:key:z123")


def test_resolve_empty_string():
    """Test resolve with empty string raises ResolutionError."""
    with pytest.raises(ResolutionError, match="Unsupported URI scheme"):
        resolve("")


def test_resolve_none():
    """Test resolve with None input."""
    with pytest.raises(AttributeError):
        resolve(None)
