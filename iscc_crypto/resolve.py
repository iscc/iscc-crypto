"""
This module implements dereferencing of URIs to Controlled Identifier Documents (CID & DID).

Controlled Identifier Documents are digital identity files (identifier metadata) that contain
cryptographic keys and other metadata to verify the identity of a subject or discover interactive
services that are associated with the subject.

This module supports the following URI schemes for resolving CID & DID documents:

- **HTTP/HTTPS URLs**: Direct document fetching
- **did:key**: Ed25519 Multikey-based DID document generation
- **did:web**: Web-based DID resolution via HTTPS transformation

Reference:
- https://www.w3.org/TR/cid-1.0/
- https://www.w3.org/TR/did-1.0/
"""

import asyncio
import time
import urllib.parse
from typing import Protocol

import niquests

from iscc_crypto.keys import pubkey_decode

# Simple in-memory cache: {url: (result, timestamp)}
_cache = {}  # type: dict[str, tuple[dict | Exception, float]]


__all__ = [
    "resolve",
    "resolve_async",
    "validate_cid",
    "build_did_web_url",
    "validate_did_doc",
    "HttpClient",
    "NiquestsHttpClient",
]


class HttpClient(Protocol):
    """HTTP client protocol for dependency injection."""

    async def get_json(self, url):
        # type: (str) -> dict
        """Fetch JSON from URL.

        :param url: The URL to fetch JSON from
        :return: Parsed JSON response as dictionary
        """
        ...


class NiquestsHttpClient:
    """Real HTTP client using niquests."""

    async def get_json(self, url):
        # type: (str) -> dict
        """Fetch JSON from URL using niquests with 5-minute cache.

        :param url: The URL to fetch JSON from
        :return: Parsed JSON response as dictionary
        :raises ResolutionError: If JSON parsing fails
        """
        # Check cache (5-minute TTL)
        now = time.time()
        if url in _cache:
            result, timestamp = _cache[url]
            if now - timestamp < 300:  # 5 minutes
                if isinstance(result, Exception):
                    raise result
                return result

        # Fetch from network
        try:
            response = await niquests.aget(url, timeout=(5, 10), headers={"User-Agent": "iscc-notary"})
            response.raise_for_status()
            json_result = response.json()
            _cache[url] = (json_result, now)
            return json_result
        except niquests.JSONDecodeError as e:
            error = ResolutionError(f"Invalid JSON response from {url}: {e}")
            _cache[url] = (error, now)
            raise error
        except Exception as e:
            # Cache network errors too
            _cache[url] = (e, now)
            raise


def resolve(uri, http_client=None):
    # type: (str, HttpClient | None) -> dict
    """Resolve a URI to a CID or DID document (wraps async function).

    :param uri: The URI to resolve (HTTP(S), did:key, or did:web)
    :param http_client: Optional HTTP client for dependency injection
    :return: Resolved CID or DID document
    :raises ResolutionError: If called from async context or resolution fails
    """
    try:
        return asyncio.run(resolve_async(uri, http_client))
    except RuntimeError as e:
        if "cannot be called from a running event loop" in str(e):
            raise ResolutionError("resolve() cannot be called from async context. Use resolve_async() instead.")
        raise  # pragma: no cover


async def resolve_async(uri, http_client=None):
    # type: (str, HttpClient | None) -> dict
    """Resolve a URI to a CID or DID document asynchronously.

    :param uri: The URI to resolve (HTTP(S), did:key, or did:web)
    :param http_client: Optional HTTP client for dependency injection
    :return: Resolved CID or DID document
    :raises ResolutionError: If URI scheme is unsupported
    """
    if http_client is None:
        http_client = NiquestsHttpClient()

    # Route to the appropriate resolver
    if uri.startswith(("http://", "https://")):
        return await resolve_url(uri, http_client)
    elif uri.startswith("did:key:"):
        return await resolve_did_key(uri)
    elif uri.startswith("did:web:"):
        return await resolve_did_web(uri, http_client)
    else:
        raise ResolutionError(f"Unsupported URI scheme: {uri}")


async def resolve_url(url, http_client):
    # type: (str, HttpClient) -> dict
    """Resolve Controlled Identifier HTTP(S) URLs per W3C CID specification.

    :param url: The HTTP(S) URL to resolve
    :param http_client: HTTP client for fetching the document
    :return: Validated CID document
    :raises NetworkError: If fetching fails
    :raises ResolutionError: If document validation fails
    """
    try:
        document = await http_client.get_json(url)
    except Exception as e:
        raise NetworkError(f"Failed to fetch {url}: {e}")
    validate_cid(document, url)
    return document


def validate_cid(document, canonical_url):
    # type: (dict, str) -> None
    """Validate a Controlled Identifier Document per W3C CID specification.

    :param document: The parsed JSON document to validate
    :param canonical_url: The canonical URL that should match the document's 'id' property
    :raises ResolutionError: If document structure is invalid or ID doesn't match
    """
    if not isinstance(document, dict) or "id" not in document:
        raise ResolutionError("Retrieved document must contain an 'id' property")

    document_id = document["id"]
    if not isinstance(document_id, str):
        raise ResolutionError("Document 'id' property must be a string")

    if document_id != canonical_url:
        raise ResolutionError(f"Document 'id' '{document_id}' does not match canonical URL '{canonical_url}'")


async def resolve_did_key(did_key):
    # type: (str) -> dict
    """Generate DID document from did:key URI.

    :param did_key: The did:key URI to resolve
    :return: Generated DID document with verification methods
    :raises ResolutionError: If did:key format is invalid
    :raises ValueError: If multikey decoding fails
    """
    if not did_key.startswith("did:key:"):
        raise ResolutionError(f"Invalid did:key format: {did_key}")

    multikey = did_key[8:]
    pubkey_decode(multikey)  # Let ValueError propagate

    verification_method_id = f"{did_key}#{multikey}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did_key,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "Multikey",
                "controller": did_key,
                "publicKeyMultibase": multikey,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
        "capabilityDelegation": [verification_method_id],
        "capabilityInvocation": [verification_method_id],
    }


async def resolve_did_web(did_web, http_client):
    # type: (str, HttpClient) -> dict
    """Convert did:web to HTTPS URL and fetch DID document per W3C spec.

    :param did_web: The did:web identifier to resolve
    :param http_client: HTTP client for fetching the document
    :return: Validated DID document
    :raises NetworkError: If fetching fails
    :raises ResolutionError: If document validation fails
    """
    https_url = build_did_web_url(did_web)
    try:
        did_document = await http_client.get_json(https_url)
    except Exception as e:
        raise NetworkError(f"Failed to fetch DID document from {https_url}: {e}")
    validate_did_doc(did_document, did_web)
    return did_document


def build_did_web_url(did_web):
    # type: (str) -> str
    """Build HTTPS URL from did:web identifier per W3C spec.

    :param did_web: The did:web identifier to convert
    :return: The HTTPS URL for fetching the DID document
    :raises ResolutionError: If did_web format is invalid
    """
    if not did_web.startswith("did:web:"):
        raise ResolutionError(f"Invalid did:web format: {did_web}")

    method_specific_id = did_web[8:]
    if not method_specific_id:
        raise ResolutionError("Empty method-specific identifier in did:web")

    url_path = method_specific_id.replace(":", "/")
    url_path = urllib.parse.unquote(url_path)
    https_url = f"https://{url_path}"

    if "/" not in url_path or url_path.count("/") == 0:
        https_url += "/.well-known"

    https_url += "/did.json"
    return https_url


def validate_did_doc(did_document, expected_did):
    # type: (dict, str) -> None
    """Validate that DID document ID matches the expected DID.

    :param did_document: The parsed DID document to validate
    :param expected_did: The DID that should match the document's 'id' property
    :raises ResolutionError: If document ID doesn't match expected DID
    """
    if did_document.get("id") != expected_did:
        raise ResolutionError(
            f"DID document ID '{did_document.get('id')}' does not match requested DID '{expected_did}'"
        )


class ResolutionError(Exception):
    """Base exception for URI resolution failures."""


class NetworkError(ResolutionError):
    """Network-related failures that might be transient (timeouts, 404s, DNS failures)."""  # pragma: no cover
