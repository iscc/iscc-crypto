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
import urllib.parse
from typing import Protocol

import niquests

from iscc_crypto.keys import pubkey_decode


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
        """Fetch JSON from URL."""
        ...


class NiquestsHttpClient:
    """Real HTTP client using niquests."""

    async def get_json(self, url):
        # type: (str) -> dict
        """Fetch JSON from URL using niquests."""
        try:
            response = await niquests.aget(url)
            response.raise_for_status()
            return response.json()
        except niquests.JSONDecodeError as e:
            raise InvalidControlledIdentifierDocument(f"Invalid JSON response from {url}: {e}")
        except niquests.RequestException as e:
            raise NetworkError(f"Failed to fetch {url}: {e}")
        except ValueError as e:  # pragma: no cover
            raise InvalidControlledIdentifierDocument(
                f"Invalid JSON response from {url}: {e}"
            )  # pragma: no cover


def resolve(uri, http_client=None):
    # type: (str, HttpClient | None) -> dict
    """Resolve a URI to a CID or DID document (wraps async function)."""
    try:
        return asyncio.run(resolve_async(uri, http_client))
    except RuntimeError as e:
        if "cannot be called from a running event loop" in str(e):
            raise ResolutionError("resolve() cannot be called from async context. Use resolve_async() instead.")
        raise  # pragma: no cover


async def resolve_async(uri, http_client=None):
    # type: (str, HttpClient | None) -> dict
    """Resolve a URI to a CID or DID document asynchronously."""
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
        raise InvalidURIError(f"Unsupported URI scheme: {uri}")


async def resolve_url(url, http_client):
    # type: (str, HttpClient) -> dict
    """Resolve Controlled Identifier HTTP(S) URLs per W3C CID specification."""
    document = await http_client.get_json(url)
    validate_cid(document, url)
    return document


def validate_cid(document, canonical_url):
    # type: (dict, str) -> None
    """Validate a Controlled Identifier Document per W3C CID specification.

    :param document: The parsed JSON document to validate
    :param canonical_url: The canonical URL that should match the document's 'id' property
    :raises InvalidControlledIdentifierDocument: If document structure is invalid
    :raises InvalidControlledIdentifierDocumentId: If document 'id' property is invalid
    """
    if not isinstance(document, dict) or "id" not in document:
        raise InvalidControlledIdentifierDocument("Retrieved document must contain an 'id' property")

    document_id = document["id"]
    if not isinstance(document_id, str):
        raise InvalidControlledIdentifierDocumentId("Document 'id' property must be a string")

    if document_id != canonical_url:
        raise InvalidControlledIdentifierDocumentId(
            f"Document 'id' '{document_id}' does not match canonical URL '{canonical_url}'"
        )


async def resolve_did_key(did_key):
    # type: (str) -> dict
    """Generate DID document from did:key URI."""
    if not did_key.startswith("did:key:"):
        raise InvalidURIError(f"Invalid did:key format: {did_key}")

    multikey = did_key[8:]
    try:
        pubkey_decode(multikey)
    except ValueError as e:
        raise InvalidURIError(f"Invalid multikey: {e}")

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
    """Convert did:web to HTTPS URL and fetch DID document per W3C spec."""
    https_url = build_did_web_url(did_web)
    try:
        did_document = await http_client.get_json(https_url)
    except (InvalidControlledIdentifierDocument, NetworkError) as e:
        # Re-raise with DID-specific error types
        if isinstance(e, InvalidControlledIdentifierDocument):
            raise InvalidDocumentError(str(e).replace("Invalid JSON response", "Invalid JSON response"))
        raise NetworkError(str(e).replace("Failed to fetch", "Failed to fetch DID document from"))

    validate_did_doc(did_document, did_web)
    return did_document


def build_did_web_url(did_web):
    # type: (str) -> str
    """Build HTTPS URL from did:web identifier per W3C spec.

    :param did_web: The did:web identifier to convert
    :return: The HTTPS URL for fetching the DID document
    :raises InvalidURIError: If did_web format is invalid
    """
    if not did_web.startswith("did:web:"):
        raise InvalidURIError(f"Invalid did:web format: {did_web}")

    method_specific_id = did_web[8:]
    if not method_specific_id:
        raise InvalidURIError("Empty method-specific identifier in did:web")

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
    :raises InvalidDocumentError: If document ID doesn't match expected DID
    """
    if did_document.get("id") != expected_did:
        raise InvalidDocumentError(
            f"DID document ID '{did_document.get('id')}' does not match requested DID '{expected_did}'"
        )


class ResolutionError(Exception):
    """Base resolution error."""


class NetworkError(ResolutionError):
    """Network-related failure."""


class InvalidURIError(ResolutionError):
    """Malformed URI."""


class InvalidDocumentError(ResolutionError):
    """Invalid DID/CID document."""


class InvalidControlledIdentifierDocument(ResolutionError):
    """Invalid Controlled Identifier Document (CID specification)."""


class InvalidControlledIdentifierDocumentId(ResolutionError):
    """Invalid Controlled Identifier Document ID (CID specification)."""
