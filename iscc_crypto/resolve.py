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

import niquests

__all__ = [
    "resolve",
    "resolve_async",
]


def resolve(uri):
    # type: (str) -> dict
    """Resolve a URI to a CID or DID document (wraps async function)."""
    try:
        return asyncio.run(resolve_async(uri))
    except RuntimeError as e:
        if "cannot be called from a running event loop" in str(e):
            raise ResolutionError(
                "resolve() cannot be called from async context. Use resolve_async() instead."
            )
        raise


async def resolve_async(uri):
    # type: (str) -> dict
    """Resolve a URI to a CID or DID document asynchronously using niquests."""
    # Route to the appropriate resolver
    if uri.startswith(("http://", "https://")):
        return await resolve_url(uri)
    elif uri.startswith("did:key:"):
        return await resolve_did_key(uri)
    elif uri.startswith("did:web:"):
        return await resolve_did_web(uri)
    else:
        raise InvalidURIError(f"Unsupported URI scheme: {uri}")


async def resolve_url(url):
    # type: (str) -> dict
    """Resolve HTTP(S) URLs."""
    try:
        response = await niquests.aget(url)
        response.raise_for_status()
        return response.json()
    except niquests.RequestException as e:
        raise NetworkError(f"Failed to fetch {url}: {e}")
    except ValueError as e:
        raise InvalidDocumentError(f"Invalid JSON response from {url}: {e}")


async def resolve_did_key(did_key):
    # type: (str) -> dict
    """
    Generate DID document from did:key.

    Extract multikey from did:key URI
    Generate standard DID document using patterns from keys.py
    """
    pass


async def resolve_did_web(did_web):
    # type: (str) -> dict
    """# Convert did:web to HTTPS URL per W3C spec"""
    pass


class ResolutionError(Exception):
    """Base resolution error."""


class NetworkError(ResolutionError):
    """Network-related failure."""


class InvalidURIError(ResolutionError):
    """Malformed URI."""


class InvalidDocumentError(ResolutionError):
    """Invalid DID/CID document."""
