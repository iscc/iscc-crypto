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

import niquests

from iscc_crypto.keys import pubkey_decode

__all__ = [
    "resolve",
    "resolve_async",
    "validate_cid",
    "build_did_web_url",
    "validate_did_document",
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
    """Resolve Controlled Identifier HTTP(S) URLs per W3C CID specification."""
    try:
        response = await niquests.aget(url)
        response.raise_for_status()
        document = response.json()
    except niquests.JSONDecodeError as e:
        raise InvalidControlledIdentifierDocument(f"Invalid JSON response from {url}: {e}")
    except niquests.RequestException as e:
        raise NetworkError(f"Failed to fetch {url}: {e}")
    except ValueError as e:
        raise InvalidControlledIdentifierDocument(f"Invalid JSON response from {url}: {e}")

    # Validate the retrieved document per CID specification
    validate_cid(document, url)

    return document


def validate_cid(document, canonical_url):
    # type: (dict, str) -> None
    """Validate a Controlled Identifier Document per W3C CID specification.

    Args:
        document: The parsed JSON document to validate
        canonical_url: The canonical URL that should match the document's 'id' property

    Raises:
        InvalidControlledIdentifierDocument: If document structure is invalid
        InvalidControlledIdentifierDocumentId: If document 'id' property is invalid
    """
    # CID specification requirement: document MUST contain an 'id' property
    if not isinstance(document, dict) or "id" not in document:
        raise InvalidControlledIdentifierDocument(
            "Retrieved document must contain an 'id' property"
        )

    document_id = document["id"]
    if not isinstance(document_id, str):
        raise InvalidControlledIdentifierDocumentId("Document 'id' property must be a string")

    # CID specification requirement: base identifier MUST match canonical URL
    if document_id != canonical_url:
        raise InvalidControlledIdentifierDocumentId(
            f"Document 'id' '{document_id}' does not match canonical URL '{canonical_url}'"
        )


async def resolve_did_key(did_key):
    # type: (str) -> dict
    """
    Generate DID document from did:key.

    Extract multikey from did:key URI
    Generate standard DID document using patterns from keys.py
    """
    if not did_key.startswith("did:key:"):
        raise InvalidURIError(f"Invalid did:key format: {did_key}")

    # Extract the multikey part (everything after "did:key:")
    multikey = did_key[8:]  # Remove "did:key:" prefix

    # Validate the multikey by attempting to decode it using existing function
    try:
        pubkey_decode(multikey)
    except ValueError as e:
        raise InvalidURIError(f"Invalid multikey: {e}")

    # Generate the standard did:key document structure
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


async def resolve_did_web(did_web):
    # type: (str) -> dict
    """
    Convert did:web to HTTPS URL and fetch DID document per W3C spec.
    See: https://w3c-ccg.github.io/did-method-web/#read-resolve

    2.5.2 Read (Resolve)

    The following steps MUST be executed to resolve the DID document from a Web DID:

    1. Replace ":" with "/" in the method specific identifier to obtain the fully qualified domain
       name and optional path.
    2. If the domain contains a port percent decode the colon.
    3. Generate an HTTPS URL to the expected location of the DID document by prepending https://.
    4. If no path has been specified in the URL, append /.well-known.
    5. Append /did.json to complete the URL.
    6. Perform an HTTP GET request to the URL using an agent that can successfully negotiate a
       secure HTTPS connection.
    7. Verify that the ID of the resolved DID document matches the Web DID being resolved.
    """
    # Build the HTTPS URL from the did:web identifier
    https_url = build_did_web_url(did_web)

    # Fetch the DID document
    try:
        response = await niquests.aget(https_url)
        response.raise_for_status()
        did_document = response.json()
    except niquests.JSONDecodeError as e:
        raise InvalidDocumentError(f"Invalid JSON response from {https_url}: {e}")
    except niquests.RequestException as e:
        raise NetworkError(f"Failed to fetch DID document from {https_url}: {e}")
    except ValueError as e:
        raise InvalidDocumentError(f"Invalid JSON response from {https_url}: {e}")

    # Validate that the document ID matches the original did:web identifier
    validate_did_document(did_document, did_web)

    return did_document


def build_did_web_url(did_web):
    # type: (str) -> str
    """Build HTTPS URL from did:web identifier per W3C spec.

    Args:
        did_web: The did:web identifier to convert

    Returns:
        The HTTPS URL for fetching the DID document

    Raises:
        InvalidURIError: If did_web format is invalid
    """
    if not did_web.startswith("did:web:"):
        raise InvalidURIError(f"Invalid did:web format: {did_web}")

    # Extract method-specific identifier (everything after "did:web:")
    method_specific_id = did_web[8:]  # Remove "did:web:" prefix

    if not method_specific_id:
        raise InvalidURIError("Empty method-specific identifier in did:web")

    # Step 1: Replace colons with slashes
    url_path = method_specific_id.replace(":", "/")

    # Step 2: Percent-decode port numbers (%3A -> :)
    # This handles cases like example.com%3A3000 -> example.com:3000
    url_path = urllib.parse.unquote(url_path)

    # Step 3: Prepend https://
    https_url = f"https://{url_path}"

    # Step 4: If no path specified (only domain), append /.well-known
    # Check if there are any path segments beyond the domain
    if "/" not in url_path or url_path.count("/") == 0:
        https_url += "/.well-known"

    # Step 5: Append /did.json
    https_url += "/did.json"

    return https_url


def validate_did_document(did_document, expected_did):
    # type: (dict, str) -> None
    """Validate that DID document ID matches the expected DID.

    Args:
        did_document: The parsed DID document to validate
        expected_did: The DID that should match the document's 'id' property

    Raises:
        InvalidDocumentError: If document ID doesn't match expected DID
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
