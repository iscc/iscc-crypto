"""
Top Level API for cryptographic operations within the ISCC Framework

This module provides a simple and minimal implementation for signing, timestamping and
verifying JSON data within the ISCC Framework.

Overview:

- We use JSON Web Signatures (JWS) for signing JSON data
- We use JCS for canonical serialization of JSON data
- We use JWS Detached format (no payload) as described by JWS/CT (Clear Text)
- We use the existing reputation of web domains as lightweight roots of trust
- On top of that we use simple third-party timestamping protocol

Timestamping:
    A timestamp is a 64-bit hex value where the first 56 bits denote the UTC time in
    Microseconds since unix timestamp epoch and the last 8 bits denote the ID of the
    timestamping server. With 56-bit timestamps a single server can issue up to
    1 Million timestamps per second for up to 2,284 years since epoch. The server-id
    suffix allows for a deployment of up to 256 timestamp servers and ensures that
    timestampes are globaly unique and sortable across timestamping server.

    Clients transmit a blake3 hash of their JCS serialized JSON to a public timestamping
    server and receive a signed UTC timestamp in microseconds.
"""

from pathlib import Path
import keyring
import jcs
import jwcrypto
import blake3
import httpx


class Key:
    pass


def create_key(name="default", autority=None):
    # type: (str, str|None) -> Key
    """
    Create a new key to be used for signing JSON data.

    If an authority URL is given for the key than verifications of signatures created by that key
    will include load and check against <autority>/.well-known/iscc-keys.json

    :param name: The name of the key for keyring storage and retrieval
    :param autority: A url where we can check the keys validity
    """
    pass


def save_key(key):
    # type: (Key) -> str
    """
    Save the key the operating system keyring.

    Returns the name under which the key was stored.
    """
    pass


def load_key(name="default"):
    # type: (str) -> Key
    """Load cryptographic key from the keyring"""
    pass


def export_key(key, filepath):
    # type: (Key, Path|str) -> None
    """Serialize and export cryptographic key to filepath"""
    pass


def import_key(filepath):
    # type: (Path|str) -> Key
    """Read and deserialize cryptographic key from filepath"""
    pass


def set_key(key):
    # type: (Key) -> None
    """Set the provided key as default key for signing operations"""
    pass


def sign(data, key=None):
    # type: (dict, Key|None) -> dict
    """
    Create a JWS/CT signature on any JSON/JCS serializable object.

    The passed in data is not allowed to have a `signature` property.

    See: https://github.com/cyberphone/jws-ct

    If no key is provided we use the currently set default key
    """
    pass


def verify_signature(data, escalate=True, require_authority=True):
    # type: (dict, bool) -> bool
    """
    Verify the signature on any JSON/JCS serializable object.
    An error will be raised if `escalate=True` and the signature is invalid.
    With `escalate=False` the function will return false on an invalid signature.
    If `require_authority=True` the signature must include a valid authority URL.
    """
    pass


def timestamp(data, key=None, server=None):
    # type: (dict, Key|None, str|None) -> dict
    """
    Create a JWT trusted timestamp on any JSON/JCS serializable object.

    The passed in data is not allowed to have a `timestamp` property.
    Idealy the object has been already signed before timestamping.

    The timestamping flow is as follows:
    - Create a blake3 hash of the JCS canonicalized data
    - Transmit the hash to the timestamping server
    - Deserialize and attach the timestamp object `data`

    If no key is provided we use the currently set default key.
    If no server is provided we use the currently set default server.
    """
    pass


def verify_timestamp(data, escalate=True, require_authority=True):
    # type: (dict) -> int|None
    """
    Verify and return the timestamp on any JSON/JCS serializable object.
    The returned timestamp is a UNIX timestamp in Microseconds since epoch.
    An error will be raised if `escalate=True` and there is no or only an invalid timestamp.
    With `escalate=False` the function will return None if the timestamp is invalid.
    If `require_authority=True` the signature of the timestamping authority must include a valid
    authority URL.
    """
    pass
