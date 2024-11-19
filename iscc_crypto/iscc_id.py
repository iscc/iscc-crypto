"""
ISCC-ID

The ISCC-ID is a 64-bit identifier constructed from a timestamp and a server-id where the first 50
bits denote the UTC time in 0.01 Milliseconds since UNIX timestamp epoch and the last 12 bits denote
the ID of the timestamping server. With 50-bit timestamps a single server can issue up to 100.000
timestamps per second until the year 2326. The server-id suffix allows for a deployment of up to
16384 timestamp servers and ensures that timestampes are distributed, globaly unique and sortable.
With 50-bits for the timestamp and 14-bits for server-ids the system supports a theoretical
maximum of 1.6384 billion timestamps per second.

We use multiformants base32hex encoding to support parity between numerical and lexical sorting.
The ISCC-ID has the following format:

String Format:

- Protocol Prefix: `iscc:
- Multibase Prefix: v
- Base32hex lower-case encoded concatention of: <multicodec><iscc-header><iscc-body>

Byte Structure:

- Base32-Encoded concatenation of:
    - 16-bit multicodec: Registerd ISCC multicodec CC01 - see https://t.ly/cOrwk
    - 16-bit header: Concatenation of the nibbles MAINTYPE, SUBTYPE, VERSION, LENGTH
    - 50-bit timestamp: Current microseconds since 1970-01-01T00:00:00Z
    - 14-bit server-id: The Time Server ID
"""

import math
from base64 import b32encode, b32decode
from iscc_crypto.timestamp import timestamp

b32_to_hex = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV")
hex_to_b32 = str.maketrans("0123456789ABCDEFGHIJKLMNOPQRSTUV", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


MULTIBASE_PREFIX = "iscc:v"
MULTICODEC = b"\xcc\x01"
MAINTYPE = "0110"  # ISCC-ID
SUBTYPE = "0000"  # None
VERSION = "0000"  # V0
LENGTH = "0001"  # 64-bit
HEADER_DATA = int(MAINTYPE + SUBTYPE + VERSION + LENGTH, 2).to_bytes(2, byteorder="big")


# 12-Bit Server-ID Suffix
SERVER_ID = 0


def iscc_id():
    # type: () -> str
    """Create a new ISCC-ID"""
    ts = timestamp()
    if ts >= 2**50:  # Ensure timestamp fits in 52 bits
        raise ValueError("Timestamp overflow")

    # Shift timestamp left by 12 bits and combine with server ID
    body = (ts << 14) | SERVER_ID

    # Pack the 64-bit body into 8 bytes
    body_bytes = body.to_bytes(8, byteorder="big")

    # Concatenate headers and body
    data = MULTICODEC + HEADER_DATA + body_bytes

    # Encode as base32
    return MULTIBASE_PREFIX + encode_base32hex(data).lower()


def encode_base32hex(data):
    # type: (bytes) ->  str
    """
    RFC4648 Base32hex encoding without padding

    see: https://tools.ietf.org/html/rfc4648#page-10
    """
    b32 = encode_base32(data)
    return b32.translate(b32_to_hex)


def decode_base32hex(code):
    # type: (str) -> bytes
    """
    RFC4648 Base32hex decoding without padding

    see: https://tools.ietf.org/html/rfc4648#page-10
    """
    # Make sure we use upper-case version for translation
    b32 = code.upper().translate(hex_to_b32)
    return decode_base32(b32)


def encode_base32(data):
    # type: (bytes) -> str
    """
    Standard RFC4648 base32 encoding without padding.
    """
    return b32encode(data).decode("ascii").rstrip("=")


def decode_base32(code):
    # type: (str) -> bytes
    """
    Standard RFC4648 base32 decoding without padding and with casefolding.
    """
    # python stdlib does not support base32 without padding, so we have to re-pad.
    cl = len(code)
    pad_length = math.ceil(cl / 8) * 8 - cl

    return bytes(b32decode(code + "=" * pad_length, casefold=True))


if __name__ == "__main__":
    print(iscc_id())
