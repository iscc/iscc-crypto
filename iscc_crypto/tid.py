"""
ISCC Time-ID

The ISCC Time-ID has the following format:

- Protocol Prefix: `ISCC:

- Base32-Encoded concatenation of:
    - 16-bit header: Concatenation of the nibbles MAINTYPE, SUBTYPE, VERSION, LENGTH
    - 52-bit timestamp: Current microseconds since 1970-01-01T00:00:00Z
    - A 12-bit suffix: Time Server ID
"""

import math
from base64 import b32encode, b32decode
from iscc_crypto.microtime import microtime

# Header - 16-Bit Prefix
MAINTYPE = "0110"  # ISCC-ID
SUBTYPE = "0000"  # TIME-ID
VERSION = "0000"  # V0
LENGTH = "0001"  # 64-bit
HEADER_DATA = int(MAINTYPE + SUBTYPE + VERSION + LENGTH, 2).to_bytes(2, byteorder="big")


# 12-Bit Server-ID Suffix
SERVER_ID = 0


def tid():
    # type: () -> str
    """Create a new ISCC Time-ID"""
    ts = microtime()
    if ts >= 2**52:  # Ensure timestamp fits in 52 bits
        raise ValueError("Timestamp overflow")

    # Shift timestamp left by 12 bits and combine with server ID
    body = (ts << 12) | SERVER_ID

    # Pack the 64-bit body into 8 bytes
    body_bytes = body.to_bytes(8, byteorder="big")

    # Concatenate header and body
    data = HEADER_DATA + body_bytes

    # Encode as base32
    return "ISCC:" + encode_base32(data)


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
    print(tid())
