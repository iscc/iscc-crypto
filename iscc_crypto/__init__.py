__version__ = '0.1.0'
from iscc_crypto.keys import get_key
from iscc_crypto.signing import sign, verify

__all__ = [
    "get_key"
]
