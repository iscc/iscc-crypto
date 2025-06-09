"""ISCC Signate Examples / Test Vectorss"""

import iscc_crypto as icr

ISCC = "ISCC:KACT4EBWK27737D2AYCJRAL5Z36G76RFRMO4554RU26HZ4ORJGIVHDI"
PUBLIC_KEY = "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
SECRET_KEY = "z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA"
KEYPAIR = icr.KeyPair(public_key=PUBLIC_KEY, secret_key=SECRET_KEY)
META = {
    "iscc": ISCC,
    "name": "Example Digital Content",
}


def main():
    pass


if __name__ == "__main__":
    main()
