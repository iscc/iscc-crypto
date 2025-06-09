"""ISCC Signate Examples / Test Vectorss"""

import iscc_crypto as icr

ISCC = "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY"
PUBLIC_KEY = "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
SECRET_KEY = "z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA"
KEYPAIR = icr.KeyPair(public_key=PUBLIC_KEY, secret_key=SECRET_KEY)
META = {
  "@context": "http://purl.org/iscc/context",
  "@type": "VideoObject",
  "$schema": "http://purl.org/iscc/schema",
  "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
  "name": "The Never Ending Story",
  "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
  "image": "https://picsum.photos/200/300.jpg"
}


def main():
    pass


if __name__ == "__main__":
    main()
