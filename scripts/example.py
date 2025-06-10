"""ISCC Signate Examples / Test Vectorss"""

import json
import iscc_crypto as icr
import jcs

ISCC = "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY"
PUBLIC_KEY = "z6MkpFpVngrAUTSY6PagXa1x27qZqgdmmy3ZNWSBgyFSvBSx"
SECRET_KEY = "z3u2So9EAtuYVuxGog4F2ksFGws8YT7pBPs4xyRbv3NJgrNA"
CONTOLLER = "did:web:crypto.iscc.codes:alice"
KEYPAIR = icr.KeyPair(public_key=PUBLIC_KEY, secret_key=SECRET_KEY, controller=CONTOLLER)
META = {
    "@context": "http://purl.org/iscc/context",
    "@type": "VideoObject",
    "$schema": "http://purl.org/iscc/schema",
    "iscc": "ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY",
    "name": "The Never Ending Story",
    "description": "a 1984 fantasy film co-written and directed by *Wolfgang Petersen*",
}


def main():
    print("## ISCC Signature Example\n")

    # Show the keypair being used
    print("### Keypair Information")
    print(f"Public Key: `{PUBLIC_KEY}`")
    print(f"Secret Key: `{SECRET_KEY}`")
    print(f"Controller: `{CONTOLLER}`")
    print()

    # Show corresponding controler document
    print("### Controlled Identity Document")
    print("Must be published at http://crypto.iscc.codes/alice/did.json:")
    print("```json")
    print(json.dumps(KEYPAIR.controller_document, indent=2))
    print("```")

    # Show the document being signed
    print("### Document to be Signed")
    print("```json")
    print(json.dumps(META, indent=2))
    print("```")
    print()

    # Example 3: IDENTITY_BOUND signature
    print("### Example: IDENTITY_BOUND Signature")
    print("Includes controller URI and public key for full attribution.")
    # Create keypair with controller
    keypair_with_controller = icr.KeyPair(
        public_key=PUBLIC_KEY, secret_key=SECRET_KEY, controller="did:web:crypto.iscc.codes:alice"
    )
    signed_identity = icr.sign_json(META, keypair_with_controller, icr.SigType.IDENTITY_BOUND)
    print("```json")
    print(json.dumps(signed_identity, indent=2))
    print("```")
    print()


if __name__ == "__main__":
    main()
