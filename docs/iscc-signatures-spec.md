# ISCC Signatures

## Introduction

The first edition of ISO 24138:2024 specifies the syntax, structure, and initial algorithms for the
International Standard Content Code (ISCC).

An ISCC is a deterministic data descriptor that applies to a specific digital asset. Anyone can generate an ISCC
using the open-source reference implementation or any other application conforming to the provisions of ISO
24138:2024.

However, an ISCC identifies only the digital asset itself. It makes no assumptions about any associated actors
or metadata. Additionally, ISO 24138:2024 does not define any methods for the interoperable discovery of actors
or metadata associated with a digital asset.

This document defines the use of digital signatures to associate ISCC metadata with an actor.



----------------------------------------------------------------------------------------------------------------
# DRAFTING NOTES — DO NOT EDIT BELOW THIS LINE
----------------------------------------------------------------------------------------------------------------

- We use JSON
- We canonicalize with JCS
- We use Ed25519 Signatures
- We protect pubkey and controller properties with the signature
- Signature properties are:
    - proof: The actual digital signature in the form of a Multibase encoded Ed25519 signature (
      z-base58-btc) - (Required)
    - pubkey: The public key of the signer for offline integrity verification (Optional)
    - controller: The entity (person, organization, or system) who has authority over the cryptographic key used
      to create the signature and is responsible for managing this digital credential represented by a
      dereferencable URI did:web or URL to a controlled identifier document (Optional). If `pubkey` is set but
      `controller` is not set we implicitly derive a `did:key` as `controller`.
    - keyid: The id of the key in the controller document (optional). If not set, but `controller` is set we
      assume the keyid is the `pubkey` itself
- Concept: Property Set Implications — Progressive Disclosure — Three Levels and their implications:
    - Anonymous
        - Providing only `proof` is anonymous (privacy preserving). For signature verification the signer musst
          provide the `pubkey` to the verifier separately
    - Pseudonymous
        - Providing `proof` and `pubkey` is pseudonymous depending on publicly linkable knowledge about the
          `pubkey` but allows non-interactive integrity verification by the recipient.
    - Public
        - Providing `proof`, `pubkey` and `controller` is public and allows the recipient to verify the
          signature, establish the identity of the signer, and confirm that the public key belongs to the
          claimed controller by dereferencing the controller URI to retrieve and validate the controlled
          identifier document.

- Signed JSON objects by themselves are of no value to end users.
  We should also define UI/UX guidelines and clearly communicate options, features, privacy, and
  security interactions and implications regarding:
    - Key Generation
    - Key Managment
    - Metadata Document Signing
    - Signature presentation to the user
    - Signature interperation by the user
