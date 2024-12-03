# ISCC Timestamping Protocol

## ISCC-IDv1

The ISCC-ID is a 64-bit identifier constructed from a timestamp and a server-id where the first 52
bits denote the UTC time in Microseconds since UNIX epoch and the last 12 bits denote the ID of the
timestamping server. With 52-bit timestamps a single server can issue up to 1 Million timestamps per
second until the year 2112. The server-id suffix allows for a deployment of up to 4096 timestamp
servers and ensures that timestampes are distributed, globaly unique and sortable. With 52-bits for
the timestamp and 12-bits for server-ids the system supports a theoretical maximum of ~4 billion
timestamps per second.

The ISCC-ID has the following canonical format:

- Protocol Prefix: `ISCC:`
- Base32-Encoded concatenation of:
  - 16-bit header: Concatenation of the nibbles:
    - MAINTYPE = `0110` # ISCC-ID
    - SUBTYPE = `0000` # None
    - VERSION = `0001` # V1
    - LENGTH = `0001` # 64-bit
  - 52-bit timestamp: Current microseconds since 1970-01-01T00:00:00Z
  - 12-bit server-id: The Time Server ID

!!! example
    ```
    ISCC:MAIWFBMUTUVMPUAA
    ```

There will be a decentralized permissionless smatcontract based registry for server ids that maps
server ids to network locations (URLs).

## Datahashes

A `datahash` is a cryptographically secure hash over some data and is represented as Multibase
encoded Multihash value for forward compatibility. For version 1 of the protocol datahases MUST use
base58-btc Multibase encoded (`z` prefix) blake3 Multihashes (`0x1E`). A `datahash` MAY double down
as an IPFS content address.

## Public Keys

The Multikey format is used to express public keys. The Multikey encoding of a Ed25519 256-bit
public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed), followed by
the 32-byte public key data. The resulting 34-byte value MUST then be encoded using the base-58-btc
alphabet and then prepended with the base-58-btc Multibase header (z). (See:
https://www.w3.org/TR/controller-document/#Multikey)

## Signatures

A `signature` is a secure cryptographic EdDSA signature over some data and is represented as
Multibase base58btc encoded signature as defined by https://www.w3.org/TR/vc-di-eddsa

## Data Timestamping

**Request**

Request for creating a verifiable `ownerless` timestamp over any data.

```json
{
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF"
}
```

**Response**

```json
{
    "iscc_id": "ISCC:MAIWFBMUTUVMPUAA",
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF",
    "notary_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "notary_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
}
```

Algorithm: The EdDSA signature is created by the ISCC Notary server over the JCS serialized data of
all response fields except for the `notary_signature` field.

Semantics: An ownerless ISCC-IDv2 that attests that the data bound by the blake3 hash existed at the
time expressed by the ISCC-ID. The signed response can be verified offline for integiry by
validating the signature against the pubkey. Additionally, verifiers can look up the ISCC-ID on the
corresponding ISCC Notary for online verification and notary key expiration checcks.

## ISCC-ID Acquisition

**Request**

ISCC-ID Acquisition request to mint an ISCC-ID as Persistent Identifier

```json
{
    "nonce": "953749e57c4bc3e031bfbba408c5e72b8a89a0e4fd1b4409d26e3688a441195e",
    "requester_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "requester_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
}
```

The nonce is a random 32byte value signed by the requester (including its public key) for unique
request identification and for protection against replay attacks.

**Response**

```json
{
    "iscc_id": "ISCC:MAIWFBMUTUVMPUAA",
    "nonce": "953749e57c4bc3e031bfbba408c5e72b8a89a0e4fd1b4409d26e3688a441195e",
    "requester_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "requester_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn",
    "notary_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "notary_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
}
```

Algorithm: The notary verifies the requesters' signature and if valid the notary EdDSA signature is
created by the ISCC Notary server over the JCS serialized data of all response fields except for the
`notary_signature` field.

Semantics: The ISCC Notary assigns the unique ISCC-ID to the requester as the sole owner and
controller of the ISCC-ID without any metadata attached to it. The requester has authority over the
semantics of the ISCC-ID. As the controller they may create, attatch, store and present claims and
assertions to the ISCC-ID using their private key. Verifiers can verify the integrity of the ISCC-ID
assignment by checking the siginater of the original request and the signature from the ISCC Notary.
Additionally, verifiers can look up the ISCC-ID on the corresponding ISCC Notary for online
verification of ID ownership and Notary signature expirey.

## ISCC-CODE Declaration

**Request**

ISCC-CODE Declaration Request

```json
{
    "nonce": "953749e57c4bc3e031bfbba408c5e72b8a89a0e4fd1b4409d26e3688a441195e",
    "iscc_code": "ISCC:KACT4EBWK27737D2AYCJRAL5Z36G76RFRMO4554RU26HZ4ORJGIVHDI",
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF",
    "requester_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "requester_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
}
```

**Response**

```json
{
    "nonce": "953749e57c4bc3e031bfbba408c5e72b8a89a0e4fd1b4409d26e3688a441195e",
    "iscc_code": "ISCC:KACT4EBWK27737D2AYCJRAL5Z36G76RFRMO4554RU26HZ4ORJGIVHDI",
    "datahash": "z9zL29fdZfXHXWbNTRdjLiSrSHGKJYxGmtsNyPVatv2zXF",
    "requester_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "requester_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn",
    "notary_pubkey": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "notary_signature": "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
}
```

Semantics: The ISCC Notary assigns the unique ISCC-ID to the requester as the sole owner and
controller of the ISCC-ID and permanently binds it to the iscc_code and the datahash.

## Optional Timestamping fields:

The following optional fields can be included in a timestamping request and will be bound to
the timestamp by the notary servers signature.

### `requester_authority`

An url under which the requester hosts authorized public keys via the
`.well-known/jwks.json` endpoint via JSON Web Key (Sets). The format enables domains to act as
lightweight roots of trust by publishing their authorized public keys in a standardized way with
support for key expiration. Timestamping servers will not verify against such URLs but downstream
users of the notarized timestamps MAY do so.


### `metahash`

A multibase/multihash encoded cryptographycally secure (blake3) hash over DATA-URL encoded metadata
that describes the content identified by the ISCC-CODE. The metahash MAY double down as a IPFS
content address.

### `url`

Permanently bound fully qualified absolute URL that points to metadata about the identified content.
