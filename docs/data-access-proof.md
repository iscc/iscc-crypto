# Data Access Proof

## The Problem

There is a semantic difference between:

1. Signing actual file content directly
1. Signing just the hash of a file

By signing only the hash, we're creating a signature that proves we had knowledge of the hash at
signing time, but not necessarily access to or knowledge of the actual file content. This could
potentially lead to scenarios where:

- Someone could collect file hashes without having the files
- Sign those hashes without ever seeing the actual content
- Claim they "signed the file" when they only signed its hash

For many use cases where cryptographic signatures are used to prove knowledge/ownership/approval of
actual content, this is problematic.

## Improving the Situation

**As discussed in:** https://crypto.stackexchange.com/a/55156/55556

For any signature scheme with appendix signing a hash, including RSASSA-PSS and (EC)DSA, changing
$\\mathcal S\_\\text{priv}(\\operatorname H(M))$ to $$\\mathcal S\_\\text{priv}(\\operatorname
H(M))|\\mathcal S\_\\text{priv}(\\operatorname{HMAC-H}(\\mathcal S\_\\text{priv}(\\operatorname
H(M)),M))$$proves possession of $M$ as well as a static signature can do. That has the advantage of
working with large messages. This is not standardized, but is a straightforward combination of
standardized things.

Addition per [comment][1]: this is out of my head. However, the security argument (not proof) is
simple:

- $\\operatorname{HMAC-H}$ is a standard Message Authentication Code construction from a hash.
- A standard single-pass interactive proof of data possession is using $\\operatorname{MAC}(R,M)$
  where $R$ is a random challenge used as key of the MAC.
- Signing that gives insurance that the signer is involved.
- Replacing $R$ with the signature of the hash makes it non-interactive and invoking the signer
  before the HMAC could be computed, yet verifiable.

Still, a dishonest signer can offload all hashing to a third party, but that seems inevitable. And
an imprudent signer hashing-and-signing any message can be abused into signing a proof of possession
of something s/he did not keep (because HMAC's result is a hash).

Note: I chose this, at the price of requiring two signatures, rather than $$\\mathcal
S\_\\text{priv}(\\operatorname H(M))|\\operatorname{HMAC-H}(\\mathcal S\_\\text{priv}(\\operatorname
H(M)),M)$$ because:

- The security argument of the former is more straightforward.

- The later succumbs if $H$ turns out not to be collision-resistant: an attacker could find $M$ and
  $M'$ with $H(M)=H(M')$, give $M'$ to signer, obtain $\\mathcal S\_\\text{priv}(\\operatorname
  H(M'))$ as part of proof of possession of $M'$ by honest signer, and turn that into a (different)
  forged proof of possession of $M$, when the honest signer never knew that $M$.

- Involving the signer at beginning and end of preparation of the proof of possession arguably makes
  repudiation harder.

[1]: https://crypto.stackexchange.com/q/55148/555#comment122007_55156
