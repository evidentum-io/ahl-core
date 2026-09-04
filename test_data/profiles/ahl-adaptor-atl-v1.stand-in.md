# STAND-IN artifact for adaptor profile `ahl-adaptor-atl-v1`

**This is not the profile.** It is a test stand-in, shipped with the AHL conformance corpus so
that the corpus can exercise the ATL binding's serialization before the profile itself is
released. Read the three paragraphs below before anything else.

1.  **The real profile is unreleased, and its digest is not stable.** `ahl-adaptor-atl-v1` §14:
    "Until this document is released as an immutable, openly published artifact at a stable
    location, its digest is not stable and no manifest may pin it." That obligation binds the
    corpus operator, and a verifier cannot enforce it: a manifest that pins a draft digest is
    indistinguishable from one that pins a released one, and prose alongside the pin is not
    something a policy loader reads.

2.  **This artifact's digest is deliberately NOT the draft's, and cannot be the released
    artifact's.** These are different bytes from any revision of the profile document, and the
    corpus pins the digest of THIS file. A manifest pinning `ahl-adaptor-atl-v1` at the digest of
    the draft, or of the artifact eventually released under that id, does not resolve against a
    verifier holding this stand-in: the held artifact differs, which I-D §7.5 step 2 makes
    `invalid`. Nothing in this corpus can therefore be mistaken for, or replayed as, a pin of the
    real profile.

3.  **A manifest pinning this stand-in verifies only against a policy that holds it.** That is
    the whole of what the corpus claims. When the profile is released, a corpus binding it will
    pin the released artifact's digest and hold the released artifact; this file will not be part
    of that arrangement.

## What a verifier needs, restated

Core spec §3 item 6 forbids verification from depending on knowledge outside the profile
document, so the rules the corpus's ATL vectors exercise are restated here in full. They are the
rules of `ahl-adaptor-atl-v1`; only the artifact identity differs.

### Hashing and family strings

SHA-256 throughout. `"sha256:<lowercase hex>"`, `"base64:<standard base64, with padding>"`.
Public keys are `"base64:<raw 32-byte Ed25519 public key>"`; a key id is
`"sha256:<hex of SHA-256 over the raw 32-byte public key>"`; signatures are
`"base64:<raw 64-byte Ed25519 signature>"`.

### Entry encoding and the log leaf

An anchored entry is `JCS(envelope)`, the I-D §2.1 statement envelope. Statement id is
`"sha256:" || hex(SHA-256(JCS(payload)))` and entry id is `"sha256:" || hex(SHA-256(JCS(envelope)))`.

The log tree does NOT hash the entry bytes directly. A leaf combines two digests:

```
log leaf_hash(i) = SHA-256( 0x00 || SHA-256(JCS(envelope_i)) || METADATA_HASH )
```

The first digest is the raw form of the AHL entry id. `METADATA_HASH` is a FIXED constant of the
profile: the SHA-256 of the JCS form of the metadata object

```
{"ahl_adaptor":"ahl-adaptor-atl-v1"}
```

which is 36 bytes, giving

```
METADATA_HASH = sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4
```

An entry whose metadata is anything else is not an AHL entry under this binding and MUST be
rejected. Pinning the constant is what keeps a leaf a pure function of the signed envelope:
metadata is operator-supplied and covered by no AHL signature.

Log leaves are in entry-index order and are never sorted.

Interior nodes are `node_hash(l, r) = SHA-256(0x01 || l || r)`, and the root over `n > 1` leaf
hashes splits at `k`, the largest power of two strictly less than `n`.

**The asymmetry stops at the log tree.** Batch output trees, input-set trees and disposition
trees are AHL constructs the log never sees: their leaf bytes are `JCS(leaf object)` and their
leaf hash is `SHA-256(0x00 || bytes)`. An implementation MUST NOT apply the payload/metadata leaf
construction to them.

### `log_id`

`log_id` = `"sha256:" || hex(Origin ID)`, where the Origin ID is the SHA-256 over the 16-byte
Data Tree UUID. A verifier never needs the UUID: the Origin ID is what the checkpoint blob binds
and what the manifest pins.

### Checkpoints

A checkpoint is signed as a fixed 98-byte blob:

| offset | size | field | encoding |
| --- | --- | --- | --- |
| 0 | 18 | magic | ASCII `ATL-Protocol-v1-CP` |
| 18 | 32 | Origin ID | raw SHA-256 of the Tree UUID |
| 50 | 8 | tree size | u64 little-endian |
| 58 | 8 | timestamp | u64 little-endian, Unix nanoseconds |
| 66 | 32 | root hash | raw SHA-256 Merkle root |

The AHL checkpoint object maps field by field: `log_id` from the Origin ID, `tree_size`
identically, `root_hash` from the root, `checkpoint_time` as the RFC 3339 rendering of the
nanosecond value, plus `key_id` and `signature`, and optionally `raw`.

`checkpoint_time` MUST be the UTC rendering with EXACTLY NINE fractional digits and the `Z`
suffix — `1767225600123456789` renders as `2026-01-01T00:00:00.123456789Z`. This is not
cosmetic: the blob binds the exact nanosecond value, so any rendering that loses precision
reconstructs different bytes and the signature will not verify over them.

To verify: recover the raw origin, the u64 tree size, the u64 nanosecond timestamp and the raw
root; assemble the 98 bytes; resolve the signing key by `key_id` against the manifest version
active for this checkpoint's `tree_size`, recomputing the key id from the carried public key; and
verify the Ed25519 signature over the 98 bytes.

### `checkpoint.raw`

This binding DEFINES a binary checkpoint framing, so a receipt MAY carry
`anchoring.checkpoint.raw` as `"base64:" || base64(the 98 bytes)`. Where it is carried, a
verifier MUST parse it and MUST reject the receipt unless the magic is exactly
`ATL-Protocol-v1-CP` and the bytes equal the blob assembled from the JSON members. The JSON
members govern the comparison and a mismatch is `invalid`. `raw` is a convenience, not a trust
step.

### Witness cosignatures

A witness cosigns the signed checkpoint object, bound to its own identity:

```
cosignature = Ed25519( JCS( { "checkpoint": <signed checkpoint object>,
                              "witness_id": "<witness id>" } ) )
```

carried as `{ "witness_id", "key_id", "cosignature", "cosigned_at" }`.

### Inclusion proofs

A list of sibling hashes leaf to root, serialized as a JSON array of `"sha256:<hex>"` family
strings and carried bare; the leaf index comes from `subject.entry_index` or
`governance.chain[].entry_index` and the tree size from the checkpoint. Verification is the
RFC 6962 recomputation of the root, with the log leaf built per the rule above.

### Consistency proofs

RFC 9162 Section 2.1.4 proofs between two tree sizes of the same Origin ID, serialized as a JSON
array of `"sha256:<hex>"` family strings in the order the algorithm produces, carried as
`anchoring.consistency_path` beside `anchoring.later_checkpoint`. An element that is not a
`sha256:<hex>` family string is a rejection. `assurance.continued_history` is true if and only if
both members are present and verify.

### Authenticated range enumeration

Given a checkpoint `C` over `N` entries, a range `[i, j)` with `0 <= i < j <= N` and an ordered
list of `j - i` envelopes, the proof is the minimal set of RFC 6962 subtree hashes covering
everything outside the range, over the standard decomposition of `[0, N)`:

```
recompute(offset, size):
    let end = offset + size
    if end <= i or offset >= j:      return the next unconsumed proof node
    if offset >= i and end <= j:     return root of the carried leaf hashes for [offset, end)
    k = largest power of two strictly less than size
    return node_hash( recompute(offset, k), recompute(offset + k, size - k) )
```

Verification rejects unless `0 <= i < j <= N`; unless exactly `j - i` envelopes are carried with
`entry_index` values `i, i+1, ..., j-1` in that order; if the node list is exhausted early; or
unless every node is consumed. It accepts if and only if `recompute(0, N)` equals `C.root_hash`.
**The leaf hash of a carried entry is the two-digest construction above**, not the plain leaf
hashing of the non-log trees.

`range_proof.adaptor_form` is `"base64:" || base64(bytes)` with all integers big-endian:

| offset | size | field |
| --- | --- | --- |
| 0 | 6 | magic, ASCII `AHLRP1` |
| 6 | 8 | `tree_size` (u64) |
| 14 | 8 | `from_index` (u64) |
| 22 | 8 | `to_index` (u64) |
| 30 | 4 | `node_count` (u32) |
| 34 | 32 x `node_count` | subtree hashes, raw 32-byte SHA-256 values, in consumption order |

Total length is `34 + 32 * node_count`; any other length is a rejection, as is a proof whose
`tree_size`, `from_index` or `to_index` disagrees with the enclosing range object or with the
checkpoint. The byte layout is identical to the one the rest of this corpus uses; only the leaf
hashing differs.

This binding provides **no typed-subset proofs**, so enumerated governance currency MUST carry
the full entry range.

### What is not defined here

Availability, cadence enforcement, operator conduct, incorporation time, and every deployment
obligation the real profile records as unmet on the published ATL stack. None of them is a rule a
receipt is verified against, and none of them is exercised by this corpus.
