# Adaptor profile `ahl-test-atl-leaf-v1`

**Status:** test profile for the AHL Protocol conformance corpus.
**Profile id:** `ahl-test-atl-leaf-v1`
**Profile hash:** `sha256:<SHA-256 over the exact bytes of this file>`, pinned in the corpus
manifest (`log.adaptor.hash`) and carried in every Evidence Receipt (`anchoring.adaptor.hash`).

This document is the whole of what a verifier needs in order to check the vectors in
`test_data/vectors/atl/` and `test_data/receipts/atl/`. Core specification §3 item 6 requires
adaptor profiles to be versioned, immutable, content-addressed, openly published and
independently implementable, and forbids verification from depending on knowledge outside the
profile document; every rule this corpus's ATL-shaped vectors are verified against is therefore
stated below, as a rule of THIS profile.

## Relationship to `ahl-adaptor-atl-v1`

The serialization defined here has the same shape as the one the AHL adaptor profile
`ahl-adaptor-atl-v1` defines for the Anchored Transparency Log, and that draft is the source the
shape was taken from. **This profile is not that profile**, is not a copy, revision, stand-in or
pre-release of it, and asserts nothing about it. Two consequences are worth being explicit about:

- A receipt or manifest pinning `ahl-adaptor-atl-v1` is pinning that profile and its released
  artifact, and does not resolve against a verifier that holds only this document. That is the
  correct outcome and not a limitation of either profile.
- Should `ahl-adaptor-atl-v1` be released, its digest is the digest of ITS artifact. Nothing here
  predicts it, stands in for it, or may be substituted for it.

The identity rule this profile lives under is the same one: any change to this file produces a
different hash and therefore a different profile, which MUST be published under a new id. The
corpus pins this file's digest and nothing else.

## 1. Hashing, encodings, family strings

SHA-256 throughout. Family strings follow the receipt format §1.4 conventions:
`"sha256:<lowercase hex>"`, `"hmac-sha256:<lowercase hex>"`, `"base64:<standard base64, with
padding>"`.

- **Public key encoding**: `"base64:<raw 32-byte Ed25519 public key>"`. No SPKI, no PEM.
- **Key id**: `"sha256:<hex of SHA-256 over the raw 32-byte public key>"`. A verifier MUST
  recompute a key id from the public key it is given and MUST reject a mismatch.
- **Signature encoding**: `"base64:<raw 64-byte Ed25519 signature>"`, Ed25519 per RFC 8032.

## 2. Statement envelopes and identifiers

An anchored entry is `JCS(envelope)`, the envelope of I-D §2.1:

```json
{ "payload": { ... }, "signatures": [ { "key_id": "sha256:<hex>", "sig": "base64:<...>" } ] }
```

Those bytes, and only those bytes, are the anchored entry.

- **statement id** = `"sha256:" || hex(SHA-256(JCS(payload)))`
- **entry id** = `"sha256:" || hex(SHA-256(JCS(envelope)))`

A non-genesis `manifest` statement references its predecessor by **entry id** in `predecessor`.

## 3. The log tree

### 3.1 Leaf construction

This profile does **not** hash the anchored entry bytes directly into the leaf. A leaf combines
two digests:

```
log leaf_hash(i) = SHA-256( 0x00 || SHA-256(JCS(envelope_i)) || METADATA_HASH )
```

The first digest is the raw form of the AHL entry id, so the entry id remains derivable from the
entry bytes alone. `METADATA_HASH` is a **fixed constant of this profile**: the SHA-256 of the
JCS form of

```json
{"ahl_adaptor":"ahl-adaptor-atl-v1"}
```

whose JCS form is the 36 bytes shown, giving

```
METADATA_HASH = sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4
```

An entry whose associated metadata is anything else is **not** an entry under this profile and
MUST be rejected. The constant is pinned rather than used: the metadata is supplied by the log
operator and is covered by no AHL signature, so a leaf that depended on it would depend on bytes
outside the signed envelope, and the entry id would no longer determine the leaf.

(The metadata object's literal content names `ahl-adaptor-atl-v1` because that is the value the
underlying log software writes. It is opaque input to the digest above, not a claim by this
profile about that profile.)

### 3.2 Ordering, nodes and roots

Log leaves are in **entry-index order** and are never sorted; the entry index is the position of
the entry in the append-only log.

```
node_hash(l, r) = SHA-256( 0x01 || l || r )
```

The root over `n > 1` leaf hashes splits at `k`, the largest power of two strictly less than `n`:
`root = node_hash(root(leaves[0..k]), root(leaves[k..n]))`. A one-leaf tree's root is its leaf
hash. Empty trees do not occur in a corpus, which always contains at least its genesis manifest.

### 3.3 The other AHL trees

Batch output trees, input-set trees and disposition trees are AHL constructs the log never sees.
Their leaf bytes are `JCS(leaf object)` and their leaf hash is `SHA-256(0x00 || bytes)`; leaves
are sorted by the leaf's `record` value as the ascending lexicographic order of the UTF-8 bytes
of the canonical commitment string, duplicates are prohibited, and a `record` value that is not a
canonical commitment string invalidates the tree. An implementation MUST NOT apply §3.1's
payload/metadata leaf construction to them.

## 4. `log_id`

`log_id` = `"sha256:" || hex(Origin ID)`, where the Origin ID is the SHA-256 over the bound log's
16-byte Data Tree UUID. A verifier never needs the UUID: the Origin ID is what the checkpoint
blob of §5 binds and what the manifest pins. `log_id` MUST equal `log.log_id` in the manifest
version active for a checkpoint's `tree_size`.

## 5. Checkpoints

### 5.1 Binary form

A checkpoint is signed as a fixed 98-byte blob:

| offset | size | field | encoding |
| --- | --- | --- | --- |
| 0 | 18 | magic | ASCII `ATL-Protocol-v1-CP` |
| 18 | 32 | Origin ID | raw SHA-256 of the Data Tree UUID |
| 50 | 8 | tree size | u64 **little-endian** |
| 58 | 8 | timestamp | u64 little-endian, Unix **nanoseconds** |
| 66 | 32 | root hash | raw SHA-256 Merkle root |

The Ed25519 signature is over these 98 bytes and is carried outside the blob.

### 5.2 The AHL checkpoint object

The receipt-borne checkpoint object of I-D §7.1 maps field by field: `log_id` from the Origin ID
as `"sha256:" || hex(origin)`; `tree_size` identically; `root_hash` as `"sha256:" || hex(root)`;
`checkpoint_time` as the rendering of §5.3; plus `key_id` and `signature`, and optionally `raw`
(§5.4). A checkpoint commits exactly the entries with index in `[0, tree_size)`.

### 5.3 Time rendering

`checkpoint_time` MUST be the UTC rendering of the nanosecond timestamp with **exactly nine
fractional digits** and the `Z` suffix:

```
1767225600123456789  ->  "2026-01-01T00:00:00.123456789Z"
```

This is normative, not cosmetic. A verifier reconstructs the 98-byte blob from the parsed
checkpoint object in order to verify the log signature, and the blob contains the exact
nanosecond value; any rendering that loses precision reconstructs different bytes and the
signature will not verify over them. Verifiers MUST parse the nine fractional digits back to the
exact u64 nanosecond value and MUST reject a `checkpoint_time` that is not in this form.

### 5.4 `checkpoint.raw`

This profile **defines** a binary checkpoint framing, so receipts under it MAY carry
`anchoring.checkpoint.raw`.

- `raw` is `"base64:" || base64(the 98 bytes of §5.1)`.
- Where `raw` is carried it MUST parse to the same values as the JSON members, **the JSON members
  govern the comparison**, and a mismatch is `invalid`. Concretely, a verifier that finds `raw`
  present MUST parse it and MUST reject the receipt unless the magic is exactly
  `ATL-Protocol-v1-CP` and the bytes equal the blob assembled from the parsed checkpoint object.
- `raw` is a convenience, not a trust step: a verifier that reconstructs the blob from the parsed
  object per §5.5 obtains the same bytes.

### 5.5 Verifying a checkpoint signature

1. Recover the raw 32-byte origin from `log_id`, the u64 `tree_size`, the u64 nanosecond
   timestamp from `checkpoint_time` (§5.3), and the raw 32-byte root from `root_hash`.
2. Assemble the 98-byte blob in the layout of §5.1, little-endian integers.
3. If `raw` is present, compare it byte for byte with the assembled blob; a mismatch is a
   rejection.
4. Resolve the signing key by `key_id` against the manifest version active for this checkpoint's
   `tree_size`, recomputing the key id from the carried public key rather than trusting the
   carried value.
5. Verify the Ed25519 signature over the 98 bytes.

## 6. Witness cosignatures

A witness cosigns the **signed** checkpoint object, bound to its own identity so a cosignature
cannot be replayed for another witness:

```
cosignature = Ed25519( JCS( { "checkpoint": <signed checkpoint object>,
                              "witness_id": "<witness id>" } ) )
```

Serialized in a receipt as
`{ "witness_id", "key_id", "cosignature": "base64:<...>", "cosigned_at": "<RFC 3339>" }`.
`assurance.witnessed` is true only where at least one such cosignature verifies under a witness
key the active manifest version declares.

## 7. Inclusion proofs

An inclusion proof is a list of sibling hashes ordered **leaf to root**, serialized as a JSON
array of `"sha256:<hex>"` family strings. In an Evidence Receipt the array appears bare, and the
index and tree size come from siblings:

| bare path | leaf index carried as | tree size taken from |
| --- | --- | --- |
| `anchoring.inclusion_path` | `subject.entry_index` | `anchoring.checkpoint.tree_size` |
| `governance.chain[].inclusion_path` | `governance.chain[].entry_index` | `anchoring.checkpoint.tree_size` |
| `claim_material.leaf_path` | `claim_material.leaf_index` | `outputs_count` / `affected_count` of the subject payload |
| `claim_material.input_members[].input_path` | `claim_material.input_members[].input_index` | `input_set_count` of the leaf's `inputs` |

Verification is the RFC 6962 recomputation of the root from the leaf hash and the path, compared
against the anchored root. For the log tree the leaf hash is §3.1's construction; for the trees
of §3.3 it is `SHA-256(0x00 || JCS(leaf object))`.

## 8. Consistency proofs

Consistency proofs are RFC 9162 §2.1.4 proofs between two tree sizes of the **same** Origin ID,
serialized as a JSON array of `"sha256:<hex>"` family strings in the order produced by the
RFC 9162 algorithm. They appear in a receipt as `anchoring.consistency_path`, paired with
`anchoring.later_checkpoint`; an element that is not a `sha256:<hex>` family string is a
rejection. `assurance.continued_history` is true if and only if both members are present and
verify (I-D §7.6).

`anchoring.later_checkpoint` is a complete signed checkpoint object of §5, authenticated on its
own terms — its own blob signature under a key declared by the manifest version active for ITS
tree size, and its own cosignatures in `anchoring.later_witnesses[]`.

## 9. Authenticated range enumeration

Given a checkpoint `C` over `N = tree_size(C)` entries, a range `[i, j)` with `0 <= i < j <= N`,
and an ordered list of `j - i` entry envelopes, the proof establishes that the carried list is
exactly and completely the leaf set of `[i, j)` under `C.root_hash`.

### 9.1 Construction and verification

The proof is the minimal set of RFC 6962 subtree hashes covering everything outside the range,
over the standard decomposition of `[0, N)`:

```
recompute(offset, size):
    let end = offset + size
    if end <= i or offset >= j:      return the next unconsumed proof node
    if offset >= i and end <= j:     return root of the carried leaf hashes for [offset, end)
    k = largest power of two strictly less than size
    return node_hash( recompute(offset, k), recompute(offset + k, size - k) )
```

Generation walks the same decomposition and emits the root hash of every maximal subtree entirely
outside `[i, j)`, so nodes are in left-to-right order.

**The leaf hash of a carried entry is §3.1's construction**, not the plain leaf hashing of §3.3.

Verification:

1. Reject unless `0 <= i < j <= N`.
2. Reject unless exactly `j - i` envelopes were carried, with `entry_index` values
   `i, i+1, ..., j-1` in that order.
3. Compute the leaf hash of each carried envelope.
4. Run `recompute(0, N)`; reject if the node list is exhausted early.
5. Reject unless every proof node was consumed.
6. Accept if and only if `recompute(0, N)` equals `C.root_hash`.

The recursion is a pure function of `(N, i, j)`, so the position at which each proof node is
consumed is fixed before any node is read and a prover cannot choose where to spend one. Carried
leaves are placed positionally, so any gap, reordering, omission or insertion changes the
recomputed root.

A range of width 1 is an inclusion proof in another serialization; a verifier MAY cross-check it
against §7.

### 9.2 Serialization

`range_proof.adaptor_form` is `"base64:" || base64(bytes)` with the layout below. All integers are
**big-endian**; there is no padding and no alignment.

| offset | size | field |
| --- | --- | --- |
| 0 | 6 | magic, ASCII `AHLRP1` |
| 6 | 8 | `tree_size` (u64) |
| 14 | 8 | `from_index` (u64) |
| 22 | 8 | `to_index` (u64) |
| 30 | 4 | `node_count` (u32) |
| 34 | 32 × `node_count` | subtree hashes, raw 32-byte SHA-256 values, in consumption order |

Total length is `34 + 32 * node_count`; any other length is a rejection, as is a proof whose
`tree_size`, `from_index` or `to_index` disagrees with the enclosing `range` object or with the
checkpoint.

### 9.3 No typed-subset proofs

This profile provides **no typed-subset proofs**: there is no capability here that proves "these
are all the manifest and key entries in this range" without carrying the range. The I-D §7.4
allowance to filter `entries` to manifest and key statements is therefore NOT available under
this profile, and enumerated governance currency MUST carry the full entry range.

## 10. Capabilities

| capability | status under `ahl-test-atl-leaf-v1` |
| --- | --- |
| binary checkpoint framing (`anchoring.checkpoint.raw`) | **defined** (§5.4) |
| consistency-proof serialization (`later_checkpoint` + `consistency_path`) | **defined** (§8) |
| authenticated range enumeration | **defined** (§9) |
| typed-subset (governance) proofs | **not defined** (§9.3) |

## 11. What this profile does not define

Availability, cadence enforcement, operator conduct, log-attested incorporation time, retrieval
interfaces, and every operational obligation a production binding would carry. None of them is a
rule a receipt is verified against, and none is exercised by the corpus that pins this document.
Like `ahl-test-log-v1`, this profile defines serialization only and is **not** a production log
binding.
