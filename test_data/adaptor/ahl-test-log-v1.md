# Adaptor profile `ahl-test-log-v1`

**Status:** test profile for the AHL Protocol conformance corpus.
**Profile id:** `ahl-test-log-v1`
**Profile hash:** `sha256:<SHA-256 over the exact bytes of this file>`, pinned in the corpus
manifest (`log.adaptor.hash`) and carried in every Evidence Receipt (`anchoring.adaptor.hash`).

This document is the whole of what a verifier needs in order to check the vectors in
`test_data/`. Core specification §3 item 6 requires adaptor profiles to be versioned,
immutable, content-addressed, openly published and independently implementable, and forbids
verification from depending on knowledge outside the profile document. This profile is
deliberately minimal and is **not** a production log binding: it defines serialization only,
and says nothing about availability, cadence enforcement, or operator conduct.

## 1. Hashing

SHA-256 throughout. Family strings follow the receipt format §1.4 conventions:
`"sha256:<lowercase hex>"`, `"hmac-sha256:<lowercase hex>"`, `"base64:<standard base64,
with padding>"`.

## 2. Trees

All AHL trees under this profile — the log tree, batch output trees, input-set trees and
disposition trees — are RFC 6962-style binary Merkle trees over SHA-256 with the domain
separation of core spec §2.5:

```
leaf_hash(b) = SHA-256( 0x00 || b )
node_hash(l, r) = SHA-256( 0x01 || l || r )
```

The root of a tree over `n > 1` leaf hashes splits at `k`, the largest power of two strictly
less than `n`: `root = node_hash(root(leaves[0..k]), root(leaves[k..n]))`. A one-leaf tree's
root is its leaf hash. Empty trees do not occur in this corpus.

### 2.1 Log tree

Leaf bytes are the anchored entry bytes: `JCS(envelope)`, the same bytes the entry id digests.

```
log leaf_hash(i) = SHA-256( 0x00 || JCS(envelope_i) )
```

Log leaves are in **entry-index order** and are never sorted: the entry index is the
position of the entry in the append-only log and is AHL's only ordering primitive
(core spec §1.2, constitution art. 9).

### 2.2 Record-sorted trees

Batch output trees, input-set trees and disposition trees carry leaf **objects**; the leaf
bytes are `JCS(leaf object)`. Their leaves are sorted and duplicate-free per core spec §2.5:

- sort key: the value of the leaf's `record` field, compared as the ascending lexicographic
  order of the **UTF-8 bytes of the canonical commitment string** (`"sha256:<hex>"` or
  `"hmac-sha256:<hex>"`, lowercase hex);
- a `record` value that is not a canonical commitment string makes the tree invalid, rather
  than being ordered by some fallback rule;
- two leaves with equal `record` values make the tree invalid.

Because the sort key is the family string rather than the raw digest, a tree whose leaves mix
commitment modes orders all `hmac-sha256:` records before all `sha256:` records (`h` < `s`).
This profile does not restrict such trees; it only fixes the ordering so two implementations
agree. `test_data/vectors/merkle/input-set-tree.json` is such a mixed tree.

Batch output leaves use `leaf_format` `ahl-leaf-v2` (core spec §2.5):
`{ "dataset", "record", "inputs": [ full derivation input objects ] }`. A leaf's `inputs` MAY
instead be the wide-input form `{ "input_set_root", "input_set_count" }` (core spec §2.5), in
which case the leaf commits its input set by root and the input-set tree is a second committed
tree that must be published under §3.5. Receipt format §3 depends on this composition:
`record-derived`'s `input_members` "applies ONLY when `batch_leaf.inputs` is the input-set
form". The batch at entry 10 of the corpus is exactly that shape.

Input-set leaves are full derivation input objects (core spec §2.3.2), carrying at least
`dataset` and `record`.

Disposition leaves use the shape of core spec §2.3.4.

### 2.3 Inclusion proofs

A proof is serialized as a JSON array of family strings, ordered **leaf to root**:

```json
{ "leaf_index": 3, "tree_size": 10, "path": [ "sha256:<hex>", "sha256:<hex>", ... ] }
```

In an Evidence Receipt the same array appears bare as `anchoring.inclusion_path`,
`governance.chain[].inclusion_path`, `claim_material.leaf_path` and
`claim_material.input_members[].input_path`. The tree size is then taken from the checkpoint's
`tree_size` or from the corresponding tree's committed count (`outputs_count`,
`input_set_count`, `affected_count`). The **leaf index** is taken from `subject.entry_index`
and `governance.chain[].entry_index` where those exist; where they do not, this profile fixes
the sibling member that carries it:

| bare path | leaf index carried as | tree size taken from |
| --- | --- | --- |
| `anchoring.inclusion_path` | `subject.entry_index` | `anchoring.checkpoint.tree_size` |
| `governance.chain[].inclusion_path` | `governance.chain[].entry_index` | `anchoring.checkpoint.tree_size` |
| `claim_material.leaf_path` | `claim_material.leaf_index` | `outputs_count` / `affected_count` of the subject payload |
| `claim_material.input_members[].input_path` | `claim_material.input_members[].input_index` | `input_set_count` of the leaf's `inputs` |

Receipt format §3 has since ratified `leaf_index` and `input_index` as members of the
`record-derived` schema itself; the table above is retained because it also covers
`disposition-declared`/`disposition-effective`, whose `leaf_path` opens `affected_root`.

Verification is the standard RFC 6962 recomputation of the root from the leaf hash and the
path, compared against the anchored root.

## 3. Keys

- **Public key encoding**: `"base64:<raw 32-byte Ed25519 public key>"`. No SPKI, no PEM.
- **Key id**: `"sha256:<hex of SHA-256 over the raw 32-byte public key>"`. For producer keys
  this is normative at core-spec level (§2.3.6); this profile adopts the identical rule for
  log and witness keys, whose derivation core spec §2.3.6 leaves adaptor-defined. The key id
  is a fingerprint, not a signature input; a verifier resolves it against key objects
  `{key_id, pubkey, valid_from_index}` in the manifest (core spec §7.2) and MUST recompute it
  from `pubkey` rather than trusting the carried value.
- **Signature encoding**: `"base64:<raw 64-byte Ed25519 signature>"`, Ed25519 per RFC 8032.

## 4. Statement envelopes

```json
{ "payload": { ... }, "signatures": [ { "key_id": "sha256:<hex>", "sig": "base64:<...>" } ] }
```

The signature member is spelled `key_id` — the same spelling as manifest key objects, `key`
statement key objects, and the receipt `keys` block. The signature covers `JCS(payload)`
exactly (core spec §2.1). An envelope with an empty `signatures` array is not an AHL
statement. Consequently:

- **statement id** = `"sha256:" || hex(SHA-256(JCS(payload)))`
- **entry id** = `"sha256:" || hex(SHA-256(JCS(envelope)))`

A non-genesis `manifest` statement references its predecessor manifest by **entry id** in the
member `predecessor` (core spec §2.3.5, which now names the member and makes it REQUIRED for
non-genesis manifests and forbidden for the genesis manifest).

### 4.1 Dataset authority

Core spec §7.2 now fixes the shape, and this profile carries it verbatim:

```json
"authority": { "producer": "<producer id>", "key_ids": [ "sha256:<hex>", ... ] }
```

`producer` MUST equal the manifest producer in core. A trigger for an ingested record of that
dataset is **effective** only if at least one of its signatures is by a key id that is in
`key_ids` **and** active at the trigger's own entry index (core spec §2.3.3, §7.2) — so a key
the authority list names but a later manifest snapshot dropped no longer triggers.

A trigger signed by any other key — including another valid key of the same producer — anchors
as a **challenge**: surfaced by verification, never traversed by closure, and never permitted
to govern. Effectiveness is decided *before* the greatest-entry-index rule of core spec §2.3.3
selects among competing triggers; a challenge at a greater entry index therefore cannot unseat
an earlier authorized trigger. `test_data/vectors/statements/23-*.json` is such a challenge,
sitting one index after the authorized retraction at entry 22:
`trigger-effective-later-challenge-ignored.ahl` shows entry 22 still governing, and
`propagation-complete-challenge-trigger-must-fail.ahl` shows a completeness claim over the
challenge being rejected.

For a *derived* record the authority is the introducing producer's key set **as of the
trigger's entry index** — not the introduction index, so a key rotation between the two applies
(core spec §2.3.3). `trigger-effective-derived-rotated-key.ahl` exercises exactly that: S1' is
introduced at entry 7, `producer-2` is added at entry 9, and the retraction at entry 19 signed
by `producer-2` is effective.

## 5. Checkpoints

```json
{ "log_id": "sha256:<hex>", "tree_size": 10, "root_hash": "sha256:<hex>",
  "checkpoint_time": "<RFC 3339>", "key_id": "sha256:<hex>", "signature": "base64:<...>" }
```

The log signs `JCS(checkpoint object with the "signature" member removed)`. `log_id` is
`"sha256:" || hex(SHA-256("ahl-test-log-1"))` for the corpus log and MUST match
`log.id` in the manifest version active for the checkpoint's `tree_size`. A checkpoint
commits exactly the entries with index in `[0, tree_size)`.

This profile defines no binary checkpoint framing, so receipts under it MUST NOT carry
`anchoring.checkpoint.raw`.

## 6. Witness cosignatures

A witness (core spec §3.3) cosigns the **signed** checkpoint object, bound to its own
identity so a cosignature cannot be replayed for another witness:

```
cosignature = Ed25519( JCS( { "checkpoint": <signed checkpoint object>,
                              "witness_id": "<witness id>" } ) )
```

Serialized in a receipt as
`{ "witness_id", "key_id", "cosignature": "base64:<...>", "cosigned_at": "<RFC 3339>" }`.

### 6.1 Refusal evidence

Core spec §3.3 step 3: on inconsistency or a missing consistency proof a witness MUST refuse
to cosign and MUST publish signed refusal evidence containing both conflicting checkpoints.
Under this profile that evidence is:

```json
{ "type": "witness-refusal",
  "witness_id": "<id>",
  "log_id": "sha256:<hex>",
  "reason": "inconsistent | missing-consistency-proof",
  "retained": { ...signed checkpoint the witness had already cosigned... },
  "offered":  { ...signed checkpoint the witness refused... },
  "detail": "<informative text; never normative>",
  "refused_at": "<RFC 3339>",
  "key_id": "sha256:<hex>",
  "signature": "base64:<...>" }
```

The witness signs `JCS(refusal object with the "signature" member removed)` — the same rule
as §5, so one signing routine serves both. Refusal evidence is **self-authenticating**: a
verifier needs only the witness public key from the manifest (core spec §7.2) plus the log
public key to establish that the log signed two checkpoints that cannot both be true. It is
not an AHL statement, is not anchored, and carries no `payload`/`signatures` envelope.

Checking refusal evidence:

1. verify the witness signature over the refusal object;
2. verify the log signature on **both** carried checkpoints — an unsigned or badly signed
   checkpoint proves nothing about the log;
3. establish the conflict. For `reason: "inconsistent"` the two checkpoints have equal
   `tree_size` and different `root_hash`, which no append-only log can produce. For
   `reason: "missing-consistency-proof"` the offered checkpoint has the greater `tree_size`
   and no consistency proof from the retained one was supplied;
4. treat a verified refusal as evidence of log equivocation, not as a verdict about any
   particular statement (core spec §3.3 claim discipline).

## 7. Capabilities this profile does NOT define

Core spec §3 item 6 forbids verification from depending on knowledge outside the profile
document, so the absence of a definition here is a **property of this profile**, not of the
container format or of any verifier. Two capabilities the format allows are deliberately
undefined in this revision:

| capability | status under `ahl-test-log-v1` | consequence |
| --- | --- | --- |
| binary checkpoint framing (`anchoring.checkpoint.raw`) | **not defined** | a receipt carrying `raw` under this profile MUST be rejected — there is no framing to parse it against, so the §5-step-2 "parses to the same values" check cannot be performed |
| consistency-proof serialization (`anchoring.later_checkpoint` + `consistency_path`) | **not defined** | a receipt claiming `assurance.continued_history: true` under this profile MUST be rejected; receipts under it carry `continued_history: false` and omit both members |

A conformant verifier reports these as limitations of the pinned profile, naming it — another
profile that defined either capability would make the same receipt verifiable without any
change to the verifier. Both are candidates for a future revision of this document, which
would carry a new profile hash and therefore a new manifest version.

Consistency proofs between checkpoints are otherwise a core-spec §3 contract item; nothing
here weakens that requirement for production adaptors.

### 7.1 Authenticating an earlier checkpoint without a consistency proof

Receipt format §3 lets `propagation-complete` authenticate the propagation's declared
checkpoint D "EITHER [by] a consistency proof D→`anchoring.checkpoint` OR [by] recomputation of
D's prefix root from the enumerated prefix". Because this profile defines no consistency-proof
serialization, only the second path is available under it — and it is sufficient:

1. the receipt carries D as a full signed checkpoint object; its log signature is verified
   against a key declared by the manifest version active for **D's** `tree_size` (§2.2), which
   may be an earlier manifest version than the one active for A;
2. the enumerated `corpus_prefix` covers `[0, tree_size(D))` and its §8 range proof is verified
   against **A's** root at A's `tree_size` — so the entries are authenticated under the
   checkpoint the verifier actually signature-checked and saw witness-cosigned;
3. the root of those `tree_size(D)` leaves is recomputed by the §2 rule and compared to D's
   `root_hash`.

Steps 2 and 3 together establish that D is exactly the size-`tree_size(D)` prefix of A, which
is precisely what an RFC 6962 consistency proof D→A asserts. The prefix is carried in full
regardless — receipt format §3 states there is no compact completeness form — so a separate
consistency proof would restate an already-proven fact in a second encoding.

## 8. Authenticated enumeration

Core spec §3 contract item 5 requires the log to serve entries `[i, j)` under a checkpoint
"with proof of completeness and order", and receipt format §4.2 carries that proof as
`range_proof.adaptor_form`. This profile defines the proof as follows.

### 8.1 What is proven

Given a checkpoint `C` over a log of `N = tree_size(C)` entries, a range `[i, j)` with
`0 <= i < j <= N`, and an ordered list of `j - i` entry envelopes, the proof establishes that
the carried list is **exactly and completely** the leaf set of `[i, j)` under `C.root_hash`:
no gaps, no reordering, no omissions, no insertions.

### 8.2 Construction

The proof is the minimal set of RFC 6962 subtree hashes covering everything *outside* the
range. Define, over the standard RFC 6962 decomposition of `[0, N)`:

```
recompute(offset, size):
    let end = offset + size
    if end <= i or offset >= j:                     # subtree entirely outside the range
        return the next unconsumed proof node
    if offset >= i and end <= j:                    # subtree entirely inside the range
        return root of the carried leaf hashes for [offset, end)
    k = largest power of two strictly less than size
    return node_hash( recompute(offset, k), recompute(offset + k, size - k) )
```

The proof node list is produced by the same recursion at generation time: walk the
decomposition of `[0, N)` and, for every maximal subtree entirely outside `[i, j)`, emit that
subtree's root hash. Nodes are therefore in left-to-right order.

The leaf hash of an entry is `SHA-256(0x00 || JCS(envelope))` (§2.1), and the root of a span
of leaf hashes is computed by the §2 splitting rule.

### 8.3 Verification

1. Reject unless `0 <= i < j <= N`.
2. Reject unless exactly `j - i` entry envelopes were carried, with `entry_index` values
   `i, i+1, ..., j-1` in that order.
3. Compute the leaf hash of each carried envelope.
4. Run `recompute(0, N)`. Reject if the node list is exhausted early.
5. Reject unless every proof node was consumed.
6. Accept iff `recompute(0, N) == C.root_hash`.

Soundness: the recursion is a pure function of `(N, i, j)`, so the position at which each
proof node is consumed is fixed before any of them is read — a prover cannot choose where to
spend a node. The carried leaves are placed positionally, so any gap, reordering, omission or
insertion changes `recompute(0, N)`. Under collision resistance of SHA-256, only the true leaf
set of `[i, j)` opens the checkpoint root.

A range of width 1 is an inclusion proof in a different serialization: its node list, sorted
by decreasing depth in the recursion, is exactly the §2.3 inclusion path for leaf `i`. A
conformant verifier MAY cross-check it that way; the reference implementation does.

### 8.4 Serialization

`range_proof.adaptor_form` is `"base64:" || base64(bytes)` with the byte layout below. All
integers are **big-endian**; there is no padding and no alignment.

| offset | size | field |
| --- | --- | --- |
| 0 | 6 | magic, ASCII `AHLRP1` |
| 6 | 8 | `tree_size` (u64) |
| 14 | 8 | `from_index` (u64) |
| 22 | 8 | `to_index` (u64) |
| 30 | 4 | `node_count` (u32) |
| 34 | 32 × `node_count` | subtree hashes, raw 32-byte SHA-256 values, in consumption order |

The total length is therefore `34 + 32 * node_count`; any other length is a rejection. A proof
whose `tree_size`, `from_index` or `to_index` disagrees with the enclosing §4.2
`range` object or with the checkpoint is a rejection.

Because this profile provides **no typed-subset proofs** (core spec §10.9), receipt format §4.2
filtering of `entries` to manifest/key statements is NOT available under it: enumerated
governance currency must carry the full entry range. That is the honest cost until a typed
governance sub-tree exists.
