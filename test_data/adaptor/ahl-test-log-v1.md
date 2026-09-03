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
`log.log_id` in the manifest version active for the checkpoint's `tree_size` — the manifest
member is spelled `log_id`, exactly as the checkpoint member is, and this profile defines no
alias for it. A checkpoint commits exactly the entries with index in `[0, tree_size)`.

The manifest `log` object of core spec §7.3 is
`{ log_id, operator, adaptor: {id, hash}, checkpoint_cadence, cadence_epoch,
witness_grace_period, keys }`, and **every member is REQUIRED**. `cadence_epoch` is the single
start of the checkpoint-series obligation: it is declared by the genesis manifest, repeated
unchanged by every later version, and the earliest checkpoint committing the genesis manifest
must fall in `[cadence_epoch, cadence_epoch + checkpoint_cadence]`. This profile defines no
cadence *enforcement* — the corpus publishes checkpoints for the scenarios its vectors need,
not on a schedule — but the members are carried because a manifest missing one is malformed.

The value grammars are core spec §7.3's, restated here so a verifier implemented from this
document alone is complete:

| member | grammar |
| --- | --- |
| `log_id`, `keys[].key_id`, `adaptor.hash` | family strings: `"sha256:"` plus 64 lowercase hex digits (§3) |
| `checkpoint_cadence`, `witness_grace_period` | `P[n]DT[n]H[n]M[n]S` — days, hours, minutes, seconds. `Y`, and `M` in the date part, are PROHIBITED; at most nine fractional digits, on the seconds component only |
| `checkpoint_cadence` | additionally MUST be greater than zero |
| `cadence_epoch` | RFC 3339 |
| `keys[]` | `{ key_id, pubkey, valid_from_index }`, the last an entry index |

A malformed value MUST be **rejected rather than approximated**, and rejection is a duty on the
value rather than a consequence of computing with it. A verifier that reads no cadence still
refuses a manifest declaring `P1Y`: admitting it would leave the corpus verifiable only by
implementations sharing that tolerance, and would make cadence, frontier and completeness bounds
implementation-dependent for every party that does compute with the value. Truncating an
over-long fraction is the same error in a quieter form.

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

Core spec §3.3 step 3: a witness that observes a fault MUST refuse to cosign and MUST publish
signed refusal evidence containing both conflicting checkpoints. Under this profile that
evidence is:

```json
{ "type": "witness-refusal",
  "witness_id": "<id>",
  "log_id": "sha256:<hex>",
  "reason": "equivocation | size-regression | extension-failed",
  "retained": { ...signed checkpoint the witness had already cosigned... },
  "offered":  { ...signed checkpoint the witness refused... },
  "proof": { "from_size": 13, "to_size": 20, "path": [ "sha256:<hex>", ... ] },
  "detail": "<informative text; never normative>",
  "refused_at": "<RFC 3339>",
  "key_id": "sha256:<hex>",
  "signature": "base64:<...>" }
```

`retained` and `offered` are REQUIRED in **every** refusal, each a complete signed checkpoint
object of §5 including its `signature` member. `proof` is REQUIRED for `extension-failed` and
MUST be absent for the other two reasons: a carried proof that no reason directs a verifier to
check is unverified material inviting misreading. The witness signs `JCS(refusal object with
the "signature" member removed)` — the same rule as §5, so one signing routine serves both.

Every reason is independently recheckable from the evidence the refusal itself carries. A
verifier never has to consult the log, the producer or the witness to decide whether a refusal
is supported:

| `reason` | emitted when | what a verifier rechecks from the carried evidence |
| --- | --- | --- |
| `equivocation` | the offered checkpoint shares a `tree_size` with a cosigned one and carries a different `root_hash` | `retained.tree_size == offered.tree_size` **and** `retained.root_hash != offered.root_hash`, both checkpoints carried and log-signed |
| `size-regression` | the offered `tree_size` is smaller than an already-cosigned size, and no history exists at the offered size | `offered.tree_size < retained.tree_size` over the two carried checkpoints |
| `extension-failed` | the offered checkpoint is larger and the consistency proof from the retained one to it fails verification | re-run the §9 consistency verification over the **carried proof**, after checking `proof.from_size == retained.tree_size` and `proof.to_size == offered.tree_size` |

The two binding equalities for `extension-failed` MUST be checked **before** the proof is
verified, and the refusal rejected as unsupported if either fails — otherwise a structurally
valid proof that fails for some unrelated pair of sizes would validate a refusal about this
pair, and the refusal would be baseless while the failure was real.

There is no reason for "the log supplied no proof". Absence of a proof is not recheckable from
a signed refusal — the evidence would carry nothing a verifier could examine, so a witness could
emit it at will and a verifier could neither confirm nor refute it. A witness that derives
consistency proofs itself, which is the arrangement this profile assumes, treats its own
inability to compute one as an internal error: it declines to cosign and reports operationally,
but publishes no refusal, because it has no evidence of log misbehaviour.

Refusal evidence is **self-authenticating**: a verifier needs only the witness public key from
the manifest (core spec §7.2) plus the log public key. It is not an AHL statement, is not
anchored, and carries no `payload`/`signatures` envelope.

Checking refusal evidence:

1. verify the witness signature over the refusal object;
2. verify the log signature on **both** carried checkpoints — an unsigned or badly signed
   checkpoint proves nothing about the log — and confirm both carry the named `log_id`;
3. apply the recheck for the declared `reason` from the table above. A refusal whose evidence
   does not support its declared reason is **unsupported** and MUST be reported as such; a
   verifier MUST NOT substitute a different reason the evidence would have supported;
4. treat a verified refusal as evidence about the log's conduct within the boundary of its
   reason, not as a verdict about any particular statement (core spec §3.3 claim discipline).
   A verified `equivocation` ends the canonical series from that `tree_size` onward; a verified
   `size-regression` or `extension-failed` is a finding about what the log offered this witness
   and by itself establishes no divergence.

## 7. Capabilities

Core spec §3 item 6 forbids verification from depending on knowledge outside the profile
document, so the absence of a definition here is a **property of this profile**, not of the
container format or of any verifier:

| capability | status under `ahl-test-log-v1` | consequence |
| --- | --- | --- |
| binary checkpoint framing (`anchoring.checkpoint.raw`) | **not defined** | a receipt carrying `raw` under this profile MUST be rejected — there is no framing to parse it against, so the §5-step-2 "parses to the same values" check cannot be performed |
| consistency-proof serialization (`anchoring.later_checkpoint` + `consistency_path`) | **defined** (§9) | `assurance.continued_history: true` is reachable under this profile; a receipt claiming it MUST carry both members and both MUST verify |
| authenticated range enumeration | **defined** (§8) | enumerated governance currency and every claim type requiring it are available |
| typed-subset (governance) proofs | **not defined** (§8.4) | enumerated governance carries the full entry range |

A conformant verifier reports an absent capability as a limitation of the pinned profile,
naming it — another profile that defined it would make the same receipt verifiable without any
change to the verifier. The binary framing is a candidate for a future revision of this
document, which would carry a new profile hash and therefore a new manifest version.

### 7.1 Authenticating an earlier checkpoint without a consistency proof

Receipt format §3 lets `propagation-complete` authenticate the propagation's declared
checkpoint D "EITHER [by] a consistency proof D→`anchoring.checkpoint` OR [by] recomputation of
D's prefix root from the enumerated prefix". Both paths exist under this profile; the corpus
uses the second, and it is sufficient on its own:

1. the receipt carries D as a full signed checkpoint object; its log signature is verified
   against a key declared by the manifest version active for **D's** `tree_size` (§2.2), which
   may be an earlier manifest version than the one active for A;
2. the enumerated `corpus_prefix` covers `[0, tree_size(D))` and its §8 range proof is verified
   against **A's** root at A's `tree_size` — so the entries are authenticated under the
   checkpoint the verifier actually signature-checked and saw witness-cosigned;
3. the root of those `tree_size(D)` leaves is recomputed by the §2 rule and compared to D's
   `root_hash`.

Steps 2 and 3 together establish that D is exactly the size-`tree_size(D)` prefix of A, which
is precisely what an RFC 9162 consistency proof D→A asserts. The prefix is carried in full
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

## 9. Consistency proofs

Core spec §3 contract item 3 requires the log to serve consistency proofs between checkpoints,
and receipt format §2.1 makes them the evidence behind `assurance.continued_history`. This
profile defines them.

### 9.1 Construction and serialization

A consistency proof is an RFC 9162 §2.1.4 proof between two tree sizes of the **same** log,
over the log tree of §2.1. It is serialized as a JSON array of `"sha256:<hex>"` family strings
in the order produced by the RFC 9162 algorithm — the same shape as an inclusion path (§2.3),
and, like it, carried bare:

```json
"consistency_path": [ "sha256:<hex>", "sha256:<hex>", ... ]
```

The two sizes are not carried inside the array. They come from the checkpoints the proof runs
between, which is what binds the proof to a specific pair:

| member | from size | to size |
| --- | --- | --- |
| `anchoring.consistency_path` | `anchoring.checkpoint.tree_size` | `anchoring.later_checkpoint.tree_size` |

`anchoring.later_checkpoint` is a complete signed checkpoint object of §5, including its
`signature` member.

### 9.2 Verification

1. Reject unless **both** `later_checkpoint` and `consistency_path` are present. Receipt format
   §2.3 states the equivalence — `assurance.continued_history` is true *iff* both are present
   and verify — so one without the other is malformed, not a weaker claim.
2. Reject unless `later_checkpoint.tree_size >= anchoring.checkpoint.tree_size`. A "later"
   checkpoint of smaller size proves no continued history; it is the size regression a witness
   refuses to cosign over (§6.1).
3. Verify `later_checkpoint`'s own log signature by §5, against a key declared by the manifest
   version active for **its** `tree_size` — which may be a later manifest version than the one
   active for `anchoring.checkpoint` (receipt format §2.2). A key one manifest version replaced
   must not validate a checkpoint issued under another.
4. Run the RFC 9162 §2.1.4 verification over the carried path, from
   `anchoring.checkpoint.root_hash` at its `tree_size` to `later_checkpoint.root_hash` at its
   own. Accept only on success; a path that is structurally impossible for that pair of sizes is
   a failed proof, exactly like one that simply does not open the pair.

### 9.3 What the proof does and does not establish

A consistency proof establishes that the later checkpoint's tree is an append-only extension of
the earlier one's: no entry the earlier checkpoint committed was removed, reordered or altered.

It does **not** establish that a checkpoint the cadence required was ever published — omission
is invisible to it (core spec §7.3) — and it says nothing about whether the operator showed the
same log to everyone, which is what the witness protocol of §6 exists for. A verdict rendered
from `continued_history` must not be stated more strongly than "the log's history continued to
be append-only through the later checkpoint carried here".
