# Adaptor profile `ahl-adaptor-atl-v1`

**Status:** adaptor profile, revision 1, pre-release. Not yet released as an immutable
artifact; until it is, no corpus can pin it (§14).
**Profile id:** `ahl-adaptor-atl-v1`
**Profile digest:** computed over the released artifact, recorded in the corpus manifest
(`log.adaptor.hash`) and in every Evidence Receipt that pins this profile
(`anchoring.adaptor.hash`). The value is deliberately not written here; see §14.
**Log class:** Anchored Transparency Log (ATL) Protocol v2.0, as published at
`atl-protocol.org` and implemented by `atl-core` and `atl-server`.

RFC 2119 keywords apply.

**Normative references used in this document.** *Core spec* citations are to the AHL Core
Specification (`ahl-spec-draft.md`). *I-D* citations are to the AHL Internet-Draft, which is
self-contained and **controls**; where the two differ, the I-D governs. The AHL Evidence Receipt
container companion is **non-normative** with respect to the I-D, and is cited here only for
receipt detail the I-D does not itself fix.

Core specification §3 item 6 requires an adaptor profile to be versioned, immutable,
content-addressed, openly published and independently implementable, and forbids conformant
verification from depending on knowledge outside the profile document. This document is
therefore the whole of what a verifier needs in order to check AHL statements, proofs and
Evidence Receipts anchored in an ATL log.

This document describes how one log class satisfies the AHL log-binding contract. It does not
argue that ATL is preferable to any other log, and nothing in it restricts AHL to ATL. Where
ATL as published does not provide something the contract requires, this profile says so, marks
the item as a deployment obligation or an explicit gap, and specifies the interface a
deployment MUST supply. Sections 15 and 16 are the honest summary; a reader evaluating
whether an ATL deployment can carry an L3 corpus should read them first.

## 1. Scope

This document is an **AHL adaptor profile for ATL**: an AHL document describing how ATL satisfies AHL's log-binding contract. It is not an "ATL profile" — ATL has none — and it must not be confused with an **APL profile**, which is a vertical vocabulary and frame family belonging to a different protocol of this family.

This profile binds:

- an AHL **corpus** (core spec §1.2) — the statements anchored under one declared manifest
  lineage — to
- exactly one ATL **Data Tree**, identified by one ATL Origin ID.

It defines entry encoding, the ordering primitive, checkpoint mapping, proof serialization,
key material, the enumeration interface, and the witness binding. It does not define operator
conduct, retention practice, cadence policy, or commercial terms; those are manifest
declarations (core spec §7.2) and deployment matters.

### 1.1 Verification results, and findings that are not results

I-D §7.7 fixes the verifier result model: a verifier's result **over a receipt** is exactly one
of `verified`, `invalid` or `unverifiable`. `refuted` is deliberately absent, because a verifier
never establishes the negation of a historic fact. This profile adopts that model unchanged,
defines no additional result value, and uses those three words **as outcome labels only where a
receipt is in hand and the label is the result over that receipt**.

With a receipt in hand, this profile's outcomes map as follows:

- **`invalid`** — the presented material does not verify, or the receipt does not carry material
  it is REQUIRED to carry. Every "MUST reject the receipt" in this document is `invalid`, and so
  is a log signature, witness cosignature, inclusion path, consistency path, checkpoint mapping
  or family-string form that fails (I-D §7.1, §7.7).
- **`unverifiable`** — the receipt is well formed and what it carries verifies, but something
  **local to the verifier, or external to the receipt**, prevents evaluation: a capability this
  profile does not provide (§13), a trust anchor the verifier has not configured, a dataset key
  it does not hold, an exhausted local budget, or material that lives outside the receipt and
  was not supplied to it.

The line between the two is the **source of the missing material**, not the fact of its absence.
Material the receipt MUST carry and does not is `invalid`; material that is the verifier's own,
or the deployment's, is `unverifiable`. Neither may be rendered as denying the asserted property
(I-D §7.7).

**Most of what this profile specifies is not a result over a receipt at all.** Series
completeness and cadence conformance (§5.2.2), the equivocation boundary, the availability of
`ITUB` (§5.2.1), an enumeration response (§10.3), refusal evidence (§11.2) and conformance
against §16 are **operational findings about a deployment and the series it publishes**. They
sit outside the I-D §7.7 model. They MUST be reported in their own terms and MUST NOT be
labelled `verified`, `invalid` or `unverifiable`.

The two connect **through a receipt, and only through a receipt**. Where an operational finding
leaves the declared claim of a *particular* receipt unevaluable, and the missing material is
external to that receipt, the result **for that receipt** is `unverifiable`, with the finding
stated as its reason. Where no receipt is in hand, or where no claim type of I-D §7.2 asserts
the quantity in question, the finding stands on its own and no result value attaches to it.

So that two implementations cannot label the same receipt differently, this document invokes
that connection **only where it names both the claim type and the material the outcome turns
on**. Where it names neither, no result value attaches and the finding is reported alone. In
particular the authenticated-versus-series-usable distinction of §6.6 is **not** such a case: it
governs this profile's own interfaces and findings, never a receipt result — §6.6 says so
explicitly, and adds no precondition to any claim type of I-D §7.2.

## 2. Hashing, encodings, family strings

SHA-256 throughout, as required by core spec §2.5 and as implemented by ATL.

Family strings follow I-D §2.1:

- `"sha256:<lowercase hex>"` — digests and key ids;
- `"hmac-sha256:<lowercase hex>"` — `keyed`-mode record commitments (core spec §2.4);
- `"base64:<...>"` — public keys, signatures, opaque proof bytes.

**The encodings are I-D §2.1's, for every object, and this profile may not vary them.** I-D
§2.1 fixes all three families once, for every object that document defines — envelopes,
statement payloads, manifests, receipts, and anything a future adaptor profile carries — and
expressly forbids an adaptor profile from redefining a family string that appears in a core
object, since such objects cross profiles. Three consequences this profile depends on and
therefore restates:

- **`sha256:` and `hmac-sha256:` are exactly 64 hexadecimal digits**, `0`-`9` and `a`-`f` only.
  Uppercase is neither emitted nor accepted; there is no `0x` prefix, no separator and no
  whitespace. Every `sha256:` and `hmac-sha256:` value this document constructs or carries takes
  exactly that form; this profile defines no shorter, longer or differently cased variant.
- **`base64:` is the standard alphabet of RFC 4648 §4, with padding** to a multiple of four
  characters. The URL-safe alphabet of RFC 4648 §5 is neither emitted nor accepted. I-D §7.1
  names which receipt members carry octets in this form — `pubkey`, `signature`, `cosignature`,
  `raw`, `record_bytes`, `output_bytes` and the `adaptor_form` member of enumeration material —
  and cites §2.1 for the encoding itself.
- **Acceptance is strict and MUST NOT be more permissive than emission** (I-D §2.1). A verifier
  rejects a family string with the wrong prefix for its member, the wrong length, a character
  outside its alphabet, omitted or misplaced padding, embedded whitespace or a line break, or a
  non-canonical base64 final quantum. In a receipt such a value is a schema failure and the
  result is `invalid` (I-D §2.1, §7.7).

What an adaptor defines is the **octets inside** its own `anchoring.checkpoint.raw` (§6.4) and
`range_proof.adaptor_form` (§10.5), and the retrieval-response form of §10.1.1 — never the
family-string wrapper carrying any of them.

JSON canonicalization is RFC 8785 (JCS). ATL implements the same scheme (`atl-core`
`core/jcs.rs`), so a single canonicalizer serves both layers. Object members are sorted by
UTF-16 code unit; a verifier MUST NOT assume byte-wise sorting is equivalent.

Ed25519 per RFC 8032 for all signatures: statement signatures, ATL checkpoint signatures, and
witness cosignatures.

## 3. Log binding topology

ATL log operators maintain **multiple, time-partitioned Data Trees**, each with its own Origin
ID, whose roots are aggregated as leaves of a **Super-Tree** (ATL protocol §3.3). Each Data
Tree has its own independent leaf indexing starting at 0.

AHL requires a single immutable ordering primitive over the whole corpus: the entry index is
"the entry's immutable position in the log", and every "before", "after", "latest" and
checkpoint-membership rule in the core specification is evaluated on it (core spec §1.2,
constitution art. 9).

Under this profile therefore:

1. A corpus MUST be bound to exactly one Data Tree. `log_id` in the manifest's `log` object
   (core spec §7.2) MUST be the AHL `log_id` of §7.1 below, which is derived from that Data
   Tree's Origin ID.
2. Every checkpoint, inclusion proof, consistency proof and enumeration used by the corpus
   MUST belong to that same Origin ID. Material from another Data Tree of the same operator
   MUST be rejected: different Data Trees are independent trees with no consistency
   relationship between them.
3. Composing a single AHL entry index across a Data Tree rotation is **NOT defined by this
   profile**. When the bound Data Tree is closed, the corpus's ability to accept new entries
   under this manifest version ends. Continuing the corpus in a new Data Tree requires a new
   manifest version pinning the new `log_id`, and this profile makes no claim that ordering,
   completeness or reconstruction compose across that boundary — core spec §10.4 records
   multi-log anchoring and log migration without evidence loss as an open issue, and this
   profile does not pre-empt it.
4. Consequently, a deployment intending a long-lived corpus MUST configure the bound Data Tree
   so that it is not rotated for the corpus's lifetime, or accept the boundary in 3.

The Super-Tree remains useful under this profile as supplementary evidence and as the anchoring
target ATL itself uses (§12); it is not used to derive AHL identity or ordering.

## 4. Entry encoding

### 4.1 What is submitted

An AHL entry is the JCS-canonical envelope bytes, `JCS(envelope)`, where the envelope is
I-D §2.1:

```json
{ "payload": { ... }, "signatures": [ { "key_id": "sha256:<hex>", "sig": "base64:<...>" } ] }
```

Those bytes, and only those bytes, are the anchored entry. The producer submits them to ATL as
the entry **payload**. Statement id and entry id are unchanged from I-D §2.1:

- **statement id** = `"sha256:" || hex(SHA-256(JCS(payload)))`
- **entry id** = `"sha256:" || hex(SHA-256(JCS(envelope)))`

### 4.2 ATL leaf construction and the entry id

ATL does not hash the payload bytes directly into the leaf. An ATL leaf combines two digests
(ATL protocol §3.1, `atl-core` `core/merkle/crypto.rs`):

```
leaf_hash = SHA-256( 0x00 || payload_hash || metadata_hash )
```

where `payload_hash` is the SHA-256 of the submitted payload bytes and `metadata_hash` is the
SHA-256 of the JCS-canonicalized ATL metadata object.

Under this profile:

- `payload_hash` = `SHA-256(JCS(envelope))` — the raw 32-byte form of the AHL **entry id**.
  The AHL entry id is therefore the ATL payload hash, and remains derivable from the entry
  bytes alone.
- the ATL metadata object is **fixed** and carries no AHL data:

```json
{"ahl_adaptor":"ahl-adaptor-atl-v1"}
```

  Its JCS form is the 36 bytes shown, and its digest is the constant

```
metadata_hash = sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4
```

- An entry whose ATL metadata is anything else is **not** an AHL entry under this profile and
  MUST be rejected by an AHL verifier, even if it is a valid ATL entry.

The AHL log leaf hash is therefore fully determined by the envelope:

```
log leaf_hash(i) = SHA-256( 0x00 || SHA-256(JCS(envelope_i)) || METADATA_HASH )
```

with `METADATA_HASH` the constant above.

Rationale for pinning metadata rather than using it: ATL metadata is operator-supplied and is
not covered by any AHL signature. If AHL data were placed there, an AHL entry's leaf would
depend on bytes outside the signed envelope, and the entry id would no longer determine the
leaf. Pinning a constant keeps the leaf a pure function of the entry and keeps the AHL entry id
equal to the ATL payload hash. The cost is that ATL's metadata-based search and filtering
features are unavailable to AHL entries; that is intended.

### 4.3 Ordering of log leaves

Log leaves are in **entry-index order** and are never sorted. Sorting applies only to the
record-keyed trees of §9.

## 5. Entry index and incorporation time

### 5.1 Entry index

The AHL **entry index** of an entry is its ATL **leaf index** within the bound Data Tree,
0-based. Nothing else plays this role under this profile.

A verifier obtains it from:

- `subject.entry_index` and `governance.chain[].entry_index` in an Evidence Receipt, checked
  against the inclusion proof (§8) — the proof only verifies at the correct index, so a
  misstated index is detected;
- the `entry_index` values in enumeration material (§10);
- `proof.leaf_index` of an ATL Evidence Receipt for the same entry, where one is held.

An AHL verifier MUST NOT accept an entry index that is not confirmed by a proof under the
checkpoint being verified.

### 5.2 Incorporation time: no LIT, and what replaces it

Core spec §3 contract item 1 requires a log-attested incorporation time (LIT) per entry: a time
the log itself attests for that entry.

**ATL does not provide one.** The ATL entry structure carries an id, a payload hash, a metadata
hash and metadata; the only log-signed time in the protocol is the `timestamp` field of a
checkpoint (ATL protocol §4.1), which attests the state of the tree, not the incorporation of
any individual entry. **This profile therefore does not satisfy the LIT requirement of contract
item 1, and no value defined here is a LIT.** §15 records the clause as unsatisfied.

What ATL does support is a weaker, differently named quantity, which this profile defines so
that deployments do not improvise one.

#### 5.2.1 Incorporation-time upper bound

The **incorporation-time upper bound** of the entry at index `i`, written `ITUB(i)`, is the
`checkpoint_time` of the checkpoint with the **smallest `tree_size` strictly greater than `i`**
among the **series-usable** members (§6.6) of the canonical checkpoint series of §5.2.2.

**Ties.** A quiet log republishes at unchanged `tree_size` (§16 obligation 4), so the selection
may land on a `tree_size` carrying several members. In that case the member with the **earliest
`checkpoint_time`** governs, giving the tightest bound the series supports (core spec §7.3).
Since all members at one `tree_size` carry the same `root_hash` (§5.2.2 item 2), they describe
the same tree and differ only in when the log restated it; taking the earliest restatement is
both the tightest and the only choice that does not let an operator loosen a bound by
republishing.

Only series-usable checkpoints may ground an incorporation-time bound (core spec §7.3). A
checkpoint that is merely authenticated — its log signature verifies, but its root has not been
recomputed against the entries held for its tree size, or its consistency relationships with its
neighbours in the series have not been verified — MUST NOT be selected, even where it is the
numerically closest member above `i`. Where the closest member above `i` is authenticated but
not series-usable, `ITUB(i)` is taken from the smallest series-usable member above `i`, and the
result MUST be reported together with the fact that a nearer, unusable member exists, since the
bound is looser than the published cadence would suggest.

`ITUB(i)` bounds incorporation from above: the entry was in the tree no later than that time.
It says nothing about how much earlier the entry was incorporated; the tighter the checkpoint
cadence, the tighter the bound. `ITUB` MUST NOT be used for ordering — ordering is the entry
index (§5.1) — and MUST NOT be presented as a LIT, as a log-attested time, or as the time at
which the entry was submitted, signed, or created.

#### 5.2.2 The canonical checkpoint series, and why it is required

Selecting "the earliest checkpoint a party happens to hold" would make the value
observer-dependent and operator-controllable: two parties holding different checkpoint sets
would derive different values for the same entry, and an operator could push the value
arbitrarily late simply by withholding checkpoints. A deadline computed from such a value is
not a deadline. Retaining history does not by itself repair this — the selection rule must
range over a series that is the same for everybody.

`ITUB` is therefore defined only where the deployment publishes a **canonical checkpoint
series** for the bound Data Tree. Core spec §7.3 fixes what such a series is; this profile
restates it in ATL terms and adds nothing to it. A canonical series is one that is:

1. **Cadence-conforming.** Over the range each manifest version governs, no two adjacent
   members differ in `checkpoint_time` by more than that version's `checkpoint_cadence`, with
   the series starting at the corpus's single `cadence_epoch` (§7.3). Cadence is a
   **maximum-gap obligation, not an expectation**: a gap wider than the declared cadence is a
   violation of the obligation, not a slow patch of an otherwise valid series. A
   `checkpoint_cadence` declared by a manifest version applies **only from that version's entry
   index forward** and is never applied retroactively; ranges before it remain governed by the
   cadence of the version active then, so a verifier evaluating a long series evaluates it
   piecewise, one governing version at a time. The version governing a checkpoint — for cadence
   exactly as for keys — is the manifest statement with the greatest entry index smaller than
   that checkpoint's `tree_size`, and a gap that **straddles** a cadence change is judged under
   the version governing its **earlier** member, so every interval is judged by the cadence in
   force when it began (core spec §7.3). Note that `cadence_epoch` itself never varies: it is
   declared once, by the genesis manifest, and repeated unchanged by every later version
   (§7.3).
2. **Ordered, and monotone in time.** Series order is **`(tree_size, checkpoint_time)`,
   ascending** (core spec §7.3). `tree_size` alone does not totally order a series, because a
   quiet log republishes at unchanged size (§16 obligation 4), so the time field breaks the tie.
   Members sharing a `tree_size` **MUST carry the same `root_hash`**: they restate one tree, and
   two different roots at one size are equivocation, not a tie — with the consequences set out
   after this list and the witness handling of §11.2. `checkpoint_time` is
   non-decreasing across this order; a member whose time precedes its predecessor's in the order
   is a **violation and a finding**, never to be treated as a zero-length gap, silently
   reordered, or normalized away. Entry ordering is unaffected and remains the entry index
   (§5.1); series order is an ordering of checkpoints, not of entries.
3. **Anchored at `cadence_epoch`, which is the series' only start.** The range begins at
   `cadence_epoch` — the single start of the obligation — and is judged there under the
   **genesis manifest version's** cadence, since no earlier version exists to govern it. The
   corpus's **genesis checkpoint** (the checkpoint whose `tree_size` equals the genesis
   manifest's entry index plus one) **need not have been published and is not a start point**:
   an operator may first publish at a larger `tree_size`, so a rule anchored on it would name a
   checkpoint that need never exist (core spec §7.3).

   The epoch is not free-floating either. The **earliest checkpoint committing the genesis
   manifest** MUST carry a `checkpoint_time` that is **at or after `cadence_epoch`, and no later
   than `cadence_epoch` plus the genesis version's `checkpoint_cadence`**. An epoch earlier than
   that window would reach back over an interval in which the corpus did not exist, letting a
   deployment claim series coverage of time it was not operating; an epoch later than the window
   would leave the corpus's opening interval ungoverned by any cadence. A deployment whose
   earliest genesis-committing checkpoint falls outside the window has a malformed manifest, and
   a verifier MUST reject it rather than adjusting the epoch to fit.

   **Completeness below the earliest published member is not provable and MUST NOT be assumed** —
   no conclusion about entries committed before the first published member follows from the
   series, however long and well-formed the rest of it is.
4. **Authenticated, and usable.** Every member carries the log signature of §6.5, verifiable
   against the manifest version active for that member's `tree_size` (§7.4), and every member
   counted toward the series is **series-usable** in the sense of §6.6. An authenticated member
   that is not yet series-usable MAY be retained, MUST be reported as such, and MUST NOT be
   counted toward the series (core spec §7.3).
5. **Published and enumerable** to any party able to verify the corpus, from the log or from an
   independent mirror outside producer control, on the same terms as §10.3 — so that the series
   a verifier evaluates is the series everyone else evaluates.
6. **Append-only in publication.** A checkpoint once published in the series is never withdrawn
   or replaced, and members are ordered as in item 2.

**Equivocation ends the series.** Two authenticated members sharing a `tree_size` with differing
`root_hash` values are **equivocation, not a tie** — no append-only tree has two roots at one
size, so the log has shown two histories. The consequence is a boundary, and it is normative
(core spec §7.3):

- From the **lowest `tree_size` at which divergence occurs**, the series is **no longer
  canonical**. No incorporation bound (§5.2.1), no enumeration response (§10.3) and no series
  completeness finding may be grounded at or beyond that point.
- **Members below the divergence remain usable.** The boundary truncates the series; it does not
  invalidate the history that preceded it, and material already grounded below the boundary
  stands.
- A party serving series-dependent material **MUST report the divergence** rather than choosing
  a branch. Neither branch is "the" series: picking one — by preferring the later
  `checkpoint_time`, the larger tree, the first seen, the locally cached copy, or any other
  tie-break — silently converts a detected fault into an answer the recipient cannot tell apart
  from a sound one.
- **Detecting equivocation and then continuing to serve one branch is a conformance violation**,
  not a degraded mode.

The boundary binds **every response derived from the series, not only the three interfaces named
above**. Any code path that reads the series and returns something shaped by it inherits the
rule — in particular a **single-checkpoint lookup**, which is the easiest place to get this
wrong: a lookup that resolves "the checkpoint at `tree_size` n" with an ordinary tie-break will
quietly return one branch of a divergence and report success. Such a lookup MUST detect the
divergence and report it in the same way as the bulk interfaces. An implementer auditing against
this profile should enumerate every path from the series to a response and check each one, rather
than checking the three named interfaces and assuming the rest are unaffected.

Divergence is also detected in a different state from the other series checks; see §6.6.1.

**What consistency proofs contribute, and what they do not.** A consistency proof between two
members establishes that the later tree is an append-only extension of the earlier one. It does
**not** establish that a checkpoint the cadence required was ever published: an omitted
checkpoint leaves no trace in the proofs between its neighbours, so omission is invisible to
consistency checking (core spec §7.3). An earlier revision of this profile leaned on pairwise
consistency for gap-freeness; that was wrong, and this section replaces it.

Completeness therefore rests on two things, neither of them a proof about a pair of
checkpoints: the **cadence rule** of item 1, which says what must have been published, and the
**publication obligation** of core spec §3.5, which says it must be reachable outside producer
control. What a verifier can establish is that the members it holds are cadence-conforming,
monotone, authenticated, series-usable and continuous under consistency — and that no required
member is missing **from the set it was given**. "The series is complete" is therefore an
**operational finding about the deployment, not a cryptographic proof** and not a receipt
result in the sense of I-D §7.7 (§1.1), and it MUST be reported in those terms. A verifier MUST
NOT report completeness as proven, MUST NOT render the finding in the `verified` / `invalid` /
`unverifiable` vocabulary, and MUST NOT infer from a well-formed series that the operator
published everything it was obliged to publish.

Given a canonical series, the selection rule of §5.2.1 is a pure function of the entry index and
the series, so every party computes the same `ITUB(i)` for the same entry. Two parties
disagreeing about `ITUB(i)` is then itself a finding: it means they were shown different series,
which is the equivocation the witness protocol exists to detect (§11).

Where a deployment does not publish such a series, `ITUB` is **undefined** under this profile,
and a verifier MUST report the entry's incorporation time as **unavailable** rather than
substituting a locally derived value. That report is an operational finding about the deployment
(§1.1), not a result over a receipt: no claim type of I-D §7.2 asserts an incorporation time, so
no I-D §7.7 label attaches to it. It is also not a denial that the entry was incorporated.

#### 5.2.3 Consequence for propagation windows

Core spec §5.2 measures the L3 propagation window from the trigger's LIT. Because this profile
supplies no LIT, a deployment claiming L3 on ATL MUST publish the canonical checkpoint series
of §5.2.2 and MUST declare in its manifest that propagation windows are measured from
`ITUB(trigger index)` under this profile. Without the series the window has no determinable
start, and a propagation-window conformance claim cannot be evaluated — by the producer, by a
verifier, or by a regulator reading the manifest. This is a deployment obligation (§16), not an
optional refinement.

**Open, and not resolvable inside this profile.** A profile cannot except itself from the core
contract, and this substitution does exactly that: core §3 item 1 requires a per-entry LIT and
§15 records the requirement as UNSATISFIED here. Two further problems were identified and are
recorded rather than patched — measuring the window from an **upper** bound starts it *later*
than true incorporation, so it grants the producer additional time rather than none, and the
compliance annex (core §8, I-D Appendix D) cites LIT as an attested event timeline in mappings
that would be false for an `ITUB`-only deployment. Resolving this requires a decision in the
core contract, not here: either the core widens item 1 with a bound derived in the conservative
direction, or this profile states that L3 is unavailable on ATL. Until then an L3 claim on ATL
rests on a substitution the core does not authorize.

The obligation stated in the first paragraph is therefore **conditional**: it says what a
deployment MUST do *if* it claims L3 on ATL, while the L3 claim itself rests on a core decision
that has not been taken. A deployment MAY publish the series and make the declaration — both are
worth doing whichever way the core decides — but MUST NOT read either as establishing that the
propagation-window requirement of core §5.2 has been met. §15 item 1 and §16 obligation 4 carry
the same caveat, and §17 records the question as open.

## 6. Checkpoints

### 6.1 ATL binary form

An ATL checkpoint is signed as a fixed 98-byte blob (ATL protocol §4.1, `atl-core`
`core/checkpoint.rs`):

| offset | size | field | encoding |
| --- | --- | --- | --- |
| 0 | 18 | magic | ASCII `ATL-Protocol-v1-CP` |
| 18 | 32 | Origin ID | raw SHA-256 of the Tree UUID |
| 50 | 8 | tree size | u64 **little-endian** |
| 58 | 8 | timestamp | u64 little-endian, Unix **nanoseconds** |
| 66 | 32 | root hash | raw SHA-256 Merkle root |

The Ed25519 signature is over these 98 bytes and is carried outside the blob.

### 6.2 Mapping to the AHL checkpoint object

The AHL checkpoint object — the committed state `{log_id, tree_size, root_hash,
checkpoint_time}` of core spec §1.2 and I-D §1.5, in the receipt-borne superset form of I-D
§7.1, which adds `key_id` and `signature` and MAY add `raw` (§6.4) — maps field by field:

| AHL field | ATL source | rule |
| --- | --- | --- |
| `log_id` | Origin ID | `"sha256:" || hex(origin)`; MUST equal `log_id` in the manifest version active for this checkpoint's `tree_size` |
| `tree_size` | tree size | identical u64 value |
| `root_hash` | root hash | `"sha256:" || hex(root)` |
| `checkpoint_time` | timestamp | RFC 3339 rendering of the nanosecond value, per §6.3 |
| `key_id` | signing key | `"sha256:" || hex(SHA-256(raw 32-byte Ed25519 public key))` (§7.2) |
| `signature` | signature | `"base64:" || base64(raw 64-byte Ed25519 signature over the 98-byte blob)` |

A checkpoint commits exactly the entries with index in `[0, tree_size)`.

### 6.3 Time rendering, and why it is normative

`checkpoint_time` MUST be the UTC rendering of the ATL nanosecond timestamp with **exactly nine
fractional digits** and the `Z` suffix:

```
1767225600123456789  ->  "2026-01-01T00:00:00.123456789Z"
```

This is not cosmetic. A verifier reconstructs the 98-byte blob from the parsed AHL checkpoint
object in order to verify the log signature, and the blob contains the exact nanosecond value.
Any rendering that loses precision — millisecond truncation, dropping trailing zeros —
reconstructs different bytes, and the log signature will not verify over them. Producers MUST
render exactly as specified; verifiers MUST parse the nine fractional digits back to the exact
u64 nanosecond value and MUST reject a `checkpoint_time` that is not in this form.

### 6.4 `checkpoint.raw`

This profile **defines** a binary checkpoint framing, so receipts under it MAY carry
`anchoring.checkpoint.raw`.

- `raw` is `"base64:" || base64(the 98 bytes of §6.1)`.
- I-D §7.1 and §7.5 step 2 fix the precedence: where `raw` is carried it MUST parse to the same
  values as the JSON members, the **JSON members govern** the comparison, and a mismatch is
  `invalid`. Concretely, a verifier that finds `raw` present MUST parse it and MUST reject the
  receipt unless the magic is exactly `ATL-Protocol-v1-CP` and all four carried values — origin,
  tree size, timestamp, root hash — equal the corresponding members of the parsed checkpoint
  object under the mappings of §6.2 and §6.3.
- `raw` is a convenience, not a trust step: a verifier that reconstructs the blob from the
  parsed object per §6.5 obtains the same bytes.

### 6.5 Verifying a checkpoint signature

1. Recover the raw 32-byte origin from `log_id`, the u64 `tree_size`, the u64 nanosecond
   timestamp from `checkpoint_time` (§6.3), and the raw 32-byte root from `root_hash`.
2. Assemble the 98-byte blob in the layout of §6.1, little-endian integers.
3. If `raw` is present, compare it byte for byte with the assembled blob; a mismatch is a
   rejection.
4. Resolve the signing key by `key_id` against the manifest version active for this
   checkpoint's `tree_size` (§7.4), recomputing the key id from the carried public key rather
   than trusting the carried value.
5. Verify the Ed25519 signature over the 98 bytes.

Completing these five steps makes the checkpoint **authenticated**, and no more than that
(§6.6).

### 6.6 Verification states: authenticated and series-usable

Core spec §7.3 makes two states normative, and this profile carries them unchanged because the
distinction is where a plausible ATL implementation goes wrong.

- A checkpoint is **authenticated** when its log signature verifies under the key set resolved
  from the governing manifest version (§6.5, §7.4). Authentication establishes that the log
  signed those field values. It establishes nothing about whether the tree they describe is the
  tree the verifier has entries for.
- A checkpoint becomes **series-usable** when, in addition:
  1. its `root_hash` has been **recomputed** from the entries held for its `tree_size` — by the
     tree rules of §8.1 over the ATL leaf construction of §4.2, whether from a full enumeration
     of `[0, tree_size)` (§10) or from held entry bytes covering that range — and matches; and
  2. its **consistency relationship with its preceding member** in the canonical series verifies
     (§8.3), and, where a following member exists, consistency to that member verifies as well.
     The newest member of a series is therefore series-usable on its predecessor relationship
     alone, and acquires the second relationship when a successor is published (core spec §7.3).

The entries used for root recomputation MAY come from **any source** — the log, a mirror, a
counterparty, local archive. Each is content-addressed and MUST verify against its own entry id
(§10.1.1), so the provenance of a copy is immaterial to correctness; what matters is that the
bytes hash correctly and that the recomputed root matches.

#### 6.6.1 Which state each series check runs in

The two series checks of §5.2.2 deliberately run in **different** states, and an implementation
that applies one scope to both will be wrong in one direction or the other (core spec §7.3).

| check | runs over | rationale |
| --- | --- | --- |
| **start window** — the earliest checkpoint committing the genesis manifest falls within `[cadence_epoch, cadence_epoch + genesis cadence]` (§5.2.2 item 3) | **series-usable members only** | Whether a range may open is a conclusion about the log's actual contents. An authenticated-but-unverified checkpoint carries a *claimed* time over a tree nobody has recomputed; letting that claim decide the start would let an operator open a range with an assertion instead of evidence |
| **divergence** — two members at one `tree_size` with differing `root_hash` (equivocation block, §5.2.2) | **every authenticated member** | Divergence is visible from checkpoint metadata alone: two signed checkpoints, one size, two roots. Neither member need be series-usable, and requiring usability first would let a deployment defer detection indefinitely by never recomputing the branch it dislikes |

Stated the other way round: **authentication is enough to condemn, but not enough to certify.**
A checkpoint the verifier cannot yet recompute still counts as evidence that the log equivocated;
it does not count as evidence that anything is sound.

**Only series-usable checkpoints may ground an incorporation-time bound (§5.2), an enumeration
response (§10.3), or a series completeness finding (§5.2.2).** An authenticated checkpoint that
is not yet series-usable MAY be retained and MUST be reported as authenticated-only; it MUST NOT
be counted toward the canonical series, MUST NOT be used to select `ITUB`, and MUST NOT be
presented as the checkpoint under which a range was enumerated.

The practical consequence for an ATL deployment: a signed 98-byte checkpoint obtained from the
log is *authenticated the moment its signature verifies*, and that is the state most naive
implementations stop at. Promoting it to series-usable requires entry material — which under
this profile means the enumeration interface of §10.3 or the byte-serving retrieval of §10.1.1,
neither of which stock ATL provides (§15). A deployment that cannot recompute roots therefore
holds authenticated checkpoints only, and every quantity in the list above is unavailable to it.
That is an operational finding about the deployment and MUST be reported as one (§1.1); it is
not a denial that the tree held what the checkpoint says it held.

**Series-usability is not a receipt-result prerequisite, and this profile does not make it one.**
The state is defined over a member of the **canonical checkpoint series** (§5.2.2), which is a
deployment publication: item 2 above asks for the member's consistency relationships with its
neighbours *in that series*. **I-D §7.2 imposes no series-usability requirement on any claim
type**, conditioning them instead on the enumerated material the receipt itself carries (I-D
§7.2, §7.4). A profile that added one would be adding a receipt-verification rule the
controlling document does not have, which is not an adaptor's to add. Accordingly:

- This profile adds **no** series-usability precondition to any claim type of I-D §7.2, and a
  verifier MUST NOT withhold or downgrade a receipt result on the ground that a checkpoint is
  authenticated-only.
- Where a claim type requires enumerated material and the receipt does not carry it, that is
  settled entirely by I-D §7.2 and §7.4: material the receipt is REQUIRED to carry and does not
  is `invalid` (§1.1). Series-usability does not enter.
- §8.4 is **not** an exception to this. What it describes is the I-D §7.2 requirement that a
  `propagation-complete` receipt authenticate its declared checkpoint D by a D→A consistency
  proof or by prefix-root recomputation. That is a requirement about material the receipt
  carries, and it is not a series-usability test; §8.4 says so in its own terms.
- The requirements of this section bind **this profile's own interfaces and findings** — which
  checkpoints may ground `ITUB` (§5.2.1), an enumeration response (§10.3) and a series
  completeness finding (§5.2.2) — and those are operational findings, reported in their own
  terms with no I-D §7.7 label (§1.1).

## 7. Keys and identity

### 7.1 `log_id`

`log_id` = `"sha256:" || hex(Origin ID)`, where the Origin ID is ATL's SHA-256 over the
16-byte Data Tree UUID. A verifier never needs the UUID itself: the Origin ID is what the
checkpoint blob binds and what the manifest pins.

### 7.2 Key ids and encodings

- **Public key encoding**: `"base64:<raw 32-byte Ed25519 public key>"`. No SPKI, no PEM.
- **Key id**: `"sha256:<hex of SHA-256 over the raw 32-byte public key>"`. This matches ATL's
  own `key_id` derivation (`atl-core` `compute_key_id`) and the producer-key rule of core spec
  §2.3.6, which leaves log and witness key-id derivation adaptor-defined; this profile adopts
  the identical rule for all three.
- **Signature encoding**: `"base64:<raw 64-byte Ed25519 signature>"`.
- A verifier MUST recompute a key id from the public key it is given and MUST reject a
  mismatch.

### 7.3 The manifest `log` object

Core spec §7.3 fixes the schema of the manifest's `log` object. It is **not** deployment-defined
and this profile does not extend it; what follows states how each member is populated for an ATL
binding.

```json
{ "log_id": "sha256:<hex>",
  "operator": "<operator id>",
  "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:<hex>" },
  "checkpoint_cadence": "PT1H",
  "cadence_epoch": "2026-08-17T00:00:00Z",
  "witness_grace_period": "PT15M",
  "keys": [ { "key_id": "sha256:<hex>", "pubkey": "base64:<...>", "valid_from_index": 0 } ] }
```

**Every member is REQUIRED.** A manifest version whose `log` object omits any of them is
malformed, and a verifier MUST reject it rather than supplying a default.

| member | value under this profile |
| --- | --- |
| `log_id` | the family string of §7.1, derived from the bound Data Tree's ATL Origin ID |
| `operator` | the identifier of the party operating the ATL instance |
| `adaptor` | `{ "id": "ahl-adaptor-atl-v1", "hash": <the profile digest of §14> }` |
| `checkpoint_cadence` | ISO 8601 duration, **time components only** (§7.3.1); the **maximum** gap between adjacent members of the canonical series (§5.2.2 item 1), not a target or an average |
| `cadence_epoch` | RFC 3339; the instant from which the corpus's cadence obligation runs. **Declared once by the genesis manifest and immutable thereafter** (§7.3.2) |
| `witness_grace_period` | ISO 8601 duration, **time components only** (§7.3.1); staleness threshold for witness cosignatures (§11.3) |
| `keys` | ATL checkpoint-signing key objects, `pubkey` as the raw 32-byte Ed25519 key per §7.2 |

#### 7.3.1 Duration syntax is restricted

`checkpoint_cadence` and `witness_grace_period` are ISO 8601 durations limited to **time
components** — days, hours, minutes and seconds, of the form `P[n]DT[n]H[n]M[n]S`. Examples:
`PT1H`, `PT15M`, `P1D`, `PT30S`.

**Years and calendar months are PROHIBITED in these fields.** Their length is
context-dependent — a month is 28 to 31 days, a year 365 or 366 — so admitting them would make
cadence, series completeness and incorporation bounds depend on which calendar arithmetic an
implementation happens to use, and two conforming verifiers could reach different findings on
the same series. A value carrying `Y`, or `M` in the **date** part, is **malformed and MUST be
rejected, never approximated** to some number of days (core spec §7.3). Note that `M` after the
`T` is minutes and is permitted: `PT5M` is five minutes and is valid; `P5M` is five months and
is not.

A verifier MUST reject a manifest version whose `log` object carries such a value rather than
accepting the version and flagging the field, since every downstream judgement about the series
depends on the duration being exact.

**Fractional seconds are bounded, and cadence is positive.** A duration MAY carry fractional
seconds with **at most nine digits** — matching the nanosecond precision of the ATL checkpoint
timestamp (§6.1) and of the `checkpoint_time` rendering of §6.3. A value with more digits is
**malformed and MUST be rejected, never truncated or rounded**: truncation would make the value
implementation-dependent in exactly the way the component restriction above exists to prevent,
with two verifiers disagreeing about whether a gap conformed. Separately, `checkpoint_cadence`
MUST be **greater than zero**; a zero or negative cadence states an obligation no series can
satisfy and is malformed (core spec §7.3).

**Comparison is by normalized value, not by spelling** (core spec §7.3). `PT60M` and `PT1H` are
the same cadence, as are `PT86400S`, `PT24H` and `P1D`. An implementation MUST normalize before
comparing — when checking a gap against the declared cadence, when deciding whether a later
manifest version changed the cadence, and when reporting a change — and MUST NOT treat a
respelling as a change or a change as a respelling. Because years and calendar months are
excluded, every permitted duration normalizes to an exact number of seconds, so normalization is
well defined and no calendar arithmetic is involved.

#### 7.3.2 The epoch is declared once and never moves

`cadence_epoch` is declared by the **genesis manifest** and MUST be **repeated unchanged by
every later manifest version**. It anchors the start of the corpus's checkpoint series and does
not move; a later version whose `cadence_epoch` differs from the genesis value is **malformed**,
and a verifier MUST reject it rather than adopting the new value or treating the change as a
re-anchoring.

"Unchanged" means **by value**, not by spelling (core spec §7.3): a later version repeats the
same RFC 3339 instant, and a different textual rendering of that instant — a different offset
form such as `+00:00` for `Z`, or added trailing zeros in the fractional part — is a repetition,
not a change. A rendering that denotes a **different instant** is a change and therefore
malformed. Deployments SHOULD nonetheless repeat the genesis spelling byte for byte, so that the
question does not arise in review.

The epoch is further constrained relative to the corpus's first checkpoint: see §5.2.2 item 3,
which fixes the window the earliest genesis-committing checkpoint must fall in.

What a later version MAY change is `checkpoint_cadence`, and only prospectively: the new value
governs from that version's own entry index forward, and earlier ranges continue to be judged by
the cadence in force when they began (§5.2.2 item 1). A deployment that changes its ATL
anchoring period MUST therefore anchor a new manifest version declaring the new
`checkpoint_cadence` while repeating `cadence_epoch` verbatim; changing the operational period
without anchoring such a version is a cadence violation from the first gap that exceeds the
still-declared value.

The asymmetry is deliberate: a movable epoch would let an operator re-anchor the series after
the fact and erase an interval it failed to cover, whereas a prospectively changeable cadence
only ever binds the operator going forward.

### 7.4 Manifest key objects, rotation, and governance authorization

Log checkpoint-signing keys appear as the `keys` array of the `log` object above; witness keys
appear in the same object form under `witnesses` (core spec §7.2).

Per I-D §7.1, a log or witness key MUST bind to the manifest version **active for
the checkpoint being verified** — the manifest statement with the greatest entry index smaller
than that checkpoint's `tree_size` — and each manifest version's log and witness key objects
replace the prior set in full. A key retired by a later manifest version MUST NOT validate a
checkpoint issued under that later state. I-D §7.6 applies the same binding to
`later_checkpoint` and its cosignatures, and to both checkpoints of a `propagation-complete`
receipt, where byte equality between the two is never a substitute for validating both. I-D §7.1
states exactly one exception to this binding, confined to `governance.rotation_proofs[]`
material: a rotation-proof checkpoint's log and witness keys bind to the manifest version active
immediately BEFORE the rotating manifest's entry index — the outgoing state — and the exception
never reaches `anchoring.checkpoint` or `later_checkpoint`.

ATL supports key rotation through the checkpoint `key_id` field; under AHL the authoritative
statement of which key was valid when is the manifest chain, not the log. Where the two
disagree, the manifest governs and the checkpoint is rejected.

#### 7.4.1 Governance statements are not self-authorizing

This is stated explicitly because an implementation built from this profile alone could
otherwise resolve keys from any anchored entry whose payload says `"type": "manifest"`. It MUST
NOT. Under core spec §7.3, an anchored `manifest` or `key` statement counts as governance —
and may therefore contribute to the key set a verifier resolves — only if **all** of the
following hold:

1. it is anchored in the bound Data Tree at a known entry index, proven by inclusion under a
   checkpoint (§8.2);
2. its **producer signature verifies** under the key set in force at **its own entry index**,
   by the envelope signature rule of I-D §2.1 restated in §7.5 — every signature entry
   resolving to an active key and verifying;
3. for a **non-genesis manifest**, its `predecessor` member links by entry id to the manifest
   version **active immediately before it** — not merely to some earlier manifest in the log;
4. for the **genesis manifest**, its entry id matches the verifier's locally configured trust
   anchor, which is never taken from the log, and — where local policy holds initial key
   fingerprints, which is optional — those match the ones the genesis manifest declares
   (I-D §2.4.5, §7.5.1 4a);
5. for a manifest version whose **log checkpoint-signing key objects or witness key objects
   differ from its predecessor's** in the chain — a governance-key rotation — its own anchoring
   is proven under the OUTGOING states by the receipt's `governance.rotation_proofs[]` element
   for it, per the element requirements of I-D §7.1 and the rotation-anchoring rule of
   I-D §7.5.1 4b(M); a manifest signature alone establishes neither set.

Anchoring proves that bytes existed at a position in the tree. It never makes an unverified
governance statement effective. Concretely, a party able to submit entries to the ATL instance —
which, on a deployment without submission controls, may be anyone who can reach the endpoint —
can place a well-formed object claiming to be a manifest into the log at a real index with a real
inclusion proof. Such an entry fails test 2, test 3, or, for a governance-key rotation, test 5, and MUST be ignored for key resolution; it
is not a fork of the corpus and does not need to be reconciled with the real chain. A verifier
that resolved keys from it would accept checkpoints and statements signed by keys the corpus
never adopted.

### 7.5 Producer keys

Producer keys are core-level (core spec §2.3.6) and are not ATL material. The envelope
signature rule is I-D §2.1: every entry in `signatures` MUST resolve to a key active at
the envelope's entry index and MUST verify; an envelope with a non-verifying entry is invalid
regardless of how many other entries verify. Trigger authorization is the separate later test
of core spec §2.3.3 — at least one verified signer in the authority key set active at the
trigger's entry index, with co-signature by other active producer keys permitted. This profile
changes neither rule and restates them only so that a verifier implemented from this document
alone is complete.

## 8. Inclusion and consistency proofs

### 8.1 Tree geometry

The bound Data Tree is an RFC 6962 binary Merkle tree over SHA-256, with ATL leaf construction
(§4.2) and the standard node rule:

```
node_hash(l, r) = SHA-256( 0x01 || l || r )
```

The root over `n > 1` leaf hashes splits at `k`, the largest power of two strictly less than
`n`: `root = node_hash(root(leaves[0..k]), root(leaves[k..n]))`. A one-leaf tree's root is its
leaf hash. The empty-tree root is `SHA-256` of the empty string; it does not occur in a corpus,
since a corpus always contains at least its genesis manifest.

### 8.2 Inclusion proofs

An inclusion proof is a list of sibling hashes ordered **leaf to root**, serialized as a JSON
array of `"sha256:<hex>"` family strings. In an Evidence Receipt the array appears bare, and
the index and tree size come from siblings:

| bare path | leaf index carried as | tree size taken from |
| --- | --- | --- |
| `anchoring.inclusion_path` | `subject.entry_index` | `anchoring.checkpoint.tree_size` |
| `governance.chain[].inclusion_path` | `governance.chain[].entry_index` | `anchoring.checkpoint.tree_size` |
| `claim_material.leaf_path` | `claim_material.leaf_index` | `outputs_count` / `affected_count` of the subject payload |
| `claim_material.input_members[].input_path` | `claim_material.input_members[].input_index` | `input_set_count` of the leaf's `inputs` |

Verification is the RFC 6962 recomputation of the root from the leaf hash and the path,
compared against the anchored root. For the log tree the leaf hash is the §4.2 construction;
for the trees of §9 it is `SHA-256(0x00 || JCS(leaf object))`.

### 8.3 Consistency proofs

Consistency proofs are RFC 9162 §2.1.4 proofs between two tree sizes of the **same** Origin ID,
serialized as a JSON array of `"sha256:<hex>"` family strings in the order produced by the
RFC 9162 algorithm. They appear in a receipt as `anchoring.consistency_path`, paired with
`anchoring.later_checkpoint`; `assurance.continued_history` is true if and only if both are
present and verify (I-D §7.6).

`atl-core` implements generation and verification of these proofs
(`core/merkle/consistency.rs`), so the algorithm is available to any implementer. Two honest
qualifications:

1. ATL's own Evidence Receipt carries a per-Data-Tree `consistency_proof` field that the ATL
   implementation marks as vestigial and slates for removal, because ATL's own global
   consistency story runs through the Super-Tree instead. AHL does not use ATL receipts and is
   unaffected in its data model: AHL carries consistency material in its own receipt fields.
   What is affected is retrieval — see 2.
2. The published `atl-server` HTTP surface exposes no route that serves a consistency proof
   (§10.1). A deployment MUST therefore supply consistency proofs through the interface of
   §10.3 or an equivalent published endpoint, or AHL receipts under this profile will be
   limited to `continued_history: false`.

### 8.4 Authenticating an earlier checkpoint without a consistency proof

I-D §7.2 permits a `propagation-complete` receipt to authenticate its declared
checkpoint D either by a consistency proof from D to `anchoring.checkpoint`, or by recomputing
D's prefix root from the enumerated prefix. Both paths are available under this profile. The
second requires no additional log capability beyond §10 and is verified as:

1. verify D's log signature (§6.5) against a key declared by the manifest version active for
   **D's** `tree_size`, which may be an earlier manifest version than the one active for the
   receipt's checkpoint A;
2. verify the enumerated prefix covering `[0, tree_size(D))` against **A's** root at A's
   `tree_size` (§10.4);
3. recompute the root of those `tree_size(D)` leaf hashes by §8.1 and compare it with D's
   `root_hash`.

Steps 2 and 3 establish that D is exactly the size-`tree_size(D)` prefix of A, which is what a
consistency proof D→A asserts. That is the whole of what I-D §7.2 asks for, and it is a
requirement about **material the receipt carries**, not a series-usability test: A need not be
D's neighbour in the canonical series, and published members may lie between them, so nothing
here promotes D to series-usable in the sense of §6.6. A `propagation-complete` receipt whose D
carries a valid log signature but neither a D→A consistency proof nor an enumerated prefix does
not carry the material I-D §7.2 requires; the result is `invalid` because required material is
absent (§1.1), and not on any ground drawn from the series.

## 9. AHL trees other than the log tree

Batch output trees, input-set trees and disposition trees (core spec §2.5) are AHL constructs,
not ATL constructs. ATL never sees them; it sees only the entries that commit their roots.
Their rules are therefore the core rules, restated here so this document is self-contained:

- leaf bytes are `JCS(leaf object)`; `leaf_hash(b) = SHA-256(0x00 || b)`;
  `node_hash(l, r) = SHA-256(0x01 || l || r)`; same splitting rule as §8.1;
- leaves are sorted by the leaf's `record` value, compared as the ascending lexicographic order
  of the UTF-8 bytes of the canonical commitment string, and duplicates are prohibited;
- a `record` value that is not a canonical commitment string invalidates the tree rather than
  being ordered by a fallback rule;
- batch output leaves use `leaf_format` `ahl-leaf-v2`:
  `{ "dataset", "record", "inputs" }`, where `inputs` is either the full array of derivation
  input objects or the wide-input form `{ "input_set_root", "input_set_count" }`;
- input-set leaves are full derivation input objects; disposition leaves are core spec §2.3.4
  objects.

Note the deliberate asymmetry: the **log** tree uses ATL leaf construction (§4.2), because ATL
builds it; these trees use plain leaf hashing, because AHL builds them. An implementation MUST
NOT apply the payload/metadata leaf construction to them.

**Availability.** The complete leaf material of every committed tree is corpus material under
core spec §3.5 and MUST be published to the log or an independent mirror outside producer
control for L3. ATL stores opaque payload bytes and is capable of carrying that material as
ordinary entries; this profile does not mandate a particular carriage, but a deployment
claiming L3 MUST declare in its manifest where committed tree material is published and MUST
ensure it is retrievable and enumerable with authenticated binding to the anchored root.

## 10. Authenticated range enumeration

### 10.1 What the published ATL server exposes today

Core spec §3 contract item 5 requires the log to serve entries `[i, j)` under a checkpoint with
proof of completeness and order, and I-D §7.4 carries that proof as
`range_proof.adaptor_form` in the enumeration material form.

The published `atl-server` HTTP router exposes exactly three routes:

| route | method | purpose |
| --- | --- | --- |
| `/v1/anchor` | POST | submit an entry |
| `/v1/anchor/:id` | GET | retrieve the ATL Evidence Receipt for an entry, by ATL entry id |
| `/health` | GET | liveness, in NODE and SEQUENCER modes only |

**There is no range-enumeration endpoint, no entries-by-index endpoint, no tree-head or
checkpoint endpoint, no consistency-proof endpoint and no public-key endpoint on that
surface.** Operations resembling some of these exist on the server's internal sequencer client
interface, which is inter-node machinery and not a published verifier-facing API.

Two consequences, stated plainly rather than papered over:

1. **A stock `atl-server` deployment does not satisfy contract item 5.** An AHL corpus at L3
   requires the interface of §10.3 to be added, either by the log operator or by an independent
   mirror outside producer control as core spec §3.5 requires. A corpus that does not have it
   cannot support `governance: "enumerated"`, and therefore cannot support the
   `trigger-effective`, `disposition-effective`, `propagation-complete` or `governance-state`
   claim types, which require enumerated material.
2. **Retrieval by entry id (contract item 4) requires a byte-serving interface that stock ATL
   does not provide.** The obligation is specified in §10.1.1; an identifier mapping alone does
   not discharge it.

#### 10.1.1 Retrieval by AHL entry id

Contract item 4 requires retrieval of an entry by its entry id. AHL's retrieval key is the AHL
entry id, `SHA-256(JCS(envelope))`, and what must come back is the **entry bytes themselves**:
`JCS(envelope)`. Every downstream operation needs those bytes — recomputing the statement id and
entry id, verifying producer signatures over `JCS(payload)`, recomputing the log leaf hash of
§4.2, and traversing the statement graph.

An identifier mapping cannot discharge this obligation. ATL's Evidence Receipt carries an entry
identifier, a payload hash, a metadata hash, the metadata object and a proof — it does **not**
carry the submitted payload bytes. Resolving an AHL entry id to an ATL identifier and fetching
the ATL receipt therefore yields a digest of the envelope and no envelope: enough to confirm a
guess, never enough to obtain the entry. Stock ATL consequently does not satisfy contract item
4 for AHL purposes, and a deployment MUST add byte-serving retrieval.

**Required response semantics.** Given a requested AHL entry id, a conforming deployment MUST
return either exactly one entry or an explicit absence:

- **Present.** The response carries the entry bytes `JCS(envelope)` — either as raw bytes with
  media type `application/json`, or, where the transport requires a text field, as
  a `base64:` family string of those bytes, in the encoding I-D §2.1 fixes for that family (§2).
  The response is a profile-defined interface rather than a receipt member, but the family string
  is the same one, so the same encoding and the same strict acceptance apply. The bytes MUST be
  returned unaltered: no re-serialization, no whitespace insertion, no member reordering, no
  Unicode normalization, no BOM. The response MAY
  additionally carry the entry index and an inclusion proof under a named checkpoint; where it
  does, both are subject to §8.2, and a verifier MUST NOT accept an entry index that is not
  confirmed by a proof.
- **Absent.** The response states unambiguously that the deployment holds no entry with that id.
  Absence is a fact about the interface, not about the corpus: it MUST NOT be read as evidence
  that no such entry was ever anchored. A verifier treats it as unavailability, and — where the
  entry id was obtained from anchored material that references it — as a finding against the
  deployment's §3.5 availability obligation, not as a negative result.

**Verifier duties on receipt of bytes.** A verifier MUST, before using the returned bytes for
anything:

1. Recompute `SHA-256(bytes)` and reject unless it equals the requested AHL entry id. This makes
   retrieval self-checking: a deployment cannot substitute a different entry, and the bytes need
   not be trusted merely because of their source.
2. Reject unless the bytes parse as a JCS-canonical AHL envelope (I-D §2.1) and
   re-serializing the parsed structure reproduces them byte for byte.
3. Where the entry is presented as an entry of the bound Data Tree, reject unless its ATL
   metadata is exactly the fixed adaptor metadata object of §4.2 — the 36-byte JCS form of
   `{"ahl_adaptor":"ahl-adaptor-atl-v1"}`, digest
   `sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4`. An entry carrying
   any other metadata is a valid ATL entry but is not an AHL entry under this profile, and its
   leaf hash (§4.2) will not reconstruct from the envelope alone.

**How a deployment satisfies it.** Any interface meeting the semantics above is acceptable: a
byte-serving HTTP endpoint keyed by AHL entry id operated by the log, a published static archive
of entry bytes addressed by entry id, or an independent mirror. For L3 the interface MUST be
outside producer control (core spec §3.5). Because the response is content-addressed and checked
by rule 1, a mirror needs no trust and no relationship with the log operator: any party holding
the bytes can serve them. Note that a deployment implementing the enumeration interface of §10.3
over the full index range already holds and serves every entry's bytes, and can satisfy this
clause with an index over the same store.

### 10.2 What the range proof proves

Given a checkpoint `C` over the bound Data Tree with `N = tree_size(C)`, a range `[i, j)` with
`0 <= i < j <= N`, and an ordered list of `j - i` entry envelopes, the proof establishes that
the carried list is exactly and completely the leaf set of `[i, j)` under `C.root_hash`: no
gaps, no reordering, no omissions, no insertions.

### 10.3 Required interface

A conforming deployment MUST make available, to any party able to verify the corpus:

- **Request**: a range `[from_index, to_index)` and the tree size of the checkpoint the range
  is to be proven under.
- **Response**: the entry envelopes for that range, in ascending entry-index order, each with
  its entry index; a range proof as in §10.4; and the signed checkpoint the proof opens.
- **Guarantees**: completeness and order of the carried range under the named checkpoint, as
  §10.2 defines them, verifiable offline from the response alone.

The transport is not constrained: an HTTP endpoint on the log, a published static archive, or
an independent mirror all satisfy this profile, provided the response material is as above.
For L3 the material MUST be available outside producer control (core spec §3.5).

**Checkpoint state.** The checkpoint an enumeration response names MUST be **series-usable**
(§6.6), not merely authenticated: an enumeration is a statement about the contents of a tree,
and a checkpoint whose root has not been recomputed against held entries describes a tree the
verifier has not established it has. A response naming an authenticated-only checkpoint MUST be
reported as such and MUST NOT be treated as an enumeration of the corpus. A response covering
`[0, tree_size(C))` is itself the material that promotes C to series-usable, so the first full
enumeration under a checkpoint and that checkpoint's promotion are one operation (§6.6 item 1).

The response material is carried in receipts using the inline enumeration form of I-D §7.4,
reproduced here with this profile's `adaptor_form` filled in:

```json
{ "range": { "from_index": 0, "to_index": 1450 },
  "entries": [ { "entry_index": 57, "envelope": { ... } } ],
  "range_proof": { "adaptor_form": "base64:<§10.5 bytes>" } }
```

### 10.4 Proof construction and verification

The proof is the minimal set of RFC 6962 subtree hashes covering everything outside the range.
Over the standard decomposition of `[0, N)`:

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

Generation walks the same decomposition and emits the root hash of every maximal subtree
entirely outside `[i, j)`, so nodes are in left-to-right order.

The leaf hash of a carried entry is the §4.2 ATL construction —
`SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)` — not the plain leaf hashing of §9.

Verification:

1. Reject unless `0 <= i < j <= N`.
2. Reject unless exactly `j - i` envelopes were carried, with `entry_index` values
   `i, i+1, ..., j-1` in that order.
3. Compute the leaf hash of each carried envelope.
4. Run `recompute(0, N)`; reject if the node list is exhausted early.
5. Reject unless every proof node was consumed.
6. Accept if and only if `recompute(0, N)` equals `C.root_hash`.

Soundness: the recursion is a pure function of `(N, i, j)`, so the position at which each proof
node is consumed is fixed before any node is read, and a prover cannot choose where to spend a
node. Carried leaves are placed positionally, so any gap, reordering, omission or insertion
changes the recomputed root. Under collision resistance of SHA-256 only the true leaf set of
`[i, j)` opens the checkpoint root.

A range of width 1 is an inclusion proof in another serialization; a verifier MAY cross-check
it against §8.2.

### 10.5 Serialization

`range_proof.adaptor_form` is `"base64:" || base64(bytes)` with the layout below. All integers
are **big-endian**; there is no padding and no alignment.

| offset | size | field |
| --- | --- | --- |
| 0 | 6 | magic, ASCII `AHLRP1` |
| 6 | 8 | `tree_size` (u64) |
| 14 | 8 | `from_index` (u64) |
| 22 | 8 | `to_index` (u64) |
| 30 | 4 | `node_count` (u32) |
| 34 | 32 × `node_count` | subtree hashes, raw 32-byte SHA-256 values, in consumption order |

Total length is `34 + 32 * node_count`; any other length is a rejection. A proof whose
`tree_size`, `from_index` or `to_index` disagrees with the enclosing `range` object or with the
checkpoint is a rejection.

The byte layout is deliberately identical to the one used by the AHL conformance corpus, so a
single range-proof implementation serves both; the leaf hashing differs, because the log leaf
construction differs (§4.2).

### 10.6 No typed-subset proofs

This profile provides **no typed-subset proofs**: there is no ATL capability that proves "these
are all the manifest and key entries in this range" without carrying the range. The I-D §7.4
allowance to filter `entries` to manifest and key statements — which is conditioned on the
adaptor profile providing typed-subset proofs — is therefore NOT available under this profile,
and enumerated governance currency MUST carry the full entry range. That is the
honest cost until a typed governance sub-tree exists (core spec §10.9); ATL's Super-Tree is a
plausible substrate for one, but no such capability is specified or implemented today, and this
profile does not anticipate it.

## 11. Witness protocol binding

ATL as published has **no witness role**. Its trust model derives from external anchors —
RFC 3161 timestamp tokens and Bitcoin OpenTimestamps — rather than from independent cosigners,
and neither the protocol document nor the server exposes checkpoint cosigning.

AHL L3 requires at least one independent witness per log, operating the state machine of core
spec §3.3. Under this profile witnessing is therefore a **deployment obligation added
alongside** the log, not an ATL feature. This profile defines its wire form so that any party
can implement one.

### 11.1 Cosigned bytes

A witness cosigns the signed AHL checkpoint object, bound to its own identity so a cosignature
cannot be replayed for another witness:

```
cosignature = Ed25519( JCS( { "checkpoint": <signed AHL checkpoint object of §6.2, including
                                             its "signature" member>,
                              "witness_id": "<witness id>" } ) )
```

Binding the object that includes the log's signature means a cosignature attests to a
checkpoint the log actually signed, not merely to values a witness was shown.

In a receipt: `{ "witness_id", "key_id", "cosignature": "base64:<...>", "cosigned_at": "<RFC 3339>" }`.

`assurance.witnessed` is true only where at least one such cosignature verifies against a
witness key resolved per §7.4.

### 11.2 Refusal evidence

Core spec §3.3 step 3 requires a witness that observes a fault to refuse to cosign and to
publish signed refusal evidence containing both conflicting checkpoints. Under this profile:

```json
{ "type": "witness-refusal",
  "witness_id": "<id>",
  "log_id": "sha256:<hex>",
  "reason": "equivocation | size-regression | extension-failed",
  "retained": { ...signed checkpoint the witness had already cosigned... },
  "offered":  { ...signed checkpoint the witness refused... },
  "proof": { "from_size": 1450, "to_size": 1600, "path": [ "sha256:<hex>", ... ] },
  "detail": "<informative text; never normative>",
  "refused_at": "<RFC 3339>",
  "key_id": "sha256:<hex>",
  "signature": "base64:<...>" }
```

`retained` and `offered` are REQUIRED in **every** refusal, each a complete signed checkpoint
object of §6.2 including its `signature` member. `proof` is REQUIRED for `extension-failed` and
MUST be absent for the other two reasons: a carried proof that no reason directs a verifier to
check is unverified material inviting misreading. The witness signs `JCS(refusal object with the
"signature" member removed)`, the same rule as §6.2, so one signing routine serves both.

#### 11.2.1 Refusal reasons

Every reason is independently checkable from the evidence the refusal itself carries. A verifier
never has to consult the log, the producer, or the witness to decide whether a refusal is
supported.

| `reason` | emitted when | what a verifier rechecks from the carried evidence |
| --- | --- | --- |
| `equivocation` | the offered checkpoint shares a `tree_size` with a cosigned one and carries a different `root_hash` | `retained.tree_size == offered.tree_size` **and** `retained.root_hash != offered.root_hash`, both checkpoints carried and log-signed |
| `size-regression` | the offered `tree_size` is smaller than an already-cosigned size, and no history exists at the offered size | `offered.tree_size < retained.tree_size` over the two carried checkpoints |
| `extension-failed` | the offered checkpoint is larger and the consistency proof from the retained one to it fails verification | re-run RFC 9162 consistency verification over the **carried proof**, which the evidence MUST include, after checking its binding per §11.2.2 |

#### 11.2.2 The proof MUST be bound to the pair

For `extension-failed`, the carried proof MUST satisfy **both**:

```
proof.from_size == retained.tree_size
proof.to_size   == offered.tree_size
```

A verifier MUST check these equalities **before** running consistency verification, and MUST
reject the refusal as unsupported if either fails — whether or not the proof then verifies.

The reason this is normative rather than obvious: without the equalities, a structurally valid
proof that fails verification for some **unrelated pair of sizes** would validate a refusal about
*this* pair. The failure would be real and the refusal would still be baseless, and a verifier
checking only "does the carried proof fail?" would accept it. This was a defect in a first
implementation of refusal checking; it is cheap to prevent and invisible if not stated.

#### 11.2.3 What `extension-failed` does and does not mean

`extension-failed` means exactly: **the carried purported extension proof fails verification.**

It does **NOT** mean, and MUST NOT be described or rendered as, evidence that no valid extension
from `retained` to `offered` exists. A witness cannot establish that from one failing proof — the
proof it was given may have been malformed, truncated, generated against a different pair, or
simply wrong, while a correct proof for the same pair exists. A verifier MUST NOT read an
`extension-failed` refusal as showing that the log's history is inconsistent; it shows that what
the log offered did not verify. The stronger conclusion belongs to `equivocation`, which is
self-contained: two signed checkpoints, one `tree_size`, two roots, no possible append-only tree.

#### 11.2.4 `missing-consistency-proof` is removed, not renamed

An earlier revision of this profile defined `missing-consistency-proof`. It is **removed**, and
no reason replaces it. Absence of a proof is not independently verifiable from a signed refusal:
the evidence would carry nothing a verifier could recheck, so a witness could emit the reason at
will and a verifier holding the refusal would have nothing to check it against — neither
corroborating material nor anything that tells against it. That fails the rule this taxonomy is
built on — every reason checkable from carried evidence.

For a witness that **derives** consistency proofs itself, which is the arrangement this profile
assumes (§11 and §8.3), a failure to generate a proof is an **internal error**: the witness
declines to cosign and reports operationally, but publishes no refusal, because it has no
evidence of log misbehaviour — its own inability to compute is not the log's fault.

**Recorded gap.** A witness that is *handed* proofs by the log rather than deriving them is a
different arrangement, and under it "the log did not supply a proof" is a real observation about
the log. Such a witness would need its own reason, separately specified, carrying evidence a
third party can recheck — for example a signed record of the request and the log's response, or
a signed statement of non-response countersigned by a second observer. **No such reason is
specified here**, and a deployment MUST NOT reintroduce `missing-consistency-proof` or any
equivalent under this profile. This is written down so the gap is recorded rather than
rediscovered the next time a proof-fed witness is built.

#### 11.2.5 Checking refusal evidence

1. Verify the witness signature over `JCS(refusal object minus "signature")`, against a witness
   key resolved per §7.4.
2. Verify the log signature on **both** carried checkpoints per §6.5 — an unsigned or badly
   signed checkpoint proves nothing about the log — and confirm both carry the `log_id` named in
   the refusal, which MUST be the corpus's bound Data Tree (§3).
3. Apply the recheck for the declared `reason` from the table in §11.2.1, including the binding
   equalities of §11.2.2 where the reason is `extension-failed`. A refusal whose evidence does
   not support its declared reason is **unsupported** and MUST be reported as such; a verifier
   MUST NOT substitute a different reason that the evidence would have supported.
4. Treat a refusal that passes steps 1 to 3 as evidence about the log's conduct within the
   boundary of its reason (§11.2.3) — an operational finding about the deployment (§1.1) — and
   never as a result about any particular statement (core spec §3.3 claim discipline).

A refusal that passes steps 1 to 3 is **checked**. Refusal evidence is not a receipt, so no I-D
§7.7 result attaches to it and it MUST NOT be labelled `verified` (§1.1); "checked" is this
profile's own term for the outcome of §11.2.5.

A checked `equivocation` refusal is exactly the divergence of §5.2.2: the series ceases to be
canonical from that `tree_size` onward, members below remain usable, and every response derived
from the series MUST report the divergence rather than choose a branch. A checked
`size-regression` or `extension-failed` refusal is a finding about what the log offered this
witness; neither by itself establishes divergence, and neither triggers that boundary.

Refusal evidence is self-authenticating, is not an AHL statement, is not anchored, and carries
no envelope.

### 11.3 Freshness

`checkpoint_cadence` and `witness_grace_period` are required members of the manifest `log`
object with the normative meanings of §7.3; neither is deployment-defined in shape, neither may
be defaulted, and both are restricted to time-component durations such as `PT1H` or `PT15M`
(§7.3.1) — a grace period expressed in years or calendar months is malformed and MUST be
rejected. A witness whose latest cosigned checkpoint is older than the cadence by more than the
grace period is stale, and verifiers treat staleness as a finding.

Two consequences of §7.3 apply here. First, staleness is judged against the cadence of the
**manifest version governing the range in question**, not against the current version's value: a
later version that relaxes cadence does not retroactively make an earlier stale interval fresh.
Second, this profile sets no cadence value of its own; ATL emits checkpoints as part of its
anchoring cycle, and a deployment MUST declare values that its actual cycle meets, since cadence
is a maximum-gap obligation the deployment is then held to (§5.2.2 item 1) rather than a
description of typical behaviour.

## 12. Super-Tree material and external anchors

ATL aggregates closed Data Tree roots into a Super-Tree and anchors externally in two tiers:
RFC 3161 tokens over a Data Tree root, and Bitcoin OpenTimestamps over the Super Root
(ATL protocol §3.3.4).

Under this profile:

- **RFC 3161 over the Data Tree root** maps directly onto AHL's receipt `anchors[]` with
  `target: "checkpoint_root"` and `target_hash` equal to the checkpoint's `root_hash`, because
  the Data Tree root and the AHL checkpoint root are the same value for the bound tree.
- **Bitcoin OTS over the Super Root** does **not** target an AHL checkpoint root. Binding it to
  an AHL checkpoint requires ATL's `super_proof` material — the Data Tree root's inclusion in
  the Super-Tree and the Super-Tree's consistency to origin — which is ATL-specific and is not
  part of any AHL claim type. A receipt MAY carry that material as supplementary evidence, but
  a conformant AHL verifier is NOT required to evaluate it, and no AHL assurance field is set
  by it.
- Anchors of either kind are **supplementary** under AHL. They are not a substitute for the
  witness protocol: an external timestamp establishes that a root existed by a time, not that
  the operator showed the same log to everyone. Core spec §3.3 is satisfied by witnessing, not
  by anchoring.
- The receipt `anchors[]` member is still only **sketched** — now in the controlling document
  rather than in the companion. I-D §7.1 fixes `type`, `target` and `target_hash` in its
  normative container shape, but leaves the element open with a trailing ellipsis and gives it
  no prose paragraph of its own, unlike `keys`, `anchoring.checkpoint`, `anchoring.witnesses`
  and `governance.chain`. This profile therefore constrains only what is stated above and
  leaves the rest to a later revision of I-D §7.1.

## 13. Capabilities

A verifier treats an unsupported feature as a limitation of the pinned profile, named as such,
rather than as generic non-conformance.

| capability | status under `ahl-adaptor-atl-v1` | consequence |
| --- | --- | --- |
| binary checkpoint framing (`anchoring.checkpoint.raw`) | **defined** (§6.4) | receipts MAY carry `raw`; it MUST parse to the same values or the receipt is rejected |
| checkpoint **authentication** (signature verifies under the governing key set) | **defined** (§6.5) | reachable from a signed 98-byte checkpoint alone; establishes only that the log signed those values |
| checkpoint **series-usability** (root recomputed against held entries; neighbour consistency verified) | **defined** (§6.6); **unreachable on the published ATL stack**, since it needs entry material from §10.3 or §10.1.1 | without it a deployment holds authenticated-only checkpoints, and `ITUB`, enumeration responses and completeness claims are all unavailable |
| inclusion proofs | **defined** (§8.2) | available for every entry under a checkpoint |
| consistency proofs (`later_checkpoint` + `consistency_path`) | **defined** (§8.3); serving them is a deployment obligation (§10.1) | `continued_history: true` is possible only where the deployment serves them |
| later-checkpoint support | **defined**, same condition as above | as above |
| authenticated range enumeration | **defined by this profile** (§10.3–§10.5); **not served by the published ATL server** | enumerated governance, and every claim type requiring it, depends on the deployment adding the interface or a mirror |
| retrieval by AHL entry id | **not served by the published ATL stack**; byte-serving interface required (§10.1.1) | ATL receipts carry a digest of the envelope, not the envelope; a mapping to ATL identifiers does not discharge the obligation |
| per-entry log-attested time (LIT) | **not provided** (§5.2) | contract item 1 is unsatisfied; no value defined here may be presented as a LIT |
| incorporation-time upper bound (`ITUB`) | **defined** (§5.2.1), conditional on a published canonical checkpoint series (§5.2.2) whose selected member is series-usable (§6.6) | without that series `ITUB` is undefined and incorporation time is reported unavailable — an operational finding, not an I-D §7.7 result (§1.1); propagation-window starts depend on it, and on the open question of §5.2.3 |
| series completeness | **operational finding only** (§5.2.2), outside the I-D §7.7 result model (§1.1) | rests on the cadence rule plus the publication obligation; consistency proofs cannot show that a required checkpoint was never published, and completeness below the earliest published member is not provable |
| equivocation boundary (two roots at one `tree_size`) | **defined** (§5.2.2), detected over every authenticated member (§6.6.1) | the series stops being canonical from the lowest divergent `tree_size`; members below remain usable; every response derived from the series — including a single-checkpoint lookup — MUST report the divergence, and serving one branch instead is a conformance violation |
| typed-subset (governance) proofs | **not available** (§10.6) | enumerated governance carries the full range |
| witness cosigning | **defined by this profile** (§11); not an ATL feature | L3 requires an independently operated witness alongside the log |
| multi-tree / rotated-tree corpora | **not defined** (§3) | one corpus binds one Data Tree; rotation ends the binding |

## 14. Profile identity and content addressing

- The **profile id** is the ASCII string `ahl-adaptor-atl-v1`.
- The **profile digest** is the SHA-256 over the exact bytes of the released artifact — this
  document as published, byte for byte, with no normalization of any kind: no whitespace
  trimming, no line-ending translation, no Unicode normalization, no re-encoding. The artifact
  is UTF-8 with LF line endings.
- **The digest is not written in this document, and cannot be.** A digest embedded in the file
  would commit to the bytes that contain it; substituting the real value would change those
  bytes and invalidate it. The digest therefore lives outside the artifact: it is recorded in
  the corpus manifest as `log.adaptor.hash` (core spec §7.2), carried in every Evidence Receipt
  as `anchoring.adaptor.hash` — I-D §7.1 fixes `anchoring.adaptor` as `{id, hash}` — and
  published alongside the artifact at release. A verifier computes it over the artifact it
  holds and compares.
- The pair `{ id, digest }` is what a corpus pins. A verifier MUST resolve the profile from
  local possession by both, MUST recompute the digest over the artifact rather than trusting any
  value carried with it, and MUST reject a receipt whose pinned digest does not match the
  artifact held.
- **Release is a precondition for use.** Until this document is released as an immutable,
  openly published artifact at a stable location, its digest is not stable and no manifest may
  pin it: an unreleased draft can still change, and a corpus that pinned it would be pinning a
  moving target. Core spec §3 item 6 requires adaptor profiles to be openly published;
  publication is an outstanding release obligation for this profile, not a property it already
  has, and §15 records it as such.
- **Any change to this document, however small, produces a different hash and therefore a
  different profile.** A changed profile MUST be published under a new id — `ahl-adaptor-atl-v2`
  and onward — and adopting it requires a new manifest version, which is itself an anchored
  statement. Editing this document in place while keeping the id is a conformance violation:
  receipts pinning the old hash would no longer resolve, and receipts pinning the new hash
  would claim verification rules their issuing corpus never declared.

## 15. Conformance statement

Core specification §3 contract, clause by clause. Status vocabulary:

- **satisfied** — satisfied by ATL as published and implemented;
- **partially satisfied** — some part of the clause is settled and the remainder is named;
- **unmet today, deployment obligation** — this profile defines the requirement completely, but
  nothing in the published ATL stack serves it: a deployment must build and operate it before
  claiming conformance;
- **unsatisfied** — the requirement is not met and cannot be met by this log class as published;
  what is available instead is named and is weaker.

| core §3 clause | requirement | status under this profile |
| --- | --- | --- |
| item 1 (append-only, opaque entries) | append-only log of opaque byte entries | **satisfied** — ATL Data Tree is append-only; entries are opaque payload bytes (§4) |
| item 1 (LIT per entry) | log-attested incorporation time per entry | **UNSATISFIED** — ATL attests no per-entry time, and this profile defines no LIT. A deployment publishing the canonical checkpoint series of §5.2.2 obtains a deterministic incorporation-time **upper bound** (`ITUB`), which is a weaker quantity under a different name; without that series `ITUB` is undefined and incorporation time is reported unavailable, as an operational finding rather than a result over a receipt (§1.1, §5.2). Measuring an L3 propagation window from `ITUB` is a substitution the core does not authorize, so an L3 propagation-window claim on ATL is not established until the core decides (§5.2.3) |
| item 2 (signed checkpoints, cadence, key discovery) | signed checkpoints at declared cadence; log keys discoverable via the manifest | **partially satisfied: signing yes, cadence obligation unmet today** — 98-byte signed checkpoints (§6) and key resolution from the normative `log` object (§7.3, §7.4) are settled. But cadence is a maximum-gap obligation over a *published* series (core spec §7.3, §5.2.2), and nothing in the published ATL stack publishes one; a deployment must do so, and its declared `checkpoint_cadence` and `cadence_epoch` are then judged against it |
| item 3 (inclusion proofs) | entry → checkpoint | **satisfied** (§8.2) |
| item 3 (consistency proofs) | checkpoint → checkpoint | **partially satisfied: algorithm yes, service unmet today** — RFC 9162 proofs are implemented in `atl-core`, but the published server exposes no route serving them, so a deployment must serve them before any receipt can claim continued history (§8.3, §10.1) |
| item 4 (retrieval by entry id) | retrieve an entry by its entry id | **UNMET TODAY, deployment obligation** — ATL receipts carry a digest of the envelope, not the envelope, so no identifier mapping can return the entry bytes. A byte-serving archive or endpoint keyed by AHL entry id MUST be added; responses are content-checked against the requested id and against the fixed adaptor metadata (§10.1.1) |
| item 5 (authenticated enumeration) | serve `[i, j)` under a checkpoint with proof of completeness and order | **UNMET TODAY, deployment obligation, and the principal gap** — fully specified here (§10.2–§10.5) but served by nothing in the published ATL stack; without it a corpus cannot support enumerated governance or any claim type requiring it (§10.1) |
| item 6 (profile properties) | versioned, immutable, content-addressed, openly published, independently implementable; no knowledge required outside the profile | **partially satisfied** — versioning, immutability, content addressing and self-containment are settled (§14), and this document restates every rule a verifier needs. **Open publication is an outstanding release obligation**: until the artifact is published at a stable location, its digest is not stable and no manifest may pin it (§14) |
| §3.3 (witness protocol, L3) | independent witness per log; cosigning state machine; refusal evidence | **UNMET TODAY, deployment obligation** — ATL has no witness role at all; wire forms are defined here (§11), but operation must be added and MUST be independent of producer and operator |
| §3.5 (L3 availability) | entries retrievable by id and by enumeration outside producer control; committed tree material published, enumerable, bound to the anchored root | **UNMET TODAY, deployment obligation** — depends on item 4, item 5 and §9 carriage; an ATL instance operated by the producer alone does not satisfy it, and an independent mirror is required |

Summary for a deployment planning an L3 corpus on ATL. Settled by this document and by ATL as
published: entry encoding, ordering, checkpoints, keys, inclusion and consistency algorithms,
and profile identity.

**Not met by any published component today** — these are missing capabilities, not optional
refinements, and a corpus cannot reach L3 until each is built and operated:

1. a byte-serving retrieval path keyed by AHL entry id (§10.1.1);
2. an authenticated enumeration interface, served outside producer control (§10.3);
3. a published, gap-free, authenticated canonical checkpoint series (§5.2.2), without which
   propagation windows have no determinable start — and with which they still rest on the
   unauthorized substitution of §5.2.3;
4. an independently operated witness (§11);
5. published, enumerable committed tree material for batch, input-set and disposition trees
   (§9).

And one property must be accepted rather than built: **there is no log-attested incorporation
time on ATL**. The best available substitute is an upper bound, and it exists only where item 3
is in place. Whether that substitute may ground an L3 propagation window is not this profile's
to decide and is open at core level (§5.2.3).

## 16. Deployment obligations, collected

A deployment claiming conformance to this profile MUST:

1. Bind the corpus to exactly one Data Tree and pin its `log_id` in the manifest (§3).
2. Submit entries as `JCS(envelope)` with the fixed metadata object of §4.2, and never place
   AHL data in ATL metadata.
3. Declare `checkpoint_cadence` and `witness_grace_period` in the manifest as time-component
   durations (§7.3.1), matching the deployment's actual anchoring cycle (§11.3).
4. Publish the canonical checkpoint series of §5.2.2 — cadence-conforming against the manifest
   version governing each range, ordered by `(tree_size, checkpoint_time)` and monotone in that
   order, anchored at `cadence_epoch` with the earliest genesis-committing checkpoint inside the
   window of §5.2.2 item 3, series-usable (§6.6), and append-only in publication.
   Retaining checkpoints privately does not discharge this: the series must be the same one every
   verifier sees. Declare a `checkpoint_cadence` the deployment's actual anchoring cycle meets,
   in time-component form (§7.3.1), and anchor a new manifest version — repeating `cadence_epoch`
   unchanged (§7.3.2) — before changing it. **Keep publishing while the log is quiet:** the
   cadence obligation is on `checkpoint_time`, not on entry arrival, so a period with no
   submissions still requires checkpoints at cadence, with `tree_size` unchanged (core spec
   §7.3). Without them a log that has nothing to say is indistinguishable from one that is
   withholding, and no completeness finding is available for that interval.

   **If, and only if, the deployment claims L3:** also declare in the manifest that propagation
   windows are measured from `ITUB` under this profile (§5.2.3). That declaration is what a
   deployment MUST do to claim L3 on ATL, and it is conditional on a core decision that has not
   been taken — an L3 claim on ATL rests on a substitution the core does not authorize (§5.2.3)
   — so making the declaration does not by itself establish that core §5.2's propagation-window
   requirement is met.
5. Provide byte-serving retrieval keyed by AHL entry id, with the response semantics of
   §10.1.1.
6. Provide the authenticated enumeration interface of §10.3, from the log or from an
   independent mirror outside producer control, if the corpus is to support enumerated
   governance or L3 (§10.1, §15).
7. Publish committed tree material for batch, input-set and disposition trees, enumerable and
   bound to the anchored root, if claiming L3 (§9).
8. Operate or contract at least one independent witness per §11, if claiming L3.
9. Not rotate the bound Data Tree during the corpus's lifetime, or accept that rotation ends
   the corpus under the current manifest version (§3).

Obligations 4 through 8 are **not met by any published component of the ATL stack today**
(§10.1, §11, §15). They are work a deployment must build and operate before claiming
conformance, not configuration it can switch on.

## 17. Questions this profile does not settle

Recorded so that a later revision addresses them deliberately rather than by accident.

1. **Cross-tree corpora.** Composing one AHL entry index across ATL Data Tree rotation is
   undefined here and open at core level (core spec §10.4). ATL's genesis-leaf chaining
   commits the immediately preceding tree's root and size, which is suggestive material for a
   future composition rule, but it is not described in the published protocol document, its use
   by the server is not established here, and it would place a non-AHL leaf at index 0 of each
   tree. No rule is proposed on that basis.
2. **Closure signalling.** ATL publishes no signal that a Data Tree has been closed. A verifier
   holding a checkpoint cannot tell from the protocol whether the tree is still open, which
   bears on how a stale `continued_history` claim should be read.
3. **Rotation policy** — when an ATL deployment closes a Data Tree — is deployment
   configuration and is not published protocol behaviour; the manifest is the only authority for
   it under AHL. (Cadence, formerly listed here as equally unsettled, is no longer open: see
   §17.1 item 1.)
4. **The receipt `anchors[]` member** is sketched rather than fully specified — now in I-D
   §7.1, which fixes `type`, `target` and `target_hash` but leaves the element open and gives
   it no prose paragraph; §12 constrains only the RFC 3161 case that maps cleanly onto a
   checkpoint root.
5. **Typed governance sub-trees** (core spec §10.9) would shrink enumerated receipts to
   O(log n). None exists; §10.6 states the consequence rather than assuming a future
   capability.
6. **Whether an L3 propagation window may be measured from `ITUB`.** Core spec §5.2 measures
   the window from a LIT; ATL supplies none, and the `ITUB` substitution this profile specifies
   is not authorized by the core contract (§5.2.3). The decision belongs to the core: either
   §3 contract item 1 widens to admit a bound derived in the conservative direction, or this
   profile states that L3 is unavailable on ATL. Until then the §16 obligation 4 declaration
   stands as what a deployment MUST do to claim L3, not as evidence that the claim holds.

### 17.1 Resolved since revision 1 drafting

Items that the mirror implementation surfaced against this profile, now settled normatively by
**core spec §7.3** and recorded here as closed rather than silently dropped.

1. **The manifest `log` object had no schema.** This profile previously referred to cadence,
   grace period and log key objects without fixing their shape, leaving an implementer to infer
   it and inviting divergent manifests. Core spec §7.3 now makes the object normative —
   `{log_id, operator, adaptor{id,hash}, checkpoint_cadence, cadence_epoch, witness_grace_period,
   keys[{key_id,pubkey,valid_from_index}]}`, every member REQUIRED, durations restricted per item
   4, `cadence_epoch` RFC 3339 — together with the rule that cadence binds only from its declaring
   version's entry index forward. §7.3 of this profile now restates it and states how each
   member is populated for an ATL binding; nothing about the shape is deployment-defined.
2. **Pairwise consistency was treated as evidence of a gap-free series.** The first revision of
   §5.2.2 required a consistency proof from each member's predecessor and inferred from that
   chain that no member had been omitted. That inference does not hold: a consistency proof shows
   append-only extension between the two checkpoints it names and is entirely silent about a
   checkpoint that was never published, so an operator that skips a required checkpoint produces
   a chain that verifies exactly as a complete one does. Core spec §7.3 now states this directly
   and grounds completeness in the cadence rule plus the publication obligation of §3.5, making
   completeness an operational finding rather than a cryptographic proof.
   §5.2.2 has been rewritten accordingly, including the rule that completeness below the earliest
   published member is not provable and MUST NOT be assumed.
3. **`cadence_epoch` was described as per-version and changeable** — a contradiction with the
   core, which this revision removes. The epoch is declared once, by the genesis manifest, and
   repeated unchanged by every later version; only `checkpoint_cadence` may change, and only
   prospectively. A later version carrying a different epoch is malformed. §7.3.2 states the rule
   and why the asymmetry exists; §5.2.2 item 1 no longer speaks of a version's own epoch.
4. **Duration syntax was unconstrained.** The profile inherited "ISO 8601 duration" without
   restriction, which admitted years and calendar months whose length is context-dependent. Core
   §7.3 now limits `checkpoint_cadence` and `witness_grace_period` to time components
   (`P[n]DT[n]H[n]M[n]S`) and requires rejection rather than approximation of `Y` or date-part
   `M`. §7.3.1 carries this, and the §7.3 example now shows conforming values.
5. **Where the series begins, and who governs the opening interval.** Settled in two steps. An
   interim revision offered two possible start points, `cadence_epoch` or the genesis checkpoint,
   which left a corpus with both — and with them disagreeing — evaluable two ways, and named a
   checkpoint (`tree_size` = genesis manifest entry index + 1) that an operator need never
   publish. Core §7.3 now removes the alternative: **`cadence_epoch` is the single start**, the
   genesis checkpoint is explicitly not a start point, and the epoch is instead constrained — the
   earliest checkpoint committing the genesis manifest must fall between `cadence_epoch` and
   `cadence_epoch` plus the genesis version's `checkpoint_cadence`. That one window closes both
   failure modes: an epoch reaching back over time the corpus did not exist for, and an epoch
   leaving the opening interval ungoverned. §5.2.2 item 3 carries the rule, the window and the
   rejection duty; the profile no longer offers a genesis-checkpoint start.
6. **Three questions this profile raised at revision 1 are answered by the current core text**,
   and the profile now states the answers rather than the questions: the version governing a
   checkpoint is the manifest with the greatest entry index smaller than its `tree_size` (as for
   keys); a gap straddling a cadence change is judged under the version governing its earlier
   member (§5.2.2 item 1); and a log with no submissions MUST keep publishing checkpoints at
   cadence with `tree_size` unchanged, since otherwise a quiet log and a withholding log are
   indistinguishable (§16 obligation 4). Core §7.3 also settles that the newest series member is
   series-usable on its predecessor relationship alone, and that entries used for root
   recomputation may come from any source because each is content-addressed (§6.6).
7. **Series ordering and ties at equal `tree_size`.** Requiring quiet logs to republish at
   unchanged `tree_size` (item 6) left `tree_size` no longer totally ordering the series, and the
   profile's non-decreasing rule presumed an order it had stopped defining. Core §7.3 now fixes
   series order as **`(tree_size, checkpoint_time)` ascending**, requires members sharing a
   `tree_size` to carry the **same `root_hash`** — differing roots at one size being equivocation
   rather than a tie — and applies the non-decreasing rule to that order. §5.2.2 item 2 carries
   all three.
8. **Which tied member `ITUB` selects.** Left to the reader in the previous revision. Core §7.3
   now fixes it: where the selection lands on a `tree_size` carrying several members, the member
   with the **earliest** `checkpoint_time` governs, giving the tightest bound the series
   supports — and denying an operator any way to loosen a published bound by republishing.
   §5.2.1 carries it.
9. **Duration and epoch comparison.** Whether `PT60M` and `PT1H` were the same cadence, and
   whether "repeated unchanged" meant byte equality, were both unstated. Core §7.3 now compares
   cadence values by **normalized value, not spelling**, and has a later version repeat
   `cadence_epoch` **by value**. §7.3.1 and §7.3.2 carry these, with the note that excluding
   years and calendar months is what makes normalization exact.
10. **What follows detection of equivocation.** The profile named two roots at one `tree_size` as
    equivocation and stopped there, leaving an implementation free to detect the divergence and
    keep serving — the defect the mirror implementation then found in four code paths, including
    a single-checkpoint lookup whose tie-break silently returned the later timestamp. Core §7.3
    now makes the consequence normative: the series ceases to be canonical from the lowest
    divergent `tree_size`, members below remain usable, a party serving series-dependent material
    MUST report the divergence rather than choose a branch, and detecting equivocation while
    continuing to serve one branch is a conformance violation. §5.2.2 carries it, and extends it
    explicitly to **every** response derived from the series rather than to the three named
    interfaces alone.
11. **Fractional seconds and positive cadence.** Duration precision was unbounded, so two
    implementations could disagree by truncating differently. Core §7.3 now caps fractional
    seconds at **nine digits** — matching ATL's nanosecond checkpoint timestamp — requires
    rejection rather than truncation or rounding beyond that, and requires `checkpoint_cadence`
    to be greater than zero. §7.3.1 carries all three.
12. **The state each series check runs in.** Previously unstated, and wrong in either direction
    if guessed: core §7.3 now scopes the start-window check to **series-usable** members, so a
    merely claimed time cannot decide whether a range opens, while divergence detection is a
    finding over **every authenticated** member, since it is visible from checkpoint metadata
    alone. §6.6.1 carries the split, with the summary that authentication is enough to condemn
    but not enough to certify.
13. **Refusal reasons were not independently checkable.** The first taxonomy,
    `inconsistent | missing-consistency-proof`, specified reasons a verifier could not always
    recheck from the refusal itself, and the witness implementation and its review replaced it.
    §11.2.1 now defines `equivocation`, `size-regression` and `extension-failed`, each with the
    recheck a verifier performs over carried evidence; §11.2.2 requires the carried proof to be
    bound to the pair (`from_size == retained.tree_size`, `to_size == offered.tree_size`), a
    defect found in a first implementation of refusal checking; §11.2.3 narrows
    `extension-failed` to "the carried proof fails verification" and forbids reading it as
    evidence that no valid extension exists; and §11.2.4 removes `missing-consistency-proof`
    outright, explains why absence is not evidence, and records — rather than leaves to be
    rediscovered — that a proof-fed witness would need its own separately specified,
    evidence-bearing reason.
