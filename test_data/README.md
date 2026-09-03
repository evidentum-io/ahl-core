# AHL test-vector corpus

The canonical conformance corpus for the AHL Protocol, generated from committed constants and
re-verified from disk on every test run. Everything here is derived; nothing is hand-edited.

Normative sources: **AHL Core Specification** v0.3-draft (statements, tree rules, conformance
levels, corpus manifest) for the pieces revision 0.4 has not restated, and the **AHL
Internet-Draft** draft-zatona-ahl-00 revision 0.4 for everything it does cover — §2.2 (the
`ahl_version`/`ahl_receipt_version`/`spec_version` clean break), §2.6 and §6.3 (canonicalization
descriptors, commitment modes, canonicalization identifier conformance) and, since revision 0.4
folded the receipt container into the core document, its own §7 (claim registry, assurance
semantics, cross-field rules, resource limits, the governance-key rotation rule of §7.1/§7.5.1).
Revision 0.4 verifies no material issued under any earlier revision (I-D §2.2, §7.1); this crate
implements it as a clean break, not a superset.

## The verification result (I-D §7.7)

A run that completes reaches exactly one of three values — `verified`, `invalid`,
`unverifiable` — and `verify_receipt_report` returns it together with the findings it reduces
from. `index.json` records both: every vector's `expect` is one of those three values, and a
non-verified vector also names, in `finding`, the required assertion whose finding produced it.

A **finding** is the outcome of one required assertion, with the same three values. The required
assertions of a receipt are the ones I-D §7.7 lists — the claim type's own §7.2 material, the
anchoring, envelope-validity, governance and cross-field checks of §7.5 steps 1-4 and §7.6, and
its content binding if and only if its own `assurance.content_binding` is not `none` — plus
every required assertion of each embedded receipt, WITH ONE EXCEPTION: an embedded receipt's
content binding is never a required assertion of the receipt that embeds it. This crate names
them `versions`, `resource-limits`, `structure`, `adaptor-profile`, `anchoring`, `governance`,
`checkpoint-authentication`, `envelope-validity`, `cross-field`, `claim-material` and
`content-binding`, and reports one finding per assertion per receipt, embedded receipts under
the `claim_material` member names that reach them.

The result is the reduction: `invalid` if any required finding is `invalid`, otherwise
`unverifiable` if any is `unverifiable`, otherwise `verified`. An `invalid` finding ends the run
— the result is decided, and the assertions after it are not reported at all — while an
`unverifiable` finding does not: the run carries on so that a defect reached later still
dominates, and the assertions that rest on the material it was short of are reported
`unverifiable` naming that prerequisite. Two conditions end the run even so, both ordering rules
rather than reductions: an unsupported version, which §7.5 step 1 follows with "no further
processing", and an exhausted verifier-local budget, which §7.8 requires to fail closed. A
boundary is rendered only for `verified`, and no result is ever expressed by rewriting the
receipt's own assurance fields.

`verify_receipt` remains as the single-value form for callers that report one rejection: `Ok`
if and only if the result is `verified`, and otherwise the rejection behind the finding that
decided it. `ReceiptError::class` gives the §7.7 value of one rejection and
`ReceiptError::assertion` the assertion it belongs to, both exhaustive over the variants.

Which conditions this build reports as `unverifiable` rather than `invalid`, and why:
`UnsupportedVersion` (I-D §2.2, §7.5 step 1), `BudgetExhausted` (§7.8, naming the budget and
the value in force), `AdaptorUnknown` and `AdaptorCapabilityUnsupported` (§7.5 step 2),
`AdaptorProfileMisconfigured` and `GenesisAnchorMismatch` and `WitnessKeyNotTrusted` (local
configuration the verifier was not given), `CanonicalizationUnsupported` (§6.3),
`DatasetKeyNotHeld` (§7.3) and `ProducerKeyNotCarried` (§7.4). Everything else is `invalid`.

`ProducerKeyNotCarried` is the one of these decided by the receipt's governance MODE rather
than by this build's capabilities. Under `declared` governance an envelope naming a producer
key the presented chain holds nothing for is `unverifiable` — the transition is a `key`
statement, and I-D §7.4 carries those in enumeration material alone, so the receipt is short
of material rather than defective. Under `enumerated` the same condition is `invalid`
(`EnvelopeSignatureInvalid`), because the range proof over exactly `[0, tree_size(C))`
forecloses omission (§7.5.1 4c). The pair
`statement-anchored-uncarried-key-transition-must-fail.ahl` and
`trigger-effective-derived-rotated-key.ahl` carry the SAME entry-19 envelope under the two
modes: the first is `unverifiable` — the corpus's one non-`invalid` negative — and the second
verifies.

Three capability gaps are exercised by `tests/vectors.rs` rather than by a vector, because what
decides each of them is the verifier's own configuration rather than anything a portable vector
can carry: a `keyed-authorized` binding under a policy holding no dataset key (I-D §7.7's own
worked example — result `unverifiable`, anchoring and claim material still `verified`, the
content binding `unverifiable`), and each of the two verifier-local budgets of §7.8 exhausted
under a tightened policy, which must name the budget and the value in force. The embedded-content
-binding exception is covered the same way, by splicing the content-bound `record-ingested`
vector into the `trigger-declared` vector's `introduction` slot, since every embedded receipt
this corpus carries asserts `content_binding: "none"`.

## Not yet implemented from revision 0.4

This crate's verifier does not yet implement every rule revision 0.4 states, and refuses rather
than silently mis-verifying wherever the gap could otherwise be mistaken for a pass:

*   **Canonicalization procedures beyond `jcs` and `exact-bytes` (I-D §2.6).** These are the
    only two the I-D itself defines, and the only two this crate implements. A dataset declaring
    any other `canonicalization` identifier — a registered one this crate has not implemented,
    or a private-use `x-` one — makes that dataset's content-binding finding `unverifiable`
    (`ReceiptError::CanonicalizationUnsupported`), never `invalid` and never rehabilitated to
    `content_binding: "none"`, exactly as I-D §6.3's conformance table requires. No vector in
    this corpus exercises an unimplemented identifier end to end: the identifier comes from the
    MANIFEST, so carrying one would mean a manifest declaring a dataset this crate cannot
    verify, and every receipt over that dataset would be built on it. The equivalent
    capability gap on the same finding — a dataset key the verifier is not authorized to hold —
    is exercised instead, in `tests/vectors.rs`.
*   **ATL adaptor profile support in the receipt verifier.** Leaf construction (adaptor
    `ahl-adaptor-atl-v1` §4.2: `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`),
    origin-derived `log_id` (§7.1: `sha256(Origin ID)`, Origin ID the SHA-256 of a 16-byte Data
    Tree UUID), and profile release (§14: "Until this document is released as an immutable,
    openly published artifact… no manifest may pin it") are pending — none is dispatched
    anywhere in this crate today, so a receipt naming that profile is refused as
    `ReceiptError::AdaptorCapabilityUnsupported`, never accepted. The checkpoint-level
    mechanism (§6.1-§6.5: assembling and signing the 98-byte blob, and reconciling a carried
    `raw` byte-for-byte against it) exists as `pub` helpers in `lib.rs` —
    `checkpoint_signing_bytes_for`, `atl_checkpoint_blob`/`atl_checkpoint_blob_from_json`,
    `reconcile_atl_checkpoint_raw`, `atl_checkpoint_time`/`atl_checkpoint_time_nanos` — and is
    unit-tested there over a synthetic checkpoint, for a client integrating ATL directly.

Also not yet in the corpus: no vector carries a witness key sourced `local-policy` (I-D §7.1).
The corpus trust policy holds no trusted witness key at all, so every witness key in every
vector is `manifest-chain`, bound by `(witness_id, key_id, pubkey)` to the manifest version
active for the checkpoint being cosigned. The `local-policy` branch — admissible only for
witness keys the verifier ALREADY TRUSTS, matched on `key_id`, `pubkey` AND the `witness_id`
policy holds the key for, and admissible only under an identity the active manifest itself
declares — is covered by `tests/vectors.rs` instead, since what decides it is the verifier's
own configuration rather than anything a portable vector can carry.

Also not yet in the corpus: this corpus's ONE governance-key rotation (manifest v2, entry 25)
rotates the WITNESS set only — the log checkpoint-signing key never itself rotates anywhere in
this corpus. `governance-key-rotation-proof-incoming-key-must-fail.ahl` therefore substitutes a
witness key for the rotation-proof checkpoint's signer to demonstrate "not a key of the outgoing
set", which exercises the same code path (`log_key_set` membership) a genuine incoming LOG key
would, but is not the same fact: a verifier that wrongly accepted an INCOMING log key
specifically is not what that vector rules out. A second, LOG-rotating manifest version (a
third manifest, or a variant corpus branch) with its own outgoing/incoming-key positive and
negative pair — and, since this corpus would then carry two governance-key rotations, a genuine
"out-of-order pair" `rotation_proofs[]` negative alongside it — is the intended follow-up.

`governance.rotation_proofs[]` verification (I-D §7.1, §7.5.1) IS implemented: a manifest whose
log or witness key objects, compared as sets, differ from its predecessor's is a GOVERNANCE-KEY
ROTATION, and its rotation-proof element is verified under the OUTGOING key state — the
checkpoint signature under the outgoing log key, the manifest's inclusion under that checkpoint,
and, AT L3, a cosignature under the outgoing witness set. The corpus's manifest version 2 (entry
25) rotates the witness key set, and every vector whose chain carries it now carries a genuine
`governance.rotation_proofs[]` element proving that transition; the eleven
`governance-key-rotation-proof-*-must-fail.ahl` vectors cover the collection-level rules (I-D
§7.1: required iff a rotation is present, one element per rotation, ascending order, no
duplicates, no extras) and the per-element ones (checkpoint and witness shape, the outgoing-key
requirement, and — since "every key used in verification MUST appear in `keys` with its source
and its binding" — that the element's log and witness keys are LISTED in `keys.log[]` and
`keys.witness[]` bound to the OUTGOING manifest version, per §7.1's transition exception).
Every receipt whose chain carries the rotation therefore lists the outgoing log key and the
outgoing witness alongside the keys its own checkpoint uses: the log key appears twice, under
two different bindings, which is the case receipt key binding is tolerant for.

## Layout

| Path | Contents |
| --- | --- |
| `adaptor/` | The test adaptor profile document, content-addressed and pinned in both manifest versions |
| `vectors/statements/` | The 38-entry toy corpus, plus malformed statements naming the rule each violates |
| `vectors/merkle/` | Log tree (entry-index order, never sorted), the record-sorted batch, wide-outputs, input-set and disposition trees, and authenticated range proofs |
| `vectors/checkpoints/` | Signed checkpoints at tree sizes 8, 13, 20, 24, 25, 26, 28, 29, 30, 32, 34, 35, 37 and 38, each cosigned by the witness its active manifest version declares — EXCEPT cp26, deliberately cosigned by the OUTGOING witness-1 for the I-D §7.1 rotation-anchoring proof at manifest v2 (see "Governance-key rotation" below) |
| `vectors/closure/` | Six closure scenarios (see below) |
| `vectors/witness/` | Signed witness refusal evidence carrying two conflicting checkpoints (spec §3.3 step 3) |
| `receipts/` | One positive and at least one negative receipt per claim-type registry entry, plus `index.json` naming the I-D §7.7 result each must reach, the assertion whose finding produces a non-verified one, the rule each negative must trip, and the trust policy those outcomes assume |
| `keys/` | Committed test key seeds — **see the warning below** |

## The scenarios

The corpus is 38 anchored entries carrying these interlocking scenarios:

1. **Propagation.** A retroactive correction at entry 6 affects four derived records; the
   successor derivation consuming the *replacement* is correctly outside the affected set.
   Entry 8 anchors the disposition tree, and `propagation-complete` proves it equals the
   closure recomputed from the enumerated corpus prefix.
2. **Correction supersession.** Entry 12 corrects the same original record again, superseding
   entry 6. Its closure seeds are the original *and* the superseded replacement — never its own
   replacement (spec §5.1). That is what pulls in the successor derivation and the batch at
   entry 10, whose outputs are reachable only by walking two committed trees: the batch outputs
   tree, and the input-set tree its leaves commit by root.
3. **Retraction after correction.** Entry 18 retracts the *original* record outright, after two
   corrections of it. A retraction seeds exactly its own record (spec §5.1), so the consumers of
   the replacements stay out of the affected set — the opposite of scenario 2, and the reason
   the two rules are not one rule.
4. **Non-retroactive scope.** Entries 14–16 derive from one record with a point valid time
   before the boundary, an open interval, and a closed interval ending before the boundary. The
   retraction at entry 17 (`retroactive: false`) affects exactly one of them. Scope is evaluated
   as an interval intersection over parsed instants, never as string comparison.
5. **Challenge.** Entry 23 retracts a record under a key that is *not* the dataset authority, so
   it anchors as a challenge (spec §2.3.3); entry 24 propagates over it anyway. No
   `propagation-complete` receipt over that propagation can verify, which is the point.
6. **Signature handling on competing triggers.** Entries 29, 32 and 33 all retract record F.
   Entry 29 is genuinely co-signed by the authority and a second active producer key (entry 28
   re-adds it after manifest v2 dropped it); entry 32 names the real authority's `key_id` with a
   signature that does not verify; entry 33 carries a genuine signature from a non-authority key
   alongside a non-verifying one that names the authority. Spec §2.1 forbids two envelopes
   sharing a statement id, and the statement id digests the payload alone, so the three carry
   different `reason_code` values — otherwise they would be one statement anchored three times,
   of which only entry 29 would govern and the other two would be void.

   The two non-verifying fixtures sit at the TAIL of the corpus on purpose. I-D §7.5.1 4d
   requires every carried envelope to verify, enumerated material included, and enumerated
   governance currency covers exactly `[0, tree_size(C))` (§7.4) — so a non-verifying envelope
   anchored at index *i* makes every enumerated claim at a tree size greater than *i* invalid.
   Placing the fixtures before the genuinely co-signed trigger would leave no checkpoint at
   which that trigger's own effectiveness could be enumerated. Two negatives exercise the rule
   from opposite ends: `trigger-effective-non-verifying-candidate-must-fail.ahl`, where the
   defective envelopes ARE competing candidates for the subject record, and
   `governance-state-non-verifying-entry-must-fail.ahl`, where no claim-specific rule looks at
   them at all. Both are refused, which is what "every carried envelope" means.
7. **A `key` statement that retires its own signing key.** Entry 30 retires `producer-2` under
   `producer-2`'s own signature; entry 31 re-adds the key, so the fixture at entry 33 keeps a
   genuine signature from a key in force. Governance statements are verified by the induction of
   I-D §7.5.1 4b — "against K AS ESTABLISHED SO FAR, the governance state in force immediately
   before this statement's own entry index" — and their effect applied only afterwards, which is
   why a self-retirement is conforming. 4d's remaining-envelope check is scoped to "every
   carried envelope that is NOT part of the induction" for the same reason: re-checking entry 30
   under the completed key state at its own index would resolve `producer-2` after its own
   retirement had taken effect. `governance-state-self-retiring-key.ahl` enumerates `[0, 32)`,
   which reaches both statements, and must be accepted.
8. **Record identity is a pair.** Entries 35 and 36 name a commitment beside the wrong
   dataset: entry 35 corrects `customers`/A to S1, a record that exists only in `scores`, and
   entry 36 retracts `scores`/A using record A's `customers` commitment. Neither is a mutated
   fixture — both are genuinely signed and genuinely anchored — because §2.6's domain
   separation makes such a pair impossible to reach through CONTENT while leaving a producer
   free to NAME one, and a verifier recomputes a commitment only where content evidence is
   carried. `trigger-declared-cross-dataset-introduction-must-fail.ahl` and
   `trigger-declared-cross-dataset-replacement-must-fail.ahl` embed introduction proofs whose
   commitment matches exactly and whose dataset does not; both must be refused (I-D §2.4.2,
   §2.4.3, §7.6).
9. **Continued history.** A consistency proof from cp20 to cp24 backs
   `assurance.continued_history` on a receipt, and a proof generated for a different pair of
   sizes — genuine, correctly built, about the wrong fact — is rejected. `anchoring.checkpoint`
   and `anchoring.later_checkpoint` each carry their OWN witness cosignatures — the primary
   one's in the sibling `anchoring.witnesses[]`, cp24's own in `anchoring.later_witnesses[]`
   (I-D §7.1: present if and only if `later_checkpoint` is carried; at L3, at least one element
   MUST verify, cosigning `later_checkpoint` itself rather than `anchoring.checkpoint`). A third
   vector pairs
   enumerated governance currency with a later checkpoint: every piece of it is individually
   valid, and it is still refused, because receipt format §2.1 wants governance coverage through
   the later checkpoint's tree size while §4 fixes enumerated material at the anchoring
   checkpoint's, and no range satisfies both. A format that cannot express the evidence is a
   reason to refuse, never a reason to report missing evidence as verified.

Entry 25 anchors a second manifest version that rotates the witness key set in full and drops a
producer key from its snapshot, chained to its predecessor by *entry* id; entries 26 onward are
anchored under it. I-D §7.1 requires a `governance.rotation_proofs[]` element proving this
transition under the OUTGOING witness state (witness-1): `cp26` (tree size 26) is that proof's
own checkpoint, deliberately cosigned by witness-1 even though it postdates entry 25, exactly
the "operator kept signing under the outgoing key until cutover" case I-D §7.1 describes as an
ordinary artifact of a real log rather than something a producer must manufacture.

10. **Stale manifest binding.** Entry 34 is a genuine, fully anchored, genuinely signed ingestion
   whose payload nonetheless names manifest v1 (genesis) as governing it, even though v2 (entry
   25) is the manifest ACTIVE at entry 34 (I-D §2.2). `record-ingested-stale-manifest-must-fail.ahl`
   proves this is `invalid` however genuine the rest of the statement is — real signature, real
   inclusion, real record — and needs a genuinely anchored statement rather than a mutated
   fixture, because mutating any already-anchored envelope invalidates its own inclusion path
   before the rule under test is ever reached.
11. **Input-set trees take the §2.7 tree rules.** I-D §2.7 states one set of rules, "identical
   for every AHL tree — outputs, input sets, and dispositions". Entry 37 is a batch whose three
   output leaves each commit an input-set tree breaking exactly one of them: leaves out of
   ascending `record` order, a record repeated under two roles, and a `record` that is not a
   family string under §2.1. The three `record-derived-input-set-*-must-fail.ahl` vectors carry
   the COMPLETE committed set for their tree, with genuine membership paths at genuine indexes,
   so nothing about paths, indexes or cardinality is wrong — only the tree is, which is the
   point: the producer who chooses the leaf order chooses the tree, so a set assembled in any
   other order opens a root of its own and is still not an AHL tree. These have to be genuinely
   anchored for the same reason the entries above do; mutating an anchored leaf's
   `input_set_root` breaks the outputs path before the rule under test is reached.

   The cost is stated rather than hidden: closure traversal opens every committed tree it
   reaches and validates it against these same rules before reading an edge, so a closure walk
   reaching entry 37 fails by §2.7. Every closure scenario this corpus publishes stops at tree
   size 28 or below, and the three defective trees are deliberately absent from
   `vectors/merkle/`, where they would be read as conforming material. That rejection is
   asserted rather than assumed: `tests/vectors.rs` reassembles the defective material from
   the three receipt vectors that carry it and runs a traversal one entry PAST the conforming
   prefix, which must stop on the tree rule the material breaks.
12. **Where governance material travels.** I-D §7.1 defines every `governance.chain[]` element
   as "an anchored manifest statement's complete envelope", and §7.4 says the other governance
   type travels elsewhere: "`governance.chain[]` carries manifest statements; producer-key
   transitions are `key` statements, and those reach a verifier only through enumeration
   material." Every chain in this corpus therefore carries manifests and nothing else — `[0]`
   or `[0, 25]` — while the `key` statements at entries 9, 28, 30 and 31 reach a verifier
   through the enumerated range, which §7.5.1 4b merges with the chain in entry-index order to
   form one induction. Two negatives police the two halves of that split.
   `governance-chain-key-statement-element-must-fail.ahl` carries the genuine entry-9 `key`
   statement as a chain element — real envelope, real signature, real inclusion path — and is
   refused as a container the format does not define, because a chain that may carry key
   transitions is a second, unenumerated carrier for them.
   `governance-enumerated-manifest-omitted-must-fail.ahl` omits manifest v2's chain element
   from a receipt whose own enumeration proves v2 anchored at entry 25, and is refused because
   §7.5.1 4c's "the range proof forecloses omission" holds only if the induction walked every
   manifest the range reveals.

   One consequence follows for declared mode and is worth stating: a declared-mode receipt
   carries no `key` statement at all, so a subject signed by a key some `key` statement added
   after the manifest version the subject binds to is not verifiable in that mode. I-D §7.4
   governs, and puts the obligation on the producer: "A producer intending its receipts to be
   verifiable in declared mode MUST anchor a manifest version snapshotting the current producer
   key set before issuing them." Every declared-mode vector in this corpus satisfies that: its
   subject resolves against the manifest snapshot in force at its own entry index.

## Regenerating

```
cargo run --bin gen_vectors
```

The generator has no wall-clock read and no randomness: every timestamp is a fixed constant,
every key comes from a committed seed, and every record is committed content. Two consecutive
runs must leave `test_data/` byte-identical — if they do not, that is a bug.

Before writing anything the generator verifies its own output and aborts on any mismatch:
statement-id and entry-id uniqueness (spec §2.1), every envelope signature — including that the
two deliberately non-verifying fixtures really do not verify — the manifest lineage and
key-snapshot semantics, the challenge's authority status, every checkpoint signature and witness
cosignature, every inclusion proof, every range proof (including that it rejects substitution),
every consistency proof between published checkpoints (including that a proof for the wrong pair
of sizes is rejected), the witness refusal evidence, and an independent recomputation of every
revocation closure. It then runs every receipt vector
through `verify_receipt_report` and requires each positive one to reach `verified` and each
negative one to reach the §7.7 result of the rejection it names, *by the specific rule it
names*. A vector that cannot be self-verified never reaches
the repository.

## Checking

```
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo llvm-cov --all-features --fail-under-lines 90
```

`tests/vectors.rs` reads only the files on disk, exactly as a foreign implementation would.

## Anti-drift with atl-core

AHL is a sibling of ATL (Anchored Transparency Log), and their Merkle semantics must not drift
apart. The crate depends on [`atl-core`](https://github.com/evidentum-io/atl-core) pinned to an
exact revision and — normatively — **verifies every inclusion proof through
`atl_core::core::merkle::verify_inclusion`**, never through a local reimplementation.
Canonicalization (RFC 8785 JCS), node hashing, root computation and proof generation come from
the same place.

Consistency proofs come from `atl-core` too — `generate_consistency_proof` and, for
verification, `verify_consistency` — so AHL's `continued_history` evidence is the RFC 9162
construction the ATL family already implements, not a second one.

Range proofs are the one construction `atl-core` has no primitive for, so the combining
recursion is local. Every hash it computes is still `atl-core`'s: subtree roots from
`compute_root`, interior nodes from `hash_children`, the split point from
`largest_power_of_2_less_than`. A width-1 range is an inclusion proof in a different
serialization, and the verifier cross-checks it through `verify_inclusion` so the two
constructions cannot diverge.

## Test keys — never reuse

Every seed in `keys/` is a **published constant** committed to a public repository,
deliberately made of trivial repeating bytes so it cannot be mistaken for generated material.
Anyone can sign statements, checkpoints and cosignatures with these keys, and anyone can
recompute every `keyed` commitment in the corpus. They exist so the vectors are reproducible.
**Never use them for anything real.**

## Status

Working draft, tracking AHL Internet-Draft draft-zatona-ahl-00 revision 0.4 (which now defines
both the core protocol and, in its own §7, the Evidence Receipt container) for everything it
covers, and spec v0.3-draft for the rest. All are drafts, so the corpus is expected to change
with them; the intended stable contract is the *shape* of the corpus, not yet its digests. See
"Not yet implemented from revision 0.4" above for what `verify_receipt_report` does not yet
check.
