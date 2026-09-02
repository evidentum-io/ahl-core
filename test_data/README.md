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

## Not yet implemented from revision 0.4

This crate's `verify_receipt` does not yet implement every rule revision 0.4 states, and refuses
rather than silently mis-verifying wherever the gap could otherwise be mistaken for a pass:

*   **The full three-valued verification-result model (I-D §7.7: `verified` / `invalid` /
    `unverifiable`, reduced from per-assertion findings).** `verify_receipt` remains the binary
    `Result<Verdict, ReceiptError>` it always was, rather than a completed-run outcome carrying
    a scalar result plus a findings list. A handful of `ReceiptError` variants represent the
    I-D's `unverifiable` outcome rather than `invalid` — `UnsupportedVersion` (I-D §7.1
    "Revision and rule selection") and `CanonicalizationUnsupported` (I-D §6.3) among them — and
    each says so on its own doc comment, but a caller that needs to DISTINGUISH `invalid` from
    `unverifiable` must match on the specific variant, and a capability gap on one assertion
    still aborts the whole run rather than being isolated to its own finding while independent
    assertions continue to be checked.
*   **Canonicalization procedures beyond `jcs` and `exact-bytes` (I-D §2.6).** These are the
    only two the I-D itself defines, and the only two this crate implements. A dataset declaring
    any other `canonicalization` identifier — a registered one this crate has not implemented,
    or a private-use `x-` one — makes that dataset's content-binding finding `unverifiable`
    (`ReceiptError::CanonicalizationUnsupported`), never `invalid` and never rehabilitated to
    `content_binding: "none"`, exactly as I-D §6.3's conformance table requires. No vector in
    this corpus currently exercises an unimplemented identifier end to end.
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
witness keys the verifier ALREADY TRUSTS, matched on both `key_id` and `pubkey` against local
configuration — is covered by `tests/vectors.rs` instead, since what decides it is the
verifier's own configuration rather than anything a portable vector can carry.

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
| `vectors/statements/` | The 32-entry toy corpus, plus malformed statements naming the rule each violates |
| `vectors/merkle/` | Log tree (entry-index order, never sorted), the record-sorted batch, wide-outputs, input-set and disposition trees, and authenticated range proofs |
| `vectors/checkpoints/` | Signed checkpoints at tree sizes 8, 13, 20, 24, 25, 26, 28, 29, 30, 32 and 33, each cosigned by the witness its active manifest version declares — EXCEPT cp26, deliberately cosigned by the OUTGOING witness-1 for the I-D §7.1 rotation-anchoring proof at manifest v2 (see "Governance-key rotation" below) |
| `vectors/closure/` | Six closure scenarios (see below) |
| `vectors/witness/` | Signed witness refusal evidence carrying two conflicting checkpoints (spec §3.3 step 3) |
| `receipts/` | One positive and at least one negative receipt per claim-type registry entry, plus `index.json` naming the expected outcome, the rule each negative must trip, and the trust policy those outcomes assume |
| `keys/` | Committed test key seeds — **see the warning below** |

## The scenarios

The corpus is 33 anchored entries carrying these interlocking scenarios:

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
6. **Signature handling on competing triggers.** Entries 28, 29 and 31 all retract record F.
   Entry 28 names the real authority's `key_id` with a signature that does not verify; entry 29
   carries a genuine signature from a non-authority key alongside a non-verifying one that names
   the authority; entry 31 is genuinely co-signed by the authority and a second active producer
   key. Spec §2.1 forbids two envelopes sharing a statement id, and the statement id digests the
   payload alone, so the three carry different `reason_code` values — otherwise they would be
   one statement anchored three times, of which only entry 28 would govern and the other two
   would be void.
7. **Continued history.** A consistency proof from cp20 to cp24 backs
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

8. **Stale manifest binding.** Entry 32 is a genuine, fully anchored, genuinely signed ingestion
   whose payload nonetheless names manifest v1 (genesis) as governing it, even though v2 (entry
   25) is the manifest ACTIVE at entry 32 (I-D §2.2). `record-ingested-stale-manifest-must-fail.ahl`
   proves this is `invalid` however genuine the rest of the statement is — real signature, real
   inclusion, real record — and needs a genuinely anchored statement rather than a mutated
   fixture, because mutating any already-anchored envelope invalidates its own inclusion path
   before the rule under test is ever reached.

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
through `verify_receipt` and requires each positive one to be accepted and each negative one to
be rejected *by the specific rule it names*. A vector that cannot be self-verified never reaches
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
"Not yet implemented from revision 0.4" above for what `verify_receipt` does not yet check.
