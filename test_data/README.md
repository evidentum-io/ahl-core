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

*   **`governance.rotation_proofs[]` verification (I-D §7.1, §7.5.1).** A manifest whose log
    checkpoint-signing key objects or whose witness key objects differ from its predecessor's is
    a GOVERNANCE-KEY ROTATION, and the I-D requires a rotation-anchoring proof under the
    outgoing key state. This crate cannot check such a proof — present, absent, or malformed —
    so ANY receipt whose carried governance chain rotates either key set is refused outright
    under `ReceiptError::GovernanceKeyRotationUnsupported`, never silently accepted and never
    reported as a definite schema defect it has not actually established. The corpus's own
    manifest version 2 (entry 25) rotates the witness key set, so no vector in this corpus can
    positively exercise material anchored under it: `governance-state-valid.ahl` and
    `governance-state-short-range-must-fail.ahl` were rewritten to stay inside the genesis
    manifest's era instead, and
    `propagation-complete-rotation-unsupported-must-fail.ahl`,
    `trigger-effective-co-signed-rotation-unsupported-must-fail.ahl` and
    `trigger-effective-non-verifying-signature-rotation-unsupported-must-fail.ahl` are vectors
    that used to be POSITIVE and now demonstrate the refusal instead — along with three existing
    negative vectors (`statement-anchored-dropped-producer-key-must-fail.ahl`,
    `trigger-effective-unverified-authority-signature-must-fail.ahl`,
    `propagation-complete-past-declared-checkpoint-must-fail.ahl`) whose ORIGINAL rule is now
    shadowed by this earlier-firing refusal. Each names both rules in its generator source
    comment and its `note`.
*   **The full three-valued verification-result model (I-D §7.7: `valid` / `invalid` /
    `unverifiable`).** `verify_receipt` remains the binary `Result<Verdict, ReceiptError>` it
    always was. A handful of `ReceiptError` variants represent the I-D's `unverifiable` outcome
    rather than `invalid` — `UnsupportedVersion` (I-D §7.1 "Revision and rule selection"),
    `CanonicalizationUnsupported` (I-D §6.3), and `GovernanceKeyRotationUnsupported` above — and
    each says so on its own doc comment, but a caller that needs to DISTINGUISH `invalid` from
    `unverifiable` must match on the specific variant; there is no separate return type or
    finding enum carrying that distinction structurally.
*   **Canonicalization procedures beyond `jcs` and `exact-bytes` (I-D §2.6).** These are the
    only two the I-D itself defines, and the only two this crate implements. A dataset declaring
    any other `canonicalization` identifier — a registered one this crate has not implemented,
    or a private-use `x-` one — makes that dataset's content-binding finding `unverifiable`
    (`ReceiptError::CanonicalizationUnsupported`), never `invalid` and never rehabilitated to
    `content_binding: "none"`, exactly as I-D §6.3's conformance table requires. No vector in
    this corpus currently exercises an unimplemented identifier end to end.

## Layout

| Path | Contents |
| --- | --- |
| `adaptor/` | The test adaptor profile document, content-addressed and pinned in both manifest versions |
| `vectors/statements/` | The 32-entry toy corpus, plus malformed statements naming the rule each violates |
| `vectors/merkle/` | Log tree (entry-index order, never sorted), the record-sorted batch, wide-outputs, input-set and disposition trees, and authenticated range proofs |
| `vectors/checkpoints/` | Signed checkpoints at tree sizes 8, 13, 20, 24, 25, 28, 29, 30 and 32, each cosigned by the witness its active manifest version declares |
| `vectors/closure/` | Six closure scenarios (see below) |
| `vectors/witness/` | Signed witness refusal evidence carrying two conflicting checkpoints (spec §3.3 step 3) |
| `receipts/` | One positive and at least one negative receipt per claim-type registry entry, plus `index.json` naming the expected outcome, the rule each negative must trip, and the trust policy those outcomes assume |
| `keys/` | Committed test key seeds — **see the warning below** |

## The scenarios

The corpus is 32 anchored entries carrying these interlocking scenarios:

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
   sizes — genuine, correctly built, about the wrong fact — is rejected. A third vector pairs
   enumerated governance currency with a later checkpoint: every piece of it is individually
   valid, and it is still refused, because receipt format §2.1 wants governance coverage through
   the later checkpoint's tree size while §4 fixes enumerated material at the anchoring
   checkpoint's, and no range satisfies both. A format that cannot express the evidence is a
   reason to refuse, never a reason to report missing evidence as verified.

Entry 25 anchors a second manifest version that rotates the witness key set in full and drops a
producer key from its snapshot, chained to its predecessor by *entry* id; entries 26 onward are
anchored under it.

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
