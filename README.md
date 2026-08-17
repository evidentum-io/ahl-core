# ahl-core

Reference primitives and the canonical **test-vector corpus** for the AHL Protocol
(Anchored History Log) — record-level, tamper-evident provenance for data and ML pipelines.

Normative sources for everything here:

- **AHL Core Specification** v0.3-draft — statements, commitments, tree rules, conformance
  levels, corpus manifest.
- **AHL Evidence Receipt (`.ahl`) container format** 1-draft r3 — claim registry, assurance
  semantics, cross-field rules, resource limits.

The vectors, the generator and the verifier are open source from the first commit
(Apache-2.0) because the AHL constitution requires it: everything that affects how
statements, receipts, manifests, trees and witness evidence are formed or checked is part of
the open core. A proprietary "official verifier" would be a constitutional violation.

## What is in here

| Path | Contents |
| --- | --- |
| `src/lib.rs` | JCS, statement/entry ids, `plain`/`keyed` commitments, Ed25519 envelopes, checkpoints, AHL Merkle trees |
| `src/bitemporal.rs` | `valid_time` and trigger `scope` (spec §2.2, §2.3.3) over parsed RFC 3339 instants |
| `src/tree.rs` | `ValidatedLeafSet` — committed tree material is checked against root, count and §2.5 ordering before use |
| `src/range_proof.rs` | Authenticated range proofs (spec §3 contract item 5, receipt §4.2), generate and verify |
| `src/closure.rs` | Revocation closure (spec §5.1): trigger scope, correction supersession, input-set expansion, cycle-safe |
| `src/receipt.rs` | `verify_receipt` — the receipt format's §5 algorithm, offline, against a locally configured `TrustPolicy` |
| `src/bin/gen_vectors/` | The deterministic generator, which is also its own conformance check |
| `tests/vectors.rs` | Re-verifies the generated corpus from disk, exactly as a foreign implementation would |
| `test_data/adaptor/` | The test adaptor profile document, content-addressed and pinned in both manifest versions |
| `test_data/vectors/statements/` | The twenty-entry toy corpus, plus malformed statements with the rule each violates |
| `test_data/vectors/merkle/` | Log tree (unsorted, entry-index order), the record-sorted batch, input-set and disposition trees, and range proofs |
| `test_data/vectors/checkpoints/` | Signed checkpoints at tree sizes 8, 13, 18 and 20, each cosigned by the witness its active manifest version declares |
| `test_data/vectors/closure/` | Three closure scenarios: the base propagation, a correction-supersession chain, and a non-retroactive retraction |
| `test_data/vectors/witness/` | Signed witness refusal evidence carrying two conflicting checkpoints (spec §3.3 step 3) |
| `test_data/receipts/` | One positive and one negative receipt per claim-type registry entry, plus `index.json` naming the outcome and rule for each |
| `test_data/keys/` | Committed test key seeds — **see the warning below** |

The toy corpus is twenty anchored entries. Three scenarios are woven through it:

1. **Propagation.** A retroactive correction at entry 6 affects four derived records; the
   successor derivation consuming the *replacement* is correctly outside the affected set.
   Entry 8 anchors the disposition tree, and `propagation-complete` proves it equals the
   closure recomputed from the enumerated corpus prefix.
2. **Correction supersession.** Entry 12 corrects the same original record again,
   superseding entry 6. Its closure seeds are the original *and* the superseded replacement
   — never its own replacement (spec §5.1). That is what pulls in the successor derivation
   and the wide-input derivation at entry 10, whose inputs are reachable only through a
   committed input-set tree.
3. **Non-retroactive scope.** Entries 14–16 derive from one record with a point valid time
   before the boundary, an open interval, and a closed interval ending before the boundary.
   The retraction at entry 17 (`retroactive: false`) affects exactly one of them. Scope is
   evaluated as an interval intersection over parsed instants, never as string comparison.

Entry 18 anchors a second manifest version that rotates the witness key set in full,
chained to its predecessor by *entry* id; entry 19 is anchored under it.

## Regenerating

```
cargo run --bin gen_vectors
```

The generator has no wall-clock read and no randomness: every timestamp is the fixed
`2026-08-16T12:00:00Z`, every key comes from a committed seed, and every record is a
committed constant. Two consecutive runs must leave `test_data/` byte-identical — if they
do not, that is a bug.

Before writing anything the generator verifies its own output and aborts on any mismatch:
all twenty envelope signatures, the manifest lineage, every checkpoint signature and witness
cosignature, every inclusion proof, every range proof (including that it rejects
substitution), the witness refusal evidence, and an independent recomputation of all three
revocation closures. It then runs every receipt vector through `verify_receipt` and requires
each positive one to be accepted and each negative one to be rejected *by the specific rule
it names*. A vector that cannot be self-verified never reaches the repository.

## Checking

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Anti-drift with atl-core

AHL is a sibling of ATL (Anchored Transparency Log), and their Merkle semantics must not
drift apart. This crate therefore depends on [`atl-core`](https://github.com/evidentum-io/atl-core)
pinned to an exact revision, and — normatively — **verifies every inclusion proof through
`atl_core::core::merkle::verify_inclusion`**, never through a local reimplementation.
Canonicalization (RFC 8785 JCS), node hashing, root computation and proof generation come
from the same place.

Range proofs are the one construction `atl-core` has no primitive for, so the combining
recursion in `src/range_proof.rs` is local. Every hash it computes is still `atl-core`'s:
subtree roots from `compute_root`, interior nodes from `hash_children`, the split point from
`largest_power_of_2_less_than`. A width-1 range is an inclusion proof in a different
serialization, and the verifier cross-checks it through `verify_inclusion` so the two
constructions cannot diverge.

## Test keys — never reuse

Every seed in `test_data/keys/` is a **published constant** committed to a public
repository, deliberately made of trivial repeating bytes so it cannot be mistaken for
generated material. Anyone can sign statements, checkpoints and cosignatures with these
keys, and anyone can recompute every `keyed` commitment in the corpus. They exist so the
vectors are reproducible. **Never use them for anything real.**

## Status

Working draft, tracking spec v0.3-draft (with errata r1) and receipt format 1-draft r3. Both
specifications are drafts, so the corpus is expected to change with them; the intended stable
contract is the *shape* of the corpus, not yet its digests.

Two things the corpus pins that the specifications leave to the adaptor profile, documented
in `test_data/adaptor/ahl-test-log-v1.md`: the member name `predecessor` for a manifest's
entry-id reference to its predecessor (§4), and the sibling members `leaf_index` /
`input_index` that carry the leaf position for the bare proof paths in `claim_material`
(§2.3). Both are serialization choices, which is the profile's remit; neither changes a
normative rule.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
