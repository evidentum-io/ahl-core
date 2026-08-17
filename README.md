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
| `src/closure.rs` | Revocation closure over an anchored statement graph (spec §5.1), cycle-safe |
| `src/bin/gen_vectors.rs` | The deterministic generator, which is also its own conformance check |
| `tests/vectors.rs` | Re-verifies the generated corpus from disk, exactly as a foreign implementation would |
| `test_data/adaptor/` | The test adaptor profile document, content-addressed and pinned in the manifest |
| `test_data/vectors/statements/` | The ten-entry toy corpus, plus malformed statements with the rule each violates |
| `test_data/vectors/merkle/` | Log tree (unsorted, entry-index order) and the record-sorted batch and disposition trees |
| `test_data/vectors/checkpoints/` | Signed checkpoints at tree sizes 8 and 10, plus the witness cosignature |
| `test_data/vectors/closure/` | The toy-corpus closure expectation and its dispositions |
| `test_data/receipts/` | A full `statement-anchored` receipt and a deliberately over-claiming receipt that MUST fail |
| `test_data/keys/` | Committed test key seeds — **see the warning below** |

The toy corpus is ten anchored entries: a genesis manifest, three ingestions, three
derivations (one of them batched), a retroactive correction, a propagation statement, and a
key transition. Its point is the propagation: the correction at entry 6 affects four derived
records, and the successor derivation that consumes the *replacement* is correctly outside
the affected set.

## Regenerating

```
cargo run --bin gen_vectors
```

The generator has no wall-clock read and no randomness: every timestamp is the fixed
`2026-08-16T12:00:00Z`, every key comes from a committed seed, and every record is a
committed constant. Two consecutive runs must leave `test_data/` byte-identical — if they
do not, that is a bug.

Before writing anything the generator verifies its own output and aborts on any mismatch:
all ten envelope signatures, both checkpoint signatures, the witness cosignature, every
inclusion proof, and an independent recomputation of the revocation closure. A vector that
cannot be self-verified never reaches the repository.

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

## Test keys — never reuse

Every seed in `test_data/keys/` is a **published constant** committed to a public
repository, deliberately made of trivial repeating bytes so it cannot be mistaken for
generated material. Anyone can sign statements, checkpoints and cosignatures with these
keys, and anyone can recompute every `keyed` commitment in the corpus. They exist so the
vectors are reproducible. **Never use them for anything real.**

## Status

Working draft, tracking spec v0.3-draft and receipt format 1-draft r3. Both specifications
are drafts, so the corpus is expected to change with them; the intended stable contract is
the *shape* of the corpus, not yet its digests.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
