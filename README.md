# ahl-core

Core library and test vectors for AHL Protocol revision 0.4 (Anchored History Log).

## Compatibility

**0.4.0 breaks the cosignature API**: `cosignature_bytes` now takes
`&CosignedCheckpoint` — the typed six-member projection of adaptor `ahl-adaptor-atl-v1` §11.1,
built with `CosignedCheckpoint::project` — instead of a checkpoint `Value`, so a checkpoint's
optional `raw` framing can no longer enter the preimage. Callers project first.

## No panic

`ahl-core` reaches no panicking construct on any input to its three parsers — the statement
envelope (`statement_id`, `entry_id`, `check_envelope`, `verify_envelope`), the Evidence
Receipt (`receipt::verify_receipt_report`, `receipt::verify_receipt`), and the governance
manifest and key statement schema the §7.5.1 walk applies — under the crate's own
`receipt::Limits`. Malformed, hostile or simply absurd input is reported as an error or as a
§7.7 finding, never as an abort of the caller's process. The mechanism is the crate-level
lints in `Cargo.toml` (`clippy::unwrap_used`, `expect_used`, `indexing_slicing`,
`arithmetic_side_effects`, `panic`, `unreachable`, `todo`, `unimplemented`,
`missing_panics_doc`, all denied and satisfied in library code rather than allowed at a site);
the evidence is the three libFuzzer targets in [`fuzz/`](fuzz/README.md). The boundary:
allocation failure and stack exhaustion are out of scope, since neither is a panic and neither
is something a library can decline; nesting depth is bounded by `serde_json`, which refuses a
document nested deeper than 128 levels with an error rather than recursing, so a `Value`
obtained by parsing bytes is already bounded when this crate sees it, while a `Value` built
programmatically to arbitrary depth is not and is outside the claim; total work is bounded by
the I-D §7.8 decoded-size budget (`Limits::max_decoded_bytes`), enforced over the canonical
form of the whole receipt after the top-level version read (I-D §7.5 step 1) and before every
remaining semantic and cryptographic check; and `atl-core` —
the sibling pinned at the exact registry version `=0.23.2`, which performs canonicalization,
node hashing and proof verification — is not covered, because the claim is about this crate's
own code.

## The ATL adaptor profile

`ahl-adaptor-atl-v1` is released, and this crate ships the artifact verbatim at
`test_data/profiles/ahl-adaptor-atl-v1.md` — 110 320 bytes, exposed as
`ahl_core::ATL_PROFILE_DOCUMENT` with its digest as `ahl_core::ATL_PROFILE_DIGEST`
(`sha256:80a7de…b805aa`). Its own §14 makes a profile's identity its bytes, so a client pinning
`{id, digest}` under the real id takes both from here rather than fetching the document to learn
its own digest. A unit test recomputes the digest over the shipped bytes.

The conformance corpus pins `ahl-test-atl-leaf-v1` — a separate profile with a document of its
own that defines the same serialization as its own rules — and pins the real id nowhere. That is
deliberate: the toy log's checkpoints are signed by a toy key over a toy tree, so binding them
to the ATL binding would assert a conformance claim the corpus cannot make. Shipping an artifact
is not configuring a policy; the corpus policy is configured with the test profile alone, which
is why a receipt pinning `ahl-adaptor-atl-v1` against it is `unverifiable` (I-D §7.5 step 2).

## Documentation

Full documentation is available at:

**https://ahl-protocol.org/implementations/ahl-core**

## License

Apache-2.0
