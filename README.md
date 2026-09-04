# ahl-core

Core library and test vectors for AHL Protocol revision 0.4 (Anchored History Log).

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
form of the whole receipt ahead of every semantic and cryptographic check; and `atl-core` —
the pinned sibling that performs canonicalization, node hashing and proof verification — is
not covered, because the claim is about this crate's own code.

## Documentation

Full documentation is available at:

**https://ahl-protocol.org/implementations/ahl-core**

## License

Apache-2.0
