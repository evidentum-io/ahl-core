# ahl-core fuzz targets

Three libFuzzer targets, one per parser the crate exposes to untrusted bytes. `envelope` takes
arbitrary bytes to JSON and then through the two I-D §2.1 identifiers and the envelope
signature check; `receipt` takes them through `verify_receipt_report` and `verify_receipt`
under the corpus trust policy of `test_data/receipts/index.json`, with the limits tightened to
256 KiB and 5 000 work units so no single input runs long; `manifest` splices the fuzzed value
into the genesis element of a real receipt's `governance.chain[]` and recomputes the anchor, so
any payload at all reaches the manifest and key statement schema validation the §7.5.1
governance walk runs — there is no standalone entry point for it, and this target reaches it
through the walk rather than inventing one. All three handle every `Result` and index nothing;
a panic reported by one is a defect in the library, never in the harness.

Run them on nightly (libFuzzer needs it), passing the committed seeds as a second corpus
directory:

```sh
cargo +nightly fuzz build
mkdir -p fuzz/corpus/envelope fuzz/corpus/manifest fuzz/corpus/receipt
cargo +nightly fuzz run envelope fuzz/corpus/envelope fuzz/seeds/envelope -- -max_total_time=60
cargo +nightly fuzz run receipt  fuzz/corpus/receipt  fuzz/seeds/receipt  -- -max_total_time=60
cargo +nightly fuzz run manifest fuzz/corpus/manifest fuzz/seeds/manifest -- -max_total_time=60
```

The seeds under `seeds/` are derived from `test_data/`: every statement vector's envelope for
`envelope`, every published `manifest` and `key` payload for `manifest`, and one verifying and
one rejecting receipt per claim type for `receipt`. Pass `test_data/receipts` as a further
corpus directory to start `receipt` from the whole committed corpus. `corpus/` and
`artifacts/` are working directories and are not committed.
