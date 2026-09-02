//! Deterministic generator for the AHL Protocol test-vector corpus.
//!
//! Everything this binary emits is a pure function of committed constants: fixed timestamps,
//! committed 32-byte key seeds, and committed record content. There is no wall-clock read and
//! no randomness anywhere, so running it twice must leave `test_data/` byte-identical.
//!
//! The generator is also its own conformance check. After building the corpus it re-verifies
//! every signature, every checkpoint, every cosignature, every inclusion proof (through
//! `atl_core::core::merkle::verify_inclusion`, never a local reimplementation), every range
//! proof, the witness refusal evidence, and independently recomputes all three revocation
//! closures — then runs every generated receipt through `ahl_core::receipt::verify_receipt` and
//! asserts the expected verdict. Any mismatch aborts the run: a vector that cannot be
//! self-verified must never reach the repository.
//!
//! Run with `cargo run --bin gen_vectors`, or `cargo run --bin gen_vectors -- <output dir>` to
//! write elsewhere — the latter is what proves determinism in CI (see
//! `tests/vectors.rs::the_generator_is_deterministic_across_runs`), by writing to two fresh
//! temporary directories and asserting they are byte-identical to each other and to the
//! committed `test_data/`, rather than relying on this doc comment's claim alone.

#![forbid(unsafe_code)]

mod atl;
mod corpus;
mod receipts;
mod scenario;
mod text;

use std::path::PathBuf;

use corpus::Corpus;

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data"), PathBuf::from);
    scenario::write_corpus_readme(&root);
    let keys = scenario::write_and_load_keys(&root);
    let dataset_key = scenario::load_dataset_key(&root);
    let adaptor_hash = scenario::write_and_hash_adaptor(&root);

    let corpus = Corpus::build(&keys, &dataset_key, &adaptor_hash);
    corpus.self_check(&keys);
    corpus.write(&root, &keys);
    receipts::write_all(&corpus, &keys, &root, &dataset_key);
    atl::write_all(&keys, &root);

    println!("test_data written to {}", root.display());
}
