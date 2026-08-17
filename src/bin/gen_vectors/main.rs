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
//! Run with `cargo run --bin gen_vectors`.

#![forbid(unsafe_code)]

mod corpus;
mod receipts;
mod scenario;
mod text;

use std::path::PathBuf;

use corpus::Corpus;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data");
    let keys = scenario::write_and_load_keys(&root);
    let dataset_key = scenario::load_dataset_key(&root);
    let adaptor_hash = scenario::write_and_hash_adaptor(&root);

    let corpus = Corpus::build(&keys, &dataset_key, &adaptor_hash);
    corpus.self_check(&keys);
    corpus.write(&root, &keys);
    receipts::write_all(&corpus, &keys, &root, &dataset_key);

    println!("test_data written to {}", root.display());
}
