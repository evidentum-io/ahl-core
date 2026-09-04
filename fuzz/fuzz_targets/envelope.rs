//! Arbitrary bytes through the AHL envelope path: JSON, then the two identifiers of I-D §2.1
//! and the signature check every carried statement is put through.
//!
//! What is under test is the reader, not the corpus: `statement_id` canonicalizes the payload,
//! `entry_id` canonicalizes the whole envelope, and `verify_envelope` walks `signatures[]`,
//! decodes each `pubkey` and each `sig`, and verifies. None of the three may panic on any
//! input, however malformed — nesting, duplicate members, non-string identifiers, signature
//! entries of the wrong shape, or values no AHL statement would ever carry.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = serde_json::from_slice::<Value>(data) else { return };

    // Identifiers first: both are defined over canonical bytes alone and take no key.
    let _ = ahl_core::statement_id(&envelope);
    let _ = ahl_core::entry_id(&envelope);

    // A fixed resolver — the corpus producer keys the genesis manifest declares. A key id the
    // fuzzer invents resolves to nothing, which is the `KeyNotResolved` path; one it copies
    // from the corpus reaches decoding and verification.
    let _ = ahl_core::verify_envelope(&envelope, |key_id| {
        ahl_core_fuzz::producer_keys().get(key_id).cloned()
    });
    let _ = ahl_core::check_envelope(&envelope, |key_id| {
        ahl_core_fuzz::producer_keys().get(key_id).cloned()
    });
});
