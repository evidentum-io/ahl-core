//! Arbitrary bytes as a governance statement payload, validated as the I-D §7.5.1 walk
//! validates one.
//!
//! `validate_governance_payload` is the seam the crate exposes under its `fuzzing` feature for
//! exactly this: the version read, §2.2's common payload fields, and then — for a `manifest` —
//! the producer key objects, the `log` object and its restricted duration grammar, `datasets`,
//! §6.2's scope members, and `witnesses`; for a `key`, the whole of 4b(K)'s form check. None
//! of it may panic on any input.
//!
//! Reaching the same code through `verify_receipt_report` is not possible for arbitrary bytes:
//! §7.5 step 3 verifies each chain hop's inclusion path against the checkpoint root before the
//! walk reads a payload, so an edited one is rejected as an unanchored hop first. The
//! `receipt` target covers that path with the corpus payloads intact.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(payload) = serde_json::from_slice::<Value>(data) else { return };
    let _ = ahl_core::receipt::validate_governance_payload(&payload);
});
