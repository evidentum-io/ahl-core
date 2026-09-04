//! Arbitrary bytes through the Evidence Receipt verifier: JSON, then the whole I-D §7.5
//! algorithm under the corpus trust policy.
//!
//! `verify_receipt_report` is the widest entry point the crate has — version reads, schema
//! validation, the governance induction, enumeration decoding, range and inclusion proofs,
//! closure walks and embedded receipts all sit behind it — and it must return a report, never
//! abort, for any input. The policy is the corpus one, with limits tightened
//! ([`ahl_core_fuzz::FUZZ_LIMITS`]) so a single input cannot spend a long time inside the run.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(receipt) = serde_json::from_slice::<Value>(data) else { return };
    let policy = ahl_core_fuzz::trust_policy();

    // The report form, which completes a run and reports every finding.
    let _ = ahl_core::receipt::verify_receipt_report(&receipt, policy);
    // The single-value form takes a different exit path out of the same run.
    let _ = ahl_core::receipt::verify_receipt(&receipt, policy);
});
