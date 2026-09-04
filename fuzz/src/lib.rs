//! Shared fixtures for the `ahl-core` fuzz targets.
//!
//! Everything here is baked in at build time with `include_str!`, so a target reads no files
//! and does no I/O per input. Every accessor returns an `Option` rather than asserting: a
//! fixture that failed to parse must not be reported as a crash in the library under test.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ahl_core::receipt::{AdaptorCapabilities, AdaptorProfile, Limits, TrustPolicy};
use serde_json::Value;

/// The corpus receipt index, which carries the locally configured trust policy the corpus
/// outcomes assume (receipt format §1 design rule 1).
const RECEIPT_INDEX: &str = include_str!("../../test_data/receipts/index.json");

/// The held adaptor profile document the corpus policy names, by the id it holds it under.
const ADAPTOR_ID: &str = "ahl-test-log-v1";
const ADAPTOR_DOCUMENT: &str = include_str!("../../test_data/adaptor/ahl-test-log-v1.md");

/// The dataset HMAC key an authorized verifier holds for the `customers` dataset.
const DATASET_KEY: &str = include_str!("../../test_data/keys/dataset_customers.key");

/// The genesis manifest vector, as the corpus publishes it.
const GENESIS_MANIFEST: &str =
    include_str!("../../test_data/vectors/statements/00-manifest-genesis.json");

/// Limits tightened well below [`Limits::default`], so a single input cannot spend a long time
/// inside the verifier. The defaults are 8 MiB and 100 000 work units; the whole committed
/// corpus fits inside these.
pub const FUZZ_LIMITS: Limits = Limits { max_decoded_bytes: 256 * 1024, max_work_units: 5_000 };

fn parse(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn flag(value: &Value, pointer: &str) -> bool {
    value.pointer(pointer) == Some(&Value::Bool(true))
}

/// The corpus trust policy, with the tightened [`FUZZ_LIMITS`].
///
/// Built from `test_data/receipts/index.json` — never from any receipt — and holding the
/// adaptor document itself, so the verifier recomputes its digest exactly as a real one would.
/// A policy that cannot be assembled from the baked-in fixtures comes back empty rather than
/// aborting; the target still runs, it just reaches fewer branches.
pub fn trust_policy() -> &'static TrustPolicy {
    static POLICY: OnceLock<TrustPolicy> = OnceLock::new();
    POLICY.get_or_init(|| {
        let index = parse(RECEIPT_INDEX).unwrap_or(Value::Null);
        let policy = index.get("policy").unwrap_or(&Value::Null).clone();

        let genesis_key_ids: BTreeSet<String> = policy
            .get("genesis_key_ids")
            .and_then(Value::as_array)
            .map(|ids| ids.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();

        let capabilities = AdaptorCapabilities {
            checkpoint_raw: flag(
                &policy,
                "/adaptor_profiles/ahl-test-log-v1/capabilities/checkpoint_raw",
            ),
            consistency_proofs: flag(
                &policy,
                "/adaptor_profiles/ahl-test-log-v1/capabilities/consistency_proofs",
            ),
        };

        let mut adaptor_profiles = BTreeMap::new();
        adaptor_profiles.insert(
            ADAPTOR_ID.to_owned(),
            AdaptorProfile { document: ADAPTOR_DOCUMENT.as_bytes().to_vec(), capabilities },
        );

        let mut dataset_keys = BTreeMap::new();
        if let Ok(key) = hex_decode(DATASET_KEY.trim()) {
            dataset_keys.insert("customers".to_owned(), key);
        }

        TrustPolicy {
            genesis_entry_id: policy
                .get("genesis_entry_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            genesis_key_ids: Some(genesis_key_ids),
            adaptor_profiles,
            dataset_keys,
            trusted_witness_keys: BTreeMap::new(),
            limits: FUZZ_LIMITS,
        }
    })
}

/// Decode a lowercase hex string without panicking on odd length or a stray character.
fn hex_decode(text: &str) -> Result<Vec<u8>, ()> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut chars = text.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = high.to_digit(16).ok_or(())?;
        let low = low.to_digit(16).ok_or(())?;
        out.push(u8::try_from(high * 16 + low).map_err(|_| ())?);
    }
    Ok(out)
}

/// The corpus producer keys the genesis manifest declares, as `key_id -> pubkey`.
///
/// This is the fixed resolver the `envelope` target verifies signatures against: a real
/// resolver reads the manifest active at the envelope's entry index, and a fuzz target has no
/// index to read one at.
pub fn producer_keys() -> &'static BTreeMap<String, String> {
    static KEYS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut keys = BTreeMap::new();
        let Some(vector) = parse(GENESIS_MANIFEST) else { return keys };
        let Some(declared) = vector.pointer("/envelope/payload/keys").and_then(Value::as_array)
        else {
            return keys;
        };
        for entry in declared {
            if let (Some(key_id), Some(pubkey)) = (
                entry.get("key_id").and_then(Value::as_str),
                entry.get("pubkey").and_then(Value::as_str),
            ) {
                keys.insert(key_id.to_owned(), pubkey.to_owned());
            }
        }
        keys
    })
}
