//! A minimal, SEPARATE corpus pinned to adaptor profile `ahl-adaptor-atl-v1`, distinct from
//! the main corpus's `ahl-test-log-v1` (I-D §3.2's profile dispatch; adaptor
//! `ahl-adaptor-atl-v1` §6 "Checkpoints"). Two anchored entries — a genesis manifest and one
//! ingestion — one checkpoint, whose Ed25519 signature is over the 98-byte blob adaptor §6.1
//! defines, never `JCS(checkpoint minus "signature")` (that is `ahl-test-log-v1`'s own form,
//! its §5).
//!
//! Simplification, deliberate and noted: this crate does not (this round) dispatch LEAF
//! HASHING or ENTRY CONSTRUCTION by adaptor profile — only checkpoint authentication. Real ATL
//! leaves combine a payload hash with a fixed metadata hash (adaptor §4.2); this corpus's log
//! tree instead uses the one generic leaf hash (`SHA-256(0x00 || JCS(envelope))`) every other
//! corpus in this repository uses, because `check_inclusion`/`verify_inclusion_proof` have no
//! profile parameter to dispatch on. That is out of this round's scope (profile-dispatched
//! CHECKPOINT authentication only) and is noted in the README's not-yet list.

use std::collections::BTreeMap;
use std::path::Path;

use ahl_core::receipt::{
    verify_receipt, AdaptorCapabilities, AdaptorProfile, ReceiptError, TrustPolicy,
};
use ahl_core::{
    atl_checkpoint, atl_checkpoint_blob, cosignature_bytes, entry_id, envelope, hash_hex,
    inclusion_proof, jcs, parse_hash_hex, sha256_hex, statement_id, tree_root,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::receipts::key_entry;
use crate::scenario::{self, write_jcs, write_json, write_text, Keys, DS_CUSTOMERS, T0};

const ATL_ADAPTOR_ID: &str = "ahl-adaptor-atl-v1";

/// The adaptor doc's own §6.4 worked example instant: `2026-01-01T00:00:00.123456789Z`.
/// Reusing it here, rather than inventing a fresh value, means the corpus doubles as a
/// worked cross-check of that example.
const ATL_TIMESTAMP_NS: u64 = 1_767_225_600_123_456_789;

fn base64_of(bytes: &[u8]) -> String {
    format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// What a vector asserts about its own verification outcome (mirrors `receipts::Expect`; a
/// separate, tiny corpus does not need that module's full generality).
enum Expect {
    Accept,
    Reject { rule: &'static str, matches: fn(&ReceiptError) -> bool },
}

struct Vector {
    file: &'static str,
    receipt: Value,
    expect: Expect,
}

/// Every field the receipt needs beyond its own `anchoring.checkpoint`, common to all three
/// vectors this module builds.
struct Fixture {
    env_0: Value,
    env_1: Value,
    m1: String,
    genesis_entry_id: String,
    path_0: Vec<String>,
    path_1: Vec<String>,
    witness_cosignature: String,
    adaptor_hash: String,
}

fn build_receipt(fixture: &Fixture, keys: &Keys, checkpoint: &Value) -> Value {
    json!({
        "ahl_receipt_version": "2",
        "spec_version": "0.4.0",
        "claim": {
            "type": "statement-anchored",
            "assurance": {
                "governance": "declared",
                "witnessed": true,
                "continued_history": false,
                "competing_triggers": "not-checked",
                "content_binding": "none",
            },
            "note": "ATL-adaptor-profile positive vector (I-D §3.2 profile dispatch; adaptor \
                     `ahl-adaptor-atl-v1` §6): proves the entry-1 ingestion is anchored under \
                     a checkpoint signed over the 98-byte ATL blob (§6.1, §6.5), reconciled \
                     against a carried `raw` (§6.4) byte-for-byte, never over \
                     `ahl-test-log-v1`'s JCS form.",
        },
        "subject": {
            "statement_id": statement_id(&fixture.env_1).expect("well-formed envelope"),
            "entry_id": entry_id(&fixture.env_1),
            "entry_index": 1,
            "manifest": fixture.m1,
        },
        "envelope": fixture.env_1,
        "keys": {
            "log": [ key_entry(&keys.log_1, None, 0) ],
            "witness": [ key_entry(&keys.witness_1, Some("witness-1"), 0) ],
            "producer": [ key_entry(&keys.producer_1, None, 0) ],
        },
        "anchoring": {
            "adaptor": { "id": ATL_ADAPTOR_ID, "hash": fixture.adaptor_hash },
            "checkpoint": checkpoint,
            "inclusion_path": fixture.path_1,
            "witnesses": [ {
                "witness_id": "witness-1",
                "key_id": keys.witness_1.key_id(),
                "cosignature": fixture.witness_cosignature,
                "cosigned_at": T0,
            } ],
        },
        "governance": {
            "genesis_entry_id": fixture.genesis_entry_id,
            "chain": [
                { "envelope": fixture.env_0, "entry_index": 0, "inclusion_path": fixture.path_0 },
            ],
            "currency": { "mode": "declared", "material": {} },
        },
        "claim_material": {},
    })
}

// One linear scenario — genesis, ingestion, tree, checkpoint, three vectors, self-check —
// splitting it would only scatter state that has to travel together anyway (see `Fixture`).
#[allow(clippy::too_many_lines)]
pub fn write_all(keys: &Keys, root: &Path) {
    let atl_root = root.join("atl");

    // Hash what is actually PUBLISHED (core spec §3 item 6: content-addressed, independently
    // implementable) — the real companion document, copied verbatim from its own source of
    // truth rather than restated, exactly as `ahl-test-log-v1` hashes ITS committed document
    // (`scenario::write_and_hash_adaptor`).
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs-md/ahl-adaptor-atl-v1.md");
    let text = std::fs::read_to_string(&source)
        .unwrap_or_else(|e| panic!("read {}: {e}", source.display()));
    let adaptor_path = atl_root.join("adaptor").join(format!("{ATL_ADAPTOR_ID}.md"));
    write_text(&adaptor_path, &text);
    let adaptor_hash = sha256_hex(&std::fs::read(&adaptor_path).expect("just-written file"));

    let log_id = sha256_hex(b"ahl-atl-test-log-1");

    // `scenario::manifest` hardcodes the corpus's own `ADAPTOR_ID` ("ahl-test-log-v1") — it
    // takes only the hash as a parameter — so this repins the `id` half after building the
    // payload, before signing.
    let mut genesis_payload = scenario::manifest(keys, &log_id, &adaptor_hash, 0, None);
    genesis_payload["log"]["adaptor"]["id"] = json!(ATL_ADAPTOR_ID);
    let env_0 = envelope(genesis_payload, &keys.producer_1);
    let m1 = statement_id(&env_0).expect("well-formed envelope");
    let genesis_entry_id = entry_id(&env_0);

    let record = format!("hmac-sha256:{}", &sha256_hex(b"atl-corpus-record-1")[7..]);
    let env_1 = scenario::signed(
        "ingestion",
        &m1,
        json!({ "dataset": DS_CUSTOMERS, "record": record, "origin": "batch:atl-corpus-01" }),
        &keys.producer_1,
    );

    let leaves = vec![jcs(&env_0), jcs(&env_1)];
    let root_hash = hash_hex(&tree_root(&leaves));
    let path_0: Vec<String> =
        inclusion_proof(&leaves, 0).expect("index within tree").path.iter().map(hash_hex).collect();
    let path_1: Vec<String> =
        inclusion_proof(&leaves, 1).expect("index within tree").path.iter().map(hash_hex).collect();

    let checkpoint = atl_checkpoint(&log_id, 2, &root_hash, ATL_TIMESTAMP_NS, &keys.log_1)
        .expect("valid family strings");
    let origin_bytes = parse_hash_hex(&log_id).expect("valid family string");
    let root_bytes = parse_hash_hex(&root_hash).expect("valid family string");
    let blob = atl_checkpoint_blob(&origin_bytes, 2, ATL_TIMESTAMP_NS, &root_bytes);
    let raw = base64_of(&blob);

    let mut valid_checkpoint = checkpoint.clone();
    valid_checkpoint["raw"] = json!(raw);

    // The witness cosigns "the signed checkpoint object, INCLUDING its signature member"
    // (adaptor §11.1) — the object AS IT APPEARS IN THE RECEIPT, `raw` included, since
    // `cosignature_bytes` JCS-serializes whatever `Value` it is handed wholesale and a
    // verifier hands it exactly `anchoring.checkpoint` as carried.
    let witness_cosignature =
        keys.witness_1.sign(&cosignature_bytes(&valid_checkpoint, "witness-1"));

    let fixture = Fixture {
        env_0,
        env_1,
        m1,
        genesis_entry_id: genesis_entry_id.clone(),
        path_0,
        path_1,
        witness_cosignature,
        adaptor_hash: adaptor_hash.clone(),
    };

    let policy = TrustPolicy {
        genesis_entry_id,
        genesis_key_ids: None,
        adaptor_profiles: BTreeMap::from([(
            ATL_ADAPTOR_ID.to_owned(),
            AdaptorProfile {
                hash: adaptor_hash.clone(),
                capabilities: AdaptorCapabilities {
                    checkpoint_raw: true,
                    consistency_proofs: false,
                },
            },
        )]),
        ..TrustPolicy::default()
    };

    let valid = build_receipt(&fixture, keys, &valid_checkpoint);

    // Negative: `raw` corrupted (one flipped bit in the decoded blob, inside the root-hash
    // field) while the JSON checkpoint members, and the log's own signature over them, stay
    // genuinely valid — adaptor §6.4/§6.5: "compare it byte for byte with the assembled blob;
    // a mismatch is a rejection."
    let mut corrupted_blob = blob;
    corrupted_blob[70] ^= 0x01;
    let mut raw_mismatch_checkpoint = checkpoint.clone();
    raw_mismatch_checkpoint["raw"] = json!(base64_of(&corrupted_blob));
    let raw_mismatch = build_receipt(&fixture, keys, &raw_mismatch_checkpoint);

    // Negative: `raw` stays the blob the log GENUINELY signed, but a JSON sibling member —
    // `tree_size` — is altered afterward. The JSON members govern (I-D §7.5 step 2); a `raw`
    // that no longer matches them is rejected exactly as if `raw` itself had been corrupted,
    // even though here `raw` is the one field that did NOT change.
    let mut altered_checkpoint = checkpoint;
    altered_checkpoint["tree_size"] = json!(3);
    altered_checkpoint["raw"] = json!(raw);
    let json_altered = build_receipt(&fixture, keys, &altered_checkpoint);

    let vectors = vec![
        Vector { file: "atl-statement-anchored-valid.ahl", receipt: valid, expect: Expect::Accept },
        Vector {
            file: "atl-checkpoint-raw-blob-mismatch-must-fail.ahl",
            receipt: raw_mismatch,
            expect: Expect::Reject {
                rule: "adaptor `ahl-adaptor-atl-v1` §6.4/§6.5 — raw MUST equal the assembled \
                       blob",
                matches: |e| matches!(e, ReceiptError::Malformed(detail) if detail.contains("does not equal the blob assembled")),
            },
        },
        Vector {
            file: "atl-checkpoint-raw-json-altered-must-fail.ahl",
            receipt: json_altered,
            expect: Expect::Reject {
                rule: "adaptor `ahl-adaptor-atl-v1` §6.4/§6.5 — the JSON members govern; a \
                       correctly-signed raw does not rehabilitate an altered member",
                matches: |e| matches!(e, ReceiptError::Malformed(detail) if detail.contains("does not equal the blob assembled")),
            },
        },
    ];

    println!("atl adaptor self-check");
    let dir = atl_root.join("receipts");
    let mut index = Vec::new();
    for vector in &vectors {
        let outcome = verify_receipt(&vector.receipt, &policy);
        match &vector.expect {
            Expect::Accept => {
                let verdict = outcome.unwrap_or_else(|error| {
                    panic!("{}: must verify, but was rejected: {error}", vector.file)
                });
                println!("  [ok] {} accepted: {}", vector.file, verdict.claim_type);
                index.push(json!({
                    "file": vector.file,
                    "claim_type": verdict.claim_type,
                    "expect": "accept",
                }));
            }
            Expect::Reject { rule, matches } => {
                let error = outcome
                    .err()
                    .unwrap_or_else(|| panic!("{}: must be rejected, but verified", vector.file));
                assert!(
                    matches(&error),
                    "{}: rejected by the wrong rule — expected {rule}, got: {error}",
                    vector.file
                );
                println!("  [ok] {} rejected by {rule}: {error}", vector.file);
                index.push(json!({
                    "file": vector.file,
                    "expect": "reject",
                    "rule": rule,
                    "reason": error.to_string(),
                }));
            }
        }
        write_jcs(&dir.join(vector.file), &vector.receipt);
    }

    write_json(
        &dir.join("index.json"),
        &json!({
            "description": "A minimal, separate corpus pinned to adaptor profile \
                            `ahl-adaptor-atl-v1` (I-D §3.2), for testing profile-dispatched \
                            checkpoint authentication distinctly from the main corpus's \
                            `ahl-test-log-v1`. See `atl/adaptor/ahl-adaptor-atl-v1.md`.",
            "policy": {
                "genesis_entry_id": fixture.genesis_entry_id,
                "adaptor_profiles": {
                    ATL_ADAPTOR_ID: {
                        "hash": adaptor_hash,
                        "capabilities": { "checkpoint_raw": true, "consistency_proofs": false },
                    },
                },
            },
            "vectors": index,
        }),
    );
}
