//! Committed constants, key handling and payload builders for the corpus.

use std::fs;
use std::path::Path;

use ahl_core::{envelope, jcs, sha256_hex, TestKey, AHL_VERSION};
use serde_json::{json, Value};

use crate::text::{ADAPTOR_DOC, CORPUS_README, KEYS_README};

// ---------------------------------------------------------------------------
// Committed constants — the entire entropy budget of this generator
// ---------------------------------------------------------------------------

/// The corpus reference instant. Every `issued_at`, every checkpoint time, and every
/// `valid_time` that has no scenario reason to differ uses exactly this value.
pub const T0: &str = "2026-08-16T12:00:00Z";

/// Valid time of the derivation that predates the non-retroactive retraction's boundary.
pub const T_EARLY: &str = "2026-06-01T00:00:00Z";

/// Lower bound of the open interval that outlives the boundary.
pub const T_OPEN_FROM: &str = "2026-09-01T00:00:00Z";

/// Lower bound of the closed interval that ends before the boundary.
pub const T_PAST_FROM: &str = "2026-05-01T00:00:00Z";

/// Upper bound of the closed interval that ends before the boundary.
pub const T_PAST_TO: &str = "2026-07-01T00:00:00Z";

/// `effective_from` of the non-retroactive retraction at entry 17.
pub const T_RETRACTION: &str = "2026-08-01T00:00:00Z";

/// `key.valid_from` of the producer-key re-add at entry 31.
///
/// Spec §2.1 forbids two envelopes sharing a statement id, and a statement id digests the
/// payload alone, so the re-add cannot repeat the payload of the `add` at entry 28 verbatim.
/// `valid_from` is the member that carries no verification weight — I-D §7.5.1 4b(K) requires
/// it to be present and well formed but says it "never orders anything and never gates a key's
/// activity, both of which are decided by entry index alone" — so it is the honest place to
/// make the two statements distinct.
pub const T_REKEY: &str = "2026-08-16T13:00:00Z";

/// `log.cadence_epoch` — the single start of the checkpoint-series obligation (spec §7.3).
///
/// Spec §7.3 pins the epoch to the corpus's opening interval: the earliest checkpoint
/// committing the genesis manifest MUST carry a `checkpoint_time` at or after `cadence_epoch`
/// and no later than `cadence_epoch` plus that version's `checkpoint_cadence`. Every corpus
/// checkpoint is stamped [`T0`] and the cadence is `PT1H`, so the epoch sits half an hour
/// before [`T0`] — strictly inside that window rather than on either boundary. It is declared
/// by the genesis manifest and repeated unchanged by every later version; the epoch never
/// moves, while a later version MAY change the cadence from its own entry index forward.
pub const T_CADENCE_EPOCH: &str = "2026-08-16T11:30:00Z";

pub const PRODUCER_1: &str = "producer-1";
pub const PRODUCER_2: &str = "producer-2";
pub const WITNESS_1: &str = "witness-1";
pub const WITNESS_2: &str = "witness-2";
pub const LOG_OPERATOR: &str = "log-operator-1";
pub const ADAPTOR_ID: &str = "ahl-test-log-v1";
pub const PIPELINE: &str = "scoring-v1";
pub const DS_CUSTOMERS: &str = "customers";
pub const DS_SCORES: &str = "scores";
pub const LEAF_FORMAT: &str = "ahl-leaf-v2";
pub const CANONICALIZATION: &str = "jcs";

/// Entry index of the manifest version that rotates the LOG checkpoint-signing key.
///
/// Named rather than repeated, because three separate rules read it: which key signs a
/// checkpoint at a given tree size (§7.5.1 4f), which key set a rotation proof must verify
/// under (§7.5.1 4b(M), the OUTGOING set), and which manifest version a receipt binds its
/// `keys.log[]` entries to.
pub const LOG_ROTATION_INDEX: u64 = 55;

/// Entry index of the manifest version that rotates the WITNESS key set (manifest v2).
///
/// A later version that keeps the same witness must repeat the key object v2 declared,
/// `valid_from_index` included: I-D §7.1 compares witness key objects AS A SET, so re-declaring
/// the same key at a new index would read as a rotation of the witness set.
pub const WITNESS_ROTATION_INDEX: u64 = 25;

/// Log id: `SHA-256("ahl-test-log-1")`.
pub const LOG_SEED: &[u8] = b"ahl-test-log-1";

/// Test key seeds. Deliberately trivial byte patterns: these are public constants and must
/// be visibly unusable for anything real.
const SEEDS: [(&str, &str); 6] = [
    (PRODUCER_1, "0101010101010101010101010101010101010101010101010101010101010101"),
    (PRODUCER_2, "0202020202020202020202020202020202020202020202020202020202020202"),
    ("log-1", "0303030303030303030303030303030303030303030303030303030303030303"),
    (WITNESS_1, "0404040404040404040404040404040404040404040404040404040404040404"),
    (WITNESS_2, "0606060606060606060606060606060606060606060606060606060606060606"),
    // The incoming log checkpoint-signing key. The manifest version that installs it replaces
    // `log-1` in `log.keys` outright, which is what makes that version a governance-key
    // rotation on the LOG side (I-D §7.1, §7.5.1 4b(M)).
    ("log-2", "0707070707070707070707070707070707070707070707070707070707070707"),
];

/// Dataset key for the `keyed` dataset `customers` (spec §2.4).
const DATASET_CUSTOMERS_KEY: &str =
    "0505050505050505050505050505050505050505050505050505050505050505";

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Every key the corpus declares.
pub struct Keys {
    pub producer_1: TestKey,
    pub producer_2: TestKey,
    pub log_1: TestKey,
    pub log_2: TestKey,
    pub witness_1: TestKey,
    pub witness_2: TestKey,
}

impl Keys {
    /// Resolve `key_id` to a `base64:` public key across every key the corpus declares.
    pub fn resolve(&self, key_id: &str) -> Option<String> {
        self.all().into_iter().find(|k| k.key_id() == key_id).map(TestKey::pubkey)
    }

    pub fn all(&self) -> Vec<&TestKey> {
        vec![
            &self.producer_1,
            &self.producer_2,
            &self.log_1,
            &self.log_2,
            &self.witness_1,
            &self.witness_2,
        ]
    }

    /// The corpus key with this `key_id`, whatever its role.
    pub fn by_key_id(&self, key_id: &str) -> &TestKey {
        self.all().into_iter().find(|key| key.key_id() == key_id).expect("a corpus key")
    }

    /// The witness key active under a given manifest version entry index.
    pub const fn witness_for(&self, manifest_index: u64) -> (&TestKey, &'static str) {
        if manifest_index == 0 {
            (&self.witness_1, WITNESS_1)
        } else {
            (&self.witness_2, WITNESS_2)
        }
    }

    /// The log checkpoint-signing key a given manifest version declares.
    ///
    /// Every version up to and including manifest v3 declares `log-1`; the version anchored at
    /// [`LOG_ROTATION_INDEX`] replaces it with `log-2`, and every version from that index
    /// onward declares the incoming key alone.
    pub const fn log_for(&self, manifest_index: u64) -> &TestKey {
        if manifest_index >= LOG_ROTATION_INDEX {
            &self.log_2
        } else {
            &self.log_1
        }
    }
}

/// Publish the corpus README alongside the vectors it describes.
pub fn write_corpus_readme(root: &Path) {
    write_text(&root.join("README.md"), CORPUS_README);
}

pub fn write_and_load_keys(root: &Path) -> Keys {
    let dir = root.join("keys");
    write_text(&dir.join("README.md"), KEYS_README);
    for (name, seed) in SEEDS {
        write_text(&dir.join(format!("{name}.seed")), &format!("{seed}\n"));
    }
    write_text(&dir.join("dataset_customers.key"), &format!("{DATASET_CUSTOMERS_KEY}\n"));

    // Load back from disk: the committed files, not the constants, are what the corpus binds to.
    let load = |name: &str| {
        let hex = read_text(&dir.join(format!("{name}.seed")));
        TestKey::from_seed_hex(name, &hex).expect("committed 32-byte hex seed")
    };
    Keys {
        producer_1: load(PRODUCER_1),
        producer_2: load(PRODUCER_2),
        log_1: load("log-1"),
        log_2: load("log-2"),
        witness_1: load(WITNESS_1),
        witness_2: load(WITNESS_2),
    }
}

pub fn load_dataset_key(root: &Path) -> Vec<u8> {
    let hex = read_text(&root.join("keys").join("dataset_customers.key"));
    hex::decode(hex.trim()).expect("committed 32-byte hex dataset key")
}

/// Write the adaptor document, and return `(hash, bytes)` of what actually landed on disk —
/// never the in-memory constant: the pinned hash, and the artifact a `TrustPolicy` holds, must
/// both be the PUBLISHED document (spec §3 item 6; I-D §3.2, §7.5 step 2: a verifier
/// "recompute\[s\] the digest over the artifact rather than trusting any value carried with it").
pub fn write_and_hash_adaptor(root: &Path) -> (String, Vec<u8>) {
    let path = root.join("adaptor").join(format!("{ADAPTOR_ID}.md"));
    write_text(&path, ADAPTOR_DOC);
    let bytes = fs::read(&path).expect("adaptor document just written");
    (sha256_hex(&bytes), bytes)
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Common payload fields (spec §2.2) merged with the type-specific members.
pub fn payload(kind: &str, manifest_id: &str, valid_time: Value, extra: Value) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("ahl_version".to_owned(), json!(AHL_VERSION));
    map.insert("type".to_owned(), json!(kind));
    map.insert("producer".to_owned(), json!(PRODUCER_1));
    map.insert("manifest".to_owned(), json!(manifest_id));
    map.insert("valid_time".to_owned(), valid_time);
    map.insert("issued_at".to_owned(), json!(T0));
    if let Value::Object(extra) = extra {
        map.extend(extra);
    }
    Value::Object(map)
}

/// A statement signed by the corpus producer, with `valid_time` fixed at [`T0`].
pub fn signed(kind: &str, manifest_id: &str, extra: Value, key: &TestKey) -> Value {
    envelope(payload(kind, manifest_id, json!(T0), extra), key)
}

/// A manifest payload (spec §2.3.5, §7.2).
///
/// A manifest statement declares no `manifest` member. The genesis manifest additionally has
/// no `predecessor`; a successor references its predecessor by **entry id**, because signature
/// identity is what matters for governance chain links.
pub fn manifest(
    keys: &Keys,
    log_id: &str,
    adaptor_hash: &str,
    entry_index: u64,
    predecessor_entry_id: Option<&str>,
) -> Value {
    let (witness_key, witness_id) = keys.witness_for(entry_index);
    // Spec §7.2: a manifest's producer `keys` array is the complete producer-key snapshot
    // effective from that manifest's entry index — it *discards* the prior snapshot, and later
    // `key` statements modify it until the next manifest version. Version 2 therefore drops
    // the key the `key` statement at entry 9 added: from entry 23 onward, `producer-2` signs
    // nothing, even though an earlier manifest version once knew it.
    // I-D §6.2: a manifest producer key object is `{key_id, pubkey}` ONLY — the array IS the
    // producer key state at the manifest's entry index, with no per-key `valid_from_index`.
    let producer_keys = vec![keys.producer_1.producer_key_object()];

    let mut payload = json!({
        "ahl_version": AHL_VERSION,
        "type": "manifest",
        "producer": PRODUCER_1,
        "valid_time": T0,
        "issued_at": T0,
        "level": "L3",
        "keys": producer_keys,
        // Spec §7.3 fixes this object's schema and makes every member REQUIRED. The id member
        // is `log_id` — the same spelling the checkpoint carries — and `cadence_epoch` is the
        // fixed start of the checkpoint series, repeated unchanged by every manifest version.
        "log": {
            "log_id": log_id,
            "operator": LOG_OPERATOR,
            "adaptor": { "id": ADAPTOR_ID, "hash": adaptor_hash },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": T_CADENCE_EPOCH,
            "witness_grace_period": "PT15M",
            // I-D §7.1 compares log key objects AS A SET, `valid_from_index` included, so a
            // version that merely re-declares the same key at a new index would read as a
            // rotation. Every version below [`LOG_ROTATION_INDEX`] therefore repeats the
            // genesis object verbatim; the version AT that index declares the incoming key
            // alone, which is the rotation this corpus proves.
            "keys": [ keys.log_for(entry_index).key_object(
                if entry_index >= LOG_ROTATION_INDEX { LOG_ROTATION_INDEX } else { 0 },
            ) ],
        },
        "witnesses": [ {
            "witness_id": witness_id,
            "keys": [ witness_key.key_object(entry_index) ],
        } ],
        "datasets": {
            DS_CUSTOMERS: {
                "canonicalization": CANONICALIZATION,
                "commitment_mode": "keyed",
                "key_access": "authorized-verifiers-only",
                // Spec §1.2 defines the dataset authority as "the key set entitled to issue
                // triggers", so it is carried as a key set rather than a bare producer id.
                // Only `producer-1` may retract a `customers` record; a trigger signed by any
                // other key anchors as a challenge (§2.3.3) and is never traversed.
                "authority": {
                    "producer": PRODUCER_1,
                    "key_ids": [ keys.producer_1.key_id() ],
                },
            },
            DS_SCORES: {
                "canonicalization": CANONICALIZATION,
                "commitment_mode": "plain",
                // Nothing is ingested into `scores`: every record in it is produced by a
                // derivation, so spec §7.2 permits the dataset authority to be omitted.
                "key_access": "not-applicable",
            },
        },
        "pipelines": { "include": [ PIPELINE ], "exclude": [] },
        "windows": { "anchoring": "PT24H", "propagation": "P30D" },
        "retention": { "statements": "P10Y" },
        "properties": { "reproducible_reconstruction": false },
    });
    if let Some(entry_id) = predecessor_entry_id {
        payload["predecessor"] = json!(entry_id);
    }
    payload
}

/// The transform block shared by every derivation in the corpus (spec §2.3.2).
pub fn transform() -> Value {
    let params = json!({ "threshold_bp": 5000, "window_days": 90 });
    json!({
        "code": { "digest": sha256_hex(b"ahl-test-code-scoring-v1"), "type": "git_commit" },
        "model": { "digest": sha256_hex(b"ahl-test-model-risk-v4.2"), "version": "risk-v4.2" },
        "params": { "digest": sha256_hex(&jcs(&params)) },
    })
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

pub fn write_text(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output directory");
    }
    fs::write(path, text).expect("write output file");
}

pub fn read_text(path: &Path) -> String {
    fs::read_to_string(path).expect("read committed test-data file")
}

/// Write a vector file as pretty JSON. `serde_json`'s default map is ordered, so the
/// serialization is deterministic.
pub fn write_json(path: &Path, value: &Value) {
    let text = serde_json::to_string_pretty(value).expect("serialize vector");
    write_text(path, &format!("{text}\n"));
}

/// Write a receipt: the file *is* the JCS-canonical serialization (receipt format §1.4), so
/// it is single-line and carries no trailing newline.
pub fn write_jcs(path: &Path, value: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output directory");
    }
    fs::write(path, jcs(value)).expect("write receipt");
}

pub fn leaf_bytes(values: &[Value]) -> Vec<Vec<u8>> {
    values.iter().map(jcs).collect()
}
