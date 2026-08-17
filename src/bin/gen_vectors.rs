//! Deterministic generator for the AHL Protocol test-vector corpus.
//!
//! Everything this binary emits is a pure function of committed constants: a fixed
//! timestamp, committed 32-byte key seeds, and committed record content. There is no
//! wall-clock read and no randomness anywhere, so running it twice must leave `test_data/`
//! byte-identical.
//!
//! The generator is also its own conformance check. After building the corpus it re-verifies
//! every signature, every checkpoint, every cosignature, every inclusion proof (through
//! `atl_core::core::merkle::verify_inclusion`, never a local reimplementation), and
//! independently recomputes the revocation closure. Any mismatch aborts the run — a vector
//! that cannot be self-verified must never reach the repository.
//!
//! Run with `cargo run --bin gen_vectors`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ahl_core::closure::{affected_set, RecordRef, TreeMaterial};
use ahl_core::{
    checkpoint, checkpoint_signing_bytes, commit_keyed, commit_plain, cosignature_bytes, entry_id,
    envelope, field_str, hash_hex, inclusion_proof, jcs, proof_path_hex, record_sorted, sha256_hex,
    statement_id, tree_root, verify_envelope, verify_inclusion_proof, verify_signature, TestKey,
    AHL_VERSION,
};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Committed constants — the entire entropy budget of this generator
// ---------------------------------------------------------------------------

/// The single timestamp used for every time field in the corpus.
const T0: &str = "2026-08-16T12:00:00Z";

const PRODUCER_1: &str = "producer-1";
const PRODUCER_2: &str = "producer-2";
const WITNESS_1: &str = "witness-1";
const LOG_OPERATOR: &str = "log-operator-1";
const ADAPTOR_ID: &str = "ahl-test-log-v1";
const PIPELINE: &str = "scoring-v1";
const DS_CUSTOMERS: &str = "customers";
const DS_SCORES: &str = "scores";
const LEAF_FORMAT: &str = "ahl-leaf-v2";

/// Log id: `SHA-256("ahl-test-log-1")`.
const LOG_SEED: &[u8] = b"ahl-test-log-1";

/// Test key seeds. Deliberately trivial byte patterns: these are public constants and must
/// be visibly unusable for anything real.
const SEEDS: [(&str, &str); 4] = [
    (PRODUCER_1, "0101010101010101010101010101010101010101010101010101010101010101"),
    (PRODUCER_2, "0202020202020202020202020202020202020202020202020202020202020202"),
    ("log-1", "0303030303030303030303030303030303030303030303030303030303030303"),
    (WITNESS_1, "0404040404040404040404040404040404040404040404040404040404040404"),
];

/// Dataset key for the `keyed` dataset `customers` (spec §2.4).
const DATASET_CUSTOMERS_KEY: &str =
    "0505050505050505050505050505050505050505050505050505050505050505";

const KEYS_README: &str = "\
# Test keys — TEST ONLY

Every file in this directory is a **published constant** of the AHL test-vector corpus.
The seeds are deliberately trivial byte patterns so that no one can mistake them for
generated material.

**Never reuse any of these values for anything real.** They are committed to a public
repository; anyone can sign statements, checkpoints, or witness cosignatures with them,
and anyone can recompute every `keyed` commitment in `test_data/`.

| File | Contents |
| --- | --- |
| `producer-1.seed` | Ed25519 seed, 32 bytes hex — the corpus producer |
| `producer-2.seed` | Ed25519 seed, 32 bytes hex — the key added by entry 9 |
| `log-1.seed` | Ed25519 seed, 32 bytes hex — checkpoint-signing key of the test log |
| `witness-1.seed` | Ed25519 seed, 32 bytes hex — the independent witness (spec §3.3) |
| `dataset_customers.key` | HMAC-SHA-256 key, 32 bytes hex — dataset `customers` (spec §2.4) |

Regenerate the corpus with `cargo run --bin gen_vectors`; the generator rewrites these
files from its own constants, so editing them by hand has no lasting effect.
";

const ADAPTOR_DOC: &str = r#"# Adaptor profile `ahl-test-log-v1`

**Status:** test profile for the AHL Protocol conformance corpus.
**Profile id:** `ahl-test-log-v1`
**Profile hash:** `sha256:<SHA-256 over the exact bytes of this file>`, pinned in the corpus
manifest (`log.adaptor.hash`) and carried in every Evidence Receipt (`anchoring.adaptor.hash`).

This document is the whole of what a verifier needs in order to check the vectors in
`test_data/`. Core specification §3 item 6 requires adaptor profiles to be versioned,
immutable, content-addressed, openly published and independently implementable, and forbids
verification from depending on knowledge outside the profile document. This profile is
deliberately minimal and is **not** a production log binding: it defines serialization only,
and says nothing about availability, cadence enforcement, or operator conduct.

## 1. Hashing

SHA-256 throughout. Family strings follow the receipt format §1.4 conventions:
`"sha256:<lowercase hex>"`, `"hmac-sha256:<lowercase hex>"`, `"base64:<standard base64,
with padding>"`.

## 2. Trees

All AHL trees under this profile — the log tree, batch output trees, input-set trees and
disposition trees — are RFC 6962-style binary Merkle trees over SHA-256 with the domain
separation of core spec §2.5:

```
leaf_hash(b) = SHA-256( 0x00 || b )
node_hash(l, r) = SHA-256( 0x01 || l || r )
```

The root of a tree over `n > 1` leaf hashes splits at `k`, the largest power of two strictly
less than `n`: `root = node_hash(root(leaves[0..k]), root(leaves[k..n]))`. A one-leaf tree's
root is its leaf hash. Empty trees do not occur in this corpus.

### 2.1 Log tree

Leaf bytes are the anchored entry bytes: `JCS(envelope)`, the same bytes the entry id digests.

```
log leaf_hash(i) = SHA-256( 0x00 || JCS(envelope_i) )
```

Log leaves are in **entry-index order** and are never sorted: the entry index is the
position of the entry in the append-only log and is AHL's only ordering primitive
(core spec §1.2, constitution art. 9).

### 2.2 Record-sorted trees

Batch output trees, input-set trees and disposition trees carry leaf **objects**; the leaf
bytes are `JCS(leaf object)`. Their leaves are sorted and duplicate-free per core spec §2.5:

- sort key: the value of the leaf's `record` field, compared as the **byte sequence of the
  family string** (`"sha256:<hex>"` or `"hmac-sha256:<hex>"`), ascending;
- two leaves with equal `record` values make the tree invalid.

Because the sort key is the family string rather than the raw digest, a tree whose leaves mix
commitment modes orders all `hmac-sha256:` records after all `sha256:` records. This profile
does not restrict such trees; it only fixes the ordering so two implementations agree.

Batch output leaves use `leaf_format` `ahl-leaf-v2` (core spec §2.5):
`{ "dataset", "record", "inputs": [ full derivation input objects ] }`.

Disposition leaves use the shape of core spec §2.3.4.

### 2.3 Inclusion proofs

A proof is serialized as a JSON array of family strings, ordered **leaf to root**:

```json
{ "leaf_index": 3, "tree_size": 10, "path": [ "sha256:<hex>", "sha256:<hex>", ... ] }
```

In an Evidence Receipt the same array appears bare as `anchoring.inclusion_path`,
`governance.chain[].inclusion_path`, `claim_material.leaf_path` and
`claim_material.input_members[].input_path`; `leaf_index` and `tree_size` are then taken from
`subject.entry_index` and the checkpoint's `tree_size`, or from the corresponding tree's
committed count.

Verification is the standard RFC 6962 recomputation of the root from the leaf hash and the
path, compared against the anchored root.

## 3. Keys

- **Public key encoding**: `"base64:<raw 32-byte Ed25519 public key>"`. No SPKI, no PEM.
- **Key id**: `"sha256:<hex of SHA-256 over the raw 32-byte public key>"`. The key id is a
  fingerprint, not a signature input; a verifier resolves it against key objects
  `{key_id, pubkey, valid_from_index}` in the manifest (core spec §7.2) and MUST recompute it
  from `pubkey` rather than trusting the carried value.
- **Signature encoding**: `"base64:<raw 64-byte Ed25519 signature>"`, Ed25519 per RFC 8032.

## 4. Statement envelopes

```json
{ "payload": { ... }, "signatures": [ { "keyid": "sha256:<hex>", "sig": "base64:<...>" } ] }
```

The signature covers `JCS(payload)` exactly (core spec §2.1). An envelope with an empty
`signatures` array is not an AHL statement. Consequently:

- **statement id** = `"sha256:" || hex(SHA-256(JCS(payload)))`
- **entry id** = `"sha256:" || hex(SHA-256(JCS(envelope)))`

## 5. Checkpoints

```json
{ "log_id": "sha256:<hex>", "tree_size": 10, "root_hash": "sha256:<hex>",
  "checkpoint_time": "<RFC 3339>", "key_id": "sha256:<hex>", "signature": "base64:<...>" }
```

The log signs `JCS(checkpoint object with the "signature" member removed)`. `log_id` is
`"sha256:" || hex(SHA-256("ahl-test-log-1"))` for the corpus log and MUST match
`log.id` in the manifest version active for the checkpoint's `tree_size`. A checkpoint
commits exactly the entries with index in `[0, tree_size)`.

This profile defines no binary checkpoint framing, so receipts under it MUST NOT carry
`anchoring.checkpoint.raw`.

## 6. Witness cosignatures

A witness (core spec §3.3) cosigns the **signed** checkpoint object, bound to its own
identity so a cosignature cannot be replayed for another witness:

```
cosignature = Ed25519( JCS( { "checkpoint": <signed checkpoint object>,
                              "witness_id": "<witness id>" } ) )
```

Serialized in a receipt as
`{ "witness_id", "key_id", "cosignature": "base64:<...>", "cosigned_at": "<RFC 3339>" }`.

Refusal evidence (core spec §3.3 step 3) is not exercised by this tranche of vectors; its
serialization is left to a later revision of this profile.

## 7. Consistency proofs

Not exercised by this tranche. Receipts under this profile therefore carry
`assurance.continued_history: false` and omit `anchoring.later_checkpoint` and
`anchoring.consistency_path`.

## 8. Authenticated enumeration

Core spec §3 item 5 and receipt format §4.2 require an adaptor-specific range proof for
enumerated governance currency. This profile does not yet define one, so receipts under it
are limited to `governance.currency.mode: "declared"` and to the claim types that permit
declared mode (receipt format §4).
"#;

// ---------------------------------------------------------------------------

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data");
    let keys = write_and_load_keys(&root);
    let dataset_key = load_dataset_key(&root);
    let adaptor_hash = write_and_hash_adaptor(&root);

    let corpus = Corpus::build(&keys, &dataset_key, &adaptor_hash);
    corpus.self_check(&keys);
    corpus.write(&root, &keys);

    println!("test_data written to {}", root.display());
}

// ---------------------------------------------------------------------------
// Keys and the adaptor document
// ---------------------------------------------------------------------------

struct Keys {
    producer_1: TestKey,
    producer_2: TestKey,
    log_1: TestKey,
    witness_1: TestKey,
}

impl Keys {
    /// Resolve `keyid` to a `base64:` public key across every key the corpus declares.
    fn resolve(&self, keyid: &str) -> Option<String> {
        [&self.producer_1, &self.producer_2, &self.log_1, &self.witness_1]
            .into_iter()
            .find(|k| k.key_id() == keyid)
            .map(TestKey::pubkey)
    }
}

fn write_and_load_keys(root: &Path) -> Keys {
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
        witness_1: load(WITNESS_1),
    }
}

fn load_dataset_key(root: &Path) -> Vec<u8> {
    let hex = read_text(&root.join("keys").join("dataset_customers.key"));
    hex::decode(hex.trim()).expect("committed 32-byte hex dataset key")
}

fn write_and_hash_adaptor(root: &Path) -> String {
    let path = root.join("adaptor").join(format!("{ADAPTOR_ID}.md"));
    write_text(&path, ADAPTOR_DOC);
    // Hash the bytes on disk, never the in-memory constant: the pinned hash must be the
    // hash of the published document (spec §3 item 6).
    sha256_hex(&fs::read(&path).expect("adaptor document just written"))
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

struct Corpus {
    /// The ten anchored envelopes, in entry-index order.
    envelopes: Vec<Value>,
    /// `test_data/vectors/statements/NN-<name>.json` basenames, aligned with `envelopes`.
    names: Vec<&'static str>,
    /// Committed tree material keyed by root: batch outputs and dispositions (spec §3.5).
    trees: TreeMaterial,
    batch_root: String,
    affected_root: String,
    /// The record the trigger names.
    trigger_record: RecordRef,
    trigger_statement_id: String,
    /// Records the scenario expects in the affected set, record-sorted.
    expected_affected: Vec<RecordRef>,
    dispositions: Vec<Value>,
    log_id: String,
    checkpoint_8: Value,
    checkpoint_10: Value,
    cosignature_10: String,
    adaptor_hash: String,
    /// Record commitment of S1', the successor that consumes the replacement.
    successor_record: String,
}

impl Corpus {
    #[allow(clippy::too_many_lines)] // One linear scenario; splitting it would obscure the order.
    fn build(keys: &Keys, dataset_key: &[u8], adaptor_hash: &str) -> Self {
        let log_id = sha256_hex(LOG_SEED);

        // --- record content (spec §2.4: canonicalization `jcs-v1`) -----------------
        let keyed = |value: &Value| {
            commit_keyed(dataset_key, DS_CUSTOMERS, &jcs(value)).expect("32-byte dataset key")
        };
        let plain = |value: &Value| commit_plain(DS_SCORES, &jcs(value));

        let c_a = keyed(&json!({ "customer_id": "C-1001", "country": "DE", "segment": "retail" }));
        let c_b = keyed(&json!({ "customer_id": "C-2002", "country": "FR", "segment": "sme" }));
        let c_a2 = keyed(&json!({ "customer_id": "C-1001", "country": "AT", "segment": "retail" }));

        let s1 = plain(&json!({ "customer_id": "C-1001", "model": "risk-v4.2", "score": 712 }));
        let s2 =
            plain(&json!({ "customer_id": "C-1001", "metric": "affordability", "value_bp": 3100 }));
        let s3 =
            plain(&json!({ "customer_id": "C-1001", "metric": "propensity", "value_bp": 6200 }));
        let s4 = plain(&json!({ "customer_id": "C-1001", "metric": "churn", "value_bp": 800 }));
        let s1p = plain(&json!({ "customer_id": "C-1001", "model": "risk-v4.2", "score": 698 }));

        // --- entry 0: the genesis manifest (spec §2.3.5, §7.2) ---------------------
        let manifest_payload = manifest(keys, &log_id, adaptor_hash);
        let env_0 = envelope(manifest_payload, &keys.producer_1);
        let manifest_id = statement_id(&env_0).expect("well-formed envelope");

        // --- entries 1, 2: ingestion of the two source records (spec §2.3.1) -------
        let env_1 = envelope(
            payload(
                "ingestion",
                &manifest_id,
                json!({
                    "dataset": DS_CUSTOMERS, "record": c_a, "origin": "batch:2026-08-16/customers-01",
                }),
            ),
            &keys.producer_1,
        );
        let id_1 = statement_id(&env_1).expect("well-formed envelope");

        let env_2 = envelope(
            payload(
                "ingestion",
                &manifest_id,
                json!({
                    "dataset": DS_CUSTOMERS, "record": c_b, "origin": "batch:2026-08-16/customers-01",
                }),
            ),
            &keys.producer_1,
        );
        let id_2 = statement_id(&env_2).expect("well-formed envelope");

        // --- entry 3: unbatched derivation S1 <- A(feature), B(reference) ----------
        let inputs_s1 = json!([
            { "dataset": DS_CUSTOMERS, "record": c_a, "role": "feature", "statement": id_1 },
            { "dataset": DS_CUSTOMERS, "record": c_b, "role": "reference", "statement": id_2 },
        ]);
        let env_3 = envelope(
            payload(
                "derivation",
                &manifest_id,
                json!({
                    "pipeline": PIPELINE,
                    "outputs": [ { "dataset": DS_SCORES, "record": s1, "locator": "urn:ahl-test:scores/S1" } ],
                    "inputs": inputs_s1,
                    "transform": transform(),
                }),
            ),
            &keys.producer_1,
        );

        // --- entry 4: batch derivation of S2, S3, S4 (spec §2.5) -------------------
        let batch_input = json!([
            { "dataset": DS_CUSTOMERS, "record": c_a, "role": "feature", "statement": id_1 },
        ]);
        let batch_leaves = record_sorted(
            [&s2, &s3, &s4]
                .iter()
                .map(|record| {
                    json!({ "dataset": DS_SCORES, "record": record, "inputs": batch_input })
                })
                .collect(),
        )
        .expect("distinct batch outputs");
        let batch_root = hash_hex(&tree_root(&leaf_bytes(&batch_leaves)));
        let env_4 = envelope(
            payload(
                "derivation",
                &manifest_id,
                json!({
                    "pipeline": PIPELINE,
                    "outputs_root": batch_root,
                    "outputs_count": batch_leaves.len(),
                    "leaf_format": LEAF_FORMAT,
                    "transform": transform(),
                }),
            ),
            &keys.producer_1,
        );

        // --- entry 5: ingestion of the replacement record A2 -----------------------
        let env_5 = envelope(
            payload(
                "ingestion",
                &manifest_id,
                json!({
                    "dataset": DS_CUSTOMERS, "record": c_a2, "origin": "batch:2026-08-16/customers-02",
                }),
            ),
            &keys.producer_1,
        );
        let id_5 = statement_id(&env_5).expect("well-formed envelope");

        // --- entry 6: the trigger, a retroactive correction A -> A2 (spec §2.3.3) --
        let env_6 = envelope(
            payload(
                "correction",
                &manifest_id,
                json!({
                    "dataset": DS_CUSTOMERS,
                    "record": c_a,
                    "replacement": c_a2,
                    "scope": { "effective_from": T0, "retroactive": true },
                    "reason_code": "error",
                }),
            ),
            &keys.producer_1,
        );
        let id_6 = statement_id(&env_6).expect("well-formed envelope");

        // --- entry 7: the successor derivation S1' <- A2, B ------------------------
        let env_7 = envelope(
            payload(
                "derivation",
                &manifest_id,
                json!({
                    "pipeline": PIPELINE,
                    "outputs": [ { "dataset": DS_SCORES, "record": s1p, "locator": "urn:ahl-test:scores/S1-prime" } ],
                    "inputs": [
                        { "dataset": DS_CUSTOMERS, "record": c_a2, "role": "feature", "statement": id_5 },
                        { "dataset": DS_CUSTOMERS, "record": c_b, "role": "reference", "statement": id_2 },
                    ],
                    "transform": transform(),
                }),
            ),
            &keys.producer_1,
        );
        let id_7 = statement_id(&env_7).expect("well-formed envelope");

        // --- entry 8: propagation over a checkpoint committing the trigger --------
        let prefix: Vec<Value> = vec![
            env_0.clone(),
            env_1.clone(),
            env_2.clone(),
            env_3.clone(),
            env_4.clone(),
            env_5.clone(),
            env_6.clone(),
            env_7.clone(),
        ];
        let root_8 = hash_hex(&tree_root(&leaf_bytes(&prefix)));

        let dispositions = record_sorted(vec![
            json!({
                "dataset": DS_SCORES, "record": s1,
                "disposition": "recomputed", "successor_statement": id_7,
            }),
            json!({ "dataset": DS_SCORES, "record": s2, "disposition": "invalidated" }),
            json!({ "dataset": DS_SCORES, "record": s3, "disposition": "invalidated" }),
            json!({ "dataset": DS_SCORES, "record": s4, "disposition": "invalidated" }),
        ])
        .expect("distinct dispositioned records");
        let affected_root = hash_hex(&tree_root(&leaf_bytes(&dispositions)));

        let env_8 = envelope(
            payload(
                "propagation",
                &manifest_id,
                json!({
                    "trigger": id_6,
                    "corpus_checkpoint": { "log_id": log_id, "tree_size": 8, "root_hash": root_8 },
                    "affected_root": affected_root,
                    "affected_count": dispositions.len(),
                    "complete_relative_to_manifest": true,
                }),
            ),
            &keys.producer_1,
        );

        // --- entry 9: key transition adding producer-2 (spec §2.3.6) --------------
        let env_9 = envelope(
            payload(
                "key",
                &manifest_id,
                json!({
                    "action": "add",
                    // Core spec §2.3.6 spells this member `keyid`, while manifest key objects
                    // (§7.2) and the receipt keys block spell it `key_id`; both are reproduced
                    // verbatim so a verifier written from either section matches the vectors.
                    "key": {
                        "keyid": keys.producer_2.key_id(),
                        "pubkey": keys.producer_2.pubkey(),
                        "valid_from": T0,
                    },
                }),
            ),
            &keys.producer_1,
        );

        let envelopes = vec![env_0, env_1, env_2, env_3, env_4, env_5, env_6, env_7, env_8, env_9];
        let root_10 = hash_hex(&tree_root(&leaf_bytes(&envelopes)));

        let cp_8 = checkpoint(&log_id, 8, &root_8, T0, &keys.log_1);
        let cp_10 = checkpoint(&log_id, 10, &root_10, T0, &keys.log_1);
        let cosignature_10 = keys.witness_1.sign(&cosignature_bytes(&cp_10, WITNESS_1));

        let mut trees = TreeMaterial::new();
        trees.insert(batch_root.clone(), batch_leaves);
        trees.insert(affected_root.clone(), dispositions.clone());

        let mut expected_affected: Vec<RecordRef> =
            [&s1, &s2, &s3, &s4].iter().map(|r| (DS_SCORES.to_owned(), (*r).clone())).collect();
        expected_affected.sort();

        Self {
            envelopes,
            names: [
                "00-manifest-genesis",
                "01-ingestion-customers-a",
                "02-ingestion-customers-b",
                "03-derivation-s1",
                "04-derivation-batch",
                "05-ingestion-customers-a2",
                "06-correction-a-to-a2",
                "07-derivation-s1-prime",
                "08-propagation",
                "09-key-add-producer-2",
            ]
            .to_vec(),
            trees,
            batch_root,
            affected_root,
            trigger_record: (DS_CUSTOMERS.to_owned(), c_a),
            trigger_statement_id: id_6,
            expected_affected,
            dispositions,
            log_id,
            checkpoint_8: cp_8,
            checkpoint_10: cp_10,
            cosignature_10,
            adaptor_hash: adaptor_hash.to_owned(),
            successor_record: s1p,
        }
    }

    // -----------------------------------------------------------------------
    // Self-checks: verify or crash
    // -----------------------------------------------------------------------

    fn self_check(&self, keys: &Keys) {
        println!("self-check");

        for (index, env) in self.envelopes.iter().enumerate() {
            let ok = verify_envelope(env, |keyid| keys.resolve(keyid))
                .expect("generated envelope is well-formed");
            assert!(ok, "entry {index}: envelope signature did not verify");
        }
        println!("  [ok] {} envelope signatures verified", self.envelopes.len());

        for (label, cp) in [("cp8", &self.checkpoint_8), ("cp10", &self.checkpoint_10)] {
            let msg = checkpoint_signing_bytes(cp).expect("checkpoint object");
            let sig = field_str(cp, "signature").expect("signed checkpoint");
            let ok = verify_signature(&keys.log_1.verifying_key(), &msg, sig)
                .expect("well-formed signature");
            assert!(ok, "{label}: checkpoint signature did not verify");
            println!("  [ok] {label} checkpoint signature verified (log-1)");
        }

        let cosigned = cosignature_bytes(&self.checkpoint_10, WITNESS_1);
        assert!(
            verify_signature(&keys.witness_1.verifying_key(), &cosigned, &self.cosignature_10)
                .expect("well-formed signature"),
            "cp10: witness cosignature did not verify"
        );
        println!("  [ok] cp10 witness cosignature verified (witness-1)");

        // Inclusion proofs. Every verification below routes through
        // atl_core::core::merkle::verify_inclusion via ahl_core::verify_inclusion_proof.
        let log_leaves = leaf_bytes(&self.envelopes);
        let log_root = tree_root(&log_leaves);
        let proof = inclusion_proof(&log_leaves, 3).expect("entry 3 is in the log");
        assert!(
            verify_inclusion_proof(&log_leaves[3], &proof, &log_root).expect("well-formed proof"),
            "log tree: inclusion proof for entry 3 did not verify"
        );
        println!("  [ok] log-tree inclusion proof for entry 3 at size 10 verified (atl-core)");

        for (label, root_hex) in
            [("batch-tree", &self.batch_root), ("disposition-tree", &self.affected_root)]
        {
            let leaves = self.trees.get(root_hex).expect("tree material present");
            let bytes = leaf_bytes(leaves);
            let root = tree_root(&bytes);
            assert_eq!(&hash_hex(&root), root_hex, "{label}: committed root mismatch");
            for index in 0..bytes.len() {
                let proof = inclusion_proof(&bytes, index).expect("index within tree");
                assert!(
                    verify_inclusion_proof(&bytes[index], &proof, &root)
                        .expect("well-formed proof"),
                    "{label}: inclusion proof for leaf {index} did not verify"
                );
            }
            println!(
                "  [ok] {label}: {} inclusion proofs verified against the committed root (atl-core)",
                bytes.len()
            );
        }

        // Independent closure recomputation over the statement graph (spec §5.1, §5.3).
        let recomputed = affected_set(&self.envelopes, &self.trees, &self.trigger_record, 8)
            .expect("well-formed corpus");
        let expected: BTreeSet<RecordRef> = self.expected_affected.iter().cloned().collect();
        assert_eq!(
            recomputed, expected,
            "recomputed closure differs from the declared affected set"
        );
        assert!(
            !recomputed.contains(&(DS_SCORES.to_owned(), self.successor_record.clone())),
            "S1' consumes the replacement and must not be in the affected set"
        );
        println!(
            "  [ok] closure recomputed independently: {} affected records, matches the \
             disposition tree; S1' correctly excluded",
            recomputed.len()
        );
    }

    // -----------------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_lines)] // A flat list of writes; splitting it adds no clarity.
    fn write(&self, root: &Path, keys: &Keys) {
        let statements = root.join("vectors").join("statements");
        for (index, env) in self.envelopes.iter().enumerate() {
            write_json(
                &statements.join(format!("{}.json", self.names[index])),
                &json!({
                    "entry_index": index,
                    "statement_id": statement_id(env).expect("well-formed envelope"),
                    "entry_id": entry_id(env),
                    "envelope": env,
                }),
            );
        }

        // Malformed statements: structurally parseable, normatively rejectable.
        let malformed = statements.join("malformed");
        let scopeless = envelope(
            payload(
                "retraction",
                &self.manifest_id(),
                json!({
                    "dataset": DS_CUSTOMERS,
                    "record": self.trigger_record.1,
                    "reason_code": "consent_withdrawn",
                }),
            ),
            &keys.producer_1,
        );
        write_json(
            &malformed.join("trigger-without-scope.json"),
            &json!({
                "name": "trigger-without-scope",
                "expect": "reject: core spec §2.3.3 requires `scope` on every trigger — \
                           \"`scope` REQUIRED; scopeless triggers are malformed\"",
                "envelope": scopeless,
            }),
        );

        let unsigned = json!({
            "payload": payload("ingestion", &self.manifest_id(), json!({
                "dataset": DS_CUSTOMERS,
                "record": self.trigger_record.1,
                "origin": "batch:2026-08-16/customers-01",
            })),
            "signatures": [],
        });
        write_json(
            &malformed.join("unsigned-statement.json"),
            &json!({
                "name": "unsigned-statement",
                "expect": "reject: core spec §2.1 requires every statement to be signed at \
                           every level — \"Unsigned objects are not AHL statements\"",
                "envelope": unsigned,
            }),
        );

        // Merkle vectors.
        let merkle = root.join("vectors").join("merkle");
        let log_leaves = leaf_bytes(&self.envelopes);
        let proof_3 = inclusion_proof(&log_leaves, 3).expect("entry 3 is in the log");
        write_json(
            &merkle.join("log-tree.json"),
            &json!({
                "description": "AHL log tree over the 10-entry toy corpus. Leaves are the \
                                anchored entry bytes JCS(envelope) in entry-index order and \
                                are never sorted (core spec §2.5, §1.2).",
                "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
                "leaf_rule": "sha256(0x00 || JCS(envelope))",
                "node_rule": "sha256(0x01 || left || right)",
                "entries": self
                    .envelopes
                    .iter()
                    .enumerate()
                    .map(|(index, env)| json!({
                        "entry_index": index,
                        "entry_id": entry_id(env),
                        "leaf_hash": hash_hex(&ahl_core::leaf_hash(&jcs(env))),
                    }))
                    .collect::<Vec<_>>(),
                "roots": [
                    { "tree_size": 8, "root": field_str(&self.checkpoint_8, "root_hash").expect("signed checkpoint") },
                    { "tree_size": 10, "root": field_str(&self.checkpoint_10, "root_hash").expect("signed checkpoint") },
                ],
                "inclusion": {
                    "leaf_index": 3,
                    "tree_size": 10,
                    "entry_id": entry_id(&self.envelopes[3]),
                    "path": proof_path_hex(&proof_3),
                    "root": field_str(&self.checkpoint_10, "root_hash").expect("signed checkpoint"),
                },
            }),
        );

        write_json(
            &merkle.join("batch-tree.json"),
            &self.tree_vector(
                "Batch derivation output tree of entry 4 (core spec §2.5). Leaves are \
                 `ahl-leaf-v2` objects, record-sorted and duplicate-free; leaf bytes are \
                 JCS(leaf).",
                &self.batch_root,
                "outputs_root",
                "outputs_count",
                Some(LEAF_FORMAT),
            ),
        );

        write_json(
            &merkle.join("disposition-tree.json"),
            &self.tree_vector(
                "Disposition tree committed by the propagation statement at entry 8 \
                 (core spec §2.3.4, §2.5). Leaves are record-sorted disposition objects; \
                 leaf bytes are JCS(leaf).",
                &self.affected_root,
                "affected_root",
                "affected_count",
                None,
            ),
        );

        // Checkpoints.
        write_json(
            &root.join("vectors").join("checkpoints").join("checkpoints.json"),
            &json!({
                "description": "Signed log checkpoints and the witness cosignature over cp10 \
                                (core spec §1.2, §3.3). Signing rules are pinned by the \
                                adaptor profile.",
                "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
                "log": { "log_id": self.log_id, "operator": LOG_OPERATOR, "key_id": keys.log_1.key_id() },
                "checkpoints": [
                    { "name": "cp8", "checkpoint": self.checkpoint_8 },
                    { "name": "cp10", "checkpoint": self.checkpoint_10 },
                ],
                "cosignatures": [ {
                    "checkpoint": "cp10",
                    "witness_id": WITNESS_1,
                    "key_id": keys.witness_1.key_id(),
                    "cosignature": self.cosignature_10,
                    "cosigned_at": T0,
                    "signed_over": "JCS({\"checkpoint\": <signed cp10>, \"witness_id\": \"witness-1\"})",
                } ],
            }),
        );

        // Closure.
        write_json(
            &root.join("vectors").join("closure").join("toy-corpus.json"),
            &json!({
                "description": "Revocation closure over the 10-entry toy corpus (core spec \
                                §5.1, §5.3), evaluated at the checkpoint committing the trigger.",
                "trigger": {
                    "statement_id": self.trigger_statement_id,
                    "entry_index": 6,
                    "type": "correction",
                    "dataset": self.trigger_record.0,
                    "record": self.trigger_record.1,
                    "scope": { "effective_from": T0, "retroactive": true },
                },
                "corpus_checkpoint": {
                    "log_id": self.log_id,
                    "tree_size": 8,
                    "root_hash": field_str(&self.checkpoint_8, "root_hash").expect("signed checkpoint"),
                },
                "expected_affected": self
                    .expected_affected
                    .iter()
                    .map(|(dataset, record)| json!({ "dataset": dataset, "record": record }))
                    .collect::<Vec<_>>(),
                "expected_dispositions": self.dispositions,
                "affected_count": self.dispositions.len(),
                "affected_root": self.affected_root,
                "note": format!(
                    "The derivation at entry 7 produces S1' ({}) from the replacement A2 and \
                     is therefore NOT affected: closure traverses (dataset, record) edges only \
                     (core spec §2.3.2), and S1' never consumed the corrected record. It \
                     appears in the corpus solely as the `successor_statement` of the \
                     `recomputed` disposition of S1.",
                    self.successor_record
                ),
            }),
        );

        // Receipts.
        let receipts = root.join("receipts");
        let valid = self.receipt(keys);
        write_jcs(&receipts.join("statement-anchored-valid.ahl"), &valid);
        write_jcs(&receipts.join("overclaim-must-fail.ahl"), &overclaim(&valid));
    }

    fn manifest_id(&self) -> String {
        statement_id(&self.envelopes[0]).expect("well-formed envelope")
    }

    fn tree_vector(
        &self,
        description: &str,
        root_hex: &str,
        root_field: &str,
        count_field: &str,
        leaf_format: Option<&str>,
    ) -> Value {
        let leaves = self.trees.get(root_hex).expect("tree material present");
        let bytes = leaf_bytes(leaves);
        let proof = inclusion_proof(&bytes, 0).expect("non-empty tree");
        let mut vector = json!({
            "description": description,
            "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
            "leaf_rule": "sha256(0x00 || JCS(leaf))",
            "node_rule": "sha256(0x01 || left || right)",
            "sort_rule": "leaves sorted ascending by the byte sequence of the `record` family \
                          string; duplicates prohibited (core spec §2.5)",
            "leaves": leaves,
            "inclusion": {
                "leaf_index": 0,
                "tree_size": bytes.len(),
                "leaf": leaves[0],
                "path": proof_path_hex(&proof),
                "root": root_hex,
            },
        });
        vector[root_field] = json!(root_hex);
        vector[count_field] = json!(leaves.len());
        if let Some(format) = leaf_format {
            vector["leaf_format"] = json!(format);
        }
        vector
    }

    /// A full `statement-anchored` Evidence Receipt for entry 3 (receipt format §2, §3).
    fn receipt(&self, keys: &Keys) -> Value {
        let log_leaves = leaf_bytes(&self.envelopes);
        let subject = &self.envelopes[3];
        let proof_subject = inclusion_proof(&log_leaves, 3).expect("entry 3 is in the log");
        let proof_genesis = inclusion_proof(&log_leaves, 0).expect("entry 0 is in the log");

        json!({
            "ahl_receipt_version": "1",
            "spec_version": "0.3.0",
            "claim": {
                "type": "statement-anchored",
                // `record_subject` MUST be absent for `statement-anchored` (receipt §3).
                "assurance": {
                    "governance": "declared",
                    "competing_triggers": "not-checked",
                    "witnessed": true,
                    "continued_history": false,
                    "content_binding": "none",
                },
                "note": "Proves that the entry-3 derivation envelope is anchored at entry \
                         index 3 under a witnessed checkpoint and signed under the \
                         producer-declared manifest chain. It asserts nothing about the \
                         truth of the derivation, about competing triggers, or about the \
                         governance state active at index 3.",
            },
            "subject": {
                "statement_id": statement_id(subject).expect("well-formed envelope"),
                "entry_id": entry_id(subject),
                "entry_index": 3,
                "manifest": self.manifest_id(),
            },
            "envelope": subject,
            "keys": {
                "log": [ key_entry(&keys.log_1, None) ],
                "witness": [ key_entry(&keys.witness_1, Some(WITNESS_1)) ],
                "producer": [ key_entry(&keys.producer_1, None) ],
            },
            "anchoring": {
                "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
                "checkpoint": self.checkpoint_10,
                "inclusion_path": proof_path_hex(&proof_subject),
                "witnesses": [ {
                    "witness_id": WITNESS_1,
                    "key_id": keys.witness_1.key_id(),
                    "cosignature": self.cosignature_10,
                    "cosigned_at": T0,
                } ],
            },
            "governance": {
                "genesis_entry_id": entry_id(&self.envelopes[0]),
                "chain": [ {
                    "envelope": self.envelopes[0],
                    "entry_index": 0,
                    "inclusion_path": proof_path_hex(&proof_genesis),
                } ],
                "currency": { "mode": "declared", "material": {} },
            },
            "claim_material": {},
        })
    }
}

/// The deliberately over-claiming receipt: `assurance.governance` is raised to `enumerated`
/// while `governance.currency.mode` stays `declared`.
fn overclaim(valid: &Value) -> Value {
    let mut bad = valid.clone();
    bad["claim"]["assurance"]["governance"] = json!("enumerated");
    bad["claim"]["note"] = json!(
        "MUST FAIL. This receipt claims `assurance.governance: \"enumerated\"` while \
         `governance.currency.mode` remains \"declared\" and no §4 enumeration material is \
         carried. Receipt format §2.3 requires a verifier to reject a receipt where \
         `assurance.governance` does not equal `governance.currency.mode`; §4 additionally \
         permits enumerated mode only with authenticated range enumeration. Every other \
         field is byte-identical to statement-anchored-valid.ahl, so a verifier that accepts \
         this file is not applying the cross-field rule."
    );
    bad
}

fn key_entry(key: &TestKey, witness_id: Option<&str>) -> Value {
    let mut entry = json!({
        "key_id": key.key_id(),
        "pubkey": key.pubkey(),
        // Every key in this receipt is bound to the genesis manifest at entry index 0, the
        // manifest version active for cp10's tree_size (receipt format §2.2).
        "source": "manifest-chain",
        "binding": { "entry_index": 0 },
    });
    if let Some(id) = witness_id {
        entry["witness_id"] = json!(id);
    }
    entry
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Common payload fields (spec §2.2) merged with the type-specific members.
fn payload(kind: &str, manifest_id: &str, extra: Value) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("ahl_version".to_owned(), json!(AHL_VERSION));
    map.insert("type".to_owned(), json!(kind));
    map.insert("producer".to_owned(), json!(PRODUCER_1));
    map.insert("manifest".to_owned(), json!(manifest_id));
    map.insert("valid_time".to_owned(), json!(T0));
    map.insert("issued_at".to_owned(), json!(T0));
    if let Value::Object(extra) = extra {
        map.extend(extra);
    }
    Value::Object(map)
}

/// The genesis manifest payload (spec §2.3.5, §7.2).
///
/// It carries no `manifest` member: a manifest statement declares none, and the genesis
/// manifest additionally has no predecessor reference.
fn manifest(keys: &Keys, log_id: &str, adaptor_hash: &str) -> Value {
    json!({
        "ahl_version": AHL_VERSION,
        "type": "manifest",
        "producer": PRODUCER_1,
        "valid_time": T0,
        "issued_at": T0,
        "level": "L3",
        "keys": [ keys.producer_1.key_object(0) ],
        "log": {
            "id": log_id,
            "operator": LOG_OPERATOR,
            "adaptor": { "id": ADAPTOR_ID, "hash": adaptor_hash },
            "checkpoint_cadence": "PT1H",
            "witness_grace_period": "PT15M",
            "keys": [ keys.log_1.key_object(0) ],
        },
        "witnesses": [ {
            "witness_id": WITNESS_1,
            "keys": [ keys.witness_1.key_object(0) ],
        } ],
        "datasets": {
            DS_CUSTOMERS: {
                "canonicalization": "jcs-v1",
                "commitment_mode": "keyed",
                "key_access": "authorized-verifiers-only",
                "authority": PRODUCER_1,
            },
            DS_SCORES: {
                "canonicalization": "jcs-v1",
                "commitment_mode": "plain",
                "key_access": "not-applicable",
                "authority": PRODUCER_1,
            },
        },
        "pipelines": { "include": [ PIPELINE ], "exclude": [] },
        "windows": { "anchoring": "PT24H", "propagation": "P30D" },
        "retention": { "statements": "P10Y" },
        "properties": { "reproducible_reconstruction": false },
    })
}

/// The transform block shared by every derivation in the corpus (spec §2.3.2).
fn transform() -> Value {
    let params = json!({ "threshold_bp": 5000, "window_days": 90 });
    json!({
        "code": { "digest": sha256_hex(b"ahl-test-code-scoring-v1"), "type": "git_commit" },
        "model": { "digest": sha256_hex(b"ahl-test-model-risk-v4.2"), "version": "risk-v4.2" },
        "params": { "digest": sha256_hex(&jcs(&params)) },
    })
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn leaf_bytes(values: &[Value]) -> Vec<Vec<u8>> {
    values.iter().map(jcs).collect()
}

fn write_text(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output directory");
    }
    fs::write(path, text).expect("write output file");
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).expect("read committed test-data file")
}

/// Write a vector file as pretty JSON. `serde_json`'s default map is ordered, so the
/// serialization is deterministic.
fn write_json(path: &Path, value: &Value) {
    let text = serde_json::to_string_pretty(value).expect("serialize vector");
    write_text(path, &format!("{text}\n"));
}

/// Write a receipt: the file *is* the JCS-canonical serialization (receipt format §1.4), so
/// it is single-line and carries no trailing newline.
fn write_jcs(path: &Path, value: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output directory");
    }
    fs::write(path, jcs(value)).expect("write receipt");
}
