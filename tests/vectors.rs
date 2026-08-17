//! Conformance tests over the generated corpus in `test_data/`.
//!
//! These tests read only what a downstream implementation in any language would read — the
//! files on disk — and re-derive every claim the corpus makes: identifiers, signatures,
//! inclusion proofs (through `atl-core`), the revocation closure, and the receipt cross-field
//! rules of the Evidence Receipt format §2.3.
//!
//! Regenerate the corpus with `cargo run --bin gen_vectors` before running these.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ahl_core::closure::{affected_set, RecordRef, TreeMaterial};
use ahl_core::{
    checkpoint_signing_bytes, cosignature_bytes, decode_pubkey, entry_id, field_str, jcs,
    parse_hash_hex, proof_from_hex, statement_id, verify_envelope, verify_inclusion_proof,
    verify_signature,
};
use serde_json::Value;

const STATEMENT_FILES: [&str; 10] = [
    "00-manifest-genesis.json",
    "01-ingestion-customers-a.json",
    "02-ingestion-customers-b.json",
    "03-derivation-s1.json",
    "04-derivation-batch.json",
    "05-ingestion-customers-a2.json",
    "06-correction-a-to-a2.json",
    "07-derivation-s1-prime.json",
    "08-propagation.json",
    "09-key-add-producer-2.json",
];

fn test_data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data")
}

fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The ten statement vectors, in entry-index order.
fn statement_vectors() -> Vec<Value> {
    let dir = test_data().join("vectors").join("statements");
    STATEMENT_FILES.iter().map(|name| read_json(&dir.join(name))).collect()
}

fn envelopes(vectors: &[Value]) -> Vec<Value> {
    vectors.iter().map(|v| v["envelope"].clone()).collect()
}

/// Every `keyid -> pubkey` binding declared by the genesis manifest (spec §7.2), plus the
/// producer key added by the `key` statement at entry 9 (spec §2.3.6).
fn key_set(vectors: &[Value]) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    let manifest = &vectors[0]["envelope"]["payload"];

    let mut absorb = |objects: &Value| {
        for object in objects.as_array().expect("key objects are an array") {
            let key_id = field_str(object, "key_id").expect("key object carries key_id");
            let pubkey = field_str(object, "pubkey").expect("key object carries pubkey");
            keys.insert(key_id.to_owned(), pubkey.to_owned());
        }
    };
    absorb(&manifest["keys"]);
    absorb(&manifest["log"]["keys"]);
    for witness in manifest["witnesses"].as_array().expect("witnesses are an array") {
        absorb(&witness["keys"]);
    }

    let added = &vectors[9]["envelope"]["payload"]["key"];
    // Core spec §2.3.6 spells the member `keyid` inside a `key` statement.
    keys.insert(
        field_str(added, "keyid").expect("key statement carries keyid").to_owned(),
        field_str(added, "pubkey").expect("key statement carries pubkey").to_owned(),
    );
    keys
}

/// Tree material for closure recomputation, recovered from the merkle vectors on disk.
fn tree_material() -> TreeMaterial {
    let dir = test_data().join("vectors").join("merkle");
    let mut trees = TreeMaterial::new();
    for (file, root_field) in
        [("batch-tree.json", "outputs_root"), ("disposition-tree.json", "affected_root")]
    {
        let vector = read_json(&dir.join(file));
        let root = field_str(&vector, root_field).expect("tree vector carries its root");
        let leaves = vector["leaves"].as_array().expect("tree vector carries leaves").clone();
        trees.insert(root.to_owned(), leaves);
    }
    trees
}

#[test]
fn statement_and_entry_ids_are_reproducible() {
    for (index, vector) in statement_vectors().iter().enumerate() {
        let env = &vector["envelope"];
        assert_eq!(
            vector["entry_index"].as_u64(),
            Some(index as u64),
            "{}: entry_index must equal the file's position",
            STATEMENT_FILES[index]
        );
        assert_eq!(
            field_str(vector, "statement_id").expect("vector carries statement_id"),
            statement_id(env).expect("well-formed envelope"),
            "{}: statement_id is not SHA-256(JCS(payload))",
            STATEMENT_FILES[index]
        );
        assert_eq!(
            field_str(vector, "entry_id").expect("vector carries entry_id"),
            entry_id(env),
            "{}: entry_id is not SHA-256(JCS(envelope))",
            STATEMENT_FILES[index]
        );
    }
}

#[test]
fn every_statement_binds_to_the_genesis_manifest() {
    let vectors = statement_vectors();
    let manifest_id = field_str(&vectors[0], "statement_id").expect("vector carries statement_id");

    // A manifest statement declares no `manifest` member (spec §2.2, receipt §2.3).
    assert!(
        vectors[0]["envelope"]["payload"].get("manifest").is_none(),
        "the genesis manifest must not declare a `manifest` member"
    );
    for vector in &vectors[1..] {
        assert_eq!(
            field_str(&vector["envelope"]["payload"], "manifest")
                .expect("payload carries manifest"),
            manifest_id
        );
    }
}

#[test]
fn every_statement_signature_verifies() {
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    for (index, vector) in vectors.iter().enumerate() {
        let ok = verify_envelope(&vector["envelope"], |keyid| keys.get(keyid).cloned())
            .expect("well-formed envelope");
        assert!(ok, "{}: signature did not verify", STATEMENT_FILES[index]);
    }
}

#[test]
fn malformed_vectors_are_rejectable_and_say_why() {
    let dir = test_data().join("vectors").join("statements").join("malformed");

    let scopeless = read_json(&dir.join("trigger-without-scope.json"));
    assert!(
        field_str(&scopeless, "expect").expect("vector carries expect").contains("§2.3.3"),
        "the expectation must name the violated rule"
    );
    assert!(
        scopeless["envelope"]["payload"].get("scope").is_none(),
        "the vector must actually lack `scope`"
    );

    let unsigned = read_json(&dir.join("unsigned-statement.json"));
    assert!(
        field_str(&unsigned, "expect").expect("vector carries expect").contains("§2.1"),
        "the expectation must name the violated rule"
    );
    assert!(
        !verify_envelope(&unsigned["envelope"], |_| None).expect("well-formed envelope"),
        "an envelope with no signatures is not an AHL statement"
    );
}

#[test]
fn log_tree_inclusion_proof_verifies_through_atl_core() {
    let vectors = statement_vectors();
    let tree = read_json(&test_data().join("vectors").join("merkle").join("log-tree.json"));

    // The vector's entry ids must match the statement vectors it claims to index.
    for (index, entry) in tree["entries"].as_array().expect("entries").iter().enumerate() {
        assert_eq!(
            field_str(entry, "entry_id").expect("entry carries entry_id"),
            field_str(&vectors[index], "entry_id").expect("vector carries entry_id")
        );
    }

    let inclusion = &tree["inclusion"];
    let leaf_index = inclusion["leaf_index"].as_u64().expect("leaf_index");
    let tree_size = inclusion["tree_size"].as_u64().expect("tree_size");
    let path: Vec<String> = inclusion["path"]
        .as_array()
        .expect("path")
        .iter()
        .map(|h| h.as_str().expect("path element is a string").to_owned())
        .collect();

    let leaf =
        jcs(&vectors[usize::try_from(leaf_index).expect("leaf index fits in usize")]["envelope"]);
    let proof = proof_from_hex(leaf_index, tree_size, &path).expect("well-formed path");
    let root = parse_hash_hex(field_str(inclusion, "root").expect("root")).expect("root hash");
    assert!(
        verify_inclusion_proof(&leaf, &proof, &root).expect("well-formed proof"),
        "log-tree inclusion proof did not verify"
    );
}

#[test]
fn record_sorted_tree_proofs_verify_through_atl_core() {
    let dir = test_data().join("vectors").join("merkle");
    for (file, root_field, count_field) in [
        ("batch-tree.json", "outputs_root", "outputs_count"),
        ("disposition-tree.json", "affected_root", "affected_count"),
    ] {
        let vector = read_json(&dir.join(file));
        let leaves = vector["leaves"].as_array().expect("leaves");
        assert_eq!(
            vector[count_field].as_u64(),
            Some(leaves.len() as u64),
            "{file}: {count_field} disagrees with the carried leaf set"
        );

        // Spec §2.5: leaves sorted by `record`, duplicates prohibited.
        let records: Vec<&str> =
            leaves.iter().map(|l| field_str(l, "record").expect("leaf carries record")).collect();
        let mut sorted = records.clone();
        sorted.sort_unstable();
        assert_eq!(records, sorted, "{file}: leaves are not record-sorted");
        assert_eq!(
            records.iter().collect::<BTreeSet<_>>().len(),
            records.len(),
            "{file}: duplicate records"
        );

        let inclusion = &vector["inclusion"];
        let leaf_index = inclusion["leaf_index"].as_u64().expect("leaf_index");
        let path: Vec<String> = inclusion["path"]
            .as_array()
            .expect("path")
            .iter()
            .map(|h| h.as_str().expect("path element is a string").to_owned())
            .collect();
        let proof = proof_from_hex(leaf_index, leaves.len() as u64, &path).expect("valid path");
        let root =
            parse_hash_hex(field_str(&vector, root_field).expect("root")).expect("root hash");
        assert!(
            verify_inclusion_proof(
                &jcs(&leaves[usize::try_from(leaf_index).expect("leaf index fits in usize")]),
                &proof,
                &root
            )
            .expect("well-formed proof"),
            "{file}: inclusion proof did not verify"
        );
    }
}

#[test]
fn checkpoints_and_the_witness_cosignature_verify() {
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    let file = read_json(&test_data().join("vectors").join("checkpoints").join("checkpoints.json"));

    for entry in file["checkpoints"].as_array().expect("checkpoints") {
        let cp = &entry["checkpoint"];
        let key_id = field_str(cp, "key_id").expect("checkpoint carries key_id");
        let pubkey = keys.get(key_id).expect("checkpoint key is declared by the manifest");
        let msg = checkpoint_signing_bytes(cp).expect("checkpoint object");
        let sig = field_str(cp, "signature").expect("signed checkpoint");
        assert!(
            verify_signature(&decode_pubkey(pubkey).expect("manifest pubkey"), &msg, sig)
                .expect("well-formed signature"),
            "{}: checkpoint signature did not verify",
            field_str(entry, "name").expect("named checkpoint")
        );
    }

    let cp10 = file["checkpoints"]
        .as_array()
        .expect("checkpoints")
        .iter()
        .find(|c| field_str(c, "name").ok() == Some("cp10"))
        .expect("cp10 is present");
    for cosignature in file["cosignatures"].as_array().expect("cosignatures") {
        let witness_id = field_str(cosignature, "witness_id").expect("witness_id");
        let pubkey = keys
            .get(field_str(cosignature, "key_id").expect("key_id"))
            .expect("witness key is declared by the manifest");
        let msg = cosignature_bytes(&cp10["checkpoint"], witness_id);
        assert!(
            verify_signature(
                &decode_pubkey(pubkey).expect("manifest pubkey"),
                &msg,
                field_str(cosignature, "cosignature").expect("cosignature"),
            )
            .expect("well-formed signature"),
            "{witness_id}: cosignature did not verify"
        );
    }
}

#[test]
fn closure_matches_the_declared_affected_set() {
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);
    let expectation =
        read_json(&test_data().join("vectors").join("closure").join("toy-corpus.json"));

    let trigger = &expectation["trigger"];
    let record: RecordRef = (
        field_str(trigger, "dataset").expect("dataset").to_owned(),
        field_str(trigger, "record").expect("record").to_owned(),
    );
    let through =
        usize::try_from(expectation["corpus_checkpoint"]["tree_size"].as_u64().expect("tree_size"))
            .expect("tree size fits in usize");

    let recomputed = affected_set(&envelopes, &tree_material(), &record, through)
        .expect("corpus and tree material are complete");
    let declared: BTreeSet<RecordRef> = expectation["expected_affected"]
        .as_array()
        .expect("expected_affected")
        .iter()
        .map(|r| {
            (
                field_str(r, "dataset").expect("dataset").to_owned(),
                field_str(r, "record").expect("record").to_owned(),
            )
        })
        .collect();

    assert_eq!(recomputed, declared, "recomputed closure differs from the declared affected set");

    // Every affected record is dispositioned exactly once (spec §2.3.4, §5.4).
    let dispositions = expectation["expected_dispositions"].as_array().expect("dispositions");
    assert_eq!(dispositions.len(), declared.len());
    let dispositioned: BTreeSet<RecordRef> = dispositions
        .iter()
        .map(|d| {
            (
                field_str(d, "dataset").expect("dataset").to_owned(),
                field_str(d, "record").expect("record").to_owned(),
            )
        })
        .collect();
    assert_eq!(dispositioned, declared);

    // The successor consuming the replacement is outside the affected set.
    let successor = &vectors[7]["envelope"]["payload"]["outputs"][0];
    let successor_ref: RecordRef = (
        field_str(successor, "dataset").expect("dataset").to_owned(),
        field_str(successor, "record").expect("record").to_owned(),
    );
    assert!(
        !recomputed.contains(&successor_ref),
        "S1' consumes the replacement and must not be affected"
    );
}

#[test]
fn propagation_statement_agrees_with_the_disposition_tree() {
    let vectors = statement_vectors();
    let payload = &vectors[8]["envelope"]["payload"];
    let tree = read_json(&test_data().join("vectors").join("merkle").join("disposition-tree.json"));

    assert_eq!(
        field_str(payload, "affected_root").expect("affected_root"),
        field_str(&tree, "affected_root").expect("affected_root")
    );
    assert_eq!(payload["affected_count"], tree["affected_count"]);
    assert_eq!(
        field_str(payload, "trigger").expect("trigger"),
        field_str(&vectors[6], "statement_id").expect("statement_id"),
        "the propagation must name the correction at entry 6"
    );

    // The corpus checkpoint must commit the trigger's entry (spec §2.3.4).
    let tree_size = payload["corpus_checkpoint"]["tree_size"].as_u64().expect("tree_size");
    assert!(tree_size > vectors[6]["entry_index"].as_u64().expect("entry_index"));
}

// ---------------------------------------------------------------------------
// Evidence Receipts
// ---------------------------------------------------------------------------

fn read_receipt(name: &str) -> (Vec<u8>, Value) {
    let path = test_data().join("receipts").join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let value: Value = serde_json::from_slice(&bytes).expect("receipt parses");
    (bytes, value)
}

#[test]
fn receipts_are_jcs_canonical_on_disk() {
    for name in ["statement-anchored-valid.ahl", "overclaim-must-fail.ahl"] {
        let (bytes, value) = read_receipt(name);
        assert_eq!(bytes, jcs(&value), "{name}: file is not its own JCS serialization");
    }
}

#[test]
fn valid_receipt_verifies_end_to_end() {
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");

    // Receipt §5 step 1: recompute the identifiers from the carried envelope.
    let env = &receipt["envelope"];
    assert_eq!(
        field_str(&receipt["subject"], "statement_id").expect("statement_id"),
        statement_id(env).expect("well-formed envelope")
    );
    assert_eq!(field_str(&receipt["subject"], "entry_id").expect("entry_id"), entry_id(env));

    // Receipt §2.3: assurance.governance must equal governance.currency.mode.
    assert_eq!(
        field_str(&receipt["claim"]["assurance"], "governance").expect("governance"),
        field_str(&receipt["governance"]["currency"], "mode").expect("mode"),
        "cross-field rule violated in the receipt that must pass"
    );

    // Receipt §3: `record_subject` MUST be absent for `statement-anchored`.
    assert_eq!(field_str(&receipt["claim"], "type").expect("claim type"), "statement-anchored");
    assert!(receipt["claim"].get("record_subject").is_none());

    // Receipt §2.2: every carried key must be one the manifest declares.
    for group in ["log", "witness", "producer"] {
        for key in receipt["keys"][group].as_array().expect("key group is an array") {
            let key_id = field_str(key, "key_id").expect("key_id");
            assert_eq!(
                keys.get(key_id).map(String::as_str),
                Some(field_str(key, "pubkey").expect("pubkey")),
                "{group} key {key_id} is not declared by the manifest"
            );
        }
    }

    // Receipt §5 step 3: checkpoint signature, cosignature, entry_index < tree_size, inclusion.
    let cp = &receipt["anchoring"]["checkpoint"];
    let log_pubkey =
        keys.get(field_str(cp, "key_id").expect("key_id")).expect("checkpoint key is declared");
    assert!(verify_signature(
        &decode_pubkey(log_pubkey).expect("manifest pubkey"),
        &checkpoint_signing_bytes(cp).expect("checkpoint object"),
        field_str(cp, "signature").expect("signature"),
    )
    .expect("well-formed signature"));

    let tree_size = cp["tree_size"].as_u64().expect("tree_size");
    let entry_index = receipt["subject"]["entry_index"].as_u64().expect("entry_index");
    assert!(entry_index < tree_size);

    let witnesses = receipt["anchoring"]["witnesses"].as_array().expect("witnesses");
    assert!(!witnesses.is_empty(), "assurance.witnessed is true, so a cosignature is required");
    for cosignature in witnesses {
        let pubkey = keys
            .get(field_str(cosignature, "key_id").expect("key_id"))
            .expect("witness key is declared");
        assert!(verify_signature(
            &decode_pubkey(pubkey).expect("manifest pubkey"),
            &cosignature_bytes(cp, field_str(cosignature, "witness_id").expect("witness_id")),
            field_str(cosignature, "cosignature").expect("cosignature"),
        )
        .expect("well-formed signature"));
    }
    assert_eq!(receipt["claim"]["assurance"]["witnessed"], Value::Bool(true));

    // §2.3: continued_history is true iff later_checkpoint + consistency_path verify.
    assert_eq!(receipt["claim"]["assurance"]["continued_history"], Value::Bool(false));
    assert!(receipt["anchoring"].get("later_checkpoint").is_none());
    assert!(receipt["anchoring"].get("consistency_path").is_none());

    let root = parse_hash_hex(field_str(cp, "root_hash").expect("root_hash")).expect("root hash");
    let path: Vec<String> = receipt["anchoring"]["inclusion_path"]
        .as_array()
        .expect("inclusion_path")
        .iter()
        .map(|h| h.as_str().expect("path element is a string").to_owned())
        .collect();
    let proof = proof_from_hex(entry_index, tree_size, &path).expect("well-formed path");
    assert!(
        verify_inclusion_proof(&jcs(env), &proof, &root).expect("well-formed proof"),
        "subject inclusion proof did not verify"
    );

    // Receipt §5 step 4: the governance chain must start at the configured genesis anchor
    // and each hop must prove its own inclusion.
    assert_eq!(
        field_str(&receipt["governance"], "genesis_entry_id").expect("genesis_entry_id"),
        field_str(&vectors[0], "entry_id").expect("entry_id"),
        "genesis anchor must match the locally configured policy value"
    );
    for hop in receipt["governance"]["chain"].as_array().expect("chain") {
        let index = hop["entry_index"].as_u64().expect("entry_index");
        let path: Vec<String> = hop["inclusion_path"]
            .as_array()
            .expect("inclusion_path")
            .iter()
            .map(|h| h.as_str().expect("path element is a string").to_owned())
            .collect();
        let proof = proof_from_hex(index, tree_size, &path).expect("well-formed path");
        assert!(
            verify_inclusion_proof(&jcs(&hop["envelope"]), &proof, &root)
                .expect("well-formed proof"),
            "governance chain hop {index} is not anchored under the checkpoint"
        );
        assert!(verify_envelope(&hop["envelope"], |keyid| keys.get(keyid).cloned())
            .expect("well-formed envelope"));
    }
}

#[test]
fn overclaiming_receipt_violates_the_cross_field_rule() {
    let (_, receipt) = read_receipt("overclaim-must-fail.ahl");

    let claimed = field_str(&receipt["claim"]["assurance"], "governance").expect("governance");
    let mode = field_str(&receipt["governance"]["currency"], "mode").expect("mode");
    assert_eq!(claimed, "enumerated");
    assert_eq!(mode, "declared");
    assert_ne!(
        claimed, mode,
        "receipt format §2.3 requires assurance.governance == governance.currency.mode; \
         this vector must fail that check"
    );

    // §4: enumerated mode additionally requires authenticated range enumeration material.
    assert_eq!(
        receipt["governance"]["currency"]["material"],
        serde_json::json!({}),
        "no enumeration material is carried, so the enumerated claim is unsupported twice over"
    );

    // Everything else must be byte-identical to the valid receipt, so the only thing a
    // verifier can be failing on is the cross-field rule.
    let (_, mut valid) = read_receipt("statement-anchored-valid.ahl");
    let mut bad = receipt;
    valid["claim"]["assurance"]["governance"] = Value::Null;
    valid["claim"]["note"] = Value::Null;
    bad["claim"]["assurance"]["governance"] = Value::Null;
    bad["claim"]["note"] = Value::Null;
    assert_eq!(valid, bad, "the negative vector must differ only in the over-claimed fields");
}

#[test]
fn adaptor_profile_hash_is_pinned_by_the_manifest() {
    let vectors = statement_vectors();
    let adaptor = &vectors[0]["envelope"]["payload"]["log"]["adaptor"];
    let id = field_str(adaptor, "id").expect("adaptor id");
    let bytes = std::fs::read(test_data().join("adaptor").join(format!("{id}.md")))
        .expect("adaptor profile document is published alongside the vectors");
    assert_eq!(
        field_str(adaptor, "hash").expect("adaptor hash"),
        ahl_core::sha256_hex(&bytes),
        "the manifest must pin the hash of the published adaptor document (spec §3 item 6)"
    );

    // The same id and hash must be carried in the receipt (spec §6.5, receipt §2).
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    assert_eq!(receipt["anchoring"]["adaptor"], *adaptor);
}
