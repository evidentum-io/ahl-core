//! Conformance tests over the generated corpus in `test_data/`.
//!
//! These tests read only what a downstream implementation in any language would read — the
//! files on disk — and re-derive every claim the corpus makes: identifiers, signatures,
//! inclusion proofs and range proofs (through `atl-core`), the three revocation closures, the
//! witness refusal evidence, and every Evidence Receipt.
//!
//! Receipts are checked by running them through [`ahl_core::receipt::verify_receipt`], not by
//! comparing fields by hand: the verifier is the thing under test. Every negative vector must
//! be rejected by the specific rule its `test_data/receipts/index.json` entry names.
//!
//! Regenerate the corpus with `cargo run --bin gen_vectors` before running these.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ahl_core::bitemporal::{Scope, ValidTime};
use ahl_core::closure::{affected_set, RecordRef, TreeMaterial};
use ahl_core::descriptor;
use ahl_core::receipt::{
    verify_receipt, AdaptorCapabilities, AdaptorProfile, Limits, ReceiptError, TrustPolicy,
    TrustedWitnessKey,
};
use ahl_core::tree::ValidatedLeafSet;
use ahl_core::{
    checkpoint, checkpoint_signing_bytes, cosignature_bytes, decode_pubkey, entry_id, field_str,
    hash_hex, inclusion_proof, jcs, leaf_hash, parse_hash_hex, proof_from_hex, proof_path_hex,
    range_proof, sha256_hex, statement_id, tree_root, verify_envelope, verify_inclusion_proof,
    verify_signature, TestKey,
};
use serde_json::{json, Value};

/// The statement vectors, in entry-index order. Entry 28 is an intentional non-verifying-
/// signature fixture: well-formed shape, real authority `key_id`, garbage `sig`. Entry 29 adds
/// a second, genuinely valid signature entry from a non-authority key alongside a non-verifying
/// authority-named one. Entry 30 re-adds `producer-2` to the producer snapshot; entry 31 is a
/// trigger genuinely CO-SIGNED by both the authority and `producer-2`.
const STATEMENT_FILES: [&str; 33] = [
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
    "10-derivation-batch-wide-inputs.json",
    "11-ingestion-customers-a3.json",
    "12-correction-a-to-a3-superseding.json",
    "13-ingestion-customers-c.json",
    "14-derivation-e1-point-past.json",
    "15-derivation-e2-open-interval.json",
    "16-derivation-e3-closed-past-interval.json",
    "17-retraction-c-non-retroactive.json",
    "18-retraction-a-original-after-correction.json",
    "19-retraction-s1-prime-derived-authority.json",
    "20-ingestion-customers-f.json",
    "21-derivation-h-from-f.json",
    "22-retraction-f-authorized.json",
    "23-challenge-retraction-f-unauthorized.json",
    "24-propagation-over-challenge.json",
    "25-manifest-v2-rotate-witness-drop-key.json",
    "26-ingestion-customers-d-under-v2.json",
    "27-derivation-z-from-affected-descendant.json",
    "28-invalid-signature-trigger-f.json",
    "29-unverified-authority-signature-trigger-f.json",
    "30-key-readd-producer-2.json",
    "31-retraction-f-co-signed-authority-and-producer-2.json",
    "32-ingestion-customers-e-stale-manifest.json",
];

/// The four published closure scenarios.
const CLOSURE_FILES: [&str; 6] = [
    "toy-corpus.json",
    "supersession-chain.json",
    "non-retroactive-retraction.json",
    "retraction-after-correction.json",
    "derived-record-authority-after-rotation.json",
    "descendant-enlargement-past-declared-checkpoint.json",
];

const TREE_VECTORS: [(&str, &str, &str); 5] = [
    ("batch-tree.json", "outputs_root", "outputs_count"),
    ("wide-outputs-tree.json", "outputs_root", "outputs_count"),
    ("input-set-tree.json", "input_set_root", "input_set_count"),
    ("disposition-tree.json", "affected_root", "affected_count"),
    ("challenge-disposition-tree.json", "affected_root", "affected_count"),
];

fn test_data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data")
}

fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn statement_vectors() -> Vec<Value> {
    let dir = test_data().join("vectors").join("statements");
    STATEMENT_FILES.iter().map(|name| read_json(&dir.join(name))).collect()
}

fn envelopes(vectors: &[Value]) -> Vec<Value> {
    vectors.iter().map(|v| v["envelope"].clone()).collect()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array of strings")
        .iter()
        .map(|h| h.as_str().expect("string element").to_owned())
        .collect()
}

/// Every `key_id -> pubkey` binding either manifest version declares, plus the producer key
/// added by the `key` statement at entry 9 (spec §2.3.6, §7.2).
fn key_set(vectors: &[Value]) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    let mut absorb = |objects: &Value| {
        for object in objects.as_array().expect("key objects are an array") {
            keys.insert(
                field_str(object, "key_id").expect("key object carries key_id").to_owned(),
                field_str(object, "pubkey").expect("key object carries pubkey").to_owned(),
            );
        }
    };
    for index in [0usize, 25] {
        let manifest = &vectors[index]["envelope"]["payload"];
        absorb(&manifest["keys"]);
        absorb(&manifest["log"]["keys"]);
        for witness in manifest["witnesses"].as_array().expect("witnesses are an array") {
            absorb(&witness["keys"]);
        }
    }
    let added = &vectors[9]["envelope"]["payload"]["key"];
    keys.insert(
        field_str(added, "key_id").expect("key statement carries key_id").to_owned(),
        field_str(added, "pubkey").expect("key statement carries pubkey").to_owned(),
    );
    keys
}

/// Tree material for closure recomputation, recovered from the merkle vectors on disk.
fn tree_material() -> TreeMaterial {
    let dir = test_data().join("vectors").join("merkle");
    let mut trees = TreeMaterial::new();
    for (file, root_field, _) in TREE_VECTORS {
        let vector = read_json(&dir.join(file));
        let root = field_str(&vector, root_field).expect("tree vector carries its root");
        let leaves = vector["leaves"].as_array().expect("tree vector carries leaves").clone();
        trees.insert(root.to_owned(), leaves);
    }
    trees
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

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
fn every_statement_binds_to_the_manifest_version_active_at_its_entry_index() {
    let vectors = statement_vectors();
    let m1 = field_str(&vectors[0], "statement_id").expect("vector carries statement_id");
    let m2 = field_str(&vectors[25], "statement_id").expect("vector carries statement_id");

    // A manifest statement declares no `manifest` member (spec §2.2, receipt §2.3).
    for index in [0usize, 25] {
        assert!(
            vectors[index]["envelope"]["payload"].get("manifest").is_none(),
            "a manifest statement must not declare a `manifest` member"
        );
    }
    for (index, vector) in vectors.iter().enumerate() {
        if index == 0 || index == 25 {
            continue;
        }
        // Entry 32 is the ONE deliberate exception: I-D §2.2 §7.6's negative vector
        // (`record-ingested-stale-manifest-must-fail.ahl`) needs a statement that is
        // genuinely signed and genuinely anchored, yet wrongly bound — see `corpus.rs`'s own
        // entry 32 and the assertion right after this loop.
        if index == 32 {
            continue;
        }
        // The manifest version id is the manifest statement's *statement id* (spec §2.3.5).
        let expected = if index < 25 { m1 } else { m2 };
        assert_eq!(
            field_str(&vector["envelope"]["payload"], "manifest")
                .expect("payload carries manifest"),
            expected,
            "{}: must bind to the manifest version active at its entry index",
            STATEMENT_FILES[index]
        );
    }

    // The exception, made explicit: entry 32 wrongly names v1 (`m1`) even though v2 (`m2`) is
    // active at its entry index — I-D §2.2's "greatest entry index smaller than the
    // statement's own" resolves to v2 there, not v1. This is what
    // `record-ingested-stale-manifest-must-fail.ahl` proves the verifier catches.
    assert_eq!(
        field_str(&vectors[32]["envelope"]["payload"], "manifest")
            .expect("payload carries manifest"),
        m1,
        "entry 32 must wrongly name v1 — that is the defect the stale-manifest vector proves \
         is caught"
    );
    assert_ne!(
        field_str(&vectors[32]["envelope"]["payload"], "manifest")
            .expect("payload carries manifest"),
        m2,
        "entry 32's wrong binding must not accidentally be correct"
    );
}

#[test]
fn the_manifest_log_object_carries_every_required_member() {
    let vectors = statement_vectors();
    let published =
        read_json(&test_data().join("vectors").join("checkpoints").join("checkpoints.json"));

    let mut epochs = BTreeSet::new();
    for index in [0usize, 25] {
        let log = &vectors[index]["envelope"]["payload"]["log"];

        // Spec §7.3 names the id member `log_id` and makes every member REQUIRED. `id` is not
        // an accepted spelling and must not appear: a silent alias is how two incompatible
        // dialects of one manifest come to coexist.
        assert!(log.get("id").is_none(), "the manifest log id member is spelled `log_id`");
        for member in
            ["log_id", "operator", "checkpoint_cadence", "cadence_epoch", "witness_grace_period"]
        {
            assert!(
                log.get(member).and_then(Value::as_str).is_some(),
                "manifest at entry {index} omits the REQUIRED `log.{member}` (spec §7.3)"
            );
        }
        assert!(log["adaptor"].get("id").is_some() && log["adaptor"].get("hash").is_some());
        assert!(log["keys"].is_array());

        // §7.3: durations are restricted to time components — years and calendar months are
        // PROHIBITED, since their length is context-dependent.
        for member in ["checkpoint_cadence", "witness_grace_period"] {
            let value = field_str(log, member).expect("duration");
            let (date_part, _) = value.split_once('T').unwrap_or((value, ""));
            assert!(
                !date_part.contains('Y') && !date_part.contains('M'),
                "`log.{member}` = `{value}` carries a calendar component (spec §7.3)"
            );
        }
        epochs.insert(field_str(log, "cadence_epoch").expect("cadence_epoch").to_owned());

        // The checkpoint every receipt binds to must name the log this manifest declares.
        for entry in published["checkpoints"].as_array().expect("checkpoints") {
            assert_eq!(
                field_str(&entry["checkpoint"], "log_id").expect("log_id"),
                field_str(log, "log_id").expect("log_id"),
                "the checkpoint `log_id` and the manifest `log.log_id` are one value"
            );
        }
    }

    // §7.3: the epoch is declared by the genesis manifest and repeated unchanged by every later
    // version — it anchors the start of the series and never moves.
    assert_eq!(epochs.len(), 1, "every manifest version repeats one `cadence_epoch`");

    // And it is not free-floating: the earliest checkpoint committing the genesis manifest must
    // fall within [cadence_epoch, cadence_epoch + checkpoint_cadence]. The corpus cadence is
    // PT1H and every checkpoint is stamped at the same instant, so the window is one hour wide.
    let genesis_log = &vectors[0]["envelope"]["payload"]["log"];
    assert_eq!(field_str(genesis_log, "checkpoint_cadence").expect("cadence"), "PT1H");
    let epoch = field_str(genesis_log, "cadence_epoch").expect("cadence_epoch");
    let earliest = published["checkpoints"].as_array().expect("checkpoints")[0]["checkpoint"]
        ["checkpoint_time"]
        .as_str()
        .expect("checkpoint_time");
    assert_eq!(epoch, "2026-08-16T11:30:00Z");
    assert_eq!(earliest, "2026-08-16T12:00:00Z");
}

#[test]
fn no_two_anchored_envelopes_share_a_statement_id() {
    // Spec §2.1: "A producer MUST NOT anchor two envelopes with the same statement id; if
    // duplicates occur, the one with the smallest entry index governs and later ones are void."
    // A corpus that broke this could not demonstrate the rules it exists for — a vector
    // asserting that some later entry governs would be asserting the opposite of §2.1.
    let vectors = statement_vectors();
    let mut statements: BTreeMap<String, usize> = BTreeMap::new();
    let mut entries: BTreeMap<String, usize> = BTreeMap::new();
    for (index, vector) in vectors.iter().enumerate() {
        let sid = field_str(vector, "statement_id").expect("statement_id").to_owned();
        if let Some(first) = statements.insert(sid.clone(), index) {
            panic!(
                "{} and {} share statement id {sid}, which §2.1 voids the later of",
                STATEMENT_FILES[first], STATEMENT_FILES[index]
            );
        }
        let eid = field_str(vector, "entry_id").expect("entry_id").to_owned();
        if let Some(first) = entries.insert(eid.clone(), index) {
            panic!(
                "{} and {} share entry id {eid}",
                STATEMENT_FILES[first], STATEMENT_FILES[index]
            );
        }
    }
    assert_eq!(statements.len(), STATEMENT_FILES.len());
    assert_eq!(entries.len(), STATEMENT_FILES.len());

    // The three retractions of record F that exist to exercise signature handling — the
    // non-verifying one, the one whose authority-named entry does not verify, and the genuinely
    // co-signed one — are distinct statements, not one statement anchored three times.
    let f_triggers: Vec<&Value> = [28usize, 29, 31].iter().map(|i| &vectors[*i]).collect();
    let records: BTreeSet<&str> = f_triggers
        .iter()
        .map(|v| field_str(&v["envelope"]["payload"], "record").expect("record"))
        .collect();
    assert_eq!(records.len(), 1, "all three name the same record, as the scenario requires");
    let ids: BTreeSet<&str> =
        f_triggers.iter().map(|v| field_str(v, "statement_id").expect("statement_id")).collect();
    assert_eq!(ids.len(), 3, "and each is nevertheless its own statement");
}

#[test]
fn the_manifest_chain_links_by_entry_id_and_rotates_the_witness_set() {
    let vectors = statement_vectors();
    let genesis = &vectors[0]["envelope"];
    let successor = &vectors[25]["envelope"]["payload"];

    assert!(
        genesis["payload"].get("predecessor").is_none(),
        "the genesis manifest has no predecessor reference (spec §2.3.5)"
    );
    // A non-genesis manifest references its predecessor by *entry* id: signature identity is
    // what matters for chain links (spec §2.3.5).
    assert_eq!(
        field_str(successor, "predecessor").expect("successor carries predecessor"),
        entry_id(genesis)
    );
    assert_ne!(
        field_str(successor, "predecessor").expect("successor carries predecessor"),
        field_str(&vectors[0], "statement_id").expect("vector carries statement_id"),
        "the predecessor reference must be the entry id, not the statement id"
    );

    // §7.2: each manifest version's witness key objects replace the prior set in full.
    let witnesses = |payload: &Value| {
        payload["witnesses"]
            .as_array()
            .expect("witnesses")
            .iter()
            .map(|w| field_str(w, "witness_id").expect("witness_id").to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(witnesses(&vectors[0]["envelope"]["payload"]), vec!["witness-1".to_owned()]);
    assert_eq!(witnesses(successor), vec!["witness-2".to_owned()]);
}

#[test]
fn every_statement_signature_verifies() {
    // Entries 28 and 29 are intentional non-verifying-signature fixtures: well-formed shape,
    // real authority `key_id`, garbage `sig` (entry 29 also carries a second, genuinely valid
    // entry from a non-authority key). Every other entry must genuinely verify; these two must
    // not.
    const NON_VERIFYING: [usize; 2] = [28, 29];
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    for (index, vector) in vectors.iter().enumerate() {
        let ok = verify_envelope(&vector["envelope"], |key_id| keys.get(key_id).cloned())
            .expect("well-formed envelope");
        if NON_VERIFYING.contains(&index) {
            assert!(
                !ok,
                "{}: the non-verifying-signature fixture must NOT verify",
                STATEMENT_FILES[index]
            );
        } else {
            assert!(ok, "{}: signature did not verify", STATEMENT_FILES[index]);
        }
    }
}

#[test]
fn envelope_signature_members_are_spelled_key_id() {
    for (index, vector) in statement_vectors().iter().enumerate() {
        for signature in
            vector["envelope"]["signatures"].as_array().expect("signatures are an array")
        {
            assert!(
                signature.get("key_id").is_some() && signature.get("keyid").is_none(),
                "{}: the envelope signature member is spelled `key_id` (spec §2.1)",
                STATEMENT_FILES[index]
            );
        }
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
        Scope::from_payload(&scopeless["envelope"]["payload"]).is_err(),
        "a scopeless trigger must be rejected, never defaulted to retroactive"
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

    // I-D revision 0.4 §2.6: a dataset id containing a control octet — 0x1F or 0x7F — is
    // syntactically invalid. Each vector's manifest carries exactly one such dataset id, and
    // `descriptor::validate_dataset_id` (the primitive `datasets_object` calls at manifest
    // validation time) must reject it as a `DatasetIdControlOctet`, never as a plain syntax
    // violation, since these bytes are the specific case §2.6 calls load-bearing.
    for (file, octet_name) in [
        ("dataset-id-control-octet-0x1f.json", "0x1F"),
        ("dataset-id-control-octet-0x7f.json", "0x7F"),
    ] {
        let vector = read_json(&dir.join(file));
        assert!(
            field_str(&vector, "expect").expect("vector carries expect").contains("§2.6"),
            "{file}: the expectation must name the violated rule"
        );
        let datasets = vector["envelope"]["payload"]["datasets"]
            .as_object()
            .expect("manifest datasets object");
        let offending = datasets
            .keys()
            .find(|id| descriptor::validate_dataset_id_syntax(id).is_err())
            .unwrap_or_else(|| panic!("{file}: no dataset id violates the syntax rule"));
        assert!(
            matches!(
                descriptor::validate_dataset_id(offending),
                Err(ahl_core::AhlError::DatasetIdControlOctet { .. })
            ),
            "{file}: dataset id `{offending}` (naming {octet_name}) must be rejected by the \
             control-octet check specifically"
        );
    }
}

/// I-D revision 0.4 §2.6 / §6.3: a dataset id carrying a control octet makes the WHOLE manifest
/// rejected, not merely that dataset's claims. Unlike the vectors above — which exercise the
/// primitive directly — this drives the same fault through the full receipt pipeline, the same
/// way `the_manifest_log_object_schema_is_enforced_and_log_id_has_no_alias` proves the `log`
/// object's schema is enforced by `verify_receipt`, not merely checkable in isolation.
#[test]
fn dataset_id_control_octets_are_rejected_by_manifest_schema() {
    for octet in ['\u{1f}', '\u{7f}'] {
        reject_by_manifest_schema(
            |payload| {
                let datasets =
                    payload["datasets"].as_object_mut().expect("manifest datasets object");
                let scores = datasets.remove("scores").expect("scores dataset declared");
                datasets.insert(format!("scores{octet}bad"), scores);
            },
            &format!("dataset id containing {:#04x}", u32::from(octet)),
        );
    }
}

// ---------------------------------------------------------------------------
// Trees and proofs
// ---------------------------------------------------------------------------

#[test]
fn log_tree_inclusion_proof_verifies_through_atl_core() {
    let vectors = statement_vectors();
    let tree = read_json(&test_data().join("vectors").join("merkle").join("log-tree.json"));

    for (index, entry) in tree["entries"].as_array().expect("entries").iter().enumerate() {
        assert_eq!(
            field_str(entry, "entry_id").expect("entry carries entry_id"),
            field_str(&vectors[index], "entry_id").expect("vector carries entry_id")
        );
        assert_eq!(
            field_str(entry, "leaf_hash").expect("entry carries leaf_hash"),
            hash_hex(&leaf_hash(&jcs(&vectors[index]["envelope"])))
        );
    }

    let inclusion = &tree["inclusion"];
    let leaf_index = inclusion["leaf_index"].as_u64().expect("leaf_index");
    let tree_size = inclusion["tree_size"].as_u64().expect("tree_size");
    let leaf = jcs(&vectors[usize::try_from(leaf_index).expect("index")]["envelope"]);
    let proof = proof_from_hex(leaf_index, tree_size, &strings(&inclusion["path"]))
        .expect("well-formed path");
    let root = parse_hash_hex(field_str(inclusion, "root").expect("root")).expect("root hash");
    assert!(
        verify_inclusion_proof(&leaf, &proof, &root).expect("well-formed proof"),
        "log-tree inclusion proof did not verify"
    );

    // Every published root must be the root of the corresponding log prefix.
    let leaves: Vec<Vec<u8>> = vectors.iter().map(|v| jcs(&v["envelope"])).collect();
    for entry in tree["roots"].as_array().expect("roots") {
        let size = usize::try_from(entry["tree_size"].as_u64().expect("tree_size")).expect("size");
        assert_eq!(
            field_str(entry, "root").expect("root"),
            hash_hex(&tree_root(&leaves[..size])),
            "root at tree size {size} does not match the log prefix"
        );
    }
}

#[test]
fn record_sorted_trees_satisfy_the_section_2_5_rules() {
    let dir = test_data().join("vectors").join("merkle");
    for (file, root_field, count_field) in TREE_VECTORS {
        let vector = read_json(&dir.join(file));
        let leaves = vector["leaves"].as_array().expect("leaves").clone();
        let root = field_str(&vector, root_field).expect("root").to_owned();
        let count = vector[count_field].as_u64().expect("count");

        // The validating constructor is the §2.5 rule set: root, count, canonical commitment
        // strings, strict ascending UTF-8 byte order, no duplicates.
        let validated = ValidatedLeafSet::open(&root, count, leaves.clone())
            .unwrap_or_else(|e| panic!("{file}: committed tree material is invalid: {e}"));
        assert_eq!(validated.leaves(), leaves.as_slice());

        // A reordered leaf set must not open the same root, and must be rejected before the
        // root is even recomputed.
        if leaves.len() > 1 {
            let mut swapped = leaves.clone();
            swapped.swap(0, leaves.len() - 1);
            assert!(ValidatedLeafSet::open(&root, count, swapped).is_err());
        }

        let inclusion = &vector["inclusion"];
        let leaf_index = inclusion["leaf_index"].as_u64().expect("leaf_index");
        let proof =
            proof_from_hex(leaf_index, count, &strings(&inclusion["path"])).expect("valid path");
        assert!(
            verify_inclusion_proof(
                &jcs(&leaves[usize::try_from(leaf_index).expect("index")]),
                &proof,
                &parse_hash_hex(&root).expect("root hash"),
            )
            .expect("well-formed proof"),
            "{file}: inclusion proof did not verify"
        );
    }
}

#[test]
fn the_input_set_tree_orders_keyed_commitments_before_plain_ones() {
    let vector = read_json(&test_data().join("vectors").join("merkle").join("input-set-tree.json"));
    let records: Vec<&str> = vector["leaves"]
        .as_array()
        .expect("leaves")
        .iter()
        .map(|l| field_str(l, "record").expect("record"))
        .collect();
    assert!(records.len() >= 3, "the input-set vector must exercise a multi-leaf tree");
    assert!(
        records.iter().any(|r| r.starts_with("hmac-sha256:"))
            && records.iter().any(|r| r.starts_with("sha256:")),
        "the vector must mix commitment modes to pin the ordering rule"
    );
    let split = records.iter().position(|r| r.starts_with("sha256:")).expect("a plain record");
    assert!(
        records[split..].iter().all(|r| r.starts_with("sha256:")),
        "`hmac-sha256:` records must all precede `sha256:` records (h < s)"
    );
}

#[test]
fn range_proofs_verify_and_reject_tampering_through_atl_core() {
    let vectors = statement_vectors();
    let leaves: Vec<Vec<u8>> = vectors.iter().map(|v| jcs(&v["envelope"])).collect();
    let vector = read_json(&test_data().join("vectors").join("merkle").join("range-proof.json"));
    let root =
        parse_hash_hex(field_str(&vector["checkpoint"], "root").expect("root")).expect("root hash");

    for case in vector["cases"].as_array().expect("cases") {
        let from = case["range"]["from_index"].as_u64().expect("from_index");
        let to = case["range"]["to_index"].as_u64().expect("to_index");
        let proof = range_proof::decode(field_str(case, "adaptor_form").expect("adaptor_form"))
            .expect("well-formed adaptor form");
        assert_eq!(proof.from_index, from);
        assert_eq!(proof.to_index, to);
        assert_eq!(
            case["node_count"].as_u64(),
            Some(proof.nodes.len() as u64),
            "the vector's node count must match the serialized proof"
        );

        let lo = usize::try_from(from).expect("index");
        let hi = usize::try_from(to).expect("index");
        let span = &leaves[lo..hi];
        assert!(
            range_proof::verify_over_leaves(&proof, span, &root).expect("well-formed proof"),
            "range [{from}, {to}) did not verify"
        );

        // Completeness and order: substituting, reordering or dropping an entry must fail.
        let mut substituted = span.to_vec();
        substituted[0] = b"substituted entry".to_vec();
        assert!(
            !range_proof::verify_over_leaves(&proof, &substituted, &root)
                .expect("well-formed proof"),
            "range [{from}, {to}): a substituted entry opened the root"
        );
        if span.len() > 1 {
            let mut reordered = span.to_vec();
            reordered.swap(0, span.len() - 1);
            assert!(
                !range_proof::verify_over_leaves(&proof, &reordered, &root)
                    .expect("well-formed proof"),
                "range [{from}, {to}): a reordered range opened the root"
            );
            assert!(
                range_proof::verify_over_leaves(&proof, &span[..span.len() - 1], &root).is_err(),
                "range [{from}, {to}): a short range must be rejected structurally"
            );
        }
    }
}

#[test]
fn checkpoints_and_witness_cosignatures_verify_under_the_active_manifest() {
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    let file = read_json(&test_data().join("vectors").join("checkpoints").join("checkpoints.json"));
    let checkpoints = file["checkpoints"].as_array().expect("checkpoints");

    for entry in checkpoints {
        let cp = &entry["checkpoint"];
        let pubkey = keys
            .get(field_str(cp, "key_id").expect("checkpoint carries key_id"))
            .expect("checkpoint key is declared by a manifest version");
        assert!(
            verify_signature(
                &decode_pubkey(pubkey).expect("manifest pubkey"),
                &checkpoint_signing_bytes(cp).expect("checkpoint object"),
                field_str(cp, "signature").expect("signed checkpoint"),
            )
            .expect("well-formed signature"),
            "{}: checkpoint signature did not verify",
            field_str(entry, "name").expect("named checkpoint")
        );

        // Format §2.2: the active manifest is the one with the greatest entry index smaller
        // than the checkpoint's tree size — EXCEPT cp26, whose `active_manifest_entry_index`
        // is deliberately the OUTGOING manifest (0), not the checkpoint's own true active one
        // (25): it exists solely as the I-D §7.1 rotation-anchoring EXCEPTION's checkpoint,
        // which binds to the manifest version active IMMEDIATELY BEFORE the rotating entry
        // index, never to the version the rotation installs.
        let tree_size = cp["tree_size"].as_u64().expect("tree_size");
        let name = field_str(entry, "name").expect("named checkpoint");
        let expected = if name == "cp26" {
            0
        } else if tree_size > 25 {
            25
        } else {
            0
        };
        assert_eq!(
            entry["active_manifest_entry_index"].as_u64(),
            Some(expected),
            "the active manifest version for tree size {tree_size} is wrong"
        );
    }

    for cosignature in file["cosignatures"].as_array().expect("cosignatures") {
        let name = field_str(cosignature, "checkpoint").expect("checkpoint name");
        let cp = &checkpoints
            .iter()
            .find(|c| field_str(c, "name").ok() == Some(name))
            .expect("named checkpoint")["checkpoint"];
        let witness_id = field_str(cosignature, "witness_id").expect("witness_id");
        let pubkey = keys
            .get(field_str(cosignature, "key_id").expect("key_id"))
            .expect("witness key is declared by a manifest version");
        assert!(
            verify_signature(
                &decode_pubkey(pubkey).expect("manifest pubkey"),
                &cosignature_bytes(cp, witness_id),
                field_str(cosignature, "cosignature").expect("cosignature"),
            )
            .expect("well-formed signature"),
            "{name}/{witness_id}: cosignature did not verify"
        );
        // The witness must be the one the active manifest version declares — except cp26,
        // deliberately cosigned by the OUTGOING witness (witness-1) even though its tree_size
        // exceeds 25; see the `active_manifest_entry_index` loop above for why.
        let tree_size = cp["tree_size"].as_u64().expect("tree_size");
        let expected_witness = if name == "cp26" {
            "witness-1"
        } else if tree_size > 25 {
            "witness-2"
        } else {
            "witness-1"
        };
        assert_eq!(witness_id, expected_witness);
    }
}

#[test]
fn witness_refusal_evidence_is_self_authenticating() {
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    let file =
        read_json(&test_data().join("vectors").join("witness").join("refusal-evidence.json"));
    let refusal = &file["refusal"];

    // Step 1: the witness signature over JCS(refusal without "signature").
    let mut unsigned = refusal.as_object().cloned().expect("refusal object");
    unsigned.remove("signature");
    let witness_key = keys
        .get(field_str(refusal, "key_id").expect("key_id"))
        .expect("witness key is declared by a manifest version");
    assert!(
        verify_signature(
            &decode_pubkey(witness_key).expect("manifest pubkey"),
            &jcs(&Value::Object(unsigned)),
            field_str(refusal, "signature").expect("signed refusal"),
        )
        .expect("well-formed signature"),
        "refusal evidence signature did not verify"
    );

    // Step 2: both carried checkpoints must actually be signed by the log.
    for side in ["retained", "offered"] {
        let cp = &refusal[side];
        let pubkey = keys.get(field_str(cp, "key_id").expect("key_id")).expect("log key");
        assert!(
            verify_signature(
                &decode_pubkey(pubkey).expect("manifest pubkey"),
                &checkpoint_signing_bytes(cp).expect("checkpoint object"),
                field_str(cp, "signature").expect("signed checkpoint"),
            )
            .expect("well-formed signature"),
            "refusal evidence: the {side} checkpoint carries no valid log signature"
        );
    }

    // Step 3: apply the recheck the declared reason directs a verifier to. The taxonomy is
    // `equivocation | size-regression | extension-failed`, and each reason is checkable from
    // the evidence the refusal itself carries; a reason outside it — the removed
    // `missing-consistency-proof`, or the `inconsistent` this corpus once declared — names no
    // recheck at all, so a verifier could neither confirm nor refute it.
    let reason = field_str(refusal, "reason").expect("reason");
    assert!(
        ["equivocation", "size-regression", "extension-failed"].contains(&reason),
        "`{reason}` is not a defined refusal reason"
    );
    assert_eq!(reason, "equivocation");

    // The `equivocation` recheck: one tree size, two roots. No append-only log can do that.
    assert_eq!(refusal["retained"]["tree_size"], refusal["offered"]["tree_size"]);
    assert_ne!(refusal["retained"]["root_hash"], refusal["offered"]["root_hash"]);

    // `proof` is required for `extension-failed` and MUST be absent otherwise: a carried proof
    // no reason directs a verifier to check is unverified material inviting misreading.
    assert!(refusal.get("proof").is_none(), "`proof` belongs only to `extension-failed`");

    // The retained checkpoint must be one the corpus actually published.
    let published =
        read_json(&test_data().join("vectors").join("checkpoints").join("checkpoints.json"));
    assert!(
        published["checkpoints"]
            .as_array()
            .expect("checkpoints")
            .iter()
            .any(|c| c["checkpoint"] == refusal["retained"]),
        "the retained checkpoint must be one the witness had already cosigned"
    );
}

// ---------------------------------------------------------------------------
// Closure
// ---------------------------------------------------------------------------

fn record_refs(value: &Value) -> BTreeSet<RecordRef> {
    value
        .as_array()
        .expect("record list")
        .iter()
        .map(|r| {
            (
                field_str(r, "dataset").expect("dataset").to_owned(),
                field_str(r, "record").expect("record").to_owned(),
            )
        })
        .collect()
}

#[test]
fn every_closure_vector_recomputes_from_the_corpus() {
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);
    let trees = tree_material();
    let dir = test_data().join("vectors").join("closure");

    for file in CLOSURE_FILES {
        let expectation = read_json(&dir.join(file));
        let trigger_index =
            usize::try_from(expectation["trigger"]["entry_index"].as_u64().expect("entry_index"))
                .expect("index");
        let through = usize::try_from(
            expectation["corpus_checkpoint"]["tree_size"].as_u64().expect("tree_size"),
        )
        .expect("size");

        // The vector's trigger must be the statement it names.
        assert_eq!(
            field_str(&expectation["trigger"], "statement_id").expect("statement_id"),
            field_str(&vectors[trigger_index], "statement_id").expect("statement_id"),
            "{file}: the closure vector names the wrong trigger"
        );

        let closure = affected_set(&envelopes, &trees, trigger_index, through)
            .unwrap_or_else(|e| panic!("{file}: closure did not compute: {e}"));
        assert_eq!(
            closure.seeds,
            record_refs(&expectation["expected_seeds"]),
            "{file}: seed set mismatch"
        );
        assert_eq!(
            closure.affected,
            record_refs(&expectation["expected_affected"]),
            "{file}: affected set mismatch"
        );
    }
}

#[test]
fn supersession_seeds_the_original_and_the_superseded_replacement_only() {
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);
    let closure = affected_set(&envelopes, &tree_material(), 12, 13).expect("corpus");

    let commitment = |index: usize, field: &str| {
        field_str(&vectors[index]["envelope"]["payload"], field).expect(field).to_owned()
    };
    let original = ("customers".to_owned(), commitment(6, "record"));
    let superseded = ("customers".to_owned(), commitment(6, "replacement"));
    let new_replacement = ("customers".to_owned(), commitment(12, "replacement"));

    assert_eq!(
        closure.seeds,
        BTreeSet::from([original, superseded]),
        "spec §5.1: seeds are the original plus every prior superseded replacement"
    );
    assert!(
        !closure.seeds.contains(&new_replacement),
        "a correction never seeds its own replacement"
    );

    // The point of seeding the superseded replacement: records derived from it are reached.
    let s1p = (
        "scores".to_owned(),
        field_str(&vectors[7]["envelope"]["payload"]["outputs"][0], "record")
            .expect("record")
            .to_owned(),
    );
    // W1 and W2 are batch outputs whose leaves commit their input set by root, so reaching
    // them requires walking two committed trees.
    let wide: BTreeSet<RecordRef> =
        read_json(&test_data().join("vectors").join("merkle").join("wide-outputs-tree.json"))
            ["leaves"]
            .as_array()
            .expect("leaves")
            .iter()
            .map(|leaf| {
                ("scores".to_owned(), field_str(leaf, "record").expect("record").to_owned())
            })
            .collect();
    assert_eq!(wide.len(), 2);
    assert!(closure.affected.contains(&s1p), "S1' consumed the superseded replacement");
    assert!(
        wide.is_subset(&closure.affected),
        "the batch outputs consumed the superseded replacement through an input-set tree"
    );

    // Seeding only the original would miss all three — the regression this vector exists for.
    let seeds_only_original = affected_set(&envelopes, &tree_material(), 6, 13).expect("corpus");
    assert!(wide.is_disjoint(&seeds_only_original.affected));
}

#[test]
fn the_non_retroactive_retraction_excludes_out_of_scope_derivations() {
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);
    let closure = affected_set(&envelopes, &tree_material(), 17, 20).expect("corpus");

    let scope = Scope::from_payload(&vectors[17]["envelope"]["payload"]).expect("scoped trigger");
    assert!(!scope.retroactive, "this vector exists to exercise the non-retroactive branch");

    let output = |index: usize| {
        (
            "scores".to_owned(),
            field_str(&vectors[index]["envelope"]["payload"]["outputs"][0], "record")
                .expect("record")
                .to_owned(),
        )
    };
    // All three consume the retracted record; only `valid_time` separates them (§2.3.3).
    for index in [14usize, 15, 16] {
        let payload = &vectors[index]["envelope"]["payload"];
        assert_eq!(
            field_str(&payload["inputs"][0], "record").expect("record"),
            field_str(&vectors[17]["envelope"]["payload"], "record").expect("record"),
        );
        let valid_time = ValidTime::from_payload(payload).expect("RFC 3339 valid_time");
        assert_eq!(
            scope.covers(valid_time),
            index == 15,
            "entry {index}: scope coverage disagrees with §2.3.3"
        );
    }
    assert_eq!(closure.affected, BTreeSet::from([output(15)]));
    assert!(!closure.affected.contains(&output(14)), "a point valid_time before the boundary");
    assert!(!closure.affected.contains(&output(16)), "an interval ending before the boundary");
}

#[test]
fn closure_rejects_tampered_committed_tree_material() {
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);

    // Drop a leaf from the input-set tree: the count no longer matches the anchored
    // `input_set_count`, so the closure must fail rather than silently shrink.
    let mut trees = tree_material();
    let root = field_str(
        &read_json(&test_data().join("vectors").join("merkle").join("input-set-tree.json")),
        "input_set_root",
    )
    .expect("input_set_root")
    .to_owned();
    assert!(vectors[10]["envelope"]["payload"].get("outputs_root").is_some());
    trees.get_mut(&root).expect("input-set material").pop();
    assert!(
        affected_set(&envelopes, &trees, 12, 13).is_err(),
        "truncated tree material must be rejected, not traversed"
    );

    // Absent material is likewise an error, never a silent truncation of the closure.
    let mut missing = tree_material();
    missing.remove(&root);
    assert!(affected_set(&envelopes, &missing, 12, 13).is_err());
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

fn receipt_index() -> Value {
    read_json(&test_data().join("receipts").join("index.json"))
}

/// The locally configured trust policy, read from the corpus receipt index rather than from
/// any receipt: a receipt never supplies its own trust anchor (receipt format §1).
fn trust_policy() -> TrustPolicy {
    let index = receipt_index();
    let policy = &index["policy"];
    let dataset_key =
        std::fs::read_to_string(test_data().join("keys").join("dataset_customers.key"))
            .expect("committed dataset key");
    TrustPolicy {
        genesis_entry_id: field_str(policy, "genesis_entry_id").expect("genesis anchor").to_owned(),
        genesis_key_ids: Some(strings(&policy["genesis_key_ids"]).into_iter().collect()),
        // I-D §3.2, §7.5 step 2: a verifier holds the ARTIFACT and recomputes its digest — so
        // this reads the actual document bytes from disk, exactly as a real verifier would,
        // rather than trusting `index.json`'s own recorded hash string as if it were already
        // the digest of anything held.
        adaptor_profiles: policy["adaptor_profiles"]
            .as_object()
            .expect("adaptor profiles")
            .iter()
            .map(|(id, profile)| {
                let capabilities = &profile["capabilities"];
                let document = std::fs::read(test_data().join("adaptor").join(format!("{id}.md")))
                    .unwrap_or_else(|e| panic!("read held adaptor document for `{id}`: {e}"));
                (
                    id.clone(),
                    AdaptorProfile {
                        document,
                        capabilities: AdaptorCapabilities {
                            checkpoint_raw: capabilities["checkpoint_raw"] == Value::Bool(true),
                            consistency_proofs: capabilities["consistency_proofs"]
                                == Value::Bool(true),
                        },
                    },
                )
            })
            .collect(),
        dataset_keys: BTreeMap::from([(
            "customers".to_owned(),
            hex::decode(dataset_key.trim()).expect("hex dataset key"),
        )]),
        trusted_witness_keys: BTreeMap::new(),
        limits: Limits::default(),
    }
}

fn read_receipt(name: &str) -> (Vec<u8>, Value) {
    let path = test_data().join("receipts").join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let value: Value = serde_json::from_slice(&bytes).expect("receipt parses");
    (bytes, value)
}

#[test]
fn the_receipt_index_lists_every_receipt_on_disk() {
    let listed: BTreeSet<String> = receipt_index()["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|v| field_str(v, "file").expect("file").to_owned())
        .collect();
    let on_disk: BTreeSet<String> = std::fs::read_dir(test_data().join("receipts"))
        .expect("receipts directory")
        .map(|e| e.expect("directory entry").file_name().to_string_lossy().into_owned())
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "ahl"))
        .collect();
    assert_eq!(listed, on_disk, "the index and the directory must agree");
    assert!(on_disk.len() >= 26, "one positive and one negative vector per registry claim type");
}

#[test]
fn receipts_are_jcs_canonical_on_disk() {
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        let name = field_str(entry, "file").expect("file");
        let (bytes, value) = read_receipt(name);
        assert_eq!(bytes, jcs(&value), "{name}: file is not its own JCS serialization");
        assert!(!bytes.contains(&b'\n'), "{name}: a JCS receipt is a single line");
    }
}

#[test]
fn every_positive_receipt_verifies_and_renders_its_boundary() {
    let policy = trust_policy();
    let mut accepted = 0;
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        if field_str(entry, "expect").expect("expect") != "accept" {
            continue;
        }
        let name = field_str(entry, "file").expect("file");
        let (_, receipt) = read_receipt(name);
        let verdict = verify_receipt(&receipt, &policy)
            .unwrap_or_else(|e| panic!("{name}: must verify, but was rejected: {e}"));

        assert_eq!(verdict.claim_type, field_str(entry, "claim_type").expect("claim_type"));
        assert_eq!(verdict.boundary, field_str(entry, "boundary").expect("boundary"));

        // Format §2.1: the rendered verdict comes from claim.type and assurance, never from
        // the informative note, and a `-declared` type never claims effectiveness.
        if verdict.claim_type.ends_with("-declared") {
            for word in ["effective", "governs", "complete"] {
                assert!(
                    !verdict.boundary.contains(word),
                    "{name}: a `-declared` verdict must not use the word `{word}`"
                );
            }
            assert_eq!(verdict.assurance.governance, "declared");
        }
        if verdict.claim_type.ends_with("-effective") || verdict.claim_type.ends_with("-complete") {
            assert_eq!(
                verdict.assurance.governance, "enumerated",
                "{name}: an effectiveness or completeness claim requires enumerated governance"
            );
        }
        accepted += 1;
    }
    assert!(accepted >= 11, "every registry claim type needs a positive vector, got {accepted}");
}

/// Assert that a rejection is the *specific* rule the index entry names.
// A flat match, one arm per negative vector on disk: splitting it into helpers would obscure
// which vector each arm belongs to.
#[allow(clippy::too_many_lines)]
fn assert_specific_rule(name: &str, rule: &str, error: &ReceiptError) {
    let fired = match name {
        "overclaim-must-fail.ahl" => {
            matches!(error, ReceiptError::AssuranceMismatch { field: "governance" })
        }
        "record-ingested-content-mismatch-must-fail.ahl" => {
            matches!(error, ReceiptError::ContentBindingMismatch { .. })
        }
        "record-derived-wrong-path-must-fail.ahl" => {
            matches!(error, ReceiptError::InclusionPathInvalid { what: "batch output leaf" })
        }
        "trigger-declared-replacement-ordering-must-fail.ahl" => matches!(
            error,
            ReceiptError::EmbeddedOrderingViolation {
                what: "replacement introduction",
                inner: 11,
                outer: 6,
            }
        ),
        "trigger-effective-short-range-must-fail.ahl" => matches!(
            error,
            ReceiptError::CompetingRangeInsufficient {
                got_from: 3,
                got_to: 8,
                tree_size: 8,
                introduction_index: 1,
            }
        ),
        "disposition-declared-wrong-path-must-fail.ahl" => {
            matches!(error, ReceiptError::InclusionPathInvalid { what: "disposition leaf" })
        }
        "disposition-effective-declared-trigger-must-fail.ahl" => matches!(
            error,
            ReceiptError::EmbeddedClaimTypeMismatch {
                slot: "trigger",
                expected: "trigger-effective",
                ..
            }
        ),
        "propagation-complete-missing-leaf-must-fail.ahl" => {
            matches!(error, ReceiptError::TreeMaterialInvalid { .. })
        }
        "governance-state-not-current-must-fail.ahl" => matches!(
            error,
            ReceiptError::GovernanceStateNotCurrent { target_index: 10, entry_index: 9, .. }
        ),
        "statement-anchored-dropped-producer-key-must-fail.ahl" => {
            matches!(error, ReceiptError::KeyNotBound { entry_index: 9, .. })
        }
        "trigger-effective-non-authority-issuer-must-fail.ahl"
        | "propagation-complete-challenge-trigger-must-fail.ahl" => {
            matches!(error, ReceiptError::TriggerNotAuthorized { entry_index: 23, .. })
        }
        "trigger-effective-unverified-authority-signature-must-fail.ahl" => {
            matches!(error, ReceiptError::EnvelopeSignatureInvalid { entry_index: 29 })
        }
        "propagation-complete-past-declared-checkpoint-must-fail.ahl" => matches!(
            error,
            ReceiptError::CheckpointNotBound { field: "claim_material.corpus_checkpoint", .. }
        ),
        "governance-state-short-range-must-fail.ahl" => matches!(
            error,
            ReceiptError::GovernanceRangeNotComplete { got_from: 0, got_to: 6, tree_size: 28 }
        ),
        "governance-state-key-subject-must-fail.ahl" => {
            matches!(error, ReceiptError::GovernanceSubjectNotManifest { .. })
        }
        "governance-key-rotation-proof-incoming-key-must-fail.ahl"
        | "governance-key-rotation-proof-missing-witness-must-fail.ahl" => {
            matches!(error, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, .. })
        }
        "governance-key-rotation-proof-missing-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                    if detail.contains("carries no (further) element")
            )
        }
        "governance-key-rotation-proof-wrong-index-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                    if detail.contains("carries `manifest_entry_index` 24, not 25")
            )
        }
        "governance-key-rotation-proof-duplicate-must-fail.ahl"
        | "governance-key-rotation-proof-extra-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::GovernanceChainInvalid(detail) if detail.contains("beyond the")
            )
        }
        "governance-key-rotation-proof-empty-on-non-rotating-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::GovernanceChainInvalid(detail) if detail.contains("rotates neither")
            )
        }
        "governance-key-rotation-proof-checkpoint-missing-log-id-must-fail.ahl" => {
            matches!(error, ReceiptError::Malformed(detail) if detail.contains("log_id"))
        }
        "governance-key-rotation-proof-malformed-witness-entry-must-fail.ahl" => {
            matches!(error, ReceiptError::Malformed(detail) if detail.contains("cosigned_at"))
        }
        "governance-key-statement-wrong-key-id-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::GovernanceChainInvalid(detail)
                    if detail.contains("does not equal `sha256:`-of-`key.pubkey`")
            )
        }
        "governance-key-statement-missing-valid-from-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::GovernanceChainInvalid(detail)
                    if detail.contains("carries no `key.valid_from`")
            )
        }
        "governance-key-statement-short-pubkey-must-fail.ahl" => {
            matches!(
                error,
                ReceiptError::GovernanceChainInvalid(detail)
                    if detail.contains("does not decode to exactly 32 octets")
            )
        }
        "governance-key-statement-missing-issued-at-must-fail.ahl" => {
            matches!(error, ReceiptError::Malformed(detail) if detail.contains("issued_at"))
        }
        "governance-key-statement-malformed-valid-time-must-fail.ahl" => {
            matches!(error, ReceiptError::Malformed(detail) if detail.contains("valid_time"))
        }
        "record-ingested-stale-manifest-must-fail.ahl" => {
            matches!(error, ReceiptError::SubjectManifestBindingInvalid(_))
        }
        "statement-anchored-continued-history-wrong-pair-must-fail.ahl" => {
            matches!(error, ReceiptError::ConsistencyPathInvalid)
        }
        "trigger-effective-enumerated-with-later-checkpoint-must-fail.ahl" => {
            matches!(error, ReceiptError::FormatConflict { .. })
        }
        other => panic!("{other}: negative vector has no rule assertion in the test suite"),
    };
    assert!(fired, "{name}: expected rejection by {rule}, got: {error}");
}

#[test]
fn every_negative_receipt_is_rejected_by_the_rule_it_names() {
    let policy = trust_policy();
    let mut rejected = 0;
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        if field_str(entry, "expect").expect("expect") != "reject" {
            continue;
        }
        let name = field_str(entry, "file").expect("file");
        let rule = field_str(entry, "rule").expect("rule");
        let (_, receipt) = read_receipt(name);
        let error = verify_receipt(&receipt, &policy)
            .err()
            .unwrap_or_else(|| panic!("{name}: must be rejected, but verified"));
        assert_specific_rule(name, rule, &error);
        assert_eq!(error.to_string(), field_str(entry, "reason").expect("reason"));
        rejected += 1;
    }
    assert!(rejected >= 15, "every registry claim type needs a negative vector, got {rejected}");
}

#[test]
fn a_receipt_carrying_the_wrong_genesis_anchor_is_rejected() {
    let mut policy = trust_policy();
    policy.genesis_entry_id = sha256_hex(b"some other corpus");
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    assert!(
        matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::GenesisAnchorMismatch)),
        "a self-supplied genesis anchor must be compared against configured policy"
    );
}

#[test]
fn a_receipt_carrying_the_wrong_genesis_key_fingerprints_is_rejected() {
    // WHERE local policy HOLDS fingerprints (this test's policy does, via `trust_policy()`),
    // a mismatch is rejected exactly like a mismatched entry id (I-D §7.5.1 4a).
    let mut policy = trust_policy();
    policy.genesis_key_ids = Some(BTreeSet::from([sha256_hex(b"not the genesis producer key")]));
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    assert!(
        matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::GenesisAnchorMismatch)),
        "a configured fingerprint set, once held, must be compared and enforced"
    );
}

#[test]
fn genesis_key_fingerprints_are_optional_local_policy() {
    // I-D §7.5.1 4a: "WHERE LOCAL POLICY HOLDS initial key fingerprints... which is optional...
    // where it holds none, this comparison does not arise and its absence is not a defect." A
    // verifier configured with `genesis_key_ids: None` — entry-id-only policy — must still
    // accept a receipt whose genesis entry id matches, never demanding fingerprints it was
    // never configured to hold.
    let policy = TrustPolicy { genesis_key_ids: None, ..trust_policy() };
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    verify_receipt(&receipt, &policy)
        .expect("an entry-id-only policy must accept a receipt it never asked for fingerprints on");
}

#[test]
fn a_receipt_pinning_an_unknown_adaptor_profile_is_rejected() {
    // I-D §7.5 step 2: the profile id itself is not locally held at all — `unverifiable`, a
    // capability gap, distinct from [`ReceiptError::AdaptorHashMismatch`] below.
    let mut policy = trust_policy();
    policy.adaptor_profiles.clear();
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    assert!(matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::AdaptorUnknown { .. })));
}

#[test]
fn a_receipt_whose_pinned_hash_disagrees_with_the_held_document_is_rejected() {
    // I-D §3.2, §7.5 step 2: "MUST recompute the digest over the artifact rather than trusting
    // any value carried with it, and MUST reject a receipt whose pinned digest does not match
    // the artifact held." The profile id IS held — this is `invalid`, distinct from
    // `AdaptorUnknown` above: the receipt names a document policy can prove is not the one it
    // trusts, not merely one it has never heard of.
    let policy = trust_policy();
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    corrupt(&mut receipt["anchoring"]["adaptor"]["hash"]);
    assert!(
        matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::AdaptorHashMismatch { ref id }) if id == "ahl-test-log-v1"
        ),
        "a receipt pinning the RIGHT profile id at the WRONG hash must be rejected as \
         `AdaptorHashMismatch`, not silently accepted or conflated with `AdaptorUnknown`"
    );
}

#[test]
fn adaptor_profile_hash_is_recomputed_from_the_held_document_not_trusted() {
    // The whole point of §3.2/§7.5 step 2: a policy's own STORED `AdaptorProfile` never
    // carries a caller-asserted hash string at all — `hash()` is always computed FROM
    // `document`, so it cannot silently drift from what is actually held.
    let policy = trust_policy();
    let profile = &policy.adaptor_profiles["ahl-test-log-v1"];
    assert_eq!(profile.hash(), sha256_hex(&profile.document));
}

#[test]
fn an_unauthorized_verifier_cannot_satisfy_a_keyed_content_binding() {
    let mut policy = trust_policy();
    policy.dataset_keys.clear();
    let (_, receipt) = read_receipt("record-ingested-valid.ahl");
    assert!(
        matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::ContentBindingMismatch { .. })
        ),
        "keyed content binding is authorized-verifier-only; dataset keys are never packaged"
    );
}

#[test]
fn resource_limits_fail_closed_rather_than_degrading() {
    let (_, receipt) = read_receipt("disposition-effective-valid.ahl");

    for (limits, label) in [
        (Limits { max_depth: 1, ..Limits::default() }, "nesting depth"),
        (Limits { max_embedded: 1, ..Limits::default() }, "embedded receipts"),
        (Limits { max_decoded_bytes: 1024, ..Limits::default() }, "decoded size"),
        (Limits { max_work_units: 2, ..Limits::default() }, "verification work"),
    ] {
        let policy = TrustPolicy { limits, ..trust_policy() };
        assert!(
            matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::LimitExceeded(_))),
            "{label}: exhaustion must reject, not degrade (receipt §3.1)"
        );
    }

    // The nesting the corpus actually uses stays inside the normative limits.
    let verdict = verify_receipt(&receipt, &trust_policy()).expect("valid receipt");
    assert!(verdict.embedded_receipts <= 64);
}

#[test]
fn the_adaptor_profile_hash_is_pinned_by_both_manifest_versions_and_by_receipts() {
    let vectors = statement_vectors();
    let bytes = std::fs::read(test_data().join("adaptor").join("ahl-test-log-v1.md"))
        .expect("adaptor profile document is published alongside the vectors");
    let hash = sha256_hex(&bytes);

    for index in [0usize, 25] {
        let adaptor = &vectors[index]["envelope"]["payload"]["log"]["adaptor"];
        assert_eq!(field_str(adaptor, "id").expect("adaptor id"), "ahl-test-log-v1");
        assert_eq!(
            field_str(adaptor, "hash").expect("adaptor hash"),
            hash,
            "manifest version at entry {index} must pin the published document (spec §3 item 6)"
        );
    }

    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        let name = field_str(entry, "file").expect("file");
        let (_, receipt) = read_receipt(name);
        assert_eq!(
            field_str(&receipt["anchoring"]["adaptor"], "hash").expect("adaptor hash"),
            hash,
            "{name}: every receipt carries the pinned profile hash (spec §6.5)"
        );
    }
}

/// Smallest work budget at which `receipt` stops failing with `LimitExceeded`.
///
/// The work counter increments once per signature check, proof check and tree opening, so this
/// is a deterministic measure of how much verification a receipt actually cost.
fn work_cost(receipt: &Value, policy: &TrustPolicy) -> u64 {
    for budget in 1..2000u64 {
        let scoped = TrustPolicy {
            limits: Limits { max_work_units: budget, ..policy.limits },
            ..policy.clone()
        };
        match verify_receipt(receipt, &scoped) {
            Err(ReceiptError::LimitExceeded("verification work budget")) => {}
            _ => return budget,
        }
    }
    panic!("receipt did not complete within the probe range");
}

#[test]
fn a_duplicated_embedded_receipt_is_verified_exactly_once() {
    let policy = trust_policy();
    let (_, receipt) = read_receipt("trigger-declared-valid.ahl");

    // The valid receipt embeds two *distinct* introduction receipts.
    let introduction = receipt["claim_material"]["introduction"].clone();
    let replacement = receipt["claim_material"]["replacement_introduction"].clone();
    assert_ne!(introduction["subject"]["entry_id"], replacement["subject"]["entry_id"]);
    let distinct_cost = work_cost(&receipt, &policy);

    // Point both slots at the same embedded receipt. Format §3.1: "Duplicate embedded receipts
    // (same entry id) MUST be verified once and referenced thereafter."
    let mut duplicated = receipt;
    duplicated["claim_material"]["replacement_introduction"] = introduction.clone();
    let duplicate_cost = work_cost(&duplicated, &policy);

    assert!(
        duplicate_cost < distinct_cost,
        "the duplicate must be served from the cache, not re-verified \
         (distinct {distinct_cost} units, duplicated {duplicate_cost})"
    );

    // Verifying the embedded receipt on its own costs the difference, which is exactly the
    // work the duplicate would have cost a verifier without the cache.
    let embedded_cost = work_cost(&introduction, &policy);
    assert_eq!(
        distinct_cost - duplicate_cost,
        embedded_cost,
        "the saving must equal one full verification of the embedded receipt"
    );

    // It is still rejected — by the §2.3 record rule, reached only *after* the cached lookup,
    // which is what proves the cache short-circuited the recursion rather than the checks.
    assert!(matches!(
        verify_receipt(&duplicated, &policy),
        Err(ReceiptError::EmbeddedSubjectMismatch { what: "replacement introduction", .. })
    ));
}

#[test]
fn adaptor_capability_gaps_are_reported_as_profile_limitations() {
    let policy = trust_policy();
    let (_, valid) = read_receipt("statement-anchored-valid.ahl");

    // The corpus profile defines no binary checkpoint framing (adaptor profile §7), so a
    // receipt carrying `raw` is rejected — but as a limitation of that profile, named, not as
    // a blanket rule of the container format.
    let mut with_raw = valid;
    with_raw["anchoring"]["checkpoint"]["raw"] = Value::String("base64:AAAA".to_owned());
    assert!(matches!(
        verify_receipt(&with_raw, &policy),
        Err(ReceiptError::AdaptorCapabilityUnsupported { ref id, .. }) if id == "ahl-test-log-v1"
    ));

    // I-D §7.1: a rotation-proof element's `checkpoint` is "in the receipt-borne form defined
    // above" — the SAME strict shape as `anchoring.checkpoint`, `raw` included, so the SAME
    // profile-capability gate applies to it. `governance-state-valid.ahl` carries a genuine
    // `governance.rotation_proofs[0]`, and this profile defines no binary framing either.
    let (_, governance_state) = read_receipt("governance-state-valid.ahl");
    let mut rotation_with_raw = governance_state;
    rotation_with_raw["governance"]["rotation_proofs"][0]["checkpoint"]["raw"] =
        Value::String("base64:AAAA".to_owned());
    assert!(matches!(
        verify_receipt(&rotation_with_raw, &policy),
        Err(ReceiptError::AdaptorCapabilityUnsupported { ref id, .. }) if id == "ahl-test-log-v1"
    ));

    // Consistency proofs ARE defined by this profile (§9), so the same material verifies here.
    let (_, continued) = read_receipt("statement-anchored-continued-history.ahl");
    let verdict = verify_receipt(&continued, &policy).expect("consistency proof verifies");
    assert!(verdict.assurance.continued_history);

    // Under a profile that does NOT define the serialization — `AdaptorProfile::minimal`, the
    // shape the corpus profile had before §9 existed — the identical receipt is rejected, and
    // the rejection names the profile rather than the format. That guard is the reason a
    // verifier may not quietly accept unverifiable material from a profile that never defined
    // how to verify it.
    let mut restricted = trust_policy();
    restricted.adaptor_profiles.insert(
        "ahl-test-log-v1".to_owned(),
        AdaptorProfile::minimal(policy.adaptor_profiles["ahl-test-log-v1"].document.clone()),
    );
    assert!(matches!(
        verify_receipt(&continued, &restricted),
        Err(ReceiptError::AdaptorCapabilityUnsupported { ref id, .. }) if id == "ahl-test-log-v1"
    ));
    assert!(!restricted.adaptor_profiles["ahl-test-log-v1"].capabilities.consistency_proofs);
    assert!(!restricted.adaptor_profiles["ahl-test-log-v1"].capabilities.checkpoint_raw);
}

#[test]
fn checkpoint_raw_capability_requires_a_known_parser() {
    // I-D §7.1, §7.5 step 2: "WHERE `raw` is carried it MUST parse to the same values as the
    // JSON members" — a capability BOOLEAN is not itself reconciliation. A policy claiming
    // `checkpoint_raw: true` for a profile this build has no wire-format parser for — every
    // profile, currently (see `ReceiptError::AdaptorProfileMisconfigured`'s own doc comment) —
    // is refused as a POLICY defect, before any receipt content — `raw`'s own presence
    // included — is even read.
    let mut policy = trust_policy();
    let document = policy.adaptor_profiles["ahl-test-log-v1"].document.clone();
    policy.adaptor_profiles.insert(
        "ahl-test-log-v1".to_owned(),
        AdaptorProfile {
            document,
            capabilities: AdaptorCapabilities { checkpoint_raw: true, consistency_proofs: true },
        },
    );
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    assert!(
        matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::AdaptorProfileMisconfigured { ref id, .. }) if id == "ahl-test-log-v1"
        ),
        "`checkpoint_raw: true` for a profile this build cannot parse must be a policy error, \
         not silent acceptance"
    );
}

#[test]
fn ahl_adaptor_atl_v1_receipts_are_refused_as_a_profile_limitation() {
    // Adaptor `ahl-adaptor-atl-v1` §4.2 (leaf construction), §7.1 (origin-derived `log_id`)
    // and §14 ("Until this document is released as an immutable, openly published artifact…
    // no manifest may pin it") together mean this crate cannot yet vouch for a receipt under
    // that profile end to end, even though its checkpoint-blob mechanism is implemented and
    // unit-tested (`ahl_core::checkpoint_signing_bytes_for`, `lib.rs`). A receipt naming it —
    // even under a policy that HOLDS the profile — is refused as
    // `AdaptorCapabilityUnsupported`, never accepted.
    // A receipt carrying SIGNED, non-genesis governance hops (entry 9's `key` statement and
    // entry 25's manifest v2): repinning the genesis manifest below breaks their lineage, so
    // if the refusal were deferred until the signing bytes are first needed, the induction
    // would report a broken chain instead — material this verifier has declined to interpret
    // deciding what it reports. The refusal at §7.5 step 2 is what keeps that from happening.
    let (_, mut receipt) = read_receipt("governance-state-valid.ahl");
    let mut policy = trust_policy();
    let document = policy.adaptor_profiles["ahl-test-log-v1"].document.clone();
    let atl_profile = AdaptorProfile {
        document,
        capabilities: AdaptorCapabilities { checkpoint_raw: false, consistency_proofs: false },
    };
    let test_hash = atl_profile.hash();

    // Repin the chain's OWN genesis manifest to `ahl-adaptor-atl-v1` too (I-D §3.2's binding
    // check would otherwise fire first, on a receipt whose manifest still pins the OTHER
    // profile) — the entry id changes, so `governance.genesis_entry_id` and policy are
    // refreshed to match, exactly as `reject_by_manifest_schema` does for a schema mutation.
    receipt["governance"]["chain"][0]["envelope"]["payload"]["log"]["adaptor"]["id"] =
        json!("ahl-adaptor-atl-v1");
    let anchor = entry_id(&receipt["governance"]["chain"][0]["envelope"]);
    receipt["governance"]["genesis_entry_id"] = json!(&anchor);
    policy.genesis_entry_id = anchor;

    receipt["anchoring"]["adaptor"]["id"] = json!("ahl-adaptor-atl-v1");
    receipt["anchoring"]["adaptor"]["hash"] = json!(test_hash);
    policy.adaptor_profiles.insert("ahl-adaptor-atl-v1".to_owned(), atl_profile);
    assert!(
        matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::AdaptorCapabilityUnsupported { ref id, .. }) if id == "ahl-adaptor-atl-v1"
        ),
        "an `ahl-adaptor-atl-v1` receipt must be refused as a profile limitation, not accepted"
    );
}

#[test]
fn continued_history_requires_both_members_and_a_later_checkpoint_of_its_own() {
    // Receipt §2.3 states the equivalence: `continued_history` is true iff `later_checkpoint`
    // and `consistency_path` are present and verify. Each half alone is malformed.
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| {
            r["anchoring"].as_object_mut().expect("anchoring").remove("consistency_path");
        },
        |e| matches!(e, ReceiptError::Malformed(_)),
        "§2.3 — a later checkpoint without a proof is malformed",
    );
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| {
            r["anchoring"].as_object_mut().expect("anchoring").remove("later_checkpoint");
        },
        |e| matches!(e, ReceiptError::Malformed(_)),
        "§2.3 — a proof without a later checkpoint is malformed",
    );

    // I-D §7.1: `anchoring.later_witnesses` is "Present if and only if `later_checkpoint` is
    // carried" — a `later_checkpoint` without it is malformed too, not merely unwitnessed.
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| {
            r["anchoring"].as_object_mut().expect("anchoring").remove("later_witnesses");
        },
        |e| matches!(e, ReceiptError::Malformed(_)),
        "I-D §7.1 — later_witnesses is REQUIRED whenever later_checkpoint is carried",
    );

    // I-D §7.1: "a receipt asserting `continued_history` MUST carry at least one element that
    // verifies, and one that does not is `invalid` for that assertion" — a non-verifying
    // cosignature is rejected outright, never merely ignored in favor of `witnessed: false`.
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| corrupt(&mut r["anchoring"]["later_witnesses"][0]["cosignature"]),
        |e| matches!(e, ReceiptError::WitnessCosignatureInvalid { .. }),
        "I-D §7.1 — a later_witnesses cosignature that does not verify is invalid",
    );

    // A "later" checkpoint smaller than the one the subject is included under proves no
    // continued history: it is the size regression a witness refuses to cosign over.
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| {
            let earlier = read_receipt("propagation-complete-valid.ahl").1["claim_material"]
                ["corpus_checkpoint"]
                .clone();
            r["anchoring"]["later_checkpoint"] = earlier;
        },
        |e| matches!(e, ReceiptError::ConsistencyPathInvalid),
        "adaptor §9.2 — later_checkpoint.tree_size >= checkpoint.tree_size",
    );

    // The later checkpoint is authenticated on its own terms (§2.1): a corrupted signature on
    // it fails exactly as one on the anchoring checkpoint would.
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| corrupt(&mut r["anchoring"]["later_checkpoint"]["signature"]),
        |e| matches!(e, ReceiptError::CheckpointSignatureInvalid),
        "§2.1 — the later checkpoint carries its own verified log signature",
    );
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| corrupt(&mut r["anchoring"]["later_checkpoint"]["log_id"]),
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "adaptor §5 — the later checkpoint names the log the active manifest declares",
    );
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| corrupt(&mut r["anchoring"]["consistency_path"][0]),
        |e| matches!(e, ReceiptError::ConsistencyPathInvalid),
        "adaptor §9.2 — the path must open the pair of roots",
    );
    assert_rejects(
        "statement-anchored-continued-history.ahl",
        |r| r["claim"]["assurance"]["continued_history"] = json!(false),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "continued_history" }),
        "§2.3 — the assurance field must state what was proven",
    );
}

#[test]
fn the_challenge_trigger_is_anchored_but_never_authorised() {
    let vectors = statement_vectors();
    let manifest = &vectors[0]["envelope"]["payload"];
    let authority: BTreeSet<String> = manifest["datasets"]["customers"]["authority"]["key_ids"]
        .as_array()
        .expect("the dataset authority is a key set (spec §1.2)")
        .iter()
        .map(|k| k.as_str().expect("key id").to_owned())
        .collect();

    // The challenge is a real, well-signed statement — that is what makes it a challenge
    // rather than a malformed object (spec §2.3.3).
    let keys = key_set(&vectors);
    assert!(verify_envelope(&vectors[23]["envelope"], |key_id| keys.get(key_id).cloned())
        .expect("well-formed envelope"));
    let signer =
        field_str(&vectors[23]["envelope"]["signatures"][0], "key_id").expect("key_id").to_owned();
    assert!(!authority.contains(&signer), "the challenge must not be signed by the authority");

    // And the propagation at entry 22 names it, so a completeness claim over that propagation
    // is exactly the thing a verifier must refuse.
    assert_eq!(
        field_str(&vectors[24]["envelope"]["payload"], "trigger").expect("trigger"),
        field_str(&vectors[23], "statement_id").expect("statement_id")
    );
}

// ---------------------------------------------------------------------------
// Receipt rejection rules, one mutation each
// ---------------------------------------------------------------------------
//
// Every rule below is reachable from a *valid* vector by a single targeted mutation, so each
// case isolates one rule rather than tripping several at once. These complement the receipt
// vectors on disk: the vectors are the portable conformance artifacts, these are the unit
// coverage of the branches a well-formed corpus never reaches.

/// Apply `mutate` to a named valid receipt and assert the rejection it must produce.
fn assert_rejects(
    base: &str,
    mutate: impl FnOnce(&mut Value),
    check: impl FnOnce(&ReceiptError) -> bool,
    rule: &str,
) {
    let policy = trust_policy();
    let (_, mut receipt) = read_receipt(base);
    mutate(&mut receipt);
    let error = verify_receipt(&receipt, &policy)
        .err()
        .unwrap_or_else(|| panic!("{rule}: mutated {base} must be rejected, but verified"));
    assert!(check(&error), "{rule}: wrong rule fired for {base}: {error}");
}

/// [`assert_rejects`], for a mutation that edits a carried governance envelope.
///
/// The edit changes that statement's entry id, so the receipt is re-anchored ([`reanchor`])
/// and — where the edited statement is the genesis manifest — its `genesis_entry_id` and the
/// policy anchor are refreshed to match. Without both repairs the receipt fails as an
/// unanchored hop, or on an anchor that no longer digests its genesis envelope: true
/// rejections, neither of them the rule under test.
fn assert_rejects_anchored(
    base: &str,
    mutate: impl FnOnce(&mut Value),
    check: impl FnOnce(&ReceiptError) -> bool,
    rule: &str,
) {
    let (_, mut receipt) = read_receipt(base);
    mutate(&mut receipt);
    reanchor(&mut receipt);
    let anchor = entry_id(&receipt["governance"]["chain"][0]["envelope"]);
    receipt["governance"]["genesis_entry_id"] = json!(&anchor);
    let policy = TrustPolicy { genesis_entry_id: anchor, ..trust_policy() };
    let error = verify_receipt(&receipt, &policy)
        .err()
        .unwrap_or_else(|| panic!("{rule}: mutated {base} must be rejected, but verified"));
    assert!(check(&error), "{rule}: wrong rule fired for {base}: {error}");
}

/// Flip one character of a family string, keeping the encoding well formed.
///
/// `sha256:`/`hmac-sha256:` values are hex, `base64:` values are base64 — in both cases the
/// substitution stays inside the alphabet, so the failure reported is the cryptographic one
/// rather than a decoding error.
fn corrupt(value: &mut Value) {
    let text = value.as_str().expect("family string").to_owned();
    // The FIRST body character: in base64 the final data character carries only part of a
    // byte, so substituting there can produce an invalid trailing symbol rather than a
    // different value.
    let at = text.find(':').map_or(0, |i| i + 1);
    assert!(at < text.len(), "the value must have a body to corrupt");
    let mut bytes = text.into_bytes();
    bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
    *value = Value::String(String::from_utf8(bytes).expect("ascii substitution"));
}

/// A corpus key, reconstructed from its committed seed — the same "published constant... never
/// use for anything real" material `gen_vectors` signs with.
fn test_key(name: &str) -> TestKey {
    let path = test_data().join("keys").join(format!("{name}.seed"));
    let seed =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    TestKey::from_seed_hex(name, seed.trim()).expect("committed 32-byte hex seed")
}

/// The corpus producer key.
fn producer_key() -> TestKey {
    test_key("producer-1")
}

/// The corpus key with this `key_id`, whatever its role.
fn key_by_id(key_id: &str) -> TestKey {
    ["producer-1", "producer-2", "log-1", "witness-1", "witness-2"]
        .into_iter()
        .map(test_key)
        .find(|key| key.key_id() == key_id)
        .expect("a corpus key")
}

/// Re-anchor a receipt whose carried governance material was edited: rebuild the corpus log
/// tree over the edited envelopes, recompute every inclusion path the receipt carries, and
/// reissue the checkpoint signature and the cosignature over it under the committed keys.
///
/// I-D §7.5 step 3 recomputes EVERY `governance.chain[]` element's inclusion path — and the
/// subject's — before step 4's induction reads a single member of any of them, because "the
/// path proof IS the index proof". An edited governance statement that is not also re-anchored
/// is therefore rejected as an unanchored hop: a true rejection, and never the rule under
/// test. Re-anchoring puts the edited statement genuinely in the log, so the rule the case
/// targets is the first thing left to fail.
fn reanchor(receipt: &mut Value) {
    let index_of = |value: &Value| {
        usize::try_from(value["entry_index"].as_u64().expect("entry_index")).expect("index fits")
    };
    let mut anchored = envelopes(&statement_vectors());
    let subject_index = index_of(&receipt["subject"]);
    for hop in receipt["governance"]["chain"].as_array().expect("chain").clone() {
        anchored[index_of(&hop)] = hop["envelope"].clone();
        // A governance statement that is ALSO the receipt's subject is ONE anchored entry, and
        // one entry index holds one envelope. An edit to the hop is therefore an edit to the
        // subject: carrying them apart would be a receipt no log could ever have produced, and
        // the subject's own identifiers (§7.5 step 1) are recomputed from the edited bytes.
        if index_of(&hop) == subject_index {
            receipt["envelope"] = hop["envelope"].clone();
            receipt["subject"]["statement_id"] =
                json!(statement_id(&hop["envelope"]).expect("well-formed envelope"));
            receipt["subject"]["entry_id"] = json!(entry_id(&hop["envelope"]));
        }
    }
    let leaves: Vec<Vec<u8>> = anchored.iter().map(jcs).collect();
    let checkpoint_object = receipt["anchoring"]["checkpoint"].clone();
    let tree_size = checkpoint_object["tree_size"].as_u64().expect("tree_size");
    let prefix = &leaves[..usize::try_from(tree_size).expect("tree size fits")];
    let root = hash_hex(&tree_root(prefix));

    let path = |index: usize| {
        json!(proof_path_hex(
            &inclusion_proof(prefix, index).expect("the entry is within the checkpoint")
        ))
    };
    receipt["anchoring"]["inclusion_path"] = path(index_of(&receipt["subject"]));
    for hop in receipt["governance"]["chain"].as_array_mut().expect("chain") {
        let index =
            usize::try_from(hop["entry_index"].as_u64().expect("entry_index")).expect("index fits");
        hop["inclusion_path"] = path(index);
    }

    let signed = checkpoint(
        field_str(&checkpoint_object, "log_id").expect("log_id"),
        tree_size,
        &root,
        field_str(&checkpoint_object, "checkpoint_time").expect("checkpoint_time"),
        &key_by_id(field_str(&checkpoint_object, "key_id").expect("key_id")),
    );
    for cosignature in receipt["anchoring"]["witnesses"].as_array_mut().expect("witnesses") {
        let witness_id = field_str(cosignature, "witness_id").expect("witness_id").to_owned();
        let witness = key_by_id(field_str(cosignature, "key_id").expect("key_id"));
        cosignature["cosignature"] = json!(witness.sign(&cosignature_bytes(&signed, &witness_id)));
    }
    receipt["anchoring"]["checkpoint"] = signed;
}

/// Re-sign `envelope["payload"]` with `key`, replacing its single signature entry in place.
///
/// I-D §7.5.1 4b phase 1 now runs BEFORE phase 2 (`read_chain`): a mutated governance-hop
/// payload fails its OWN signature before the type-specific rule a test targets is ever
/// reached, unless the mutation is re-signed — exactly the ordering B1 fixed.
fn resign(envelope: &mut Value, key: &TestKey) {
    let sig = key.sign(&jcs(&envelope["payload"]));
    envelope["signatures"][0]["sig"] = json!(sig);
    envelope["signatures"][0]["key_id"] = json!(key.key_id());
}

#[test]
fn version_and_identifier_rules_reject() {
    assert_rejects(
        "statement-anchored-valid.ahl",
        // "1" is the PRIOR revision's `ahl_receipt_version` — the exact case I-D §7.1
        // "Revision and rule selection" describes: unverifiable, never invalid.
        |r| r["ahl_receipt_version"] = Value::String("1".to_owned()),
        |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_receipt_version", .. }),
        "§5 step 1 — receipt version",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["spec_version"] = Value::String("0.3.0".to_owned()),
        |e| matches!(e, ReceiptError::UnsupportedVersion { field: "spec_version", .. }),
        "§5 step 1 — spec version",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["subject"]["statement_id"]),
        |e| matches!(e, ReceiptError::IdentifierMismatch { field: "statement_id" }),
        "§5 step 1 — statement id recomputation",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["subject"]["entry_id"]),
        |e| matches!(e, ReceiptError::IdentifierMismatch { field: "entry_id" }),
        "§5 step 1 — entry id recomputation",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["subject"]["entry_index"] = json!(9_999),
        |e| matches!(e, ReceiptError::EntryIndexBeyondCheckpoint { .. }),
        "§5 step 3 — entry_index < tree_size",
    );
}

#[test]
fn anchoring_rules_reject() {
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["anchoring"]["checkpoint"]["signature"]),
        |e| matches!(e, ReceiptError::CheckpointSignatureInvalid),
        "§5 step 3 — checkpoint signature",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["anchoring"]["witnesses"][0]["cosignature"]),
        |e| matches!(e, ReceiptError::WitnessCosignatureInvalid { .. }),
        "§5 step 3 — witness cosignature",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["anchoring"]["inclusion_path"][0]),
        |e| matches!(e, ReceiptError::InclusionPathInvalid { what: "subject" }),
        "§5 step 3 — inclusion path",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["governance"]["chain"][0]["inclusion_path"][0]),
        |e| matches!(e, ReceiptError::InclusionPathInvalid { what: "governance chain hop" }),
        "§5 step 4 — chain hop anchoring",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["envelope"]["signatures"][0]["sig"]),
        // The envelope digest changes with the signature, so the identifier check fires first —
        // which is itself the point: an envelope cannot be edited without breaking its ids.
        |e| matches!(e, ReceiptError::IdentifierMismatch { .. }),
        "§2.1 — the envelope is digest-bound",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["keys"]["log"][0]["key_id"]),
        |e| matches!(e, ReceiptError::KeyNotBound { .. }),
        "adaptor §3 — key ids are recomputed from the public key",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["keys"]["log"][0]["binding"]["entry_index"] = json!(7),
        |e| matches!(e, ReceiptError::KeyNotBound { entry_index: 7, .. }),
        "§2.2 — log keys bind to the manifest active for the checkpoint",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["keys"]["log"][0]["source"] = Value::String("local-policy".to_owned()),
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("witness keys")),
        "I-D §7.1 — local-policy source is witness-only",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["anchoring"]["checkpoint"]["log_id"]),
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "adaptor §5 — checkpoint log_id matches the active manifest",
    );
}

/// A witness key nobody declared, cosigning under an identity of its own choosing.
///
/// I-D §7.1: "`source: \"local-policy\"` is an acceptable source only for witness keys the
/// verifier ALREADY TRUSTS." The receipt's `keys` block is carried material, so `local-policy`
/// is a claim about the VERIFIER's configuration, never one the receipt can make good on
/// itself. Without that check an unauthorized party assembles the whole of L3's independence
/// out of material it controls: put a witness key of its own in `keys.witness[]`, label it
/// `local-policy`, cosign the checkpoint with the matching private key, and the "at least one
/// witness cosignature verified" requirement is satisfied by the party the witness exists to
/// be independent of.
///
/// Everything here is genuine except the trust: the cosignature really does verify under the
/// key presented. What decides the outcome is whether local policy holds that key.
#[test]
fn a_local_policy_witness_key_is_accepted_only_from_the_verifiers_own_trusted_set() {
    let impostor = TestKey::from_seed_hex("impostor", &"ee".repeat(32)).expect("32-byte seed");

    // The same receipt throughout, cosigned for real by a key no manifest declares, under
    // whichever identity the case is about. Only the trust decision differs between cases.
    let cosigned_as = |witness_id: &str| {
        let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
        receipt["keys"]["witness"] = json!([{
            "witness_id": witness_id,
            "key_id": impostor.key_id(),
            "pubkey": impostor.pubkey(),
            "source": "local-policy",
        }]);
        receipt["anchoring"]["witnesses"] = json!([{
            "witness_id": witness_id,
            "key_id": impostor.key_id(),
            "cosignature": impostor
                .sign(&cosignature_bytes(&receipt["anchoring"]["checkpoint"], witness_id)),
            "cosigned_at": "2026-08-16T12:00:00Z",
        }]);
        receipt
    };
    let holding = |pubkey: String, witness_id: &str| {
        let mut policy = trust_policy();
        policy.trusted_witness_keys.insert(
            impostor.key_id(),
            TrustedWitnessKey { pubkey, witness_id: witness_id.to_owned() },
        );
        policy
    };

    // A verifier trusting no witness key of its own trusts none of the receipt's.
    assert!(
        matches!(
            verify_receipt(&cosigned_as("witness-1"), &trust_policy()),
            Err(ReceiptError::WitnessKeyNotTrusted { ref key_id }) if key_id == &impostor.key_id()
        ),
        "a local-policy witness key absent from the policy set must not be accepted"
    );

    // Nor does holding the id alone suffice: the receipt supplies the public key the
    // cosignature is verified under, so a trusted id carrying an unknown key would let the
    // presenter choose the verification key.
    assert!(
        matches!(
            verify_receipt(
                &cosigned_as("witness-1"),
                &holding(producer_key().pubkey(), "witness-1")
            ),
            Err(ReceiptError::WitnessKeyNotTrusted { .. })
        ),
        "a trusted key id carrying a public key policy never saw must not be accepted"
    );

    // Nor is a key trusted for ONE witness a key trusted to cosign as another: the identity is
    // in the cosignature preimage, and policy holds the key for a named witness.
    assert!(
        matches!(
            verify_receipt(&cosigned_as("witness-2"), &holding(impostor.pubkey(), "witness-1")),
            Err(ReceiptError::WitnessKeyNotTrusted { .. })
        ),
        "a local-policy key must cosign under the identity policy holds it for"
    );

    // And policy cannot invent a witness. `witness-of-its-own` is declared by no manifest in
    // this corpus, so even a verifier that genuinely holds the key for exactly that identity
    // is being asked to accept a witness the log's own governance never named.
    assert!(
        matches!(
            verify_receipt(
                &cosigned_as("witness-of-its-own"),
                &holding(impostor.pubkey(), "witness-of-its-own")
            ),
            Err(ReceiptError::WitnessNotDeclared { ref witness_id, tree_size: 20 })
                if witness_id == "witness-of-its-own"
        ),
        "a cosignature must name an identity the active manifest declares, whatever the source"
    );

    // Held for a declared identity, and cosigning under it: admissible. The rule is the policy
    // set plus the manifest's own witness list, not a blanket refusal of the source.
    let verdict =
        verify_receipt(&cosigned_as("witness-1"), &holding(impostor.pubkey(), "witness-1"))
            .expect("a local-policy witness key the verifier holds is admissible (I-D §7.1)");
    assert!(verdict.assurance.witnessed, "its cosignature is what makes the checkpoint witnessed");
}

/// I-D §7.1: a witness key object "additionally carries `witness_id`, the identity under which
/// the manifest declares that witness", and each `anchoring.witnesses[]` element names "the
/// witness identity as declared in the manifest".
///
/// The identity is inside the cosignature preimage, so binding by `key_id` alone would let a
/// declared witness's key be presented under any identity at all.
#[test]
fn witness_identity_is_bound_to_the_manifests_own_declaration() {
    assert_rejects(
        "statement-anchored-valid.ahl",
        // The key is the one the manifest declares; the identity it cosigns under is not.
        |r| r["anchoring"]["witnesses"][0]["witness_id"] = json!("witness-2"),
        |e| {
            matches!(
                e,
                ReceiptError::WitnessIdentityMismatch { ref declared, ref carried, .. }
                    if declared == "witness-1" && carried == "witness-2"
            )
        },
        "I-D §7.1 — a cosignature's witness_id is the manifest's declared identity",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        // The same substitution made in the `keys` block instead: no manifest witness key
        // object matches `(witness-2, this key_id, this pubkey)`, so the key does not bind.
        |r| {
            r["keys"]["witness"][0]["witness_id"] = json!("witness-2");
            r["anchoring"]["witnesses"][0]["witness_id"] = json!("witness-2");
        },
        |e| matches!(e, ReceiptError::KeyNotBound { .. }),
        "I-D §7.1 — a manifest-chain witness key binds by (witness_id, key_id, pubkey)",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["keys"]["witness"][0].as_object_mut().expect("key object").remove("witness_id");
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("witness_id")),
        "I-D §7.1 — a witness key object carries witness_id",
    );
}

/// I-D §7.1: "The member shapes shown above are normative."
///
/// A present member of the wrong JSON type is `invalid`, never read as absent. Read as absent,
/// `\"witnesses\": {}` would turn a checkpoint that carries no verifying cosignature into one
/// that was never asked for any — and at L3 that is the whole of the witness requirement.
#[test]
fn a_present_cosignature_member_of_the_wrong_type_is_invalid() {
    for wrong in [json!({}), json!("witness-1"), json!(0)] {
        let value = wrong.clone();
        assert_rejects(
            "statement-anchored-valid.ahl",
            move |r| r["anchoring"]["witnesses"] = value,
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("MUST be an array")),
            "I-D §7.1 — anchoring.witnesses is an array where present",
        );
        let value = wrong.clone();
        assert_rejects(
            "statement-anchored-continued-history.ahl",
            move |r| r["anchoring"]["later_witnesses"] = value,
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("MUST be an array")),
            "I-D §7.1 — anchoring.later_witnesses is an array where present",
        );
        let value = wrong.clone();
        assert_rejects(
            "propagation-complete-valid-across-manifest-rotation.ahl",
            move |r| r["governance"]["rotation_proofs"][0]["witnesses"] = value,
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("MUST be an array")),
            "I-D §7.1 — a rotation proof's witnesses is an array where present",
        );
    }

    // Every ELEMENT of each of those arrays is validated too, whether or not verification would
    // have reached it: the shape is normative, not a precondition of use.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["anchoring"]["witnesses"] = json!([{ "witness_id": "witness-1" }]),
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("witness cosignature")),
        "I-D §7.1 — every anchoring.witnesses[] element takes the shape",
    );
}

/// I-D §7.1: a `governance.rotation_proofs[]` element's `witnesses` is "an array in the shape
/// of `anchoring.witnesses[]`", and at L3 at least one of its cosignatures must verify "under a
/// witness key of the OUTGOING state".
///
/// Those keys are resolved straight out of the outgoing manifest by `(witness_id, key_id)`, so
/// the identity binding of `anchoring.witnesses[]` holds here by construction: a cosignature
/// naming an identity the outgoing manifest does not declare for that key resolves to no key
/// at all, and at L3 that leaves the rotation unattested.
#[test]
fn a_rotation_proof_cosignature_binds_to_the_outgoing_manifests_identity() {
    assert_rejects(
        "governance-state-valid.ahl",
        // The outgoing state declares this key under `witness-1`; `witness-2` is the identity
        // the rotation INSTALLS, and naming it here attests nothing about the handover.
        |r| {
            r["governance"]["rotation_proofs"][0]["witnesses"][0]["witness_id"] =
                json!("witness-2");
        },
        |e| {
            matches!(
                e,
                ReceiptError::RotationProofInvalid { manifest_entry_index: 25, ref detail }
                    if detail.contains("OUTGOING")
            )
        },
        "I-D §7.1 — a rotation proof cosigns under the outgoing manifest's own witness identity",
    );
}

/// I-D §7.1: "`source` is exactly one of `\"manifest-chain\"` or `\"local-policy\"`."
///
/// There is no third token and no default. An unrecognized one is a schema failure over the
/// whole `keys` block, reported whether or not verification would ever have reached that
/// entry — binding itself is deliberately tolerant per entry, so a shape defect checked only
/// at binding time would go unreported on any key no checkpoint happens to need.
#[test]
fn a_key_object_declares_one_of_the_two_sources_the_container_admits() {
    for group in ["log", "witness", "producer"] {
        assert_rejects(
            "statement-anchored-valid.ahl",
            |r| r["keys"][group][0]["source"] = json!("other"),
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("`other`")),
            "I-D §7.1 — source is exactly manifest-chain or local-policy",
        );
        assert_rejects(
            "statement-anchored-valid.ahl",
            |r| {
                r["keys"][group][0].as_object_mut().expect("key object").remove("source");
            },
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("`source`")),
            "I-D §7.1 — source is REQUIRED",
        );
        assert_rejects(
            "statement-anchored-valid.ahl",
            |r| {
                r["keys"][group][0].as_object_mut().expect("key object").remove("binding");
            },
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("`binding`")),
            "I-D §7.1 — binding is REQUIRED where source is manifest-chain",
        );
        // The member's SHAPE is normative wherever it appears, and that is the wider rule:
        // required for one source, but `{"entry_index": <integer>}` for both.
        for wrong in [json!({}), json!({ "entry_index": "0" }), json!(0), json!([0])] {
            let value = wrong.clone();
            assert_rejects(
                "statement-anchored-valid.ahl",
                move |r| r["keys"][group][0]["binding"] = value,
                |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("`binding`")),
                "I-D §7.1 — a present binding is {\"entry_index\": <integer>}",
            );
        }
    }
    // Including on a `local-policy` witness key, where the member is optional but not thereby
    // shapeless.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["keys"]["witness"][0]["source"] = json!("local-policy");
            r["keys"]["witness"][0]["binding"] = json!({ "entry_index": "0" });
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("`binding`")),
        "I-D §7.1 — a present binding is shaped even where it is optional",
    );
}

/// Edit the genesis manifest's `log` object, then repair the receipt's own genesis anchor and
/// the policy that must match it, and assert the §7.3 rejection.
///
/// Repairing the anchor is what makes the assertion mean anything: editing an anchored envelope
/// changes its entry id, so without this the receipt would be rejected for carrying an anchor
/// that no longer digests its genesis envelope — a true rejection, but not the one under test.
fn reject_by_manifest_schema(mutate: impl FnOnce(&mut serde_json::Map<String, Value>), case: &str) {
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    mutate(
        receipt["governance"]["chain"][0]["envelope"]["payload"]
            .as_object_mut()
            .expect("manifest payload"),
    );
    reanchor(&mut receipt);
    let anchor = entry_id(&receipt["governance"]["chain"][0]["envelope"]);
    receipt["governance"]["genesis_entry_id"] = json!(&anchor);
    let policy = TrustPolicy { genesis_entry_id: anchor, ..trust_policy() };

    let error = verify_receipt(&receipt, &policy)
        .err()
        .unwrap_or_else(|| panic!("{case}: must be rejected, but verified"));
    assert!(
        matches!(error, ReceiptError::ManifestSchemaInvalid { .. }),
        "{case}: expected a manifest-schema rejection, got: {error}"
    );
}

/// The same, scoped to the `log` object every §7.3 member lives in.
fn reject_by_log_schema(mutate: impl FnOnce(&mut serde_json::Map<String, Value>), case: &str) {
    reject_by_manifest_schema(
        |payload| mutate(payload["log"].as_object_mut().expect("manifest log object")),
        case,
    );
}

#[test]
fn the_manifest_log_object_schema_is_enforced_and_log_id_has_no_alias() {
    // Renaming `log.log_id` to `log.id` — the spelling `ahl-core` once read — must break
    // verification outright. If a verifier fell back to `id`, a corpus written in the old
    // dialect would keep verifying against one implementation and fail against its siblings,
    // and nothing would ever surface the divergence.
    reject_by_log_schema(
        |log| {
            let value = log.remove("log_id").expect("log_id");
            log.insert("id".to_owned(), value);
        },
        "log.log_id renamed to log.id",
    );

    // Spec §7.3: every member of the object is REQUIRED, so dropping any one is a rejection —
    // including `cadence_epoch`, which no corpus in this family carried until it was noticed.
    for member in [
        "log_id",
        "operator",
        "checkpoint_cadence",
        "cadence_epoch",
        "witness_grace_period",
        "adaptor",
        "keys",
    ] {
        reject_by_log_schema(
            |log| {
                log.remove(member);
            },
            member,
        );
    }
    for member in ["id", "hash"] {
        reject_by_log_schema(
            |log| {
                log["adaptor"].as_object_mut().expect("adaptor object").remove(member);
            },
            member,
        );
    }

    // Wrong shapes are rejected as firmly as absent ones: a member present but not a string
    // proves nothing, and reading it as one would be reading whatever `serde_json` coerced.
    reject_by_log_schema(|log| log["log_id"] = json!(7), "log_id is not a string");
    reject_by_log_schema(|log| log["adaptor"] = json!("ahl-test-log-v1"), "adaptor is not object");
    reject_by_log_schema(|log| log["keys"] = json!({}), "keys is not an array");

    // And the whole object is required in the first place.
    reject_by_manifest_schema(
        |payload| {
            payload.remove("log");
        },
        "the log object itself",
    );
    reject_by_manifest_schema(|payload| payload["log"] = json!("a log"), "log is not an object");
}

#[test]
fn the_manifest_log_object_value_grammars_are_enforced() {
    // §7.3 states value grammars, not just membership, and requires a malformed value to be
    // "rejected rather than approximated". The duty is on the value: this verifier computes no
    // cadence or freshness verdict, but a manifest carrying `P1Y` would make those verdicts
    // implementation-dependent for whoever does compute them, so it must not verify here.

    // Family strings: `sha256:` plus exactly 64 lowercase hex digits. Uppercase hex names the
    // same digest but compares unequal as a string, and every key lookup here is a comparison.
    reject_by_log_schema(|log| log["log_id"] = json!("sha256:00ff"), "log_id is too short");
    reject_by_log_schema(
        |log| log["log_id"] = json!(format!("sha256:{}", "AB".repeat(32))),
        "log_id in uppercase hex",
    );
    reject_by_log_schema(
        |log| log["log_id"] = json!(format!("md5:{}", "ab".repeat(32))),
        "log_id under another hash family",
    );
    reject_by_log_schema(
        |log| log["adaptor"]["hash"] = json!("sha256:not-hex"),
        "adaptor.hash is not hex",
    );

    // Durations: time components only. Years and a date-part `M` are PROHIBITED because their
    // length is context-dependent, which is exactly what would make cadence, frontier and
    // completeness bounds implementation-dependent.
    for bad in [
        "P1Y",             // years
        "P1M",             // calendar months in the date part
        "P1YT1H",          // years alongside a legal time part
        "P1W",             // weeks are not in the restricted grammar either
        "PT1H30",          // a component with no designator
        "PTH",             // a designator with no digits
        "PT",              // `T` with no component
        "P1DT",            // a dangling `T`
        "P",               // no component at all
        "1H",              // no leading `P`
        "PT1S1H",          // out of order
        "PT1H1H",          // repeated component
        "PT-1H",           // signed
        "pt1h",            // lowercase designators are not the grammar as written
        "PT1.5H",          // a fraction on a component other than seconds
        "PT0.1234567891S", // ten fractional digits
    ] {
        reject_by_log_schema(|log| log["checkpoint_cadence"] = json!(bad), bad);
        reject_by_log_schema(|log| log["witness_grace_period"] = json!(bad), bad);
    }

    // A zero cadence is a maximum gap no published series could ever meet.
    for zero in ["PT0S", "PT0H0M0S", "P0D"] {
        reject_by_log_schema(|log| log["checkpoint_cadence"] = json!(zero), zero);
    }

    // The grace period, by contrast, may legitimately be zero: §7.3 fixes the "greater than
    // zero" rule on the cadence alone, and a deployment allowing no slack at all is strict
    // rather than malformed. Accepting the forms §7.3 admits matters as much as rejecting the
    // rest — a validator that rejected everything would pass every negative test above.
    for good in ["PT0S", "P1D", "PT15M", "P1DT2H3M4S", "PT0.123456789S", "PT1H0M0S"] {
        let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
        receipt["governance"]["chain"][0]["envelope"]["payload"]["log"]["witness_grace_period"] =
            json!(good);
        let anchor = entry_id(&receipt["governance"]["chain"][0]["envelope"]);
        receipt["governance"]["genesis_entry_id"] = json!(&anchor);
        let policy = TrustPolicy { genesis_entry_id: anchor, ..trust_policy() };
        // Editing the manifest breaks its chain hop's inclusion proof, which is checked well
        // after the schema, so the receipt may still be rejected — just never by the schema.
        // (`PT15M` is the corpus value, so that one edit changes nothing and verifies outright.)
        if let Err(error) = verify_receipt(&receipt, &policy) {
            assert!(
                !matches!(error, ReceiptError::ManifestSchemaInvalid { .. }),
                "`{good}` is a duration §7.3 admits and must not be rejected by the schema: \
                 {error}"
            );
        }
    }

    // `cadence_epoch` is RFC 3339, and a date alone is not an instant.
    for bad in ["2026-08-16", "16/08/2026", "not a time", "2026-08-16T11:30:00"] {
        reject_by_log_schema(|log| log["cadence_epoch"] = json!(bad), bad);
    }

    // Key objects carry `{key_id, pubkey, valid_from_index}`, and an entry index is an
    // unsigned integer: a negative or fractional value indexes nothing in an append-only log.
    for member in ["key_id", "pubkey", "valid_from_index"] {
        reject_by_log_schema(
            |log| {
                log["keys"][0].as_object_mut().expect("key object").remove(member);
            },
            member,
        );
    }
    reject_by_log_schema(|log| log["keys"][0]["valid_from_index"] = json!(-1), "negative index");
    reject_by_log_schema(|log| log["keys"][0]["valid_from_index"] = json!(1.5), "fractional index");
    reject_by_log_schema(|log| log["keys"][0]["key_id"] = json!("sha256:zz"), "key_id not hex");

    // I-D §6.2: a PRODUCER key object is `{key_id, pubkey}` ONLY — no `valid_from_index` at
    // all, unlike log/witness key objects (checked next) which require it. So a producer key
    // object that DOES carry `valid_from_index` is the schema failure here, not one that
    // lacks it.
    reject_by_manifest_schema(
        |payload| {
            payload["keys"][0]["valid_from_index"] = json!(0);
        },
        "producer key object carrying valid_from_index",
    );
    reject_by_manifest_schema(
        |payload| {
            payload["keys"][0]["extra"] = json!("unexpected");
        },
        "producer key object carrying an unknown member",
    );
    // I-D §6.2: "`pubkey` decodes to exactly the 32 octets... `key_id` equals `sha256:`
    // followed by the lowercase hex SHA-256 of those octets, so it is recomputable rather than
    // merely declared." A syntactically well-formed `key_id` that simply belongs to a
    // DIFFERENT key is exactly what recomputation catches, and a bare family-string shape
    // check ([`is_family_hash`]) alone would miss.
    reject_by_manifest_schema(
        |payload| {
            payload["keys"][0]["key_id"] = json!(sha256_hex(b"not the real producer key"));
        },
        "producer key object whose key_id does not match its pubkey",
    );

    // The log/witness key-object shape DOES require `valid_from_index` (§7.2/§7.3, "same
    // form" as one another, but distinct from the producer shape above).
    reject_by_manifest_schema(
        |payload| {
            payload["witnesses"][0]["keys"][0]
                .as_object_mut()
                .expect("key object")
                .remove("valid_from_index");
        },
        "witness key object without valid_from_index",
    );
}

#[test]
fn the_manifest_scope_fields_are_enforced() {
    // I-D §6.2: the manifest "contains at minimum" `pipelines`, `windows`, `retention`, and
    // `level`, beyond producer/log/witness keys and datasets (covered above). `level` in
    // particular gates the L3 cosignature requirement elsewhere in this verifier, so an
    // absent or out-of-vocabulary value must fail HERE, in schema — never be silently read as
    // "not L3".
    reject_by_manifest_schema(
        |payload| {
            payload.remove("level");
        },
        "manifest missing level",
    );
    reject_by_manifest_schema(
        |payload| payload["level"] = json!("L4"),
        "manifest level outside {L1, L2, L3}",
    );
    reject_by_manifest_schema(
        |payload| {
            payload.remove("retention");
        },
        "manifest missing retention",
    );
    reject_by_manifest_schema(
        |payload| {
            payload["retention"].as_object_mut().expect("retention object").remove("statements");
        },
        "manifest retention missing statements",
    );
    reject_by_manifest_schema(
        |payload| {
            payload.remove("pipelines");
        },
        "manifest missing pipelines",
    );
    reject_by_manifest_schema(
        |payload| {
            payload.remove("windows");
        },
        "manifest missing windows",
    );
    // "Retention: for statements, and for artifacts IF REPRODUCIBLE RECONSTRUCTION IS
    // CLAIMED" — the second retention duration becomes REQUIRED exactly when that property
    // claims true, so claiming it true without also carrying `retention.artifacts` is invalid.
    reject_by_manifest_schema(
        |payload| payload["properties"]["reproducible_reconstruction"] = json!(true),
        "reproducible reconstruction claimed without retention.artifacts",
    );
}

#[test]
fn l3_witness_requirements_are_enforced() {
    // I-D §6.2: "Witnesses: at L3, witness ids with key objects" — the corpus genesis manifest
    // is L3, so its `witnesses` array is REQUIRED and non-empty; a schema failure otherwise.
    reject_by_manifest_schema(
        |payload| {
            payload.remove("witnesses");
        },
        "L3 manifest without witnesses",
    );

    // I-D §3.3, §7.5: "At L3 a verifier accepts a checkpoint C only with a valid witness
    // cosignature" — the corpus's PRIMARY checkpoint (governed by the same L3 genesis
    // manifest) must therefore carry at least one verifying cosignature; emptying
    // `anchoring.witnesses` must be rejected, not merely leave `assurance.witnessed` false.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |receipt| receipt["anchoring"]["witnesses"] = json!([]),
        |error| matches!(error, ReceiptError::CheckpointUnwitnessed { .. }),
        "AT L3, the primary checkpoint needs a verifying witness cosignature",
    );
}

#[test]
fn anchoring_adaptor_must_match_the_active_manifests_own_pin() {
    // I-D §3.2: "the profile id and hash are pinned in the manifest and carried in every
    // Evidence Receipt" — the two carriers of the SAME fact, which MUST agree. A receipt
    // naming a DIFFERENT profile in `anchoring.adaptor` than its governance chain's manifest
    // pins in `log.adaptor` must not reach that other profile's capabilities merely because
    // local policy happens to recognize it too.
    let mut policy = trust_policy();
    let other_profile = AdaptorProfile {
        document: b"a second document, distinct from the corpus's own".to_vec(),
        capabilities: AdaptorCapabilities::default(),
    };
    let other_hash = other_profile.hash();
    policy
        .adaptor_profiles
        .insert("a-second-profile-local-policy-also-holds".to_owned(), other_profile);
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    receipt["anchoring"]["adaptor"]["id"] = json!("a-second-profile-local-policy-also-holds");
    receipt["anchoring"]["adaptor"]["hash"] = json!(&other_hash);
    // This build interprets exactly ONE profile id, so naming another is refused at §7.5
    // step 2 as a profile limitation — before the receipt's own material is read at all, which
    // is a stronger refusal than the binding disagreement, not a weaker one.
    assert!(
        matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::AdaptorCapabilityUnsupported { ref id, .. })
                if id == "a-second-profile-local-policy-also-holds"
        ),
        "`anchoring.adaptor` naming a profile this build cannot interpret must be refused"
    );

    // The same disagreement in the other direction, where the profile IS one this build
    // interprets: the receipt names `ahl-test-log-v1` while the active manifest pins the other
    // profile. That is the §3.2 binding failure, and nothing about it is a capability gap.
    let (_, mut mismatched) = read_receipt("statement-anchored-valid.ahl");
    mismatched["governance"]["chain"][0]["envelope"]["payload"]["log"]["adaptor"] = json!({
        "id": "a-second-profile-local-policy-also-holds",
        "hash": other_hash,
    });
    reanchor(&mut mismatched);
    let anchor = entry_id(&mismatched["governance"]["chain"][0]["envelope"]);
    mismatched["governance"]["genesis_entry_id"] = json!(&anchor);
    let repinned = TrustPolicy { genesis_entry_id: anchor, ..policy };
    assert!(
        matches!(
            verify_receipt(&mismatched, &repinned),
            Err(ReceiptError::AdaptorBindingInvalid { .. })
        ),
        "`anchoring.adaptor` naming a profile the manifest itself does not pin must be rejected"
    );
}

#[test]
fn enumerated_currency_with_a_later_checkpoint_fails_closed() {
    // Receipt §2.1 requires governance material covering through `later_checkpoint.tree_size`;
    // §4 fixes enumerated material at exactly [0, tree_size(C)) for the anchoring checkpoint.
    // Both cannot hold at once, and the format defines no second authenticated range, so the
    // combination is refused. Accepting it would report as established a coverage requirement
    // nothing in the receipt proves — a manifest rotating the log key set between the two
    // checkpoints would be invisible to an enumeration bounded at the earlier size.
    let policy = trust_policy();
    let (_, receipt) =
        read_receipt("trigger-effective-enumerated-with-later-checkpoint-must-fail.ahl");
    let error = verify_receipt(&receipt, &policy).expect_err("the combination must be refused");
    assert!(matches!(error, ReceiptError::FormatConflict { .. }), "{error}");
    // The error names the conflict rather than pretending a rule failed.
    let rendered = error.to_string();
    assert!(rendered.contains("§2.1") && rendered.contains("§4"), "{rendered}");

    // Removing the later checkpoint — and the proof that pairs with it — leaves the very same
    // enumerated receipt verifying. Nothing about the enumeration was wrong; it simply cannot
    // reach a checkpoint beyond its own range.
    let mut without = receipt;
    let anchoring = without["anchoring"].as_object_mut().expect("anchoring");
    anchoring.remove("later_checkpoint");
    anchoring.remove("later_witnesses");
    anchoring.remove("consistency_path");
    without["claim"]["assurance"]["continued_history"] = json!(false);
    let verdict = verify_receipt(&without, &policy).expect("the enumerated claim itself is sound");
    assert_eq!(verdict.claim_type, "trigger-effective");
    assert!(!verdict.assurance.continued_history);

    // Declared mode is unaffected: it makes no currency claim to begin with (§2.1).
    let (_, declared) = read_receipt("statement-anchored-continued-history.ahl");
    assert_eq!(declared["governance"]["currency"]["mode"], json!("declared"));
    assert!(
        verify_receipt(&declared, &policy)
            .expect("declared mode is unaffected")
            .assurance
            .continued_history
    );
}

#[test]
fn a_governance_hop_the_checkpoint_cannot_commit_is_refused() {
    // The coverage §2.1 wants for a later checkpoint under a rotated key set would need a
    // manifest hop anchored beyond the anchoring checkpoint. Its inclusion cannot be proven
    // against that root, so it is a named refusal — never a pass on the strength of an older
    // key that happens to remain usable.
    // Append a genuine, well-formed manifest hop — version 2, chained to genesis by entry id —
    // at an index beyond the anchoring checkpoint of size 20. Everything about the statement is
    // real; what cannot exist is a proof of its inclusion under a root that never committed it.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            // chain[2] (manifest v2) would ALSO trip the I-D §7.1 rotation-proof check here,
            // since appending it makes this receipt's chain show a rotation relative to
            // genesis — pre-empting the "does not commit" check this test is actually about.
            // chain[1], the entry-9 `key` statement, carries no such baggage: `read_chain`
            // never applies the rotation check to a `key` hop, only to `manifest` ones.
            let (_, source) = read_receipt("governance-state-valid.ahl");
            let mut hop = source["governance"]["chain"][1].clone();
            hop["entry_index"] = json!(9_999);
            r["governance"]["chain"].as_array_mut().expect("chain").push(hop);
        },
        |e| {
            matches!(e, ReceiptError::GovernanceChainInvalid(detail)
                if detail.contains("does not commit"))
        },
        "§5 step 4 — a chain hop must be committed by the checkpoint it is proven against",
    );
}

#[test]
fn governance_chain_rules_reject() {
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["governance"]["chain"] = json!([]),
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.5 — the chain starts at genesis",
    );
    assert_rejects_anchored(
        "statement-anchored-valid.ahl",
        |r| r["governance"]["chain"][0]["envelope"]["payload"]["predecessor"] = json!("sha256:00"),
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.5 — the genesis manifest has no predecessor",
    );
    // These three mutate a governance hop's own PAYLOAD, so they must re-sign afterward — I-D
    // §7.5.1 4b phase 1 (signature, against K as established so far) runs BEFORE phase 2, the
    // type-specific rule each of these targets — and they must be re-anchored, because §7.5
    // step 3 proves every hop's inclusion path before phase 1 runs at all. Either repair
    // omitted, the mutation is caught by a real but different rule.
    assert_rejects_anchored(
        "governance-state-valid.ahl",
        |r| {
            r["governance"]["chain"][2]["envelope"]["payload"]
                .as_object_mut()
                .expect("manifest payload")
                .remove("predecessor");
            resign(&mut r["governance"]["chain"][2]["envelope"], &producer_key());
        },
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.5 — a non-genesis manifest references its predecessor",
    );
    assert_rejects_anchored(
        "governance-state-valid.ahl",
        |r| {
            corrupt(&mut r["governance"]["chain"][2]["envelope"]["payload"]["predecessor"]);
            resign(&mut r["governance"]["chain"][2]["envelope"], &producer_key());
        },
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.5 — the predecessor reference is the predecessor's entry id",
    );
    assert_rejects(
        "governance-state-valid.ahl",
        |r| r["governance"]["chain"].as_array_mut().expect("chain").swap(0, 1),
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.5 — chain hops ascend by entry index",
    );
    assert_rejects_anchored(
        "governance-state-valid.ahl",
        |r| {
            r["governance"]["chain"][1]["envelope"]["payload"]["action"] = json!("revoke");
            resign(&mut r["governance"]["chain"][1]["envelope"], &producer_key());
        },
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.6 — key actions are add or retire",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| corrupt(&mut r["governance"]["genesis_entry_id"]),
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§5 step 4 — the anchor must digest the carried genesis envelope",
    );
}

/// I-D §7.5: step 3 is "key-independent structural and path checks — no signature and no
/// cosignature is verified in this step", and step 4's induction runs only after it.
///
/// A receipt carrying BOTH a broken chain inclusion path and a broken chain signature has two
/// defects, one per step, and which one a verifier reports is the whole of the observable
/// difference between the two orders. It must be the path: a governance statement whose
/// asserted entry index is unproven has not been shown to be in the log at all, and verifying
/// its signature first would be work driven by material nothing has anchored. The I-D permits
/// an early signature check only as a fail-fast optimization whose "provisional pass is not a
/// result", which is a licence to check early, never a licence to REPORT in that order.
#[test]
fn step_3_path_checks_precede_the_step_4_induction() {
    // Entry 9's `key` statement, anchored WITH a signature that does not verify: corrupting a
    // signature changes the envelope's bytes and therefore its entry id, so the hop has to be
    // re-anchored or the defect under test never gets past step 3 on its own.
    let (_, mut signature_only) = read_receipt("governance-state-valid.ahl");
    corrupt(&mut signature_only["governance"]["chain"][1]["envelope"]["signatures"][0]["sig"]);
    reanchor(&mut signature_only);

    // The signature defect alone: step 3 passes, and phase 1 of the induction reports it.
    assert!(
        matches!(
            verify_receipt(&signature_only, &trust_policy()),
            Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: 9 })
        ),
        "a chain hop whose signature does not verify is caught by the induction (4b phase 1)"
    );

    // Both defects together: the path failure is what a verifier reports, because step 3 is
    // where it is decided.
    let mut both = signature_only;
    corrupt(&mut both["governance"]["chain"][1]["inclusion_path"][0]);
    assert!(
        matches!(
            verify_receipt(&both, &trust_policy()),
            Err(ReceiptError::InclusionPathInvalid { what }) if what == "governance chain hop"
        ),
        "with a broken path AND a broken signature on the same hop, the path failure is the \
         result: step 3 runs before step 4"
    );
}

#[test]
fn cross_field_consistency_rules_reject() {
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["claim"]["assurance"]["witnessed"] = json!(false),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "witnessed" }),
        "§2.3 — witnessed iff a cosignature verifies",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["claim"]["assurance"]["continued_history"] = json!(true),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "continued_history" }),
        "§2.3 — continued_history iff a consistency proof verifies",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["claim"]["record_subject"] = json!({ "dataset": "customers", "record": "sha256:00" });
        },
        |e| matches!(e, ReceiptError::RecordSubjectMismatch { .. }),
        "§3 — record_subject is absent for statement-anchored",
    );
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| {
            r["claim"].as_object_mut().expect("claim").remove("record_subject");
        },
        |e| matches!(e, ReceiptError::RecordSubjectMismatch { .. }),
        "§3 — record_subject is required for record-*",
    );
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| corrupt(&mut r["claim"]["record_subject"]["record"]),
        |e| matches!(e, ReceiptError::RecordSubjectMismatch { .. }),
        "§2.3 — record_subject matches the subject envelope",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["subject"].as_object_mut().expect("subject").remove("manifest");
        },
        |e| matches!(e, ReceiptError::SubjectManifestPresence { .. }),
        "§2.3 — subject.manifest present for every non-manifest subject",
    );
    assert_rejects(
        "governance-state-valid.ahl",
        |r| r["subject"]["manifest"] = json!("sha256:00"),
        |e| matches!(e, ReceiptError::SubjectManifestPresence { .. }),
        "§2.3 — subject.manifest absent for manifest subjects",
    );
    assert_rejects(
        "governance-state-valid.ahl",
        |r| r["claim"]["type"] = json!("not-a-registry-type"),
        |e| matches!(e, ReceiptError::Malformed(_)),
        "§3 — claim.type must be a registry id",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        // A type §4 does not permit in declared mode.
        |r| r["claim"]["type"] = json!("propagation-complete"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "governance" }),
        "§4 — declared mode is limited to the compact claim types",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["claim"]["assurance"]["governance"] = json!("assumed");
            r["governance"]["currency"]["mode"] = json!("assumed");
        },
        |e| matches!(e, ReceiptError::Malformed(_)),
        "§4 — governance mode is declared or enumerated",
    );
    assert_rejects(
        "trigger-declared-valid.ahl",
        |r| r["claim"]["assurance"]["competing_triggers"] = json!("enumerated"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "competing_triggers" }),
        "§2.3 — competing_triggers enumerated only with the §3 range",
    );
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| r["claim"]["assurance"]["content_binding"] = json!("none"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "content_binding" }),
        "§2.1 — content evidence absent iff content_binding is none",
    );
}

#[test]
fn claim_material_rules_reject() {
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| r["claim_material"]["checkpoint_C"]["tree_size"] = json!(13),
        |e| {
            matches!(
                e,
                ReceiptError::CheckpointNotBound { field: "claim_material.checkpoint_C", .. }
            )
        },
        "§3 — checkpoint_C is the receipt's verified checkpoint",
    );
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| {
            r["claim_material"]["checkpoint_C"]
                .as_object_mut()
                .expect("checkpoint")
                .remove("root_hash");
        },
        |e| matches!(e, ReceiptError::CheckpointNotBound { member, .. } if member == "root_hash"),
        "§2.3.4 — a corpus checkpoint carries log_id, tree_size and root_hash",
    );
    assert_rejects(
        "propagation-complete-valid.ahl",
        |r| r["claim_material"]["corpus_checkpoint"]["log_id"] = json!("sha256:00"),
        |e| {
            matches!(
                e,
                ReceiptError::CheckpointNotBound { field: "claim_material.corpus_checkpoint", .. }
            )
        },
        "§3 — propagation-complete's corpus_checkpoint is the verified checkpoint",
    );
    assert_rejects(
        "propagation-complete-valid.ahl",
        |r| corrupt(&mut r["envelope"]["payload"]["trigger"]),
        // Editing the payload changes the statement id, which is checked first.
        |e| matches!(e, ReceiptError::IdentifierMismatch { .. }),
        "§2.1 — the payload is digest-bound",
    );
    assert_rejects(
        "propagation-complete-valid.ahl",
        |r| {
            r["claim_material"].as_object_mut().expect("material").remove("trigger");
        },
        |e| matches!(e, ReceiptError::ClaimMaterialMissing { field: "trigger", .. }),
        "§3 — propagation-complete requires an embedded trigger-effective receipt",
    );
    assert_rejects(
        "disposition-declared-valid.ahl",
        |r| {
            r["claim_material"].as_object_mut().expect("material").remove("disposition_leaf");
        },
        |e| matches!(e, ReceiptError::ClaimMaterialMissing { field: "disposition_leaf", .. }),
        "§3 — disposition claims carry the leaf they open",
    );
    assert_rejects(
        "record-derived-valid.ahl",
        |r| corrupt(&mut r["claim_material"]["output"]["record"]),
        |e| matches!(e, ReceiptError::RecordSubjectMismatch { .. }),
        "§3 — record_subject matches claim_material.output",
    );
    assert_rejects(
        "record-derived-valid.ahl",
        |r| {
            corrupt(&mut r["claim_material"]["batch_leaf"]["record"]);
            corrupt(&mut r["claim_material"]["output"]["record"]);
            corrupt(&mut r["claim"]["record_subject"]["record"]);
        },
        |e| matches!(e, ReceiptError::InclusionPathInvalid { what: "batch output leaf" }),
        "§3 — batch_leaf must open outputs_root",
    );
    assert_rejects(
        "record-derived-valid.ahl",
        |r| corrupt(&mut r["claim_material"]["input_members"][0]["input_path"][0]),
        |e| matches!(e, ReceiptError::InclusionPathInvalid { what: "input-set member" }),
        "§3 — input_members open the leaf's input_set_root",
    );
    assert_rejects(
        "governance-state-valid.ahl",
        |r| r["claim_material"]["target_index"] = json!(1),
        |e| matches!(e, ReceiptError::EmbeddedOrderingViolation { what: "governance subject", .. }),
        "§3 — subject.entry_index <= target_index",
    );
    assert_rejects(
        "governance-state-valid.ahl",
        |r| r["claim_material"]["target_index"] = json!(99),
        |e| matches!(e, ReceiptError::GovernanceRangeNotComplete { .. }),
        "§3/§4 — the enumeration must reach the target index",
    );
}

#[test]
fn enumeration_rules_reject() {
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| {
            r["governance"]["currency"]["material"]["entries"]
                .as_array_mut()
                .expect("entries")
                .pop();
        },
        |e| matches!(e, ReceiptError::RangeProofInvalid { what: "governance", .. }),
        "§4.2 — the carried entry count equals the range width",
    );
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| r["governance"]["currency"]["material"]["entries"][2]["entry_index"] = json!(99),
        |e| matches!(e, ReceiptError::RangeProofInvalid { what: "governance", .. }),
        "§4.2 — entries are in index order with no gaps",
    );
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| r["governance"]["currency"]["material"]["range"]["to_index"] = json!(7),
        |e| matches!(e, ReceiptError::RangeProofInvalid { what: "governance", .. }),
        "§4.2 — the range proof covers the declared range",
    );
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| {
            r["governance"]["currency"]["material"]["entries"][2]["envelope"]["payload"]
                ["issued_at"] = json!("2000-01-01T00:00:00Z");
        },
        |e| matches!(e, ReceiptError::RangeProofInvalid { what: "governance", .. }),
        "§4.2 — a substituted entry does not open the checkpoint root",
    );
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| {
            let range = r["claim_material"]["competing"]["corpus_range"].clone();
            r["governance"]["currency"]["material"] = range;
        },
        |e| matches!(e, ReceiptError::GovernanceRangeNotComplete { got_from: 1, .. }),
        "§4 — enumerated governance covers exactly [0, tree_size(C))",
    );
}

#[test]
fn the_governing_trigger_must_be_the_subject() {
    // Re-point the competing enumeration at a checkpoint whose range contains a *later*
    // trigger for the same record; the subject then no longer governs.
    let policy = trust_policy();
    let (_, valid) = read_receipt("trigger-effective-valid.ahl");
    let mut receipt = valid;
    // Drop the subject's own entry from the enumeration so no trigger for the record is found.
    let entries = receipt["claim_material"]["competing"]["corpus_range"]["entries"]
        .as_array_mut()
        .expect("entries");
    for entry in entries.iter_mut() {
        if entry["entry_index"] == json!(6) {
            entry["envelope"]["payload"]["type"] = json!("ingestion");
        }
    }
    assert!(
        matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::RangeProofInvalid { .. })),
        "editing an enumerated entry must break the range proof before anything else"
    );
}

#[test]
fn dedup_keys_on_the_whole_receipt_not_the_envelope() {
    // Format §3.1: "Embedded-receipt deduplication MUST key on the JCS digest of the complete
    // embedded receipt object — the entry id alone is insufficient (claim material is not
    // determined by the envelope); non-identical receipt objects sharing an entry id are each
    // verified in full."
    //
    // What an entry-id cache would enable: carry one honest embedded receipt and one invalid
    // receipt *about the same statement*, so the invalid one is waved through as a
    // "duplicate" of the honest one.
    let policy = trust_policy();
    let (_, receipt) = read_receipt("trigger-declared-valid.ahl");
    let honest = receipt["claim_material"]["introduction"].clone();

    let mut invalid = honest.clone();
    // Same envelope — therefore the same entry id — but different claim material.
    invalid["claim"]["assurance"]["content_binding"] = json!("plain-verified");
    invalid["claim_material"] = json!({
        // Valid JSON so it clears canonicalization (I-D §2.6/§7.2) and reaches the commitment
        // comparison this test is actually about; "jcs" matches the manifest's declared
        // descriptor so it clears the I-D §6.3 descriptor-equality check first.
        "record_bytes": "base64:e30=",
        "canonicalization": "jcs",
    });
    assert_eq!(
        honest["subject"]["entry_id"], invalid["subject"]["entry_id"],
        "the two embedded receipts must share an entry id for this to be the right test"
    );
    assert_ne!(honest["claim_material"], invalid["claim_material"]);

    let mut attack = receipt;
    attack["claim_material"]["replacement_introduction"] = invalid.clone();
    let error = verify_receipt(&attack, &policy)
        .expect_err("the invalid embedded receipt must be verified in full, not skipped");
    assert!(
        matches!(error, ReceiptError::ContentBindingMismatch { .. }),
        "the invalid receipt must fail on its own claim material, not be waved through: {error}"
    );

    // And the honest receipt in that slot fails only on the §2.3 record rule — proving the
    // rejection above came from the invalid material rather than from the slot itself.
    let mut control = attack;
    control["claim_material"]["replacement_introduction"] = honest;
    assert!(matches!(
        verify_receipt(&control, &policy),
        Err(ReceiptError::EmbeddedSubjectMismatch { what: "replacement introduction", .. })
    ));
}

#[test]
fn completeness_is_pinned_to_the_declared_checkpoint() {
    // The corpus itself carries the counterexample: a legal derivation consuming an already
    // affected descendant enlarges the trigger's closure past the propagation's declared
    // checkpoint D (spec §2.3.4).
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);
    let trees = tree_material();

    let declared = &vectors[8]["envelope"]["payload"]["corpus_checkpoint"];
    let d_size = usize::try_from(declared["tree_size"].as_u64().expect("tree_size")).expect("size");
    let at_d = affected_set(&envelopes, &trees, 6, d_size).expect("corpus");
    let later = affected_set(&envelopes, &trees, 6, envelopes.len()).expect("corpus");

    assert!(at_d.affected.is_subset(&later.affected));
    assert!(
        at_d.affected.len() < later.affected.len(),
        "the corpus must demonstrate closure growing past D, or the rule has nothing to bite on"
    );

    // The enlarging derivation consumes a record that IS in the affected set at D, and is
    // anchored after the propagation — both legal, because §2.3.2 bars only the triggered
    // record itself.
    let consumed = (
        "scores".to_owned(),
        field_str(&vectors[27]["envelope"]["payload"]["inputs"][0], "record")
            .expect("record")
            .to_owned(),
    );
    assert!(at_d.affected.contains(&consumed));
    assert!(vectors[27]["entry_index"].as_u64().expect("index") > 8);

    // The anchored disposition tree matches the closure at D, and only at D.
    let dispositioned: BTreeSet<RecordRef> =
        read_json(&test_data().join("vectors").join("merkle").join("disposition-tree.json"))
            ["leaves"]
            .as_array()
            .expect("leaves")
            .iter()
            .map(|leaf| {
                (
                    field_str(leaf, "dataset").expect("dataset").to_owned(),
                    field_str(leaf, "record").expect("record").to_owned(),
                )
            })
            .collect();
    assert_eq!(dispositioned, at_d.affected);
    assert_ne!(dispositioned, later.affected);
}

#[test]
fn a_later_challenge_cannot_unseat_an_authorized_trigger() {
    let vectors = statement_vectors();
    let manifest = &vectors[0]["envelope"]["payload"];
    let authority: BTreeSet<String> = manifest["datasets"]["customers"]["authority"]["key_ids"]
        .as_array()
        .expect("authority key set")
        .iter()
        .map(|k| k.as_str().expect("key id").to_owned())
        .collect();

    let record = field_str(&vectors[22]["envelope"]["payload"], "record").expect("record");
    let signer = |index: usize| {
        field_str(&vectors[index]["envelope"]["signatures"][0], "key_id")
            .expect("key_id")
            .to_owned()
    };

    // Both triggers name the same record; the later one is the unauthorized signer.
    assert_eq!(field_str(&vectors[23]["envelope"]["payload"], "record").expect("record"), record);
    assert!(authority.contains(&signer(22)), "entry 22 must be the authorized trigger");
    assert!(!authority.contains(&signer(23)), "entry 23 must be the challenge");

    // Bounded to [0, 25): entries 22 (authorized) and 23 (challenge) are what this test
    // illustrates. Entry 28 also names F — it is the non-verifying-signature fixture, covered
    // end to end by `trigger-effective-non-verifying-signature-ignored.ahl` — and is
    // deliberately out of scope here: a `key_id`-only "authority" filter, as used below, cannot
    // tell it apart from a genuine signature, which is exactly why `is_authorized_trigger` in
    // the verifier checks the signature cryptographically rather than reusing this shortcut.
    let mut scope = 0..25;

    // Selecting by greatest entry index *first* would pick the challenge — the pre-fix bug.
    let naive_governing = scope
        .clone()
        .rfind(|i| {
            let payload = &vectors[*i]["envelope"]["payload"];
            matches!(payload["type"].as_str(), Some("retraction" | "correction"))
                && payload["record"].as_str() == Some(record)
        })
        .expect("a trigger names the record");
    assert_eq!(naive_governing, 23, "the unfiltered rule would wrongly select the challenge");

    // Filtering challenges first selects the authorized trigger, which is what the receipt
    // vector `trigger-effective-later-challenge-ignored.ahl` asserts end to end.
    let governing = scope
        .rfind(|i| {
            let payload = &vectors[*i]["envelope"]["payload"];
            matches!(payload["type"].as_str(), Some("retraction" | "correction"))
                && payload["record"].as_str() == Some(record)
                && authority.contains(&signer(*i))
        })
        .expect("an authorized trigger names the record");
    assert_eq!(governing, 22);
}

// ---------------------------------------------------------------------------
// I-D revision 0.4 §2.6 / §6.3: descriptor conformance, full pipeline
// ---------------------------------------------------------------------------
//
// Unlike the unit-level coverage in `src/descriptor.rs`, every case here runs a complete
// receipt through `verify_receipt`, matching this file's own convention: these are the "full
// pipeline" vectors the descriptor/preimage change added, exercised the same way every other
// manifest-schema and claim-material rule in this file is (`reject_by_manifest_schema`,
// `assert_rejects`), rather than as static fixture files — this corpus keeps schema-level
// negative cases as reproducible mutations of a known-good receipt, not as hand-authored JSON on
// disk (see `reject_by_log_schema` above for the established precedent).

#[test]
fn canonicalization_identifier_syntax_is_enforced_by_manifest_schema() {
    // I-D §2.6 "Identifier syntax" / §6.3 table row 1: a syntactically invalid canonicalization
    // identifier rejects the WHOLE manifest.
    reject_by_manifest_schema(
        |payload| {
            payload["datasets"]["customers"]["canonicalization"] = json!("Bad-Identifier");
        },
        "canonicalization identifier syntax (I-D §2.6): uppercase is not admitted",
    );
    reject_by_manifest_schema(
        |payload| {
            payload["datasets"]["customers"]["canonicalization"] = json!(7);
        },
        "canonicalization identifier syntax (I-D §2.6): must be a string",
    );
}

#[test]
fn media_type_production_is_enforced_by_manifest_schema() {
    // I-D §2.6 "Descriptor media-type production" / §6.3 table row 1: a `media_type` present
    // but not matching the production rejects the WHOLE manifest — quoted-string parameter
    // values and case-insensitive duplicate parameter names included.
    reject_by_manifest_schema(
        |payload| {
            payload["datasets"]["customers"]["media_type"] = json!(r#"text/plain;a="b;c=d""#);
        },
        "descriptor media-type production (I-D §2.6): quoted-string parameter value",
    );
    reject_by_manifest_schema(
        |payload| {
            payload["datasets"]["customers"]["media_type"] = json!("text/plain;Foo=1;foo=2");
        },
        "descriptor media-type production (I-D §2.6): duplicate parameter name, \
         case-insensitive (`Foo` vs `foo`)",
    );
}

#[test]
fn claim_material_descriptor_must_equal_the_governing_manifest() {
    // I-D §6.3: `claim_material.canonicalization`/`media_type` must equal (normalized-form
    // equality, I-D §2.6) the descriptor declared by the manifest version the SUBJECT
    // STATEMENT's own `manifest` binding names.
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| r["claim_material"]["canonicalization"] = json!("exact-bytes"),
        |e| matches!(e, ReceiptError::ClaimDescriptorMismatch { .. }),
        "I-D §2.6/§6.3 — claim_material's descriptor must equal the governing manifest's",
    );
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| {
            r["claim_material"].as_object_mut().expect("claim_material").remove("canonicalization");
        },
        |e| matches!(e, ReceiptError::ClaimMaterialMissing { field: "canonicalization", .. }),
        "I-D §6.3 — claim_material.canonicalization is required where content_binding != none",
    );
}

// I-D §2.6 `media_type` PRESENCE rule ("jcs" MUST NOT carry it, "exact-bytes" MUST): unlike the
// schema-syntax cases above, testing this end to end would require mutating the anchored
// GENESIS MANIFEST's own descriptor content, which changes that envelope's JCS bytes and so
// its leaf hash — invalidating the chain hop's own committed inclusion path long before
// content-binding logic is ever reached, and recomputing a genuine inclusion path for a
// mutated envelope is a generator-level operation (rebuilding the log tree), not something an
// ad-hoc receipt mutation can do. The rule itself — `descriptor::media_type_required` — is
// therefore covered directly, at the unit level, immediately below and in `descriptor.rs`.
#[test]
fn media_type_presence_rule_matches_the_registered_identifiers() {
    use ahl_core::descriptor::media_type_required;
    assert_eq!(media_type_required("jcs"), Some(false), "jcs must not carry media_type");
    assert_eq!(media_type_required("exact-bytes"), Some(true), "exact-bytes must carry media_type");
    assert_eq!(
        media_type_required("x-custom"),
        None,
        "an identifier this crate does not implement has an undecidable presence rule, not a \
         false one"
    );
}

// ---------------------------------------------------------------------------
// Generator determinism, proven in CI
// ---------------------------------------------------------------------------

/// Removes its directory on drop, so a panicking assertion above still cleans up.
struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every file under `root`, keyed by its path relative to `root`, with its exact bytes.
fn collect_generated_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let relative = path.strip_prefix(root).expect("entry is under root").to_path_buf();
                out.insert(relative, std::fs::read(&path).expect("read generated file"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn the_generator_is_deterministic_across_runs() {
    // "Two consecutive runs must leave `test_data/` byte-identical — if they do not, that is a
    // bug" (test_data/README.md). Proven here, in CI, by running the generator into two fresh
    // temporary directories and diffing byte-for-byte, rather than asserted only in that
    // sentence. The third comparison — against the COMMITTED `test_data/` — is what catches a
    // generator change whose output was never regenerated onto disk.
    let base = std::env::temp_dir()
        .join(format!("ahl-core-gen-vectors-determinism-{}", std::process::id()));
    let run_a = base.join("run-a");
    let run_b = base.join("run-b");
    let _cleanup = TempDirGuard(base);

    for dir in [&run_a, &run_b] {
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_gen_vectors"))
            .arg(dir)
            .status()
            .expect("gen_vectors binary runs");
        assert!(status.success(), "gen_vectors exited with {status} writing to {}", dir.display());
    }

    let a = collect_generated_files(&run_a);
    let b = collect_generated_files(&run_b);
    assert_eq!(
        a.keys().collect::<Vec<_>>(),
        b.keys().collect::<Vec<_>>(),
        "two generator runs must write the same set of files"
    );
    for (path, bytes_a) in &a {
        assert_eq!(
            bytes_a,
            &b[path],
            "{}: two generator runs produced different bytes — the generator has hidden \
             nondeterminism",
            path.display()
        );
    }

    let committed = collect_generated_files(&test_data());
    assert_eq!(
        a.keys().collect::<Vec<_>>(),
        committed.keys().collect::<Vec<_>>(),
        "the generator's file set must match the committed test_data/ exactly — regenerate \
         with `cargo run --bin gen_vectors`"
    );
    for (path, bytes) in &a {
        assert_eq!(
            bytes,
            &committed[path],
            "{}: committed test_data/ is stale relative to the generator — regenerate with \
             `cargo run --bin gen_vectors`",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// I-D revision 0.4 §7.5 step 1 / §2.2 / §7.6: version-first ordering and manifest binding
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_version_subject_is_unverifiable_even_with_a_corrupted_id() {
    // I-D §7.5 step 1 / §2.2: "A verifier MUST likewise check each carried statement's
    // ahl_version before validating that statement. Any value other than 0.4 yields
    // unverifiable." Before the fix, id recomputation ran first, so a foreign-version subject
    // whose copied id also happened to be wrong came out `invalid` instead.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["envelope"]["payload"]["ahl_version"] = json!("0.3");
            corrupt(&mut r["subject"]["statement_id"]);
        },
        |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_version", .. }),
        "§7.5 step 1 / §2.2 — ahl_version is checked before id recomputation",
    );
}

#[test]
fn a_foreign_version_enumerated_envelope_is_unverifiable() {
    // The same rule applied to every enumerated envelope — governance currency, competing
    // triggers, and propagation prefixes alike — not only the subject and the governance
    // chain. `governance-state-valid.ahl` carries enumerated governance currency material.
    assert_rejects(
        "governance-state-valid.ahl",
        |r| {
            r["governance"]["currency"]["material"]["entries"][0]["envelope"]["payload"]
                ["ahl_version"] = json!("0.3");
        },
        |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_version", .. }),
        "§7.5 step 1 / §2.2 — every enumerated envelope's ahl_version is checked",
    );
}

#[test]
fn subject_manifest_must_equal_the_payloads_own_copy() {
    // I-D §7.6: "subject.manifest equals the subject envelope's payload.manifest... this
    // equality is the only thing that authenticates the copy." Corrupting only the receipt's
    // OWN (unsigned) copy — never touching the signed envelope — isolates exactly this rule.
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| corrupt(&mut r["subject"]["manifest"]),
        |e| matches!(e, ReceiptError::SubjectManifestBindingInvalid(_)),
        "I-D §7.6 — subject.manifest equals the subject envelope's own payload.manifest",
    );

    // MINOR, undertested by construction: I-D §7.6 also requires the manifest version named by
    // `subject.manifest` to have `entry_index` STRICTLY SMALLER than `subject.entry_index` — a
    // "future manifest" binding must be `invalid`. Every genuinely anchored, genuinely signed
    // statement in this corpus already satisfies that bound by construction, and satisfying it
    // WRONGLY end to end would require a statement whose payload names a later manifest, signed
    // and genuinely included in the log tree at its stated index — a generator-level fixture
    // (a fresh, deliberately-malformed anchored entry, plus a rebuilt inclusion proof), not
    // something an existing envelope's `manifest` field can be mutated into: any change to a
    // signed envelope's payload changes its JCS bytes and so its leaf hash, invalidating the
    // very inclusion path (I-D §7.5 step 3) that must pass before this cross-field check is
    // ever reached — the same structural wall documented for `media_type` presence above and
    // for key-array reordering in `receipt::tests::key_set_comparison_is_order_independent`.
    // The "entry_index strictly smaller" half of `SubjectManifestBindingInvalid` is therefore
    // exercised by code inspection and by the equality half's sibling branch, not by a vector
    // here.
}
