//! Conformance tests over the generated corpus in `test_data/`.
//!
//! These tests read only what a downstream implementation in any language would read — the
//! files on disk — and re-derive every claim the corpus makes: identifiers, signatures,
//! inclusion proofs and range proofs (through `atl-core`), the three revocation closures, the
//! witness refusal evidence, and every Evidence Receipt.
//!
//! Receipts are checked by running them through [`ahl_core::receipt::verify_receipt_report`],
//! not by comparing fields by hand: the verifier is the thing under test. Every vector must
//! reach the I-D §7.7 result its `test_data/receipts/index.json` entry records — `verified`,
//! `invalid` or `unverifiable` — a non-verified one on the required assertion the entry names,
//! and by the specific rule it names.
//!
//! Regenerate the corpus with `cargo run --bin gen_vectors` before running these.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ahl_core::bitemporal::{Scope, ValidTime};
use ahl_core::closure::{affected_set, edges, RecordRef, TreeMaterial};
use ahl_core::descriptor;
use ahl_core::receipt::{
    verify_receipt, verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Assertion, Limits,
    Outcome, ReceiptError, TrustPolicy, TrustedWitnessKey, VoidReason,
};
use ahl_core::tree::ValidatedLeafSet;
use ahl_core::{
    atl_checkpoint_blob_from_json, checkpoint, checkpoint_signing_bytes, cosignature_bytes,
    decode_pubkey, entry_id, field_str, hash_hex, inclusion_proof, jcs, leaf_hash, parse_hash_hex,
    proof_from_hex, proof_path_hex, range_proof, reconcile_atl_checkpoint_raw, sha256_hex,
    statement_id, tree_root, verify_envelope, verify_inclusion_proof, verify_signature, AhlError,
    TestKey,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Value};

/// The statement vectors, in entry-index order. Entry 28 re-adds `producer-2` to the producer
/// snapshot and entry 29 is a trigger genuinely CO-SIGNED by both the authority and
/// `producer-2`. Entry 30 retires `producer-2` under `producer-2`'s own signature and entry 31
/// re-adds it. Entry 32 is an intentional non-verifying-signature fixture: well-formed shape,
/// real authority `key_id`, garbage `sig`. Entry 33 adds a second, genuinely valid signature
/// entry from a non-authority key alongside a non-verifying authority-named one. The two
/// non-verifying fixtures sit at the tail so that enumerated material below them stays
/// verifiable (I-D §7.5.1 4d).
const STATEMENT_FILES: [&str; 57] = [
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
    "28-key-readd-producer-2.json",
    "29-retraction-f-co-signed-authority-and-producer-2.json",
    "30-key-retire-producer-2-self-signed.json",
    "31-key-readd-producer-2-after-self-retire.json",
    "32-invalid-signature-trigger-f.json",
    "33-unverified-authority-signature-trigger-f.json",
    "34-ingestion-customers-e-stale-manifest.json",
    "35-correction-a-to-cross-dataset-replacement.json",
    "36-retraction-cross-dataset-record.json",
    "37-invalid-signature-derivation-k-from-h.json",
    "38-invalid-signature-key-add.json",
    "39-invalid-signature-manifest.json",
    "40-key-retire-producer-2-again.json",
    "41-key-add-producer-2-verifying-copy.json",
    "42-ingestion-customers-g-under-producer-2.json",
    "43-derivation-k-from-h-verifying-copy.json",
    "44-propagation-over-f-retraction-at-cp38.json",
    "45-propagation-over-f-retraction-at-cp44.json",
    "46-manifest-v3-resnapshot-producer-2.json",
    "47-manifest-v3-second-envelope.json",
    "48-invalid-signature-manifest-v3-third-envelope.json",
    "49-ingestion-customers-i-under-v3.json",
    "50-derivation-batch-defective-input-sets.json",
    "51-ingestion-foreign-revision.json",
    "52-manifest-foreign-revision.json",
    "53-key-add-foreign-revision.json",
    "54-manifest-foreign-revision-unsigned.json",
    "55-manifest-v4-rotate-log-key.json",
    "56-ingestion-customers-j-under-v4.json",
];

/// The corpus prefix over which closure recomputation is defined.
///
/// Entry 37 anchors a batch whose input-set trees deliberately break the I-D §2.7 tree rules,
/// one rule each, so the `record-derived-input-set-*-must-fail.ahl` vectors have something to
/// bite on. Closure traversal validates every committed tree it opens against those same rules
/// before reading an edge from it, so a walk reaching entry 37 fails by §2.7 — and the trees
/// are deliberately not published under `vectors/merkle/`, where they would be read as
/// conforming material. Every published closure scenario stops at tree size 28 or below.
const CONFORMING_TREE_PREFIX: usize = 50;

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
    for index in [0usize, 25, 46, 55] {
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
    let m3 = field_str(&vectors[46], "statement_id").expect("vector carries statement_id");
    let m4 = field_str(&vectors[55], "statement_id").expect("vector carries statement_id");

    // A manifest statement declares no `manifest` member (spec §2.2, receipt §2.3).
    for index in [0usize, 25, 46, 47, 48, 55] {
        assert!(
            vectors[index]["envelope"]["payload"].get("manifest").is_none(),
            "a manifest statement must not declare a `manifest` member"
        );
    }
    for (index, vector) in vectors.iter().enumerate() {
        if matches!(index, 0 | 25 | 46 | 47 | 48 | 55) {
            continue;
        }
        // Entry 34 is the ONE deliberate exception: I-D §2.2 §7.6's negative vector
        // (`record-ingested-stale-manifest-must-fail.ahl`) needs a statement that is
        // genuinely signed and genuinely anchored, yet wrongly bound — see `corpus.rs`'s own
        // entry 34 and the assertion right after this loop.
        if index == 34 {
            continue;
        }
        // Entries 39, 52 and 54 are purported MANIFESTS — a manifest statement declares no
        // `manifest` member (spec §2.3.5): 39 void for want of a verifying signature, 52
        // verifying but declaring a revision this document does not define, 54 neither signed
        // nor of a revision this document defines (I-D §7.5.1 4b, 4d).
        if matches!(index, 39 | 52 | 54) {
            continue;
        }
        // The manifest version id is the manifest statement's *statement id* (spec §2.3.5).
        // Version 3 is anchored at entry 46 and version 4 at entry 55, so a statement past
        // either binds the version active at its own entry index (I-D §2.2).
        let expected = if index < 25 {
            m1
        } else if index < 46 {
            m2
        } else if index < 55 {
            m3
        } else {
            m4
        };
        assert_eq!(
            field_str(&vector["envelope"]["payload"], "manifest")
                .expect("payload carries manifest"),
            expected,
            "{}: must bind to the manifest version active at its entry index",
            STATEMENT_FILES[index]
        );
    }

    // The exception, made explicit: entry 34 wrongly names v1 (`m1`) even though v2 (`m2`) is
    // active at its entry index — I-D §2.2's "greatest entry index smaller than the
    // statement's own" resolves to v2 there, not v1. This is what
    // `record-ingested-stale-manifest-must-fail.ahl` proves the verifier catches.
    assert_eq!(
        field_str(&vectors[34]["envelope"]["payload"], "manifest")
            .expect("payload carries manifest"),
        m1,
        "entry 34 must wrongly name v1 — that is the defect the stale-manifest vector proves \
         is caught"
    );
    assert_ne!(
        field_str(&vectors[34]["envelope"]["payload"], "manifest")
            .expect("payload carries manifest"),
        m2,
        "entry 34's wrong binding must not accidentally be correct"
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
    // Three groups are deliberate. Entries 38 and 41 are a purported `key` statement whose
    // envelope does not verify and the same statement genuinely signed; entries 37 and 43 are
    // the same for a derivation. §2.1 voids later duplicates among GOVERNING statements, and
    // I-D §7.5.1 4b admits an enumeration-only entry to the induction "only if its envelope
    // verifies in phase 1" — so the void copy governs nothing, occupies no statement id, and the
    // verifying copy is inducted. Entries 46, 47 and 48 are §2.1's own case: one manifest
    // version under three signature sets, of which the smallest entry index governs. Every ENTRY
    // id in all three groups differs, since the signature sets do.
    const DUPLICATED_ON_PURPOSE: [usize; 7] = [37, 38, 41, 43, 46, 47, 48];
    let vectors = statement_vectors();
    let mut statements: BTreeMap<String, usize> = BTreeMap::new();
    let mut entries: BTreeMap<String, usize> = BTreeMap::new();
    for (index, vector) in vectors.iter().enumerate() {
        let sid = field_str(vector, "statement_id").expect("statement_id").to_owned();
        if DUPLICATED_ON_PURPOSE.contains(&index) {
            statements.entry(sid).or_insert(index);
            let eid = field_str(vector, "entry_id").expect("entry_id").to_owned();
            assert!(
                entries.insert(eid.clone(), index).is_none(),
                "{}: even this pair carries distinct entry ids",
                STATEMENT_FILES[index]
            );
            continue;
        }
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
    // Four statement ids fewer than entries: two void-then-verifying pairs (37/43 and 38/41)
    // and one manifest version under three signature sets (46/47/48).
    assert_eq!(statements.len(), STATEMENT_FILES.len() - 4);
    assert_eq!(entries.len(), STATEMENT_FILES.len());

    // The three retractions of record F that exist to exercise signature handling — the
    // genuinely co-signed one, the non-verifying one, and the one whose authority-named entry
    // does not verify — are distinct statements, not one statement anchored three times.
    let f_triggers: Vec<&Value> = [29usize, 32, 33].iter().map(|i| &vectors[*i]).collect();
    let records: BTreeSet<&str> = f_triggers
        .iter()
        .map(|v| field_str(&v["envelope"]["payload"], "record").expect("record"))
        .collect();
    assert_eq!(records.len(), 1, "all three name the same record, as the scenario requires");
    let ids: BTreeSet<&str> =
        f_triggers.iter().map(|v| field_str(v, "statement_id").expect("statement_id")).collect();
    assert_eq!(ids.len(), 3, "and each is nevertheless its own statement");
}

/// The cross-dataset fixtures must really collide on the commitment string, or the vectors
/// built on them prove nothing about record identity.
///
/// I-D §2.4.2 makes identity the `(dataset, record)` pair, and §2.6 puts `dsid` in the
/// commitment preimage — so the same bytes in two datasets commit differently, and a pair like
/// this is unreachable through content. It is reachable by a producer NAMING one, which is
/// what entries 35 and 36 do: each references a commitment computed for `customers` beside a
/// `scores`-side claim. If a future corpus change made these entries name distinct
/// commitments, both negatives would still fail — on the commitment rather than the dataset —
/// and would silently stop testing the rule they exist for.
#[test]
fn the_cross_dataset_fixtures_reuse_one_commitment_under_two_datasets() {
    let vectors = statement_vectors();
    let ingestion = &vectors[1]["envelope"]["payload"];
    let correction = &vectors[35]["envelope"]["payload"];
    let retraction = &vectors[36]["envelope"]["payload"];
    let derivation_output = &vectors[3]["envelope"]["payload"]["outputs"][0];

    // Entry 36 retracts `scores`/A using record A's own `customers` commitment.
    assert_eq!(field_str(retraction, "dataset").expect("dataset"), "scores");
    assert_eq!(
        field_str(retraction, "record").expect("record"),
        field_str(ingestion, "record").expect("record"),
        "the retraction must reuse the commitment the customers ingestion introduced"
    );
    assert_eq!(field_str(ingestion, "dataset").expect("dataset"), "customers");

    // Entry 35 corrects `customers`/A to S1, which exists only as a `scores` output.
    assert_eq!(field_str(correction, "dataset").expect("dataset"), "customers");
    assert_eq!(
        field_str(correction, "replacement").expect("replacement"),
        field_str(derivation_output, "record").expect("record"),
        "the correction's replacement must be the commitment the scores derivation produced"
    );
    assert_eq!(field_str(derivation_output, "dataset").expect("dataset"), "scores");
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
    // Entries 32 and 33 are intentional non-verifying-signature fixtures: well-formed shape,
    // real authority `key_id`, garbage `sig` (entry 33 also carries a second, genuinely valid
    // entry from a non-authority key). Every other entry must genuinely verify; these two must
    // not.
    // Entries 38 and 39 join the two at 32 and 33: a purported `key` statement and a purported
    // `manifest` whose envelopes do not verify, anchored past every checkpoint the rest of the
    // corpus uses, for the reliance rule of I-D §7.5.1 4d. Entry 46 is the third of that kind
    // and declares `ahl_version: "0.5"` besides, for the ordering rule of 4b: a chain element's
    // phase-1 failure is `invalid` whatever revision it declares.
    const NON_VERIFYING: [usize; 7] = [32, 33, 37, 38, 39, 48, 54];
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
        // The published `INTENTIONALLY NON-VERIFYING` warning must sit on exactly the entries
        // that do not verify. The generator attaches it by entry index, so a corpus reordering
        // moves the fixtures and leaves the note behind — which is how entries 30 and 31, two
        // genuine `key` statements, came to be labelled as forgeries while the real fixtures
        // carried no warning at all. Pinning the note to the same set the assertions above use
        // makes the two impossible to separate again.
        let labelled = vector
            .get("note")
            .and_then(Value::as_str)
            .is_some_and(|note| note.contains("INTENTIONALLY NON-VERIFYING"));
        assert_eq!(
            labelled,
            NON_VERIFYING.contains(&index),
            "{}: the INTENTIONALLY NON-VERIFYING note must be carried by exactly the entries \
             whose signatures do not verify",
            STATEMENT_FILES[index]
        );
    }
}

/// The self-retirement fixture must really retire the key that signs it, or the vector built
/// on it proves nothing about the induction's two key states.
///
/// I-D §7.5.1 4b verifies a governance statement "against K AS ESTABLISHED SO FAR — the
/// governance state in force immediately before this statement's own entry index" and applies
/// its effect only afterwards, which is what makes a self-retirement conforming; 4d then scopes
/// the remaining-envelope check to "every carried envelope that is NOT part of the induction".
/// `governance-state-self-retiring-key.ahl` enumerates a range covering entry 30 and must be
/// accepted. If a future corpus change made entry 30 retire some OTHER key, or signed it with
/// one, the vector would keep passing while testing nothing.
#[test]
fn the_self_retiring_key_statement_is_signed_by_the_key_it_retires() {
    let vectors = statement_vectors();
    let envelope = &vectors[30]["envelope"];
    let payload = &envelope["payload"];
    assert_eq!(field_str(payload, "type").expect("type"), "key");
    assert_eq!(field_str(payload, "action").expect("action"), "retire");
    let retired = field_str(&payload["key"], "key_id").expect("key_id");
    let signers: BTreeSet<&str> = envelope["signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|signature| field_str(signature, "key_id").expect("key_id"))
        .collect();
    assert_eq!(
        signers,
        BTreeSet::from([retired]),
        "entry 30 must be signed by exactly the key it retires — that pairing is the whole \
         fixture"
    );

    // Entry 31 puts the key back, which is what keeps entry 33's genuine `producer-2`
    // signature resolving to a key in force.
    let readd = &vectors[31]["envelope"]["payload"];
    assert_eq!(field_str(readd, "type").expect("type"), "key");
    assert_eq!(field_str(readd, "action").expect("action"), "add");
    assert_eq!(field_str(&readd["key"], "key_id").expect("key_id"), retired);
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
        // than the checkpoint's tree size. Manifest versions are anchored at entries 0, 25, 46
        // and 55 — entries 47 and 48 are further envelopes of the version at 46, void under
        // I-D §2.1's first-wins rule, so neither becomes the active version.
        //
        // Two checkpoints are deliberate exceptions, and both are rotation-anchoring proofs:
        // cp26 for the witness-set rotation at entry 25 and cp56 for the log-key rotation at
        // entry 55. I-D §7.1 binds such a checkpoint to the manifest version active IMMEDIATELY
        // BEFORE the rotating manifest's own entry index — the OUTGOING state — never to the
        // version the rotation installs.
        let tree_size = cp["tree_size"].as_u64().expect("tree_size");
        let name = field_str(entry, "name").expect("named checkpoint");
        let expected = match name {
            "cp26" => 0,
            "cp56" => 46,
            _ if tree_size > 55 => 55,
            _ if tree_size > 46 => 46,
            _ if tree_size > 25 => 25,
            _ => 0,
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
        if field_str(entry, "expect").expect("expect") != "verified" {
            continue;
        }
        let name = field_str(entry, "file").expect("file");
        let (_, receipt) = read_receipt(name);
        let verdict = verify_receipt(&receipt, &policy)
            .unwrap_or_else(|e| panic!("{name}: must verify, but was rejected: {e}"));

        // I-D §7.7: `verified` is the reduction of findings that are themselves all `verified`,
        // and it is the only result that renders a boundary.
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Verified, "{name}");
        assert_eq!(report.verdict.as_ref(), Some(&verdict), "{name}");
        for finding in &report.findings {
            assert_eq!(finding.outcome, Outcome::Verified, "{name}: {finding:?}");
        }

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
        // Entry 33 carries a genuine signature from a non-authority key beside a non-verifying
        // one naming the authority. The enumerated vector reaches it as 4d over the subject's
        // own envelope; the declared one reaches it with the FIRST entry additionally
        // unresolvable, and I-D §2.1's conjunction plus §7.7's reduction still put the
        // signature failure on top. Asserting the specific variant is the point of the second:
        // `ProducerKeyNotCarried` there would be the array order deciding a verdict.
        "trigger-effective-unverified-authority-signature-must-fail.ahl"
        | "statement-anchored-uncarried-key-with-bad-signature-must-fail.ahl" => {
            matches!(error, ReceiptError::EnvelopeSignatureInvalid { entry_index: 33 })
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
        // The two defects on this vector's entry-9 `key` statement are independent, so the
        // assertion has to be on the SPECIFIC variant: `Malformed(... issued_at ...)` is the
        // outcome of the phase order I-D §7.5.1 4b forbids, and a test that accepted either
        // would be blind to exactly the regression the vector exists to catch.
        "governance-key-statement-unsigned-common-field-must-fail.ahl" => {
            matches!(error, ReceiptError::KeyNotBound { entry_index: 9, .. })
        }
        "statement-anchored-broken-foreign-revision-chain-hop-must-fail.ahl" => {
            matches!(error, ReceiptError::EnvelopeSignatureInvalid { entry_index: 54 })
        }
        "governance-state-foreign-revision-key-must-fail.ahl"
        | "governance-state-foreign-revision-manifest-must-fail.ahl"
        | "governance-state-foreign-revision-entry-must-fail.ahl"
        | "statement-anchored-foreign-revision-chain-hop-must-fail.ahl" => {
            matches!(error, ReceiptError::UnsupportedVersion { field: "ahl_version", .. })
        }
        "governance-key-rotation-proof-witness-key-unlisted-must-fail.ahl" => {
            matches!(error, ReceiptError::KeyNotBound { entry_index: 0, .. })
        }
        "governance-key-rotation-proof-key-bound-to-incoming-must-fail.ahl" => {
            matches!(error, ReceiptError::KeyNotBound { entry_index: 25, .. })
        }
        // The pair I-D §7.4 separates. Both assertions name the specific variant, because the
        // whole content of the rule is which of the two fires: a test satisfied by either
        // would pass on a verifier that had collapsed them back into one outcome.
        "statement-anchored-uncarried-key-transition-must-fail.ahl" => {
            matches!(error, ReceiptError::ProducerKeyNotCarried { entry_index: 19, .. })
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
        // I-D §7.2's `record-derived` row: `input_members` is carried "only where
        // `batch_leaf.inputs` is the input-set form, proving the listed inputs and no others",
        // and I-D §2.7 gives the two forms. Three ways to break that, three different errors:
        // absent under the form that requires it, short of the committed set, and carried
        // under the form that commits no root for it to open.
        "record-derived-missing-input-members-must-fail.ahl" => {
            matches!(error, ReceiptError::ClaimMaterialMissing { field: "input_members", .. })
        }
        "record-derived-partial-input-members-must-fail.ahl" => {
            matches!(error, ReceiptError::TreeMaterialInvalid { detail, .. }
                if detail.contains("no others"))
        }
        "record-derived-input-members-on-full-array-must-fail.ahl" => {
            matches!(error, ReceiptError::Malformed(detail) if detail.contains("input_members"))
        }
        // I-D §7.2's record rows: the bytes and `canonicalization` are carried if and only if
        // `content_binding` is not `none`, `media_type` only alongside a carried descriptor.
        // Breaking the biconditional either way is `invalid`; the error distinguishes the two
        // directions, since a member carried where the assurance forbids it overstates the
        // claim, while a half-carried pair is material the claim type requires and lacks.
        "record-ingested-none-with-canonicalization-must-fail.ahl"
        | "record-ingested-none-with-media-type-must-fail.ahl" => {
            matches!(error, ReceiptError::AssuranceMismatch { field: "content_binding" })
        }
        "record-ingested-bytes-without-canonicalization-must-fail.ahl" => {
            matches!(error, ReceiptError::ClaimMaterialMissing { field: "canonicalization", .. })
        }
        "record-ingested-canonicalization-without-bytes-must-fail.ahl" => {
            matches!(error, ReceiptError::ClaimMaterialMissing { field: "record_bytes", .. })
        }
        // I-D §2.4.2 / §7.6: record identity is the `(dataset, record)` pair. Both vectors
        // carry an embedded introduction whose COMMITMENT matches the referencing material
        // exactly and whose DATASET does not, so a verifier comparing the commitment alone
        // accepts them; the slot named in the error is what says which of the two references
        // — the trigger's own introduction, or a correction's replacement introduction — the
        // vector isolates.
        "trigger-declared-cross-dataset-introduction-must-fail.ahl" => {
            matches!(error, ReceiptError::EmbeddedSubjectMismatch { what: "introduction", .. })
        }
        "trigger-declared-cross-dataset-replacement-must-fail.ahl" => matches!(
            error,
            ReceiptError::EmbeddedSubjectMismatch { what: "replacement introduction", .. }
        ),
        // I-D §7.5.1 4d: every enumerated envelope is verified under K at its own entry index.
        // The three vectors reach the same rule from three directions — one where the
        // defective envelope IS a competing candidate for the subject record (§7.2: "Every
        // competing candidate's envelope MUST be verified under Section 2.1 before authority is
        // compared"), one where no claim-specific rule looks at it at all, and one where it is
        // the SUBJECT of a declared-mode receipt — and all three name the entry index of the
        // first non-verifying envelope in range, never a later one. The third is the `invalid`
        // half of the I-D §7.4 pair: the key it names IS resolvable, so the defect is
        // demonstrated rather than missing, and the governance mode does not enter into it.
        "trigger-effective-non-verifying-candidate-must-fail.ahl"
        | "governance-state-non-verifying-entry-must-fail.ahl"
        | "statement-anchored-non-verifying-envelope-must-fail.ahl" => {
            matches!(error, ReceiptError::EnvelopeSignatureInvalid { entry_index: 32 })
        }
        // I-D §2.7: one set of tree rules, "identical for every AHL tree — outputs, input sets,
        // and dispositions". Each vector carries the COMPLETE committed input set with genuine
        // membership paths, so the rejection can only come from the tree rules themselves.
        // Sortedness is strict, which is simultaneously the ordering rule and the no-duplicate
        // rule, so the first two report the same ordering defect at the leaf that repeats.
        "record-derived-input-set-unsorted-must-fail.ahl"
        | "record-derived-input-set-duplicate-record-must-fail.ahl" => {
            matches!(error, ReceiptError::TreeMaterialInvalid { detail, .. }
                if detail.contains("ascending UTF-8 byte order"))
        }
        "record-derived-input-set-non-canonical-record-must-fail.ahl" => {
            matches!(error, ReceiptError::TreeMaterialInvalid { detail, .. }
                if detail.contains("is not a canonical record commitment"))
        }
        // I-D §7.1's container shape for `governance.chain[]` — "an anchored manifest
        // statement's complete envelope" — and I-D §7.5.1 4c's completeness rule, the two
        // halves of where governance material may travel once §7.4 puts producer-key
        // transitions in enumeration material alone.
        "governance-chain-key-statement-element-must-fail.ahl" => {
            matches!(error, ReceiptError::GovernanceChainInvalid(detail)
                if detail.contains("carries a `key` statement at entry index 9"))
        }
        "governance-enumerated-manifest-omitted-must-fail.ahl" => {
            matches!(error, ReceiptError::GovernanceChainInvalid(detail)
                if detail.contains("`manifest` statement at entry index 25"))
        }
        // I-D §2.1's duplicate rule reaches EFFECT, never verification: a void duplicate chain
        // hop is one of the three kinds of envelope §7.5.1 4d says a receipt rests on.
        "statement-anchored-duplicate-manifest-unsigned-must-fail.ahl" => {
            matches!(error, ReceiptError::EnvelopeSignatureInvalid { entry_index: 48 })
        }
        "propagation-complete-void-prefix-entry-control-must-fail.ahl" => {
            matches!(error, ReceiptError::ClosureMismatch(detail)
                if detail.contains("recomputed 2 affected records"))
        }
        // The LOG-key rotation at manifest v4 (entry 55): I-D §7.1's outgoing-state rules, and
        // §7.5.1 4f's rule about which key a checkpoint of a given tree size resolves to.
        "governance-key-rotation-proof-incoming-log-key-must-fail.ahl" => {
            matches!(error, ReceiptError::RotationProofInvalid { manifest_entry_index: 55, detail }
                if detail.contains("is not a log key of the OUTGOING state"))
        }
        "governance-key-rotation-proofs-out-of-order-must-fail.ahl" => {
            matches!(error, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                if detail.contains("ascending `manifest_entry_index` order"))
        }
        "governance-key-rotation-proof-incoming-witness-must-fail.ahl" => {
            matches!(error, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                if detail.contains("none did"))
        }
        "statement-anchored-outgoing-log-key-after-rotation-must-fail.ahl" => {
            matches!(error, ReceiptError::KeyNotBound { entry_index: 46, .. })
        }
        other => panic!("{other}: negative vector has no rule assertion in the test suite"),
    };
    assert!(fired, "{name}: expected rejection by {rule}, got: {error}");
}

#[test]
fn every_negative_receipt_reaches_its_result_on_the_finding_it_names() {
    let policy = trust_policy();
    let mut rejected = 0;
    let mut unverifiable = 0;
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        let expect = field_str(entry, "expect").expect("expect");
        if expect == "verified" {
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

        // The scalar result, and the assertion whose finding produced it.
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result.name(), expect, "{name}: the §7.7 result");
        assert_eq!(report.result, error.class(), "{name}");
        assert!(report.verdict.is_none(), "{name}: no boundary is rendered for {expect}");
        let named = field_str(entry, "finding").expect("finding");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.assertion.name() == named)
            .unwrap_or_else(|| panic!("{name}: no finding for `{named}`"));
        assert_eq!(finding.outcome, report.result, "{name}: `{named}` produced the result");
        assert!(finding.detail.is_some(), "{name}: a non-verified finding says what produced it");

        // I-D §7.7: "A verifier MUST report the findings alongside it... and a verifier MUST NOT
        // present a finding as though it were the result." For an `unverifiable` vector the run
        // carries on, so the assertions that DID hold are reported as `verified` beside the one
        // that did not — that is what makes the result actionable.
        if expect == "unverifiable" {
            unverifiable += 1;
            let verified = report
                .findings
                .iter()
                .filter(|finding| finding.outcome == Outcome::Verified)
                .count();
            assert!(
                verified >= 4,
                "{name}: an unverifiable result must report the assertions that held, got \
                 {:#?}",
                report.findings
            );
            // The assertions that hold whatever the gap is: step 3's paths need no key, and
            // the version read of the receipt's own carried statements precedes everything.
            // `governance` is not among them — it is the assertion an unestablished key state
            // is reported on (I-D §7.5.1 4b).
            for assertion in [Assertion::Anchoring, Assertion::Versions] {
                assert_eq!(
                    report.finding(assertion).map(|finding| finding.outcome),
                    Some(Outcome::Verified),
                    "{name}: {assertion} held and must be reported so"
                );
            }
        }
        rejected += 1;
    }
    assert!(rejected >= 15, "every registry claim type needs a negative vector, got {rejected}");
    assert!(unverifiable >= 1, "the corpus must carry an `unverifiable` vector");
}

/// I-D §7.1: every `governance.chain[]` element is "an anchored manifest statement's complete
/// envelope", and §7.4 puts producer-key transitions in enumeration material alone.
///
/// This guards the corpus premise the round's structural change rests on. A future generator
/// change that put a `key` statement back into some chain would leave every vector still
/// passing — the receipt would simply be refused for a different reason, or, if the rule were
/// ever relaxed, silently accepted — while the corpus quietly stopped demonstrating where
/// governance material travels.
#[test]
fn every_accepted_receipt_carries_manifests_only_in_its_governance_chain() {
    let mut checked = 0;
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        if field_str(entry, "expect").expect("expect") != "verified" {
            continue;
        }
        let name = field_str(entry, "file").expect("file");
        let (_, receipt) = read_receipt(name);
        for hop in receipt["governance"]["chain"].as_array().expect("chain") {
            let kind = field_str(&hop["envelope"]["payload"], "type").expect("statement type");
            assert_eq!(
                kind, "manifest",
                "{name}: `governance.chain[]` carries a `{kind}` statement at entry index {}",
                hop["entry_index"]
            );
            checked += 1;
        }
    }
    assert!(checked >= 15, "the accepted vectors must carry chain elements at all, got {checked}");
}

/// I-D §7.4's argument for `unverifiable` is that "a verifier holding the enumerated material
/// would verify the same bytes, so `invalid` would put two verifiers in contradiction over one
/// artifact". That argument is only made in this corpus if the two receipts really do carry the
/// same bytes.
///
/// Both vectors are subject entry 19, whose envelope is signed by `producer-2` — added by the
/// `key` statement at entry 9, which declared mode does not carry. The declared one is refused
/// as `unverifiable`; the enumerated one is in the accept list. A generator change that moved
/// either subject would leave both files passing while the pair stopped being a pair.
#[test]
fn the_declared_and_enumerated_receipts_over_entry_19_carry_one_envelope() {
    let (_, declared) = read_receipt("statement-anchored-uncarried-key-transition-must-fail.ahl");
    let (_, enumerated) = read_receipt("trigger-effective-derived-rotated-key.ahl");

    assert_eq!(declared["subject"]["entry_index"], json!(19));
    assert_eq!(declared["envelope"], enumerated["envelope"], "the two vectors must be one pair");
    assert_eq!(declared["governance"]["currency"]["mode"], json!("declared"));
    assert_eq!(enumerated["governance"]["currency"]["mode"], json!("enumerated"));

    let signer = field_str(&declared["envelope"]["signatures"][0], "key_id").expect("key_id");
    assert_eq!(signer, test_key("producer-2").key_id(), "entry 19 is signed by producer-2");

    // The enumerated half really does accept, so the contradiction §7.4 rules out would be a
    // live one if the declared half were reported `invalid`.
    verify_receipt(&enumerated, &trust_policy()).expect("the enumerated counterpart accepts");
}

/// The other side of I-D §7.4's rule, which no vector can carry: under `enumerated` governance
/// the range proof over exactly `[0, tree_size(C))` "forecloses omission, so K at each index IS
/// the state that was in force" (§7.5.1 4c). An unresolvable `key_id` there is not missing
/// material — it is a key the complete record shows was never in force — so it stays `invalid`.
///
/// A vector cannot demonstrate this, because a conforming corpus anchors no such envelope: the
/// I-D §7.5.1 4d's reliance rule over an entry the receipt does not rest on: an envelope naming
/// a key not active at its own index is VOID, not `invalid`.
///
/// "For every other carried envelope — a purported competing-trigger envelope, an entry of a
/// propagation prefix, any entry an enumeration reveals — a non-verifying envelope is VOID
/// (Section 2.1): it is excluded before any authority comparison, it is never effective and
/// never traversed, it does not affect the result, and the verifier reports it as an informative
/// item naming its entry index." The reason is the log contract: "a log anchors opaque bytes and
/// validates none, so were a void entry a defect of every later receipt, any party able to
/// anchor one envelope could disable every enumerated claim of that log from that index on."
#[test]
fn an_unresolvable_key_on_a_non_relied_entry_is_void() {
    let (_, mut receipt) = read_receipt("governance-state-valid.ahl");
    // Entry 3 is an ordinary derivation inside the enumerated range, and not a chain hop.
    // Corrupting the `key_id` its signature names — not the signature — leaves the envelope
    // well formed and its named key unresolvable under any state.
    corrupt(
        &mut receipt["governance"]["currency"]["material"]["entries"][3]["envelope"]["signatures"]
            [0]["key_id"],
    );
    reanchor(&mut receipt);
    let anchor = entry_id(&receipt["governance"]["chain"][0]["envelope"]);
    receipt["governance"]["genesis_entry_id"] = json!(&anchor);
    let policy = TrustPolicy { genesis_entry_id: anchor, ..trust_policy() };

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert!(verify_receipt(&receipt, &policy).is_ok());
    let item = report
        .informative
        .iter()
        .find(|item| item.entry_index == 3)
        .expect("the void entry is reported by index");
    assert_eq!(item.reason, VoidReason::KeyNotActive);
    assert!(item.receipt_path.is_empty());
    // An informative item is not a finding: it belongs to no assertion and never enters the
    // reduction, so it cannot be what `dominating()` returns.
    assert!(report.findings.iter().all(|finding| finding.outcome == Outcome::Verified));
    assert!(report.dominating().is_none());
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

/// I-D §7.7's own worked example, over the one capability gap this corpus can present without
/// a fixture built for it: "A `record-ingested` receipt asserting a content binding the
/// verifier cannot compute has result `unverifiable` — its content binding is a required
/// assertion — and its report MUST show the anchoring and introduction findings as `verified`
/// and the content-binding finding as `unverifiable`. Those are findings; the receipt still has
/// exactly one result, and a verifier MUST NOT present a finding as though it were the result."
///
/// The gap is the dataset key: the receipt is the accepted `record-ingested` vector, verified
/// under a policy holding no key for its dataset. What makes it the example is the shape — a
/// verifier-local capability the receipt cannot supply, on the content binding alone — and not
/// which capability it is.
#[test]
fn a_capability_gap_is_reported_beside_the_assertions_that_held() {
    let mut policy = trust_policy();
    policy.dataset_keys.clear();
    let (_, receipt) = read_receipt("record-ingested-valid.ahl");

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert!(report.verdict.is_none(), "only `verified` is rendered in words (I-D §7.7)");

    let binding = report.finding(Assertion::ContentBinding).expect("content-binding finding");
    assert_eq!(binding.outcome, Outcome::Unverifiable);
    assert!(
        binding.detail.as_ref().is_some_and(|detail| detail.contains("customers")),
        "the finding must say what was missing: {binding:?}"
    );

    // Everything the run did establish is reported as established, the introduction the claim
    // type is about included.
    for assertion in [
        Assertion::Versions,
        Assertion::Structure,
        Assertion::AdaptorProfile,
        Assertion::Anchoring,
        Assertion::Governance,
        Assertion::CheckpointAuthentication,
        Assertion::EnvelopeValidity,
        Assertion::CrossField,
        Assertion::ClaimMaterial,
    ] {
        let finding = report.finding(assertion).unwrap_or_else(|| panic!("{assertion} finding"));
        assert_eq!(finding.outcome, Outcome::Verified, "{assertion} held and must be reported so");
    }
}

/// The reduction of I-D §7.7 over a receipt with nothing missing: every required assertion is
/// `verified`, the result is `verified`, and the boundary is rendered.
#[test]
fn a_verified_receipt_reports_every_required_assertion() {
    let policy = trust_policy();
    for name in ["statement-anchored-valid.ahl", "disposition-effective-valid.ahl"] {
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Verified, "{name}");
        assert!(report.verdict.is_some(), "{name}: a verified result renders its boundary");
        assert!(
            report.findings.iter().all(|finding| finding.outcome == Outcome::Verified),
            "{name}: a verified result reduces from verified findings alone"
        );
        // The content binding is required "if and only if its own `assurance.content_binding`
        // is not `none`" (I-D §7.7), and neither of these asserts one.
        assert!(report.finding(Assertion::ContentBinding).is_none(), "{name}");
        for assertion in [Assertion::Versions, Assertion::Anchoring, Assertion::ClaimMaterial] {
            assert!(report.finding(assertion).is_some(), "{name}: {assertion} is required");
        }
    }
}

/// An `invalid` finding decides the result where it is reached, and the report names the
/// assertion that produced it. I-D §7.7: "`invalid` dominates `unverifiable` because a
/// demonstrated defect in required material is a fact about the artifact."
#[test]
fn an_invalid_result_names_the_assertion_that_produced_it() {
    let policy = trust_policy();
    let (_, receipt) = read_receipt("record-ingested-content-mismatch-must-fail.ahl");
    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert!(report.verdict.is_none());
    let binding = report.finding(Assertion::ContentBinding).expect("content-binding finding");
    assert_eq!(binding.outcome, Outcome::Invalid);
    assert_eq!(
        report.finding(Assertion::Anchoring).map(|finding| finding.outcome),
        Some(Outcome::Verified),
        "the assertions settled before the defect keep the outcome they reached"
    );
}

/// I-D §7.4's `unverifiable` outcome ends nothing: the run carries on, and the assertions that
/// rest on the material the mode does not carry say so rather than claiming to have held.
#[test]
fn an_uncarried_key_transition_is_reported_as_the_prerequisite_it_is() {
    let policy = trust_policy();
    let (_, receipt) = read_receipt("statement-anchored-uncarried-key-transition-must-fail.ahl");
    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);

    let envelope = report.finding(Assertion::EnvelopeValidity).expect("envelope-validity finding");
    assert_eq!(envelope.outcome, Outcome::Unverifiable);

    // Nothing else rests on the subject's own envelope here: this claim type carries no
    // material that tests authority (§7.5.1 4e), and every §7.6 rule is decidable from the
    // receipt's own bytes. Reporting them as unverifiable would overstate what is missing.
    for assertion in [
        Assertion::Anchoring,
        Assertion::Governance,
        Assertion::CheckpointAuthentication,
        Assertion::Witnesses,
        Assertion::CrossField,
        Assertion::ClaimMaterial,
    ] {
        assert_eq!(
            report.finding(assertion).map(|finding| finding.outcome),
            Some(Outcome::Verified),
            "{assertion} does not rest on the uncarried transition"
        );
    }
}

/// Which assertion a rejection belongs to is decided by the phase of the §7.5 algorithm that
/// raised it, not by the error type the check reached for.
///
/// I-D §7.7 asks for a finding "for each assertion the receipt REQUIRES". One variant —
/// `Malformed`, here — is raised by the container shape checks of step 3, by phase-2 validation
/// of a governance statement inside the §7.5.1 induction, and by the §7.2 claim-material schema.
/// Those are three different assertions, and a reader told "structure" about a malformed
/// governance payload has been told the wrong thing.
#[test]
fn one_variant_is_reported_under_the_assertion_whose_phase_raised_it() {
    let policy = trust_policy();
    for (name, expected) in [
        // Step 3, the container's own shapes.
        (
            "governance-key-rotation-proof-malformed-witness-entry-must-fail.ahl",
            Assertion::Structure,
        ),
        // §7.5.1 4b(K), phase 2 of the induction.
        ("governance-key-statement-malformed-valid-time-must-fail.ahl", Assertion::Governance),
        // §7.2, the claim type's own material.
        ("record-derived-input-members-on-full-array-must-fail.ahl", Assertion::ClaimMaterial),
    ] {
        let (_, receipt) = read_receipt(name);
        let error = verify_receipt(&receipt, &policy).expect_err("a negative vector");
        assert!(matches!(error, ReceiptError::Malformed(_)), "{name}: {error}");
        // The variant's own answer is the same for all three: it is the fallback for a
        // rejection examined outside a run, and cannot tell them apart.
        assert_eq!(error.assertion(), Assertion::Structure, "{name}");

        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.outcome == Outcome::Invalid)
            .unwrap_or_else(|| panic!("{name}: an invalid finding"));
        assert_eq!(finding.assertion, expected, "{name}: reported under the wrong assertion");
    }
}

/// A rotation whose proof cannot be authenticated applies no effect to K.
///
/// I-D §7.5.1 4b: "Only after phases 1 and 2 have BOTH passed, apply the statement's effect to
/// K", and "No effect is ever applied to K by a statement that has not completed both earlier
/// phases." 4b(M)'s rotation-anchoring proof rests on a checkpoint, and a checkpoint cannot be
/// authenticated without the adaptor profile that fixes its serialization — so with no profile
/// the induction stops at the rotating manifest, K stays at the pre-rotation state, and 4f's
/// own rule follows: it "MUST NOT resolve a checkpoint-verification or cosignature-validating
/// key from a manifest version whose log or witness key set was not established by the
/// governance-key induction."
#[test]
fn an_unauthenticated_rotation_applies_no_effect_to_the_key_state() {
    let mut policy = trust_policy();
    policy.adaptor_profiles.clear();

    for name in [
        "trigger-effective-co-signed-by-authority.ahl",
        "propagation-complete-valid-across-manifest-rotation.ahl",
        "governance-state-valid.ahl",
    ] {
        let (_, receipt) = read_receipt(name);
        assert_eq!(
            receipt["governance"]["chain"][1]["entry_index"],
            json!(25),
            "{name}: this test needs a chain carrying the corpus's rotating manifest"
        );

        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Unverifiable, "{name}");

        let governance = report.finding(Assertion::Governance).expect("governance finding");
        assert_eq!(governance.outcome, Outcome::Unverifiable, "{name}");
        assert!(
            governance.detail.as_ref().is_some_and(|detail| detail.contains("25")),
            "{name}: the finding must name the rotation it stopped at: {governance:?}"
        );

        // Nothing that would have needed a key from the rotating manifest is reported as
        // established: the checkpoints these receipts carry are at tree sizes past entry 25,
        // their subjects and enumerated envelopes are verified under K at their own indexes,
        // and the authority tests of 4e resolve producer keys the same way.
        for assertion in [
            Assertion::CheckpointAuthentication,
            Assertion::Witnesses,
            Assertion::EnvelopeValidity,
            Assertion::ClaimMaterial,
            Assertion::CrossField,
        ] {
            assert_eq!(
                report.finding(assertion).map(|finding| finding.outcome),
                Some(Outcome::Unverifiable),
                "{name}: {assertion} needs the key state past the rotation"
            );
        }
        // What needs no key at all is still checked, which is what keeps a defect reachable.
        for assertion in [Assertion::Versions, Assertion::Structure, Assertion::Anchoring] {
            assert_eq!(
                report.finding(assertion).map(|finding| finding.outcome),
                Some(Outcome::Verified),
                "{name}: {assertion} needs no key"
            );
        }
        // And nothing the gap reached is reported as a DEFECT: a capability the verifier lacks
        // never becomes a statement about the artifact (I-D §7.7).
        assert!(
            report.findings.iter().all(|finding| finding.outcome != Outcome::Invalid),
            "{name}: a capability gap must produce no `invalid` finding: {:#?}",
            report.findings
        );
    }

    // A chain that rotates nothing is untouched by the same gap: only the assertions that rest
    // on the checkpoint serialization are unverifiable, exactly as before.
    let (_, unrotated) = read_receipt("record-ingested-valid.ahl");
    assert_eq!(unrotated["governance"]["chain"].as_array().expect("chain").len(), 1);
    let report = verify_receipt_report(&unrotated, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    for assertion in [
        Assertion::Governance,
        Assertion::EnvelopeValidity,
        Assertion::ClaimMaterial,
        Assertion::ContentBinding,
    ] {
        assert_eq!(
            report.finding(assertion).map(|finding| finding.outcome),
            Some(Outcome::Verified),
            "{assertion} is unaffected where the chain rotates nothing"
        );
    }
}

/// A `manifest-chain` key entry is judged against the manifest its binding names, used or not.
///
/// I-D §7.1: "A `manifest-chain` key that matches no object in the manifest version its binding
/// names, or that differs from the matching object in any compared member, is `invalid`." The
/// rule is about the ENTRY, so an entry no cosignature ever selects is as much a defect as a
/// selected one — unlike a `local-policy` entry, whose obligation §7.1 makes conditional on use
/// because what it depends on is the verifier's own configuration rather than the receipt's own
/// material.
///
/// The finding is `witnesses` because the entry sits in `keys.witness[]`, which is scanned
/// while the witness half of 4f resolves its keys; the same defect in a `keys.log[]` entry is
/// `checkpoint-authentication`, scanned while the checkpoint signature's key is resolved.
#[test]
fn an_unused_manifest_chain_key_entry_is_validated_anyway() {
    let policy = trust_policy();
    let impostor = TestKey::from_seed_hex("impostor", &"ee".repeat(32)).expect("32-byte seed");
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    // Well formed, correctly self-consistent (`key_id` is `sha256:`-of-`pubkey`), bound to the
    // genesis manifest — and matching no witness object that manifest declares. No cosignature
    // names it.
    receipt["keys"]["witness"].as_array_mut().expect("witness keys").push(json!({
        "witness_id": "witness-1",
        "key_id": impostor.key_id(),
        "pubkey": impostor.pubkey(),
        "source": "manifest-chain",
        "binding": { "entry_index": 0 },
    }));

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
    let finding = report.finding(Assertion::Witnesses).expect("witnesses finding");
    assert_eq!(finding.outcome, Outcome::Invalid);
    assert!(matches!(
        verify_receipt(&receipt, &policy),
        Err(ReceiptError::KeyNotBound { ref key_id, entry_index: 0 }) if key_id == &impostor.key_id()
    ));

    // The receipt without that entry is the accepted vector it was built from.
    let (_, clean) = read_receipt("statement-anchored-valid.ahl");
    assert!(verify_receipt(&clean, &policy).is_ok());
}

/// The dominating finding is the CAUSE, not whatever the report happens to list first.
///
/// I-D §7.8: "A verifier MUST report WHICH budget was exhausted and the value that was in
/// force." I-D §7.7: "a reader cannot act on `unverifiable` without knowing what was missing."
/// A run that ends on an exhausted budget reports every assertion it never settled as resting
/// on `resource-limits`, and those findings sort ahead of it — so the finding that carries the
/// budget and its value is the one `Report::dominating` must return.
#[test]
fn the_dominating_finding_names_the_budget_that_was_exhausted() {
    let (_, receipt) = read_receipt("disposition-effective-valid.ahl");

    for (limits, budget, value) in [
        (Limits { max_work_units: 2, ..Limits::default() }, "verification work units", "2"),
        (Limits { max_decoded_bytes: 1024, ..Limits::default() }, "decoded size in bytes", "1024"),
    ] {
        let policy = TrustPolicy { limits, ..trust_policy() };
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Unverifiable, "{budget}");

        let dominating = report.dominating().expect("a non-verified result has a cause");
        assert_eq!(dominating.assertion, Assertion::ResourceLimits, "{budget}");
        assert_eq!(dominating.rests_on, None, "the cause rests on nothing");
        let detail = dominating.detail.as_ref().expect("the rule that fired");
        assert!(detail.contains(budget), "the finding must name the budget: {detail}");
        assert!(detail.contains(value), "the finding must carry the value in force: {detail}");

        // Every OTHER unverifiable finding is a derivation, and says so structurally rather
        // than only in prose — including the ones that sort ahead of the cause.
        for finding in &report.findings {
            if finding.outcome == Outcome::Unverifiable
                && finding.assertion != Assertion::ResourceLimits
            {
                assert_eq!(
                    finding.rests_on,
                    Some(Assertion::ResourceLimits),
                    "{finding:?} inherited the gap and must name it"
                );
            }
        }
        // The single-value form agrees with the report.
        let error = verify_receipt(&receipt, &policy).expect_err("the budget is exhausted");
        assert!(matches!(error, ReceiptError::BudgetExhausted { .. }), "{error}");
    }
}

/// The same rule where the gap is a capability rather than a budget, and where a defect sits
/// beside one: `invalid` dominates, and among `unverifiable` findings the cause wins.
#[test]
fn the_dominating_finding_is_the_cause_and_invalid_wins() {
    let policy = trust_policy();

    // I-D §7.4's declared-mode gap: the subject's envelope names a key the mode does not carry.
    let (_, uncarried) = read_receipt("statement-anchored-uncarried-key-transition-must-fail.ahl");
    let report = verify_receipt_report(&uncarried, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    let dominating = report.dominating().expect("a non-verified result has a cause");
    assert_eq!(dominating.assertion, Assertion::EnvelopeValidity);
    assert_eq!(dominating.rests_on, None);

    // An authority-dependent claim type over the same gap: its claim material rests on the
    // envelope, and says which assertion it rests on rather than only saying so in prose.
    let mut gapped = trust_policy();
    gapped.adaptor_profiles.clear();
    let (_, rotating) = read_receipt("trigger-effective-co-signed-by-authority.ahl");
    let report = verify_receipt_report(&rotating, &gapped).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert_eq!(
        report.dominating().map(|finding| finding.assertion),
        Some(Assertion::AdaptorProfile),
        "the capability the verifier lacks is the cause: {:#?}",
        report.findings
    );
    let claim_material = report.finding(Assertion::ClaimMaterial).expect("claim-material finding");
    assert_eq!(claim_material.outcome, Outcome::Unverifiable);
    assert!(
        claim_material.rests_on.is_some(),
        "a derived finding names the assertion it inherited from: {claim_material:?}"
    );

    // A defect beside a capability gap: `invalid` dominates (I-D §7.7's reduction).
    let (_, defective) = read_receipt("record-ingested-content-mismatch-must-fail.ahl");
    let report = verify_receipt_report(&defective, &gapped).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    let dominating = report.dominating().expect("an invalid result has a cause");
    assert_eq!(dominating.outcome, Outcome::Invalid);
    assert_eq!(dominating.assertion, Assertion::ContentBinding);
    assert!(report.findings.iter().any(|finding| finding.outcome == Outcome::Unverifiable));
}

/// Two independent causes in one run, and the two APIs still name the same one.
///
/// I-D §7.7: "the result alone does not say which assertion produced it." Where a run tolerates
/// more than one gap — each recorded by its own check, each `rests_on: None` — the report and
/// the single-value form must not disagree about which of them decided the result, or a caller
/// reading one and a caller reading the other would act on different facts about one artifact.
///
/// The pair here is a cosignature under a `local-policy` witness key local policy does not hold
/// (settling `witnesses`) and a `keyed-authorized` content binding over a dataset the verifier
/// holds no key for (settling `content-binding`). Neither ends the run, so both are reached.
#[test]
fn two_independent_causes_agree_between_the_report_and_the_error() {
    let mut policy = trust_policy();
    policy.dataset_keys.clear();
    let impostor = TestKey::from_seed_hex("impostor", &"ee".repeat(32)).expect("32-byte seed");
    let (_, mut receipt) = read_receipt("record-ingested-valid.ahl");
    assert_eq!(receipt["claim"]["assurance"]["content_binding"], json!("keyed-authorized"));
    receipt["keys"]["witness"] = json!([{
        "witness_id": "witness-1",
        "key_id": impostor.key_id(),
        "pubkey": impostor.pubkey(),
        "source": "local-policy",
    }]);
    receipt["anchoring"]["witnesses"] = json!([{
        "witness_id": "witness-1",
        "key_id": impostor.key_id(),
        "cosignature": impostor
            .sign(&cosignature_bytes(&receipt["anchoring"]["checkpoint"], "witness-1")),
        "cosigned_at": "2026-08-16T12:00:00Z",
    }]);

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);

    // Two causes, each produced by its own check, and nothing else claiming to be one.
    let causes: Vec<Assertion> = report
        .findings
        .iter()
        .filter(|finding| finding.outcome == Outcome::Unverifiable && finding.rests_on.is_none())
        .map(|finding| finding.assertion)
        .collect();
    assert_eq!(
        causes,
        vec![Assertion::Witnesses, Assertion::ContentBinding],
        "two independent gaps, in report order: {:#?}",
        report.findings
    );
    // What rests on one of them is reported as resting on it, not as a second cause.
    assert_eq!(
        report.finding(Assertion::CrossField).and_then(|finding| finding.rests_on),
        Some(Assertion::Witnesses)
    );

    // The report leads with the earlier of the two, and the single-value form returns the
    // rejection behind that same finding.
    let dominating = report.dominating().expect("a non-verified result has a cause");
    assert_eq!(dominating.assertion, Assertion::Witnesses);
    let error = verify_receipt(&receipt, &policy).expect_err("two gaps, one result");
    assert_eq!(error.class(), dominating.outcome);
    assert_eq!(error.assertion(), dominating.assertion);
    assert_eq!(Some(error.to_string()), dominating.detail, "one fact, reported once");
    assert!(matches!(error, ReceiptError::WitnessKeyNotTrusted { .. }), "{error}");
}

/// Every vector's void entries are reported, counted, and consequential nowhere.
///
/// I-D §7.7: "For each void entry it inspected (Section 7.5.1 4d) the verifier MUST report one
/// informative item carrying the entry index and the failure reason... Informative items are not
/// findings: they belong to no required assertion, carry no result value, and never enter the
/// reduction. Their number is the number of void entries inspected." `index.json` records that
/// number for the vectors that have one, and no number for the vectors that have none.
#[test]
fn every_vector_reports_the_void_entries_it_inspected() {
    let policy = trust_policy();
    let mut with_void = 0;
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        let name = field_str(entry, "file").expect("file");
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        let declared = entry.get("informative").and_then(Value::as_u64).unwrap_or(0);
        assert_eq!(report.informative.len() as u64, declared, "{name}");
        if declared > 0 {
            with_void += 1;
        }
        // Reported, and consequential nowhere: an informative item belongs to no assertion, so
        // it can change neither the reduction nor which finding decided it.
        let findings_before = report.findings.len();
        assert_eq!(
            report.result,
            report
                .findings
                .iter()
                .filter(|finding| finding.counts_toward_result())
                .map(|finding| finding.outcome)
                .max()
                .unwrap_or(Outcome::Verified),
            "{name}: the result is the reduction of the FINDINGS alone"
        );
        assert_eq!(report.findings.len(), findings_before);
    }
    assert!(with_void >= 3, "the corpus must exercise the reliance rule, got {with_void}");
}

/// A void prefix entry is "never traversed by closure" (I-D §2.1, §7.5.1 4d), and voiding it is
/// not cosmetic: it changes what the closure reaches.
///
/// The material is the corpus prefix `propagation-complete-valid.ahl` carries — entries [0, 8),
/// the correction at entry 6 as the trigger, and the committed trees that prefix references —
/// walked through `affected_set`, the same function the verifier calls. Entry 3 derives S1 from
/// the record the correction at entry 6 supersedes, so it is a derivation the closure reaches:
/// with the entry carried the closure includes its output, and with the entry VOID — replaced positionally by material the
/// walk reads nothing from, exactly as `verify_propagation_complete` does — it does not. A
/// verifier that traversed a void entry would recompute a different affected set and refuse a
/// receipt whose anchored set is the right one.
///
/// The receipt half of the same fact is the control: `propagation-complete-valid.ahl` verifies,
/// its prefix root recomputed over the CARRIED bytes rather than the traversable copy.
///
/// A vector whose prefix carries a void derivation is not constructible from this corpus, and
/// the reason is structural: every propagation it anchors declares D at tree size 8 or 13, the
/// free entry indexes are all past the deliberately non-conforming batch at entry 39, and a
/// closure walk reaching that batch fails on the I-D §2.7 tree rules before any traversal
/// question is reached. Adding one means moving that batch — a corpus renumbering, not another
/// entry.
#[test]
fn a_void_prefix_entry_is_not_traversed_by_closure() {
    let policy = trust_policy();
    let (_, receipt) = read_receipt("propagation-complete-valid.ahl");
    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert!(report.informative.is_empty(), "no entry of this prefix is void");

    // The prefix the receipt carries, and the trees it references.
    let prefix: Vec<Value> = receipt["claim_material"]["corpus_prefix"]["entries"]
        .as_array()
        .expect("prefix entries")
        .iter()
        .map(|entry| entry["envelope"].clone())
        .collect();
    assert_eq!(prefix.len(), 8, "the prefix is [0, 8)");
    let trees = tree_material();

    // Carried: the derivation at entry 3 is reached, and its output is in the closure.
    let carried = affected_set(&prefix, &trees, 6, prefix.len()).expect("closure over [0, 8)");

    // Void: the same walk with entry 3 replaced positionally by material it reads nothing from.
    let mut voided = prefix;
    voided[3] = Value::Null;
    let without = affected_set(&voided, &trees, 6, voided.len()).expect("closure over [0, 8)");

    assert_ne!(
        carried.affected, without.affected,
        "voiding a derivation the closure reaches must change the closure, or this test proves \
         nothing about traversal"
    );
    assert!(
        carried.affected.len() > without.affected.len(),
        "the void entry is what put its output in the affected set"
    );
    // The seeds come from the trigger, which is not void either way.
    assert_eq!(carried.seeds, without.seeds);
}

/// A void entry occupies no statement id, so a later verifying copy of the same statement is
/// inducted and its effect applied.
///
/// I-D §2.1's first-wins rule voids "later ones" among GOVERNING statements, and §7.5.1 4b
/// admits an enumeration-only entry to the induction "only if its envelope verifies in phase 1":
/// a void entry never governs, so it claims nothing. The corpus anchors the same `key` statement
/// twice — void at entry 38, genuinely signed at entry 41 — with entry 40 retiring the key in
/// between, so the subject at entry 42 verifies only if the copy at 41 was inducted.
#[test]
fn a_void_entry_leaves_its_statement_id_free_for_a_verifying_copy() {
    let policy = trust_policy();
    let (_, receipt) = read_receipt("statement-anchored-void-then-verifying-key.ahl");
    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert!(verify_receipt(&receipt, &policy).is_ok());

    // The void copy is reported, and it is not the copy that governed.
    assert!(
        report.informative.iter().any(|item| item.entry_index == 38),
        "the void copy is named by index: {:#?}",
        report.informative
    );
    assert!(
        !report.informative.iter().any(|item| item.entry_index == 41),
        "the verifying copy is not void: {:#?}",
        report.informative
    );

    // The two copies really are one statement, anchored twice.
    let statements = statement_vectors();
    assert_eq!(
        field_str(&statements[38], "statement_id").expect("statement_id"),
        field_str(&statements[41], "statement_id").expect("statement_id"),
    );
    assert_ne!(
        field_str(&statements[38], "entry_id").expect("entry_id"),
        field_str(&statements[41], "entry_id").expect("entry_id"),
    );
}

/// A VERIFYING governance statement of a revision this document does not define is
/// `unverifiable`, whichever path reaches it: the induction (a `key` statement) or the
/// completeness check (a `manifest` absent from the chain).
///
/// I-D §7.5.1 4b: it "is not inducted, K is unestablished at and after its index, the governance
/// finding is `unverifiable`". §7.4's omission rule reaches VERIFYING manifest entries OF THIS
/// REVISION, so calling the manifest's absence an omission would report a statement this
/// verifier cannot interpret as a defect of the receipt.
#[test]
fn a_verifying_foreign_revision_governance_entry_is_unverifiable_either_way() {
    let policy = trust_policy();
    for (name, index) in [
        ("governance-state-foreign-revision-key-must-fail.ahl", 53usize),
        ("governance-state-foreign-revision-manifest-must-fail.ahl", 52),
    ] {
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Unverifiable, "{name}");
        let governance = report.finding(Assertion::Governance).expect("governance finding");
        assert_eq!(governance.outcome, Outcome::Unverifiable, "{name}");
        assert_eq!(governance.rests_on, None, "{name}: the cause, not a derivation");
        assert!(
            governance.detail.as_ref().is_some_and(|detail| detail.contains("0.5")),
            "{name}: the finding names the revision it cannot interpret: {governance:?}"
        );
        // Nothing is reported as a defect of the artifact.
        assert!(
            report.findings.iter().all(|finding| finding.outcome != Outcome::Invalid),
            "{name}: {:#?}",
            report.findings
        );
        // "K is unestablished at and after its index… every K-dependent check at or after that
        // index rests on it" (I-D §7.5.1 4b). Both receipts anchor at a checkpoint whose tree
        // size is past the stop, and their subjects' envelopes are resolved under K, so none of
        // these may be evaluated against the state the walk had reached before it stopped.
        for assertion in
            [Assertion::CheckpointAuthentication, Assertion::Witnesses, Assertion::EnvelopeValidity]
        {
            let finding =
                report.finding(assertion).unwrap_or_else(|| panic!("{name}: {assertion} finding"));
            assert_eq!(finding.outcome, Outcome::Unverifiable, "{name}: {assertion}");
            assert_eq!(
                finding.rests_on,
                Some(Assertion::Governance),
                "{name}: {assertion} must rest on the stop, not be checked against the pre-stop \
                 key state"
            );
        }
        // And the checks themselves did not RUN against the pre-stop key state, which is what
        // the findings above would not by themselves show. The 4d sweep over the enumerated
        // range is the observable one: it reports every void entry it inspects, and this range
        // reaches the two non-verifying retractions at entries 32 and 33. Where the walk stopped,
        // it is not performed at all, so those two are never inspected — the only void entries
        // reported are the ones the stopped walk itself met.
        let inspected: Vec<u64> = report.informative.iter().map(|item| item.entry_index).collect();
        assert!(
            !inspected.contains(&32) && !inspected.contains(&33),
            "{name}: the enumerated sweep must not run past the stop, got {inspected:?}"
        );

        // And the run CARRIES ON past the stop, which is the other half of 4b's sentence: "the
        // scalar result is reduced under Section 7.7 — a later required `invalid` still
        // dominates". A §7.6 disagreement the receipt's own bytes settle is reached and decides
        // the result, where a run that ended at the version read could never have found it.
        let mut defective = receipt.clone();
        defective["claim"]["assurance"]["governance"] = json!("declared");
        let later = verify_receipt_report(&defective, &policy).expect("the run completes");
        assert_eq!(later.result, Outcome::Invalid, "{name}: a later invalid dominates the gap");
        assert_eq!(
            later.dominating().map(|finding| finding.assertion),
            Some(Assertion::CrossField),
            "{name}"
        );
        assert_eq!(
            later.finding(Assertion::Governance).map(|finding| finding.outcome),
            Some(Outcome::Unverifiable),
            "{name}: the gap is still reported beside the defect that dominates it"
        );
        // The statement really is at that index, and really does verify.
        let statements = statement_vectors();
        let keys = key_set(&statements);
        assert!(
            verify_envelope(&statements[index]["envelope"], |key_id| keys.get(key_id).cloned())
                .expect("well-formed envelope"),
            "{name}: the entry at {index} must VERIFY, or it is the void case instead"
        );
    }
}

/// A `governance.chain[]` element's phase-1 failure is `invalid`, whatever revision it declares.
///
/// I-D §7.5.1 4b states the two rules in this order: "A `governance.chain[]` element is
/// different: the receipt presents it as its own lineage, so its phase-1 failure is `invalid`",
/// and the foreign-revision rule that follows applies to "A VERIFYING purported governance
/// entry". Reading the version member before the signature is settled would let a receipt
/// reduce any broken chain element to a capability gap by declaring a revision of its own.
#[test]
fn a_chain_hop_that_does_not_verify_is_invalid_whatever_revision_it_declares() {
    let policy = trust_policy();

    // Entries 52 and 54 are the same manifest shape at the same declared revision; only the
    // signature differs, and only these two vectors' last hop differs with it.
    let statements = statement_vectors();
    let keys = key_set(&statements);
    for (index, verifies) in [(52usize, true), (54, false)] {
        let entry = &statements[index];
        assert_eq!(entry["envelope"]["payload"]["ahl_version"], json!("0.5"), "entry {index}");
        assert_eq!(entry["envelope"]["payload"]["type"], json!("manifest"), "entry {index}");
        assert_eq!(
            verify_envelope(&entry["envelope"], |key_id| keys.get(key_id).cloned())
                .expect("well-formed envelope"),
            verifies,
            "entry {index}"
        );
    }

    let (_, broken) =
        read_receipt("statement-anchored-broken-foreign-revision-chain-hop-must-fail.ahl");
    let report = verify_receipt_report(&broken, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
    let governance = report.finding(Assertion::Governance).expect("governance finding");
    assert_eq!(governance.outcome, Outcome::Invalid);
    assert_eq!(governance.rests_on, None, "the cause, not a derivation");
    assert_eq!(
        report.dominating().map(|finding| finding.assertion),
        Some(Assertion::Governance),
        "{:#?}",
        report.findings
    );
    assert!(
        matches!(
            verify_receipt(&broken, &policy),
            Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: 54 })
        ),
        "the failure is named at the hop's own index: {:?}",
        verify_receipt(&broken, &policy)
    );
    // Nothing here is a capability gap: the revision the hop declares never gets to soften the
    // signature failure, so no finding may be `unverifiable`.
    assert!(
        report.findings.iter().all(|finding| finding.outcome != Outcome::Unverifiable),
        "{:#?}",
        report.findings
    );

    // And the VERIFYING hop of the same revision is untouched: still a gap, still not a defect.
    let (_, verifying) =
        read_receipt("statement-anchored-foreign-revision-chain-hop-must-fail.ahl");
    let report = verify_receipt_report(&verifying, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable, "{:#?}", report.findings);
    assert_eq!(
        report.finding(Assertion::Governance).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable)
    );
    assert!(report.findings.iter().all(|finding| finding.outcome != Outcome::Invalid));
}

/// A carried statement of an unsupported revision is a gap, not the end of the run.
///
/// I-D §7.1: only the receipt's own `ahl_receipt_version` read says "no further processing"; a
/// carried statement's unsupported `ahl_version` "is `unverifiable` as for any carried
/// statement". §7.5.1 4b closes the foreign-revision governance entry rule with "a later
/// required `invalid` still dominates". These are the two remaining carriers: a
/// `governance.chain[]` hop the walk cannot interpret, and an enumeration-only entry a sweep
/// meets. Each is paired here with a later disagreement the receipt's own bytes settle.
#[test]
fn a_carried_statement_of_an_unsupported_revision_does_not_end_the_run() {
    let policy = trust_policy();
    // Each disagreement is a §7.6 rule the receipt's own bytes settle, and each is reached
    // AFTER the gap. The two differ because the two gaps sit at opposite ends of the run. The
    // chain hop is met by the step-3 walk, so the first cross-field rule is already later than
    // it: `claim.assurance.governance` must equal `governance.currency.mode`. The enumerated
    // sweep, by contrast, runs inside the cross-field phase, so the defect has to be one of the
    // subject-level rules that follow it — here the presence rule, which forbids a manifest
    // subject from also carrying `subject.manifest`. (Flipping the assurance member on the
    // enumerated receipt would not do: that member also SELECTS the work, and setting it to
    // `declared` would switch off the very sweep that meets the entry.)
    let mutations: [fn(&mut Value); 2] = [
        |receipt| receipt["claim"]["assurance"]["governance"] = json!("enumerated"),
        |receipt| {
            receipt["subject"]["manifest"] =
                json!("sha256:00000000000000000000000000000000000000000000000000000000000000ff");
        },
    ];
    for ((name, assertion, index), mutate) in [
        ("statement-anchored-foreign-revision-chain-hop-must-fail.ahl", Assertion::Governance, 52),
        ("governance-state-foreign-revision-entry-must-fail.ahl", Assertion::EnvelopeValidity, 51),
    ]
    .into_iter()
    .zip(mutations)
    {
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");

        // The gap alone: `unverifiable`, on the assertion of the phase that met the entry.
        assert_eq!(report.result, Outcome::Unverifiable, "{name}: {:#?}", report.findings);
        let gap = report.finding(assertion).unwrap_or_else(|| panic!("{name}: {assertion}"));
        assert_eq!(gap.outcome, Outcome::Unverifiable, "{name}");
        assert_eq!(gap.rests_on, None, "{name}: the cause, not a derivation");
        assert!(
            gap.detail.as_ref().is_some_and(|detail| detail.contains("0.5")),
            "{name}: the finding names the revision it cannot interpret: {gap:?}"
        );
        assert_eq!(report.dominating().map(|finding| finding.assertion), Some(assertion), "{name}");
        // Nothing is reported as a defect of the artifact: the verifier's reach ran out.
        assert!(
            report.findings.iter().all(|finding| finding.outcome != Outcome::Invalid),
            "{name}: {:#?}",
            report.findings
        );
        // A set-aside entry is neither effective nor void: it is reported as a finding, so it
        // must not also appear among the void entries the run names.
        assert!(
            report.informative.iter().all(|item| item.entry_index != index),
            "{name}: a foreign-revision entry is a gap, not a void entry: {:#?}",
            report.informative
        );
        // The statement really is at that index, and really does verify — this is the carried
        // case, not the non-verifying one the reliance rule voids.
        let statements = statement_vectors();
        let keys = key_set(&statements);
        let entry = &statements[usize::try_from(index).expect("index fits")];
        assert!(
            verify_envelope(&entry["envelope"], |key_id| keys.get(key_id).cloned())
                .expect("well-formed envelope"),
            "{name}: the entry at {index} must VERIFY, or it is the void case instead"
        );
        assert_eq!(entry["envelope"]["payload"]["ahl_version"], json!("0.5"), "{name}");

        // And the run carries on: a §7.6 disagreement past the gap is reached and dominates,
        // where a run that ended at the version read could never have found it.
        let mut defective = receipt.clone();
        mutate(&mut defective);
        let later = verify_receipt_report(&defective, &policy).expect("the run completes");
        assert_eq!(later.result, Outcome::Invalid, "{name}: a later invalid dominates the gap");
        assert_eq!(
            later.dominating().map(|finding| finding.assertion),
            Some(Assertion::CrossField),
            "{name}"
        );
        assert_eq!(
            later.finding(assertion).map(|finding| finding.outcome),
            Some(Outcome::Unverifiable),
            "{name}: the gap is still reported beside the defect that dominates it"
        );
    }
}

/// The two vectors the erratum turns from `invalid` into `verified`, and what they now report.
///
/// I-D §7.5.1 4d: a non-verifying envelope the receipt does not rest on "is VOID (Section 2.1):
/// it is excluded before any authority comparison, it is never effective and never traversed, it
/// does not affect the result". Entries 32 and 33 of this corpus are the two deliberately
/// non-verifying retractions of record F; both vectors carry them inside an enumerated range,
/// and neither rests on either.
#[test]
fn a_void_entry_in_a_range_leaves_the_result_alone() {
    let policy = trust_policy();
    for name in ["trigger-effective-void-candidate.ahl", "governance-state-void-entry.ahl"] {
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Verified, "{name}: {:#?}", report.findings);
        assert!(report.verdict.is_some(), "{name}");
        assert!(report.dominating().is_none(), "{name}: nothing decided against this receipt");

        let indexes: Vec<u64> = report.informative.iter().map(|item| item.entry_index).collect();
        assert_eq!(indexes, vec![32, 33], "{name}: both void entries are named by index");
        for item in &report.informative {
            assert_eq!(item.reason, VoidReason::SignatureInvalid, "{name}");
            assert!(item.receipt_path.is_empty(), "{name}: carried by the receipt itself");
        }
        assert!(verify_receipt(&receipt, &policy).is_ok(), "{name}");
    }
}

/// A void governance statement applies no effect, and a receipt that RESTS on that effect is
/// `invalid` — on its own key listing, not on the void entry.
///
/// I-D §7.5.1 4b: an enumeration-only entry "ENTERS the induction only if its envelope verifies
/// in phase 1... a purported `manifest` or `key` entry that does not verify is void — not
/// inducted, no effect on K, the walk continues past it". §7.5 step 1 exempts it from the
/// version read and from §2.2's common fields until that check passes, so the vector's second
/// defect — a missing `issued_at` — is never reached.
#[test]
fn a_receipt_resting_on_a_void_key_statement_is_invalid_on_its_own_listing() {
    let policy = trust_policy();
    let (_, receipt) = read_receipt("governance-key-statement-unsigned-common-field-must-fail.ahl");
    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert_eq!(
        report.informative.iter().map(|item| item.entry_index).collect::<Vec<_>>(),
        vec![9],
        "the void statement is reported as an informative item"
    );
    let error = verify_receipt(&receipt, &policy).expect_err("the listing rests on it");
    assert!(matches!(error, ReceiptError::KeyNotBound { entry_index: 9, .. }), "{error}");
    assert!(
        !error.to_string().contains("issued_at"),
        "a void entry takes no type-specific validation at all: {error}"
    );
}

/// Every non-verified vector's dominating finding is a cause, never a derivation — the fallback
/// arm of `Report::dominating` is unreachable across the corpus.
#[test]
fn every_non_verified_vector_has_a_dominating_cause() {
    let policy = trust_policy();
    for entry in receipt_index()["vectors"].as_array().expect("vectors") {
        let expect = field_str(entry, "expect").expect("expect");
        if expect == "verified" {
            continue;
        }
        let name = field_str(entry, "file").expect("file");
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        let dominating =
            report.dominating().unwrap_or_else(|| panic!("{name}: a result comes from a finding"));
        assert_eq!(dominating.outcome, report.result, "{name}");
        assert_eq!(dominating.rests_on, None, "{name}: the dominating finding is the cause");
        assert_eq!(
            dominating.assertion.name(),
            field_str(entry, "finding").expect("finding"),
            "{name}: the index names the dominating finding"
        );
    }
}

/// §7.6's `subject.manifest` rules hold whether or not the induction stopped.
///
/// §7.6: "Each of the following is a disagreement among fields the receipt itself carries,
/// decidable from the receipt alone and identically by every verifier. A receipt failing any of
/// them is `invalid`; none of them is ever a capability gap, and none is downgraded." Among
/// them: "The manifest version named by `subject.manifest` is PRESENT in `governance.chain` —
/// as the element whose envelope's statement id equals that value — and that element's
/// `entry_index` is strictly smaller than `subject.entry_index`."
///
/// Both are read off the chain the receipt carries, at the entry index step 3 proved for each
/// element, so a capability gap elsewhere — no adaptor profile, an induction stopped at a
/// rotation — cannot turn either into `unverifiable`.
#[test]
fn the_subject_manifest_rules_are_never_downgraded_by_a_gap() {
    let mut gapped = trust_policy();
    gapped.adaptor_profiles.clear();
    let absent = format!("sha256:{}", "0".repeat(64));

    // A post-stop subject (entry 29, past the rotation at 25) naming a version the chain does
    // not carry: `invalid`, on `cross-field`, with no profile held.
    let (_, base) = read_receipt("trigger-effective-co-signed-by-authority.ahl");
    assert_eq!(base["subject"]["entry_index"], json!(29));
    let mut unknown_version = base.clone();
    unknown_version["subject"]["manifest"] = json!(absent);
    let report = verify_receipt_report(&unknown_version, &gapped).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    let finding = report.finding(Assertion::CrossField).expect("cross-field finding");
    assert_eq!(finding.outcome, Outcome::Invalid);
    assert!(
        finding.detail.as_ref().is_some_and(|detail| detail.contains("PRESENT")),
        "the presence rule must be the one that fired: {finding:?}"
    );

    // A subject naming a version anchored at or after it — the rotating manifest at entry 25,
    // named by the subject at entry 8 — is `invalid` on the same terms. The subject cannot also
    // be post-stop here: this corpus carries one rotation, so the only version at or after a
    // post-stop subject is that rotation itself, and it is the stop.
    let (_, propagation) = read_receipt("propagation-complete-valid-across-manifest-rotation.ahl");
    assert_eq!(propagation["subject"]["entry_index"], json!(8));
    let rotated = statement_id(&propagation["governance"]["chain"][1]["envelope"])
        .expect("the rotating manifest's version id");
    let mut not_before = propagation;
    not_before["subject"]["manifest"] = json!(rotated);
    let report = verify_receipt_report(&not_before, &gapped).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    let finding = report.finding(Assertion::CrossField).expect("cross-field finding");
    assert_eq!(finding.outcome, Outcome::Invalid);
    assert!(
        finding.detail.as_ref().is_some_and(|detail| detail.contains("strictly before")),
        "the ordering rule must be the one that fired: {finding:?}"
    );

    // And the receipt that names its version correctly is `unverifiable` under the same gap,
    // exactly as in round 24: only what needs the manifest's CONTENT is a capability gap.
    let report = verify_receipt_report(&base, &gapped).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert!(report.findings.iter().all(|finding| finding.outcome != Outcome::Invalid));

    // With the profile, both mutations are `invalid` too: the rules never depended on the gap.
    for receipt in [&unknown_version, &not_before] {
        assert!(matches!(
            verify_receipt(receipt, &trust_policy()),
            Err(ReceiptError::SubjectManifestBindingInvalid(_))
        ));
    }
}

/// An untrusted `local-policy` witness entry no cosignature names costs the run nothing.
///
/// I-D §7.1: "Every key USED in verification MUST appear in `keys` with its source and its
/// binding." The obligation is conditional on use, so an entry the verifier cannot resolve and
/// no cosignature reaches for is not a gap in anything the receipt asserts — reporting one
/// would make a receipt `unverifiable` over a key nothing in it depends on.
#[test]
fn an_unused_untrusted_witness_entry_is_not_a_gap() {
    let policy = trust_policy();
    let impostor = TestKey::from_seed_hex("impostor", &"ee".repeat(32)).expect("32-byte seed");
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    // Local policy holds no trusted witness key at all, so this entry cannot be resolved. Every
    // carried cosignature keeps naming the manifest-chain key it always named.
    receipt["keys"]["witness"].as_array_mut().expect("witness keys").push(json!({
        "witness_id": "witness-1",
        "key_id": impostor.key_id(),
        "pubkey": impostor.pubkey(),
        "source": "local-policy",
    }));

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert_eq!(
        report.finding(Assertion::Witnesses).map(|finding| finding.outcome),
        Some(Outcome::Verified),
        "an entry no cosignature names is not a witness gap"
    );
    assert!(verify_receipt(&receipt, &policy).is_ok());
}

/// A gap on the PRIMARY checkpoint's cosignatures does not suppress the later checkpoint.
///
/// I-D §7.6 states `continued_history` as its own rule — "`later_checkpoint`,
/// `later_witnesses`, and `consistency_path` are present and verify" — over a different
/// checkpoint, with its own log signature and its own cosignatures. A verifier that stopped at
/// the primary checkpoint's untrusted witness key would hide a defective later checkpoint
/// behind an unrelated capability gap.
#[test]
fn a_primary_witness_gap_does_not_suppress_the_later_checkpoint() {
    let policy = trust_policy();
    let impostor = TestKey::from_seed_hex("impostor", &"ee".repeat(32)).expect("32-byte seed");
    // Local policy holds no trusted witness key, so the primary cosignature — and only it — is
    // under a key this verifier cannot resolve. `later_witnesses` keeps the manifest-chain key.
    let gapped = || {
        let (_, mut receipt) = read_receipt("statement-anchored-continued-history.ahl");
        let entry = json!({
            "witness_id": "witness-1",
            "key_id": impostor.key_id(),
            "pubkey": impostor.pubkey(),
            "source": "local-policy",
        });
        receipt["keys"]["witness"].as_array_mut().expect("witness keys").push(entry);
        receipt["anchoring"]["witnesses"] = json!([{
            "witness_id": "witness-1",
            "key_id": impostor.key_id(),
            "cosignature": impostor
                .sign(&cosignature_bytes(&receipt["anchoring"]["checkpoint"], "witness-1")),
            "cosigned_at": "2026-08-16T12:00:00Z",
        }]);
        receipt
    };

    // The gap alone: `unverifiable` on the witnesses, and the later checkpoint still evaluated.
    let report = verify_receipt_report(&gapped(), &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert_eq!(
        report.finding(Assertion::Witnesses).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable)
    );
    assert_eq!(
        report.finding(Assertion::CheckpointAuthentication).map(|finding| finding.outcome),
        Some(Outcome::Verified),
        "the checkpoint signatures are under log keys and are unaffected"
    );

    // That the `continued_history` rule really was evaluated: falsifying the assurance member
    // while its material verifies is a §7.6 disagreement, and it fires.
    let mut overclaimed = gapped();
    overclaimed["claim"]["assurance"]["continued_history"] = json!(false);
    assert!(
        matches!(
            verify_receipt(&overclaimed, &policy),
            Err(ReceiptError::AssuranceMismatch { field: "continued_history" })
        ),
        "the continued-history rule is evaluated despite the primary-checkpoint gap"
    );

    // And a defective later checkpoint is `invalid`, not hidden behind the gap.
    let mut defective = gapped();
    let signature = defective["anchoring"]["later_checkpoint"]["signature"]
        .as_str()
        .expect("signature")
        .to_owned();
    defective["anchoring"]["later_checkpoint"]["signature"] =
        json!(format!("base64:{}", BASE64.encode([0u8; 64])));
    assert_ne!(defective["anchoring"]["later_checkpoint"]["signature"], json!(signature));
    let report = verify_receipt_report(&defective, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert!(
        matches!(
            verify_receipt(&defective, &policy),
            Err(ReceiptError::CheckpointSignatureInvalid)
        ),
        "a later checkpoint that does not verify is a defect of the artifact"
    );
}

/// A capability gap does not end the run, and reaches exactly the assertions that rest on it.
///
/// I-D §7.5 step 2: "If the verifier possesses NO profile under that id, it lacks a capability
/// and the result is `unverifiable`." What the profile document fixes is the checkpoint
/// serialization, so checkpoint authentication and the witness cosignatures over it rest on it
/// — and nothing else does. §7.5 step 3's paths are hash recomputations against the carried
/// `root_hash`, the governance induction reads carried statements, and the §7.6 rules and the
/// claim material are decidable from the receipt's own bytes. All of those are still checked,
/// which is what lets a defect elsewhere still dominate the gap (§7.7's reduction).
#[test]
fn a_capability_gap_reaches_only_the_assertions_that_rest_on_it() {
    let mut policy = trust_policy();
    policy.adaptor_profiles.clear();
    let (_, receipt) = read_receipt("record-ingested-valid.ahl");

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert_eq!(
        report.finding(Assertion::AdaptorProfile).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable)
    );
    // What rests on it, and says so.
    for assertion in [Assertion::CheckpointAuthentication, Assertion::Witnesses] {
        let finding = report.finding(assertion).unwrap_or_else(|| panic!("{assertion} finding"));
        assert_eq!(finding.outcome, Outcome::Unverifiable);
        assert!(
            finding.detail.as_ref().is_some_and(|detail| detail.contains("adaptor-profile")),
            "{assertion} must name the prerequisite it rests on: {finding:?}"
        );
    }
    // What does not, and was checked.
    for assertion in [
        Assertion::Versions,
        Assertion::Structure,
        Assertion::Anchoring,
        Assertion::Governance,
        Assertion::EnvelopeValidity,
        Assertion::ClaimMaterial,
        // Required here because this vector's own `assurance.content_binding` is not `none`.
        Assertion::ContentBinding,
    ] {
        assert_eq!(
            report.finding(assertion).map(|finding| finding.outcome),
            Some(Outcome::Verified),
            "{assertion} does not rest on the adaptor profile and must be checked"
        );
    }
    // §7.6 lists `witnessed` and `continued_history` among the cross-field rules, and with no
    // checkpoint authenticated neither was evaluated — so the cross-field finding says so
    // rather than reporting the rules that DID run as though they were all of them.
    let finding = report.finding(Assertion::CrossField).expect("cross-field finding");
    assert_eq!(finding.outcome, Outcome::Unverifiable);
    assert!(
        finding.detail.as_ref().is_some_and(|detail| detail.contains("checkpoint-authentication")),
        "the cross-field finding must name the rule it could not evaluate: {finding:?}"
    );

    // And a defect elsewhere still dominates the gap, which is the whole reason the run carries
    // on: `invalid` if any required finding is `invalid`, whichever was reached first.
    let (_, defective) = read_receipt("record-ingested-content-mismatch-must-fail.ahl");
    let report = verify_receipt_report(&defective, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert_eq!(
        report.finding(Assertion::AdaptorProfile).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable),
        "the gap is still reported beside the defect that dominates it"
    );
    assert_eq!(
        report.finding(Assertion::ContentBinding).map(|finding| finding.outcome),
        Some(Outcome::Invalid)
    );
}

/// An `invalid` finding decides the result where it is reached, so the assertions after it are
/// not reported at all rather than reported as unverifiable.
#[test]
fn an_invalid_result_reports_no_assertion_the_run_never_reached() {
    let (_, defective) =
        read_receipt("statement-anchored-continued-history-wrong-pair-must-fail.ahl");
    let report = verify_receipt_report(&defective, &trust_policy()).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert!(
        report.finding(Assertion::ClaimMaterial).is_none(),
        "an assertion the run never reached under an `invalid` result is not reported: {:#?}",
        report.findings
    );
}

/// The genesis anchor is the trust root (I-D §7.5.1 4a), and a receipt carrying another
/// corpus's anchor is `unverifiable` — receipt format §1 rule 1: "a configured anchor DIFFERING
/// from the carried one is also `unverifiable`... since the receipt may be a perfectly valid
/// receipt of another corpus".
///
/// The run carries on: whether each chain hop is signed under the key state its predecessors
/// establish is decidable from the receipt's own bytes, so what the anchor decides is only
/// whether that state is this verifier's log. Governance, envelope validity, checkpoint
/// authentication and the witnesses rest on it; the paths, the §7.6 rules and the content
/// binding do not.
#[test]
fn an_anchor_of_another_corpus_is_unverifiable_and_stops_nothing_else() {
    let mut policy = trust_policy();
    policy.genesis_entry_id = format!("sha256:{}", "0".repeat(64));
    let (_, receipt) = read_receipt("record-ingested-valid.ahl");

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert_eq!(
        report.finding(Assertion::Governance).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable)
    );
    for assertion in
        [Assertion::EnvelopeValidity, Assertion::CheckpointAuthentication, Assertion::Witnesses]
    {
        let finding = report.finding(assertion).unwrap_or_else(|| panic!("{assertion} finding"));
        assert_eq!(finding.outcome, Outcome::Unverifiable);
        assert!(
            finding.detail.as_ref().is_some_and(|detail| detail.contains("governance")),
            "{assertion} must name the prerequisite it rests on: {finding:?}"
        );
    }
    for assertion in [Assertion::Anchoring, Assertion::CrossField, Assertion::ContentBinding] {
        assert_eq!(
            report.finding(assertion).map(|finding| finding.outcome),
            Some(Outcome::Verified),
            "{assertion} does not rest on the configured anchor and must be checked"
        );
    }

    // The single-value form still reports the gap that decided the result.
    assert!(matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::GenesisAnchorMismatch)));

    // And a defect elsewhere dominates it: the receipt is refused for what its own bytes show,
    // with the anchor gap reported beside it rather than instead of it (I-D §7.7's reduction).
    let (_, defective) = read_receipt("record-ingested-content-mismatch-must-fail.ahl");
    let report = verify_receipt_report(&defective, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert_eq!(
        report.finding(Assertion::Governance).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable)
    );
    assert_eq!(
        report.finding(Assertion::ContentBinding).map(|finding| finding.outcome),
        Some(Outcome::Invalid)
    );
}

/// A witness key local policy does not hold settles the WITNESS assertion and nothing else
/// (I-D §7.1: `local-policy` is admissible "only for witness keys the verifier already
/// trusts"); the checkpoint signature is under a log key and is unaffected.
#[test]
fn an_untrusted_local_policy_witness_key_settles_only_the_witness_assertion() {
    let policy = trust_policy();
    let impostor = TestKey::from_seed_hex("impostor", &"ee".repeat(32)).expect("32-byte seed");
    // Local policy holds no trusted witness key at all, so a cosignature under a key sourced
    // `local-policy` is one this verifier cannot resolve — a gap in its own configuration.
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    receipt["keys"]["witness"] = json!([{
        "witness_id": "witness-1",
        "key_id": impostor.key_id(),
        "pubkey": impostor.pubkey(),
        "source": "local-policy",
    }]);
    receipt["anchoring"]["witnesses"] = json!([{
        "witness_id": "witness-1",
        "key_id": impostor.key_id(),
        "cosignature": impostor
            .sign(&cosignature_bytes(&receipt["anchoring"]["checkpoint"], "witness-1")),
        "cosigned_at": "2026-08-16T12:00:00Z",
    }]);

    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable);
    assert_eq!(
        report.finding(Assertion::Witnesses).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable)
    );
    for assertion in [
        Assertion::Governance,
        Assertion::CheckpointAuthentication,
        Assertion::EnvelopeValidity,
        Assertion::ClaimMaterial,
    ] {
        assert_eq!(
            report.finding(assertion).map(|finding| finding.outcome),
            Some(Outcome::Verified),
            "{assertion} does not rest on a witness key the verifier holds"
        );
    }
    // §7.6's `witnessed` rule is one of the cross-field rules, and it was not evaluated.
    let finding = report.finding(Assertion::CrossField).expect("cross-field finding");
    assert_eq!(finding.outcome, Outcome::Unverifiable);
    assert!(
        finding.detail.as_ref().is_some_and(|detail| detail.contains("witnesses")),
        "the cross-field finding must name the rule it could not evaluate: {finding:?}"
    );

    // With a byte-decidable defect on the same receipt, the defect decides the result and the
    // witness gap is reported beside it.
    let mut defective = receipt;
    defective["claim"]["assurance"]["governance"] = json!("enumerated");
    let report = verify_receipt_report(&defective, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert_eq!(
        report.finding(Assertion::CrossField).map(|finding| finding.outcome),
        Some(Outcome::Invalid)
    );
    assert_eq!(
        report.finding(Assertion::Witnesses).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable),
        "the gap is still reported: {:#?}",
        report.findings
    );
}

/// I-D §7.7's exception, and the two consequences it draws from it.
///
/// "for each embedded receipt, every required assertion of THAT receipt, determined by this
/// same rule, with one exception: an embedded receipt's CONTENT BINDING is never a required
/// assertion of the receipt that embeds it." And: "a `trigger-effective` receipt whose embedded
/// introduction receipt has a non-`verified` finding ONLY on its own content binding has result
/// `verified` where everything else holds: by the exception above, that finding is not among
/// the outer receipt's required assertions and never enters the outer reduction."
///
/// No corpus vector embeds a content-bound receipt — every embedded receipt in the corpus is
/// compact, asserting `content_binding: "none"` — so the case is built here from two corpus
/// vectors that share a subject: the `record-ingested` vector over entry 1, which carries the
/// keyed binding, spliced into the `introduction` slot of the `trigger-declared` vector, whose
/// own introduction is over that same entry and record.
#[test]
fn an_embedded_content_binding_never_enters_the_outer_reduction() {
    let policy = trust_policy();
    let (_, trigger) = read_receipt("trigger-declared-valid.ahl");
    let (_, bound) = read_receipt("record-ingested-valid.ahl");
    assert_eq!(
        bound["claim"]["record_subject"],
        trigger["claim_material"]["introduction"]["claim"]["record_subject"],
        "the splice is only sound while the two vectors are about one record"
    );
    assert_eq!(bound["claim"]["assurance"]["content_binding"], json!("keyed-authorized"));

    let mut spliced = trigger;
    spliced["claim_material"]["introduction"] = bound;

    // Held key: the embedded binding is verified, and reported, like any other finding.
    let report = verify_receipt_report(&spliced, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified);
    assert_eq!(
        report
            .finding_at(&["introduction"], Assertion::ContentBinding)
            .map(|finding| finding.outcome),
        Some(Outcome::Verified)
    );

    // No key held: the embedded binding is `unverifiable` and the outer result is `verified`,
    // because that finding is not one of the outer receipt's required assertions.
    let mut unauthorized = policy.clone();
    unauthorized.dataset_keys.clear();
    let report = verify_receipt_report(&spliced, &unauthorized).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified);
    let finding = report
        .finding_at(&["introduction"], Assertion::ContentBinding)
        .expect("the finding is still REPORTED, only excluded from the reduction");
    assert_eq!(finding.outcome, Outcome::Unverifiable);
    assert!(verify_receipt(&spliced, &unauthorized).is_ok());

    // A DEFECT in the embedded binding is the same: `invalid` decides a result only where the
    // finding is a required assertion of the receipt whose result it would decide.
    let mut defective = spliced;
    defective["claim_material"]["introduction"]["claim_material"]["record_bytes"] =
        json!(format!("base64:{}", BASE64.encode(br#"{"a":1}"#)));
    let report = verify_receipt_report(&defective, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified);
    assert_eq!(
        report
            .finding_at(&["introduction"], Assertion::ContentBinding)
            .map(|finding| finding.outcome),
        Some(Outcome::Invalid)
    );
    // The embedded receipt verified ON ITS OWN is `invalid`: the exception is about which
    // receipt's reduction the finding enters, never about whether the finding was reached.
    let (_, standalone) = read_receipt("record-ingested-valid.ahl");
    let mut standalone_defective = standalone;
    standalone_defective["claim_material"]["record_bytes"] =
        json!(format!("base64:{}", BASE64.encode(br#"{"a":1}"#)));
    let report = verify_receipt_report(&standalone_defective, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
}

/// I-D §7.3: a `keyed-authorized` binding "whose evidence is present and well formed but for
/// which the verifier holds no dataset key... MUST NOT be rendered as though it had been
/// established... that content binding is `unverifiable` (Section 7.7), and the receipt is not
/// thereby invalid."
#[test]
fn an_unauthorized_verifier_cannot_satisfy_a_keyed_content_binding() {
    let mut policy = trust_policy();
    policy.dataset_keys.clear();
    let (_, receipt) = read_receipt("record-ingested-valid.ahl");
    let error = verify_receipt(&receipt, &policy).expect_err("no dataset key is held");
    assert!(
        matches!(error, ReceiptError::DatasetKeyNotHeld { ref dataset } if dataset == "customers"),
        "keyed content binding is authorized-verifier-only; dataset keys are never packaged, \
         got: {error}"
    );
    assert_eq!(
        error.class(),
        Outcome::Unverifiable,
        "a dataset key the verifier is not authorized to hold is a capability gap (I-D §7.7)"
    );
    assert_eq!(error.assertion(), Assertion::ContentBinding);
}

/// I-D §7.8's two classes of limit, and the two different outcomes they produce.
///
/// The FIXED limits — nesting depth 4, 64 embedded receipts — "are properties of the artifact,
/// decided identically by every verifier in every year, so a receipt exceeding either is
/// `invalid`". The VERIFIER-LOCAL budgets are the opposite: "Exhaustion of either budget yields
/// `unverifiable`, never `invalid`", and the verifier "MUST report WHICH budget was exhausted
/// and the value that was in force". Both fail closed either way.
/// A receipt tree nested `levels` deep, built by putting a copy of the `trigger-declared`
/// vector into its own `introduction` slot.
///
/// The corpus cannot carry an over-deep receipt: every vector in it is a conforming artifact,
/// and one exceeding a FIXED limit is by definition not. The tree is therefore assembled here.
/// The innermost trigger keeps its own `record-ingested` introduction, so a tree of `levels`
/// nested triggers reaches nesting depth `levels + 1`.
fn nested_triggers(levels: usize) -> Value {
    let (_, base) = read_receipt("trigger-declared-valid.ahl");
    let mut receipt = base.clone();
    for _ in 0..levels {
        let mut outer = base.clone();
        outer["claim_material"]["introduction"] = receipt;
        receipt = outer;
    }
    receipt
}

/// I-D §7.8's FIXED limits: "These are properties of the artifact, decided identically by every
/// verifier in every year, so a receipt exceeding either is `invalid`: Maximum embedded-receipt
/// nesting depth: 4. Maximum embedded receipts per file: 64."
///
/// They are constants of the crate, not members of `Limits`: a verifier that could lower either
/// would report `invalid` over a receipt another verifier verifies, which I-D §7.7 forbids.
#[test]
fn the_fixed_nesting_depth_is_a_property_of_the_artifact() {
    let policy = trust_policy();
    assert_eq!(ahl_core::receipt::MAX_EMBEDDED_DEPTH, 4);
    assert_eq!(ahl_core::receipt::MAX_EMBEDDED_RECEIPTS, 64);

    // Depth 5, one past the limit.
    let error = verify_receipt(&nested_triggers(4), &policy).expect_err("the depth cap fires");
    assert!(
        matches!(error, ReceiptError::LimitExceeded("embedded-receipt nesting depth")),
        "an over-deep tree is invalid however the verifier is configured, got: {error}"
    );
    assert_eq!(error.class(), Outcome::Invalid);
    assert_eq!(
        error.assertion(),
        Assertion::Structure,
        "the fixed limits `bound a receipt's STRUCTURE and not its size` (I-D §7.8)"
    );
    let report = verify_receipt_report(&nested_triggers(4), &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);

    // Depth 4 is inside the limit, so the tree is refused for what it says rather than for how
    // deep it is — proving the cap fired at 5 rather than everywhere.
    let error = verify_receipt(&nested_triggers(3), &policy).expect_err("still not a valid tree");
    assert!(
        !matches!(error, ReceiptError::LimitExceeded(_)),
        "depth 4 is within the fixed limit, got: {error}"
    );

    // The nesting the corpus actually uses stays inside the normative limits.
    let (_, receipt) = read_receipt("disposition-effective-valid.ahl");
    let verdict = verify_receipt(&receipt, &policy).expect("valid receipt");
    assert!(verdict.embedded_receipts <= ahl_core::receipt::MAX_EMBEDDED_RECEIPTS);
}

#[test]
fn an_exhausted_local_budget_names_the_budget_and_the_value_in_force() {
    let (_, receipt) = read_receipt("disposition-effective-valid.ahl");

    for (limits, budget, value) in [
        (Limits { max_decoded_bytes: 1024, ..Limits::default() }, "decoded size in bytes", 1024),
        (Limits { max_work_units: 2, ..Limits::default() }, "verification work units", 2),
    ] {
        let policy = TrustPolicy { limits, ..trust_policy() };
        let error = verify_receipt(&receipt, &policy).expect_err("the budget must fire");
        assert!(
            matches!(
                error,
                ReceiptError::BudgetExhausted { budget: named, in_force }
                    if named == budget && in_force == value
            ),
            "{budget}: exhaustion must name the budget and the value in force (I-D §7.8), \
             got: {error}"
        );
        // The message a holder of the receipt reads carries both, which is what makes
        // `unverifiable` actionable rather than a bare refusal.
        let rendered = error.to_string();
        assert!(rendered.contains(budget), "the message must name the budget: {rendered}");
        assert!(
            rendered.contains(&value.to_string()),
            "the message must carry the value in force: {rendered}"
        );
    }
}

/// I-D §7.5 step 1 orders the version read ahead of the §7.8 limits, and the order is
/// observable exactly here: a receipt that breaks BOTH rules at once must report the version.
///
/// The two outcomes are not interchangeable. An unsupported version is a fixed property of the
/// artifact under §7.7 — every verifier reaches it, at any size — while the decoded-size budget
/// is verifier-local policy that a differently-configured verifier would not hit at all
/// (§7.8). Reporting the budget would tell the receipt's holder to produce a smaller receipt
/// that this build would refuse just the same.
#[test]
fn an_unsupported_version_is_reported_ahead_of_the_size_budget() {
    let (_, valid) = read_receipt("statement-anchored-valid.ahl");

    // Small enough that every receipt in the corpus exceeds it, so the budget really is live.
    let starved = TrustPolicy {
        limits: Limits { max_decoded_bytes: 1, ..Limits::default() },
        ..trust_policy()
    };
    assert!(
        matches!(verify_receipt(&valid, &starved), Err(ReceiptError::BudgetExhausted { .. })),
        "the size budget must fire for a receipt this verifier does support"
    );

    let mut foreign = valid;
    foreign["ahl_receipt_version"] = json!("1");
    assert!(
        matches!(
            verify_receipt(&foreign, &starved),
            Err(ReceiptError::UnsupportedVersion { field: "ahl_receipt_version", got, .. })
                if got == "1"
        ),
        "an oversized receipt of an unsupported version must report the version (I-D §7.5 \
         step 1)"
    );
}

/// The same §7.5 step-1 ordering, one level down: the version read of an EMBEDDED receipt
/// precedes the §7.8 nesting-depth limit that would otherwise stop the recursion at its door.
///
/// I-D §7.5 step 1: "Read `ahl_receipt_version` and act on it before any other check, including
/// schema validation... Then parse the receipt, enforce the resource limits of Section 7.8."
/// The depth cap is one of those limits, so a receipt tree that breaks both rules must report
/// the version: the two are different §7.7 values — an unsupported revision is `unverifiable`,
/// the fixed depth cap is `invalid` — and the step-1 order decides which of them a holder of
/// the receipt is told about.
#[test]
fn an_embedded_receipts_version_is_read_before_the_depth_limit() {
    let shallow = trust_policy();
    let valid = nested_triggers(4);

    // The cap really is live for this tree: its innermost receipt sits at depth 5.
    assert!(
        matches!(
            verify_receipt(&valid, &shallow),
            Err(ReceiptError::LimitExceeded("embedded-receipt nesting depth"))
        ),
        "the depth cap must fire for a tree this deep"
    );

    let mut foreign = valid;
    foreign["claim_material"]["introduction"]["claim_material"]["introduction"]["claim_material"]
        ["introduction"]["claim_material"]["introduction"]["claim_material"]["introduction"]
        ["ahl_receipt_version"] = json!("1");
    assert!(
        matches!(
            verify_receipt(&foreign, &shallow),
            Err(ReceiptError::UnsupportedVersion { field: "ahl_receipt_version", got, .. })
                if got == "1"
        ),
        "an over-deep receipt whose innermost embedded receipt carries an unsupported version \
         must report the version (I-D §7.5 step 1)"
    );
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
    // Both carriers of governance material are read as substitutions into the log: the chain
    // for manifest statements (I-D §7.1) and the enumeration for `key` statements (I-D §7.4).
    // Where an index appears in both, the chain hop governs and the enumerated entry is
    // rewritten from it below, so the two carriers never disagree about one entry.
    let carried: Vec<Value> = receipt["governance"]["currency"]["material"]["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .chain(receipt["governance"]["chain"].as_array().expect("chain"))
        .cloned()
        .collect();
    for hop in carried {
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
    // Enumerated currency is authenticated against the same root, so its range proof is
    // reissued over the rebuilt tree; without this every edited receipt would fail on the range
    // proof rather than on the rule under test.
    let material = &mut receipt["governance"]["currency"]["material"];
    if let Some(range) = material.get("range").cloned() {
        let from = range["from_index"].as_u64().expect("from_index");
        let to = range["to_index"].as_u64().expect("to_index");
        let hashes: Vec<_> = prefix.iter().map(|leaf| leaf_hash(leaf)).collect();
        let proof = range_proof::generate(&hashes, from, to).expect("range within the checkpoint");
        for entry in material["entries"].as_array_mut().expect("entries") {
            let index =
                usize::try_from(entry["entry_index"].as_u64().expect("entry_index")).expect("fits");
            entry["envelope"] = anchored[index].clone();
        }
        material["range_proof"] = json!({ "adaptor_form": range_proof::encode(&proof) });
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

/// I-D §7.1's transition exception: for a `governance.rotation_proofs[]` element "the
/// corresponding `keys.log[]` and `keys.witness[]` entries carry `manifest-chain` bindings
/// naming that predecessor version."
///
/// `local-policy` is not such a listing, however genuinely the verifier trusts the key. The
/// point of the proof is what the RETIRING authority attested, and that is established by the
/// outgoing manifest's own witness key object — not by this verifier's configuration, which
/// could otherwise supply the whole of a handover attestation on its own.
#[test]
fn a_rotation_proof_witness_must_be_listed_as_manifest_chain() {
    let witness_1 = test_key("witness-1");
    let (_, mut receipt) = read_receipt("governance-state-valid.ahl");
    for entry in receipt["keys"]["witness"].as_array_mut().expect("keys.witness array") {
        if field_str(entry, "witness_id").ok() == Some("witness-1") {
            entry["source"] = json!("local-policy");
            entry.as_object_mut().expect("key object").remove("binding");
        }
    }
    // Policy genuinely holds the key, under the very identity the outgoing manifest declares
    // it by: everything about the cosignature is real. What is missing is the listing the
    // transition exception requires.
    let mut policy = trust_policy();
    policy.trusted_witness_keys.insert(
        witness_1.key_id(),
        TrustedWitnessKey { pubkey: witness_1.pubkey(), witness_id: "witness-1".to_owned() },
    );
    assert!(
        matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::KeyNotBound { ref key_id, .. }) if key_id == &witness_1.key_id()
        ),
        "a rotation proof's outgoing witness must be listed as manifest-chain, bound to the \
         predecessor version — a trusted local-policy key is not that listing"
    );
}

/// I-D §2.1: a verifier rejects a family string whose prefix, alphabet, padding or encoding is
/// not the strict one, and §7.1 subjects every byte-carrying member to that rule.
///
/// The two cases here are the ones decoding-at-the-point-of-use cannot reach: a rotation-proof
/// cosignature the selection walk passes over, and a `keys.witness[]` entry no checkpoint
/// resolves. Both are carried material, and both are `invalid` however little verification
/// wanted them.
#[test]
fn every_carried_byte_field_is_a_family_string_even_where_unused() {
    assert_rejects(
        "governance-state-valid.ahl",
        // A second rotation-proof cosignature, by a witness the OUTGOING manifest does not
        // declare — so the selection walk skips it — carrying an ill-formed cosignature.
        |r| {
            let mut skipped = r["governance"]["rotation_proofs"][0]["witnesses"][0].clone();
            skipped["witness_id"] = json!("witness-2");
            skipped["cosignature"] = json!("base64:!");
            r["governance"]["rotation_proofs"][0]["witnesses"]
                .as_array_mut()
                .expect("witnesses array")
                .push(skipped);
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("cosignature")),
        "I-D §2.1 — a skipped cosignature is still a family string",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        // A `keys.witness[]` entry nothing resolves, whose `pubkey` decodes only if trailing
        // bits are discarded — which the strict rule forbids.
        |r| {
            let mut unused = r["keys"]["witness"][0].clone();
            unused["witness_id"] = json!("witness-2");
            unused["pubkey"] = json!("base64:AB==");
            r["keys"]["witness"].as_array_mut().expect("keys.witness array").push(unused);
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("pubkey")),
        "I-D §2.1 — an unused pubkey is still a family string",
    );
}

/// I-D §7.1, keys block: "a receipt-side entry carrying any member beyond those and
/// `source`/`binding` is a schema failure."
///
/// The member set is closed, and closing it is what keeps the match meaningful. The match
/// compares the members the receipt-side entry and the manifest key object SHARE; an entry
/// free to carry others could assert `valid_from_index` — or anything else — alongside the
/// compared members, where nothing compares it and a reader might believe it.
#[test]
fn a_key_object_carries_no_member_beyond_the_closed_set() {
    for (group, extra) in [
        // A selected log key, an unused witness entry, and a producer entry: the rule is a
        // property of the receipt, not of what verification happened to reach for.
        ("log", "valid_from_index"),
        ("witness", "trusted"),
        ("producer", "note"),
    ] {
        assert_rejects(
            "statement-anchored-valid.ahl",
            move |r| r["keys"][group][0][extra] = json!("anything at all"),
            move |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains(extra)),
            "I-D §7.1 — a key object carries no member beyond the closed set",
        );
    }
    // The unused-entry case in full: a second witness entry nothing resolves, carrying a
    // member no rule compares.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            let mut unused = r["keys"]["witness"][0].clone();
            unused["witness_id"] = json!("witness-2");
            unused["valid_from_index"] = json!(0);
            r["keys"]["witness"].as_array_mut().expect("keys.witness array").push(unused);
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("valid_from_index")),
        "I-D §7.1 — the closed set applies to entries verification never selects",
    );
}

/// I-D §7.3 gives every assurance member a closed domain, and §7.6 ties two of them to what
/// the claim type's own §7.2 material can carry: "`assurance.competing_triggers` is
/// `enumerated` only where the range required by Section 7.2 is present", and
/// "`assurance.content_binding` other than `none` occurs only with the content evidence the
/// claim type requires; a combination the type cannot satisfy is `invalid` rather than
/// downgraded."
///
/// Both are checked where the block is read, not where some path happens to consult them —
/// which is the whole point. A `statement-anchored` receipt's verification looks at neither
/// member, so before this it could assert either freely and be accepted.
#[test]
fn assurance_members_are_held_to_their_domain_and_to_the_claim_type() {
    for unknown in ["checked", "Enumerated", ""] {
        assert_rejects(
            "statement-anchored-valid.ahl",
            move |r| r["claim"]["assurance"]["competing_triggers"] = json!(unknown),
            |e| matches!(e, ReceiptError::AssuranceMismatch { field: "competing_triggers" }),
            "I-D §7.3 — competing_triggers is not-checked or enumerated",
        );
    }
    for unknown in ["verified", "None", ""] {
        assert_rejects(
            "statement-anchored-valid.ahl",
            move |r| r["claim"]["assurance"]["content_binding"] = json!(unknown),
            |e| matches!(e, ReceiptError::AssuranceMismatch { field: "content_binding" }),
            "I-D §7.3 — content_binding is none, plain-verified or keyed-authorized",
        );
    }
    // A non-STRING is a schema failure rather than an overstatement: there is no token to
    // compare against a domain.
    for member in ["governance", "competing_triggers", "content_binding"] {
        assert_rejects(
            "statement-anchored-valid.ahl",
            move |r| r["claim"]["assurance"][member] = json!(true),
            move |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains(member)),
            "I-D §7.3 — an assurance token is a string",
        );
    }

    // `enumerated` on a claim type that carries no competing range in any of its material.
    // Nothing in `statement-anchored` verification reads the member, so nothing else would
    // ever refuse this.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| r["claim"]["assurance"]["competing_triggers"] = json!("enumerated"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "competing_triggers" }),
        "I-D §7.6 — enumerated only where the §7.2 range is present",
    );
    // And `trigger-effective` may not drop it: §7.2 REQUIRES the value of that type.
    assert_rejects(
        "trigger-effective-valid.ahl",
        |r| r["claim"]["assurance"]["competing_triggers"] = json!("not-checked"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "competing_triggers" }),
        "I-D §7.2 — trigger-effective REQUIRES competing_triggers enumerated",
    );

    // A content binding on a claim type whose §7.2 material carries no record bytes at all.
    // The namespace member travels with it, so both are set — otherwise the §7.3 presence rule
    // fires and the claim-type rule is never reached.
    for (base, binding) in [
        ("statement-anchored-valid.ahl", "plain-verified"),
        ("trigger-declared-valid.ahl", "keyed-authorized"),
        ("governance-state-valid.ahl", "plain-verified"),
    ] {
        assert_rejects(
            base,
            move |r| {
                r["claim"]["assurance"]["content_binding"] = json!(binding);
                r["claim"]["assurance"]["canonicalization_namespace"] = json!("public");
            },
            |e| matches!(e, ReceiptError::AssuranceMismatch { field: "content_binding" }),
            "I-D §7.6 — a content binding only where the type carries content evidence",
        );
    }
}

/// I-D §7.3: `canonicalization_namespace` is "REQUIRED where `content_binding` is not `none`,
/// and absent otherwise. `private-use`, where the carried descriptor's `canonicalization`
/// identifier begins `x-`, so that the binding holds only for a verifier configured for this
/// corpus and never across corpora; or `public` otherwise." §7.6 states the same as a
/// cross-field rule.
///
/// The member is computable from the receipt alone, so every one of these is `invalid` rather
/// than a capability gap — including the `x-` case, which a verifier that decided the namespace
/// AFTER §6.3's capability outcome would report as unverifiable instead.
#[test]
fn the_canonicalization_namespace_tracks_the_carried_descriptor() {
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| {
            r["claim"]["assurance"]
                .as_object_mut()
                .expect("assurance object")
                .remove("canonicalization_namespace");
        },
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" }),
        "I-D §7.3 — REQUIRED where content_binding is not none",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        // `content_binding` is `none` here, so the member must be absent.
        |r| r["claim"]["assurance"]["canonicalization_namespace"] = json!("public"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" }),
        "I-D §7.3 — absent where content_binding is none",
    );
    for unknown in [json!("registered"), json!("x-"), json!(true), json!("Public")] {
        let value = unknown.clone();
        assert_rejects(
            "record-ingested-valid.ahl",
            move |r| r["claim"]["assurance"]["canonicalization_namespace"] = value,
            |e| {
                matches!(e, ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" })
            },
            "I-D §7.3 — the namespace is exactly `public` or `private-use`",
        );
    }

    // `public` alongside an `x-` identifier. The rule is about the CARRIED descriptor and is
    // "computable from the receipt alone" (§7.3), so it is decided without consulting the
    // manifest — which is what lets it fire here rather than the descriptor-equality rule of
    // §6.3, and rather than the capability outcome an `x-` identifier always reaches.
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| r["claim_material"]["canonicalization"] = json!("x-corpus-local"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" }),
        "I-D §7.6 — private-use if and only if the identifier begins `x-`",
    );

    // And the converse: `private-use` where the identifier is registered. `jcs` is not an `x-`
    // identifier, so claiming the private-use namespace over it is equally a disagreement.
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| r["claim"]["assurance"]["canonicalization_namespace"] = json!("private-use"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" }),
        "I-D §7.6 — private-use only where the identifier begins `x-`",
    );
}

/// I-D §7.1: `binding` "is the object `{ \"entry_index\": <integer> }`", and "the member shapes
/// shown above are normative".
///
/// One member, and it is an entry index — so a float, a negative, a string, or a companion
/// member alongside it is a schema failure, on every entry the receipt carries.
#[test]
fn a_binding_is_exactly_one_entry_index() {
    for (case, binding) in [
        ("an extra member", json!({ "entry_index": 0, "ignored": true })),
        ("a fractional entry index", json!({ "entry_index": 1.5 })),
        ("a negative entry index", json!({ "entry_index": -1 })),
        ("a stringly entry index", json!({ "entry_index": "0" })),
        ("no entry index at all", json!({})),
        ("not an object", json!(0)),
    ] {
        let value = binding.clone();
        assert_rejects(
            "statement-anchored-valid.ahl",
            // The SELECTED log key: this is the binding the checkpoint's own signing key is
            // resolved through, so nothing about it is incidental.
            move |r| r["keys"]["log"][0]["binding"] = value,
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("binding")),
            case,
        );
    }
}

/// I-D §7.1: "The member shapes shown above are normative." The container marks its own
/// extension points — an elided body (`{ ... }`) or a trailing `...` — and draws every other
/// object complete.
///
/// So the complete ones are closed, and the elided ones are not. Both halves are the rule: a
/// verifier that closed `claim_material` would reject claim types §7.2 defines and this build
/// does not implement, and one that left `anchoring` open would accept a member no rule reads
/// beside the ones every rule does.
#[test]
fn the_container_objects_drawn_complete_are_closed() {
    for (case, path) in [
        ("the receipt itself", vec!["extra"]),
        ("claim", vec!["claim", "extra"]),
        ("claim.record_subject", vec!["claim", "record_subject", "extra"]),
        ("subject", vec!["subject", "extra"]),
        ("keys", vec!["keys", "extra"]),
        ("anchoring", vec!["anchoring", "extra"]),
        ("anchoring.adaptor", vec!["anchoring", "adaptor", "extra"]),
        ("anchoring.checkpoint", vec!["anchoring", "checkpoint", "extra"]),
        ("a witness cosignature", vec!["anchoring", "witnesses", "0", "extra"]),
        ("governance", vec!["governance", "extra"]),
        ("governance.currency", vec!["governance", "currency", "extra"]),
        ("a chain element", vec!["governance", "chain", "0", "extra"]),
    ] {
        // `record_subject` is absent from `statement-anchored`, so that one case uses a receipt
        // whose claim type carries it.
        let base = if path.contains(&"record_subject") {
            "record-ingested-valid.ahl"
        } else {
            "statement-anchored-valid.ahl"
        };
        let path = path.clone();
        assert_rejects(
            base,
            move |r| {
                let mut cursor = r;
                for step in &path[..path.len() - 1] {
                    cursor = match step.parse::<usize>() {
                        Ok(index) => &mut cursor[index],
                        Err(_) => &mut cursor[*step],
                    };
                }
                cursor[path[path.len() - 1]] = json!("not a member of this object");
            },
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("extra")),
            case,
        );
    }

    // A rotation-proof element, on the one receipt family that carries the member.
    assert_rejects(
        "governance-state-valid.ahl",
        |r| r["governance"]["rotation_proofs"][0]["extra"] = json!(true),
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("extra")),
        "a rotation-proof element",
    );

    // The two envelopes need their identifiers repaired first, and that is the whole point of
    // checking their shape: an envelope with an extra member whose ids were computed OVER that
    // member satisfies §2.1's digest binding, so the member set is the only thing left to
    // refuse it.
    assert_rejects(
        "statement-anchored-valid.ahl",
        |r| {
            r["envelope"]["extra"] = json!("digest-bound, and still not a member");
            r["subject"]["statement_id"] =
                json!(statement_id(&r["envelope"]).expect("well-formed envelope"));
            r["subject"]["entry_id"] = json!(entry_id(&r["envelope"]));
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("extra")),
        "the subject envelope",
    );
    assert_rejects_anchored(
        "statement-anchored-valid.ahl",
        |r| {
            r["governance"]["chain"][0]["envelope"]["extra"] =
                json!("re-anchored, still not a member");
        },
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("extra")),
        "a chain element's envelope",
    );

    // And the elided bodies stay open, which is the other half of the rule. `assurance` is
    // `{ ... }` in the container — §7.3 defines its members, not §7.1 — so this verifier reads
    // the members §7.3 gives it and does not refuse a receipt over one §7.1 never fixed.
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    receipt["claim"]["assurance"]["future_field"] = json!("reserved for a later revision");
    verify_receipt(&receipt, &trust_policy())
        .expect("an elided body is not closed by §7.1's normative shapes");
}

/// I-D §7.1: "The member shapes shown above are normative", and the container gives an anchor
/// as `{ "type": ..., "target": ..., "target_hash": "sha256:<hex>", ... }`.
///
/// This verifier computes no verdict from `anchors[]` — §8.3 offers external timestamps as
/// evidence a deployment can compose with checkpoints, not as an input to any rule here — and
/// that is exactly why the shape has to be checked rather than assumed: nothing downstream
/// would ever notice. The trailing ellipsis leaves an anchor format's own members alone.
#[test]
fn a_carried_anchor_takes_the_shape_the_container_fixes() {
    let well_formed = json!({
        "type": "rfc3161",
        "target": "checkpoint_root",
        "target_hash": format!("sha256:{}", "11".repeat(32)),
    });
    for (case, anchors) in [
        ("a null element", json!([Value::Null])),
        ("an empty object", json!([{}])),
        ("no target_hash", json!([{ "type": "rfc3161", "target": "checkpoint_root" }])),
        (
            "a non-canonical target_hash",
            json!([{
                "type": "rfc3161",
                "target": "checkpoint_root",
                "target_hash": "sha256:00FF",
            }]),
        ),
        (
            "a non-string type",
            json!([{ "type": 1, "target": "checkpoint_root", "target_hash": format!("sha256:{}", "11".repeat(32)) }]),
        ),
        ("not an array", json!({ "type": "rfc3161" })),
    ] {
        let value = anchors.clone();
        assert_rejects(
            "statement-anchored-valid.ahl",
            move |r| r["anchors"] = value,
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("anchors")),
            case,
        );
    }

    // And an anchor that takes the shape verifies, carrying whatever else its own format needs
    // — the ellipsis is not a licence this verifier withdraws.
    let (_, mut receipt) = read_receipt("statement-anchored-valid.ahl");
    let mut carried = well_formed;
    carried["token"] = json!("base64:AAAA");
    receipt["anchors"] = json!([carried]);
    verify_receipt(&receipt, &trust_policy())
        .expect("a well-formed anchor is carried, not interpreted (I-D §7.1)");
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
            |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("binding")),
            "I-D §7.1 — binding is REQUIRED where source is manifest-chain",
        );
        // The member's SHAPE is normative wherever it appears, and that is the wider rule:
        // required for one source, but `{"entry_index": <integer>}` for both.
        for wrong in [json!({}), json!({ "entry_index": "0" }), json!(0), json!([0])] {
            let value = wrong.clone();
            assert_rejects(
                "statement-anchored-valid.ahl",
                move |r| r["keys"][group][0]["binding"] = value,
                |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("binding")),
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
        |e| matches!(e, ReceiptError::Malformed(ref detail) if detail.contains("binding")),
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
            r["governance"]["chain"][1]["envelope"]["payload"]
                .as_object_mut()
                .expect("manifest payload")
                .remove("predecessor");
            resign(&mut r["governance"]["chain"][1]["envelope"], &producer_key());
        },
        |e| matches!(e, ReceiptError::GovernanceChainInvalid(_)),
        "§2.3.5 — a non-genesis manifest references its predecessor",
    );
    assert_rejects_anchored(
        "governance-state-valid.ahl",
        |r| {
            corrupt(&mut r["governance"]["chain"][1]["envelope"]["payload"]["predecessor"]);
            resign(&mut r["governance"]["chain"][1]["envelope"], &producer_key());
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
    // The `key` statement's own 4b(K) rules are exercised through the ENUMERATION, which is
    // where I-D §7.4 puts producer-key transitions; entry 9 is the corpus's first one.
    assert_rejects_anchored(
        "governance-state-valid.ahl",
        |r| {
            let entry = &mut r["governance"]["currency"]["material"]["entries"][9];
            entry["envelope"]["payload"]["action"] = json!("revoke");
            resign(&mut entry["envelope"], &producer_key());
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
    // Manifest version 2's chain hop, anchored WITH a signature that does not verify: corrupting
    // a signature changes the envelope's bytes and therefore its entry id, so the hop has to be
    // re-anchored or the defect under test never gets past step 3 on its own.
    let (_, mut signature_only) = read_receipt("governance-state-valid.ahl");
    corrupt(&mut signature_only["governance"]["chain"][1]["envelope"]["signatures"][0]["sig"]);
    reanchor(&mut signature_only);

    // The signature defect alone: step 3 passes, and phase 1 of the induction reports it.
    assert!(
        matches!(
            verify_receipt(&signature_only, &trust_policy()),
            Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: 25 })
        ),
        "a chain hop whose signature does not verify is caught by the induction (4b phase 1)"
    );

    // A `raw` checkpoint form on the same receipt: reconciling it is step 2, and this build
    // wires no profile's `raw` parser, so its mere presence is the profile-limitation outcome
    // (I-D §7.5 step 2). That outcome is `unverifiable` and does not end the run, so the
    // induction is still walked and its signature defect still dominates it (§7.7's reduction):
    // both are reported, and the result is `invalid`.
    let mut with_raw = signature_only.clone();
    with_raw["anchoring"]["checkpoint"]["raw"] = json!("base64:AAAA");
    let report = verify_receipt_report(&with_raw, &trust_policy()).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid);
    assert_eq!(
        report.finding(Assertion::AdaptorProfile).map(|finding| finding.outcome),
        Some(Outcome::Unverifiable),
        "the step-2 gap is reported: {:#?}",
        report.findings
    );
    assert!(
        matches!(
            verify_receipt(&with_raw, &trust_policy()),
            Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: 25 })
        ),
        "the induction's defect dominates the step-2 capability gap"
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
        // Well formed as a family string, so the PRESENCE rule is what fires rather than the
        // §2.1 acceptance rule the shape pass applies to the member.
        |r| r["subject"]["manifest"] = json!(format!("sha256:{}", "00".repeat(32))),
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
        // I-D §7.1 draws `governance.currency.mode` as the enumerated token
        // `"declared | enumerated"`, and the mode now decides at step 3 whether enumeration
        // material is decoded at all, so an unknown token is a container-shape failure there —
        // ahead of the assurance block it has to equal.
        |e| matches!(e, ReceiptError::Malformed(detail) if detail.contains("governance mode")),
        "I-D §7.1 — governance.currency.mode is declared or enumerated",
    );
    assert_rejects(
        "statement-anchored-valid.ahl",
        // The same unknown token on the assurance side alone, where §7.3's closed domain is
        // what rejects it.
        |r| r["claim"]["assurance"]["governance"] = json!("assumed"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "governance" }),
        "I-D §7.3 — assurance.governance is declared or enumerated",
    );
    assert_rejects(
        "trigger-declared-valid.ahl",
        |r| r["claim"]["assurance"]["competing_triggers"] = json!("enumerated"),
        |e| matches!(e, ReceiptError::AssuranceMismatch { field: "competing_triggers" }),
        "§2.3 — competing_triggers enumerated only with the §3 range",
    );
    assert_rejects(
        "record-ingested-valid.ahl",
        |r| {
            r["claim"]["assurance"]["content_binding"] = json!("none");
            // Dropping the namespace member with it, since I-D §7.3 makes the two travel
            // together — otherwise THAT rule fires and the content-evidence one is never
            // reached.
            r["claim"]["assurance"]
                .as_object_mut()
                .expect("assurance object")
                .remove("canonicalization_namespace");
        },
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
    // I-D §7.3: the member is REQUIRED wherever a content binding is asserted, and `jcs` is a
    // registered identifier — without it the receipt fails on the assurance rule instead of
    // reaching the commitment comparison this test is about.
    invalid["claim"]["assurance"]["canonicalization_namespace"] = json!("public");
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
    // The defect is READ, at its own path: the second receipt was verified in full rather than
    // served from the first one's cache entry. It does not end the run — I-D §7.7 keeps an
    // embedded receipt's content binding out of the embedding receipt's required assertions —
    // and the finding is what shows the material was examined at all.
    let report = verify_receipt_report(&attack, &policy).expect("the run completes");
    let finding = report
        .finding_at(&["replacement_introduction"], Assertion::ContentBinding)
        .expect("the invalid receipt must be verified in full, not waved through as a duplicate");
    assert_eq!(finding.outcome, Outcome::Invalid);
    assert!(
        finding.detail.as_ref().is_some_and(|detail| detail.contains("content binding")),
        "the finding must name the rule that fired: {finding:?}"
    );

    // And the honest receipt in that slot reaches the §2.3 record rule with no content-binding
    // finding at all — proving the finding above came from the invalid material rather than
    // from the slot itself. Both fail on that rule, which is about the slot.
    let mut control = attack.clone();
    control["claim_material"]["replacement_introduction"] = honest;
    let report = verify_receipt_report(&control, &policy).expect("the run completes");
    assert!(report.finding_at(&["replacement_introduction"], Assertion::ContentBinding).is_none());
    for receipt in [&control, &attack] {
        assert!(matches!(
            verify_receipt(receipt, &policy),
            Err(ReceiptError::EmbeddedSubjectMismatch { what: "replacement introduction", .. })
        ));
    }
}

/// The committed-tree material the three `record-derived-input-set-*-must-fail.ahl` vectors
/// carry, reassembled from the vectors themselves.
///
/// There is no third source of truth for it. Entry 37's batch is the corpus's non-conforming
/// tree material, and it is deliberately absent from `vectors/merkle/`, where a reader would
/// take it for conforming material; the receipt vectors are where it lives, each carrying one
/// output leaf and the COMPLETE input set that leaf commits. Reassembling it here is what makes
/// the closure regression below a statement about the same bytes the receipt vectors are
/// rejected over, rather than about a copy that could drift from them.
fn defective_tree_material() -> TreeMaterial {
    let mut trees = tree_material();
    let batch = &statement_vectors()[50]["envelope"]["payload"];
    let mut outputs: Vec<(u64, Value)> = Vec::new();
    for name in [
        "record-derived-input-set-unsorted-must-fail.ahl",
        "record-derived-input-set-duplicate-record-must-fail.ahl",
        "record-derived-input-set-non-canonical-record-must-fail.ahl",
    ] {
        let (_, receipt) = read_receipt(name);
        let material = &receipt["claim_material"];
        let leaf = material["batch_leaf"].clone();
        let root = field_str(&leaf["inputs"], "input_set_root").expect("input_set_root").to_owned();
        let mut members: Vec<(u64, Value)> = material["input_members"]
            .as_array()
            .expect("input_members")
            .iter()
            .map(|member| {
                (member["input_index"].as_u64().expect("input_index"), member["input"].clone())
            })
            .collect();
        members.sort_by_key(|(index, _)| *index);
        trees.insert(root, members.into_iter().map(|(_, input)| input).collect());
        outputs.push((material["leaf_index"].as_u64().expect("leaf_index"), leaf));
    }
    outputs.sort_by_key(|(index, _)| *index);
    trees.insert(
        field_str(batch, "outputs_root").expect("outputs_root").to_owned(),
        outputs.into_iter().map(|(_, leaf)| leaf).collect(),
    );
    trees
}

/// I-D §2.7: "Tree rules, identical for every AHL tree — outputs, input sets, and
/// dispositions." Closure traversal is one of the two consumers of committed tree material, and
/// it must reject a non-conforming tree exactly as receipt verification does.
///
/// `CONFORMING_TREE_PREFIX` caps every other closure walk in this suite at entry 50, so without
/// this test nothing shows what happens at the entry the cap exists for — the rejection would
/// be asserted only about receipts. Here the walk is deliberately run one entry further, over
/// the SAME committed material the receipt vectors carry: entry 50's outputs tree is well
/// formed and opens correctly, and the first input-set tree the traversal then opens carries a
/// `record` that is not a family string, so the traversal stops on the tree rule rather than
/// reading an edge out of material it has not validated.
#[test]
fn closure_traversal_rejects_a_non_conforming_committed_tree() {
    let envelopes = envelopes(&statement_vectors());
    let trees = defective_tree_material();

    edges(&envelopes, &trees, CONFORMING_TREE_PREFIX)
        .expect("the conforming prefix must traverse cleanly, or the cap is in the wrong place");

    let error = edges(&envelopes, &trees, CONFORMING_TREE_PREFIX + 1)
        .expect_err("a traversal reaching entry 50 must be refused by the §2.7 tree rules");
    assert!(
        matches!(&error, AhlError::InvalidCommitment(record) if record == "not-a-commitment"),
        "the tree rule that fires must be the one the material breaks, got: {error}"
    );

    // The other two defects are reached by opening their own trees directly, since a traversal
    // stops at the first one. Both are the strict-ascending rule, which is simultaneously the
    // sort rule and the no-duplicate rule of §2.7.
    for name in [
        "record-derived-input-set-unsorted-must-fail.ahl",
        "record-derived-input-set-duplicate-record-must-fail.ahl",
    ] {
        let (_, receipt) = read_receipt(name);
        let inputs = &receipt["claim_material"]["batch_leaf"]["inputs"];
        let root = field_str(inputs, "input_set_root").expect("input_set_root");
        let count = inputs["input_set_count"].as_u64().expect("input_set_count");
        let error = ValidatedLeafSet::open(root, count, trees[root].clone())
            .expect_err("a tree breaking the §2.7 ordering rule must not open");
        assert!(
            matches!(&error, AhlError::TreeUnsorted { root: named, .. } if named == root),
            "{name}: expected the §2.7 ordering rule for {root}, got: {error}"
        );
    }
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
    let later = affected_set(&envelopes, &trees, 6, CONFORMING_TREE_PREFIX).expect("corpus");

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
    // illustrates. Entries 29, 30 and 31 also name F — the genuinely co-signed trigger and the
    // two non-verifying fixtures — and are deliberately out of scope here: a `key_id`-only
    // "authority" filter, as used below, cannot tell a non-verifying signature apart from a
    // genuine one, which is exactly why the verifier checks each candidate's signature
    // cryptographically rather than reusing this shortcut.
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

/// I-D §7.5 step 1, as the erratum leaves it: an entry an enumeration alone carries has its
/// version read "only after its own-index signature check has passed (Section 7.5.1 4b and 4d):
/// one that does not verify is void with no version or type validation at all, so that no
/// non-verifying enumeration-only entry can make a run `unverifiable` merely by declaring a
/// version."
///
/// Mutating a carried entry's payload therefore no longer reaches the version read at all: the
/// entry is no longer the one the log committed at that index, and the range proof says so
/// first. That ordering is the point — the version of an entry nothing has authenticated is not
/// a fact about the receipt.
#[test]
fn an_enumerated_entrys_version_is_read_only_behind_its_own_range_proof() {
    assert_rejects(
        "governance-state-valid.ahl",
        |r| {
            r["governance"]["currency"]["material"]["entries"][0]["envelope"]["payload"]
                ["ahl_version"] = json!("0.3");
        },
        |e| matches!(e, ReceiptError::RangeProofInvalid { what: "governance", .. }),
        "§7.5 step 1 — an enumeration-only entry's version is read behind its own-index checks",
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

/// I-D §2.1, end to end: one manifest version anchored three times.
///
/// "A producer MUST NOT anchor two envelopes bearing the same statement id. If duplicates
/// nevertheless occur, the envelope with the smallest entry index governs and later ones are
/// void." The statement id digests the PAYLOAD and the entry id the ENVELOPE, so one payload
/// under three signature sets really is one statement over three anchored entries — reachable
/// by a producer, and reachable by this corpus, which is what separates this from a unit test
/// over a synthesized chain.
#[test]
fn one_manifest_version_anchored_three_times_is_governed_by_its_smallest_index() {
    let statements = statement_vectors();
    let ids: Vec<&str> = [46usize, 47, 48]
        .iter()
        .map(|index| field_str(&statements[*index], "statement_id").expect("statement_id"))
        .collect();
    assert_eq!(ids[0], ids[1], "one payload, one statement id");
    assert_eq!(ids[0], ids[2], "one payload, one statement id");
    let entry_ids: BTreeSet<&str> = [46usize, 47, 48]
        .iter()
        .map(|index| field_str(&statements[*index], "entry_id").expect("entry_id"))
        .collect();
    assert_eq!(entry_ids.len(), 3, "three envelopes, three entry ids");

    // Two of the three verify; the third is the fixture the negative vector hangs off.
    let keys = key_set(&statements);
    for (index, verifies) in [(46usize, true), (47, true), (48, false)] {
        assert_eq!(
            verify_envelope(&statements[index]["envelope"], |key_id| keys.get(key_id).cloned())
                .expect("well-formed envelope"),
            verifies,
            "entry {index}"
        );
    }

    let policy = trust_policy();

    // The governing copy plus the VERIFYING duplicate: `verified`, and — the question the
    // duplicate exists to answer — with NO informative item. An informative item reports a void
    // entry the run inspected and found wanting; a void duplicate that verifies is neither.
    let (_, carried) = read_receipt("statement-anchored-duplicate-manifest.ahl");
    let report = verify_receipt_report(&carried, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert!(
        report.informative.is_empty(),
        "a void duplicate that verifies is not an informative item: {:#?}",
        report.informative
    );
    assert_eq!(
        report.finding(Assertion::EnvelopeValidity).map(|finding| finding.outcome),
        Some(Outcome::Verified)
    );

    // The governing copy plus the NON-VERIFYING duplicate: `invalid` at the duplicate's own
    // index, on envelope validity, however good the copy that governs is.
    let (_, unsigned) =
        read_receipt("statement-anchored-duplicate-manifest-unsigned-must-fail.ahl");
    let report = verify_receipt_report(&unsigned, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
    assert_eq!(
        report.dominating().map(|finding| finding.assertion),
        Some(Assertion::EnvelopeValidity),
        "{:#?}",
        report.findings
    );
    assert!(matches!(
        verify_receipt(&unsigned, &policy),
        Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: 48 })
    ));

    // Enumerated currency reaches all three. 4c counts what the chain CARRIES, so both
    // verifying copies must be present; the non-verifying one is not an omission and is
    // reported as an informative item instead.
    let (_, enumerated) = read_receipt("governance-state-duplicate-manifest.ahl");
    let report = verify_receipt_report(&enumerated, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    let void: BTreeSet<u64> = report.informative.iter().map(|item| item.entry_index).collect();
    assert!(void.contains(&48), "the third envelope is void: {void:?}");
    assert!(!void.contains(&47), "the second envelope verifies: {void:?}");

    // Dropping the verifying duplicate from the chain is an omission under 4c: the range
    // reveals a manifest the chain does not show.
    let mut short = enumerated;
    short["governance"]["chain"]
        .as_array_mut()
        .expect("chain")
        .retain(|hop| hop["entry_index"].as_u64() != Some(47));
    let report = verify_receipt_report(&short, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
    assert_eq!(
        report.dominating().map(|finding| finding.assertion),
        Some(Assertion::Governance),
        "{:#?}",
        report.findings
    );
}

/// I-D §7.5.1 4d and §2.1, end to end over a propagation prefix.
///
/// 4d names "an entry of a propagation prefix" among the carried envelopes reliance excludes,
/// and §2.1 says a void entry is "never traversed by closure". Both vectors below prove the
/// SAME completeness claim for the SAME trigger; their prefixes differ by exactly which
/// envelope over one payload they reach.
#[test]
fn a_void_prefix_entry_is_excluded_from_the_anchored_affected_set() {
    let policy = trust_policy();
    let statements = statement_vectors();
    let keys = key_set(&statements);

    // Entries 37 and 43 are one statement over two envelopes: the first does not verify.
    assert_eq!(
        field_str(&statements[37], "statement_id").expect("statement_id"),
        field_str(&statements[43], "statement_id").expect("statement_id"),
        "the control must be the SAME derivation, not a similar one"
    );
    for (index, verifies) in [(37usize, false), (43, true)] {
        assert_eq!(
            verify_envelope(&statements[index]["envelope"], |key_id| keys.get(key_id).cloned())
                .expect("well-formed envelope"),
            verifies,
            "entry {index}"
        );
    }

    let (_, verified) = read_receipt("propagation-complete-void-prefix-entry.ahl");
    let report = verify_receipt_report(&verified, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    let void: BTreeSet<u64> = report.informative.iter().map(|item| item.entry_index).collect();
    assert!(void.contains(&37), "the prefix entry is reported as a void entry: {void:?}");

    // The disposition tree the propagation anchored has exactly one member, which is what the
    // closure over a prefix that does not traverse entry 37 recomputes.
    let anchored = &statements[44]["envelope"]["payload"];
    assert_eq!(anchored["affected_count"].as_u64(), Some(1));

    // The control: the same anchored set, over a prefix that reaches the VERIFYING copy.
    let (_, control) = read_receipt("propagation-complete-void-prefix-entry-control-must-fail.ahl");
    assert_eq!(
        statements[45]["envelope"]["payload"]["affected_root"], anchored["affected_root"],
        "the control anchors the same affected set, so only the prefix differs"
    );
    let report = verify_receipt_report(&control, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
    assert_eq!(
        report.dominating().map(|finding| finding.assertion),
        Some(Assertion::ClaimMaterial),
        "{:#?}",
        report.findings
    );
    assert!(matches!(
        verify_receipt(&control, &policy),
        Err(ReceiptError::ClosureMismatch(detail)) if detail.contains("recomputed 2")
    ));
}

/// I-D §7.1 and §7.5.1 4b(M)/4f over a rotation of the LOG checkpoint-signing key.
///
/// Manifest v4 (entry 55) replaces `log-1` with `log-2` and changes nothing else, so the corpus
/// carries one witness-set rotation and one log-key rotation and a chain over both needs two
/// `rotation_proofs[]` elements. What the log rotation adds over the witness one is the pair of
/// rules only a second log key can exercise: a proof under the INCOMING key, and a checkpoint
/// past the rotation still signed by the OUTGOING one.
#[test]
fn a_log_key_rotation_is_proven_under_the_outgoing_key_state() {
    let policy = trust_policy();
    let statements = statement_vectors();

    // The rotation is on the log side alone: the witness objects and the producer snapshot are
    // version 3's, unchanged.
    let v3 = &statements[46]["envelope"]["payload"];
    let v4 = &statements[55]["envelope"]["payload"];
    assert_ne!(v3["log"]["keys"], v4["log"]["keys"], "the log key set rotates");
    assert_eq!(v3["witnesses"], v4["witnesses"], "the witness set does not");
    assert_eq!(v3["keys"], v4["keys"], "the producer snapshot does not");

    let (_, valid) = read_receipt("statement-anchored-log-key-rotation.ahl");
    let report = verify_receipt_report(&valid, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);

    // Two rotations in the chain, two elements, ascending.
    let proofs = valid["governance"]["rotation_proofs"].as_array().expect("rotation_proofs");
    let indexes: Vec<u64> =
        proofs.iter().map(|p| p["manifest_entry_index"].as_u64().expect("index")).collect();
    assert_eq!(indexes, vec![25, 55]);

    // The log rotation's proof checkpoint is signed by the OUTGOING key, and the receipt's own
    // checkpoint by the INCOMING one — 4f resolving each from the version active for its own
    // tree size.
    let outgoing_key_id = field_str(&v3["log"]["keys"][0], "key_id").expect("outgoing log key");
    let incoming_key_id = field_str(&v4["log"]["keys"][0], "key_id").expect("incoming log key");
    assert_ne!(outgoing_key_id, incoming_key_id);
    assert_eq!(
        field_str(&proofs[1]["checkpoint"], "key_id").expect("checkpoint key_id"),
        outgoing_key_id
    );
    assert_eq!(
        field_str(&valid["anchoring"]["checkpoint"], "key_id").expect("checkpoint key_id"),
        incoming_key_id
    );

    for (name, assertion) in [
        ("governance-key-rotation-proof-incoming-log-key-must-fail.ahl", Assertion::Governance),
        ("governance-key-rotation-proofs-out-of-order-must-fail.ahl", Assertion::Governance),
        ("governance-key-rotation-proof-incoming-witness-must-fail.ahl", Assertion::Governance),
        (
            "statement-anchored-outgoing-log-key-after-rotation-must-fail.ahl",
            Assertion::CheckpointAuthentication,
        ),
    ] {
        let (_, receipt) = read_receipt(name);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Invalid, "{name}: {:#?}", report.findings);
        assert_eq!(
            report.dominating().map(|finding| finding.assertion),
            Some(assertion),
            "{name}: {:#?}",
            report.findings
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
            Err(ReceiptError::BudgetExhausted { budget: "verification work units", .. }) => {}
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

// ---------------------------------------------------------------------------
// The ATL-bound corpus (adaptor profile `ahl-adaptor-atl-v1`)
// ---------------------------------------------------------------------------

fn atl_dir() -> PathBuf {
    test_data().join("receipts").join("atl")
}

fn atl_index() -> Value {
    read_json(&atl_dir().join("index.json"))
}

/// The ATL corpus's own trust policy, read from its own index.
///
/// It is a SECOND policy because a trust policy names one published genesis anchor (I-D §7.5.1
/// 4a) and this is a second log. As with the main one, the adaptor document is read from disk
/// and its digest recomputed, never taken from the index's recorded hash string.
fn atl_trust_policy() -> TrustPolicy {
    let index = atl_index();
    let policy = &index["policy"];
    TrustPolicy {
        genesis_entry_id: field_str(policy, "genesis_entry_id").expect("genesis anchor").to_owned(),
        genesis_key_ids: Some(strings(&policy["genesis_key_ids"]).into_iter().collect()),
        adaptor_profiles: policy["adaptor_profiles"]
            .as_object()
            .expect("adaptor profiles")
            .iter()
            .map(|(id, profile)| {
                let capabilities = &profile["capabilities"];
                // The ATL index names the artifact it holds, because what it holds is a STAND-IN
                // rather than a document named after the profile id — the profile is unreleased
                // and §14 forbids pinning it. As with the main policy the bytes are read from
                // disk and the digest recomputed, never taken from the recorded hash string.
                let held = field_str(profile, "document").expect("the artifact policy holds");
                let document = std::fs::read(test_data().join(held))
                    .unwrap_or_else(|e| panic!("read held artifact for `{id}`: {e}"));
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
        dataset_keys: BTreeMap::new(),
        trusted_witness_keys: BTreeMap::new(),
        limits: Limits::default(),
    }
}

fn read_atl_receipt(name: &str) -> (Vec<u8>, Value) {
    let path = atl_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let value: Value = serde_json::from_slice(&bytes).expect("receipt parses");
    (bytes, value)
}

/// Every ATL vector reaches the result its own index records.
#[test]
fn every_atl_vector_reaches_its_recorded_result() {
    let policy = atl_trust_policy();
    let mut listed = BTreeSet::new();
    for entry in atl_index()["vectors"].as_array().expect("vectors") {
        let name = field_str(entry, "file").expect("file");
        listed.insert(name.to_owned());
        let (bytes, receipt) = read_atl_receipt(name);
        assert_eq!(bytes, jcs(&receipt), "{name}: file is not its own JCS serialization");
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(
            report.result.name(),
            field_str(entry, "expect").expect("expect"),
            "{name}: {:#?}",
            report.findings
        );
        if let Some(finding) = entry.get("finding").and_then(Value::as_str) {
            let dominating = report.dominating().expect("a non-verified result has a cause");
            assert_eq!(dominating.assertion.name(), finding, "{name}");
        }
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(atl_dir())
        .expect("ATL receipts directory")
        .map(|e| e.expect("directory entry").file_name().to_string_lossy().into_owned())
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "ahl"))
        .collect();
    assert_eq!(listed, on_disk, "the ATL index and its directory must agree");
}

/// Adaptor `ahl-adaptor-atl-v1` §4.2, §6, §7.1 in the verifier, over a real second log.
///
/// The profile differs from `ahl-test-log-v1` in exactly three serializations — the log leaf,
/// the checkpoint signing bytes, and the `raw` framing — and this asserts each is dispatched
/// rather than assumed.
#[test]
fn the_atl_shaped_profile_is_dispatched_end_to_end() {
    let policy = atl_trust_policy();
    let (_, receipt) = read_atl_receipt("statement-anchored-atl-leaf.ahl");
    let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert_eq!(
        field_str(&receipt["anchoring"]["adaptor"], "id").expect("adaptor id"),
        "ahl-test-atl-leaf-v1"
    );

    let tree = read_json(&test_data().join("vectors").join("atl").join("log-tree.json"));
    let checkpoint = &receipt["anchoring"]["checkpoint"];
    let committed = usize::try_from(checkpoint["tree_size"].as_u64().expect("tree_size"))
        .expect("small tree size");

    // §4.2: the log leaf is NOT the anchored entry bytes, and the ATL geometry's root is the one
    // the checkpoint commits. A verifier applying the other profile's leaf rule would recompute
    // a different root for the same entries, which is what the metadata negative turns on.
    let entries = tree["entries"].as_array().expect("entries");
    let atl_leaves: Vec<Vec<u8>> = entries
        .iter()
        .take(committed)
        .map(|entry| {
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(
                &parse_hash_hex(field_str(entry, "entry_id").expect("entry_id")).expect("entry id"),
            );
            preimage.extend_from_slice(
                &parse_hash_hex(field_str(&tree, "metadata_hash").expect("metadata_hash"))
                    .expect("metadata hash"),
            );
            preimage
        })
        .collect();
    assert_eq!(
        hash_hex(&tree_root(&atl_leaves)),
        field_str(checkpoint, "root_hash").expect("root_hash"),
        "the checkpoint must commit the ATL-geometry root"
    );
    assert_eq!(
        field_str(&tree, "metadata_hash").expect("metadata_hash"),
        "sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4",
        "§3.1 pins the metadata digest as a constant of the profile"
    );

    // §6.1/§6.3/§6.5: the signature is over the 98-byte blob assembled from the JSON members,
    // and `checkpoint_time` renders the exact nanosecond value with nine fractional digits.
    let time = field_str(checkpoint, "checkpoint_time").expect("checkpoint_time");
    assert_eq!(time.len(), 30, "§6.3: exactly nine fractional digits and a `Z`");
    let blob = atl_checkpoint_blob_from_json(checkpoint).expect("well-formed checkpoint");
    let log_key = &receipt["keys"]["log"][0];
    assert!(
        verify_signature(
            &decode_pubkey(field_str(log_key, "pubkey").expect("pubkey")).expect("pubkey"),
            &blob,
            field_str(checkpoint, "signature").expect("signature"),
        )
        .expect("well-formed signature"),
        "the checkpoint signature is over the 98-byte blob, not over JCS(cp minus signature)"
    );
    assert_ne!(
        blob.as_slice(),
        checkpoint_signing_bytes(checkpoint).expect("checkpoint").as_slice(),
        "the two profiles' signing bytes must actually differ"
    );

    // §7.1: `log_id` is the Origin ID, and the blob binds those same 32 octets at offset 18.
    let log_id = field_str(checkpoint, "log_id").expect("log_id");
    assert_eq!(&blob[18..50], &parse_hash_hex(log_id).expect("log id")[..]);
    assert_eq!(
        log_id,
        sha256_hex(&hex::decode(field_str(&tree, "tree_uuid").expect("tree_uuid")).expect("uuid")),
        "§4: log_id = sha256: || hex(SHA-256(the 16-byte Data Tree UUID))"
    );

    // §6.4: `raw` is carried, and it reconciles with the JSON members.
    let raw = field_str(checkpoint, "raw").expect("§5.4 raw");
    reconcile_atl_checkpoint_raw(checkpoint, raw).expect("the carried raw must reconcile");

    // And the capability gap the profile's own release status makes real: a verifier that holds
    // NO document under this id lacks a capability, so the result is `unverifiable` (I-D §7.5
    // step 2) — never `invalid`, and never an acceptance. It is a fact about the verifier's
    // configuration rather than about the artifact, which is why it is tested here and not
    // carried as a vector.
    let mut unheld = policy;
    unheld.adaptor_profiles.clear();
    let report = verify_receipt_report(&receipt, &unheld).expect("the run completes");
    assert_eq!(report.result, Outcome::Unverifiable, "{:#?}", report.findings);
    let finding = report.finding(Assertion::AdaptorProfile).expect("adaptor-profile finding");
    assert_eq!(finding.outcome, Outcome::Unverifiable);
    assert_eq!(finding.rests_on, None, "the cause, not a derivation");
    assert!(matches!(
        verify_receipt(&receipt, &unheld),
        Err(ReceiptError::AdaptorUnknown { id }) if id == "ahl-test-atl-leaf-v1"
    ));

    // A policy that claims a capability the profile does define is not a misconfiguration:
    // `checkpoint_raw` is true here and this build parses it. The main corpus's profile defines
    // no framing at all, and a policy claiming one for THAT profile is still refused.
    let mut claimed = trust_policy();
    claimed
        .adaptor_profiles
        .get_mut("ahl-test-log-v1")
        .expect("the test profile")
        .capabilities
        .checkpoint_raw = true;
    let (_, main) = read_receipt("statement-anchored-valid.ahl");
    assert!(matches!(
        verify_receipt(&main, &claimed),
        Err(ReceiptError::AdaptorProfileMisconfigured { .. })
    ));
}

/// A profile's identity is its bytes, so the corpus publishes one of its own.
///
/// `ahl-adaptor-atl-v1` §14: "Any change to this document, however small, produces a different
/// hash and therefore a different profile. A changed profile MUST be published under a new id."
/// No document a corpus could ship is that artifact, so nothing a corpus ships may be published
/// under that id — a label saying "test only" changes nothing, and neither does the fact that a
/// policy holding it is local. What the corpus pins instead is `ahl-test-atl-leaf-v1`, a profile
/// with a document of its own that defines the same serialization as its own rules.
#[test]
fn the_atl_corpus_pins_its_own_profile_under_its_own_id() {
    let index = atl_index();
    let profiles = index["policy"]["adaptor_profiles"].as_object().expect("adaptor profiles");
    assert_eq!(
        profiles.keys().collect::<Vec<_>>(),
        vec!["ahl-test-atl-leaf-v1"],
        "the corpus policy holds exactly one profile, and it is not the ATL binding"
    );
    let held = field_str(&profiles["ahl-test-atl-leaf-v1"], "document").expect("held artifact");
    assert_eq!(held, "profiles/ahl-test-atl-leaf-v1.md");
    let document = std::fs::read(test_data().join(held)).expect("the document is committed");
    let pinned = sha256_hex(&document);

    // The document names the profile it defines, and states its relationship to the ATL binding
    // rather than claiming to be it.
    let text = String::from_utf8(document).expect("UTF-8");
    assert!(
        text.starts_with("# Adaptor profile `ahl-test-atl-leaf-v1`"),
        "first line: {:?}",
        text.lines().next()
    );
    for required in [
        "**This profile is not that profile**",
        "is not a copy, revision, stand-in or\npre-release of it",
        "any change to this file produces a\ndifferent hash and therefore a different profile",
    ] {
        assert!(text.contains(required), "the document must state: {required}");
    }
    // It defines the rules it exercises AS ITS OWN, so a verifier reading only it is complete.
    for rule in [
        "log leaf_hash(i) = SHA-256( 0x00 || SHA-256(JCS(envelope_i)) || METADATA_HASH )",
        "METADATA_HASH = sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4",
        "ATL-Protocol-v1-CP",
        "**exactly nine\nfractional digits**",
        "the Origin ID is the SHA-256 over the bound log's",
        "AHLRP1",
    ] {
        assert!(text.contains(rule), "the document must define: {rule}");
    }

    // The genesis manifest pins that document's digest under that profile's id.
    let genesis = read_json(
        &test_data()
            .join("vectors")
            .join("atl")
            .join("statements")
            .join("00-manifest-genesis.json"),
    );
    let adaptor = &genesis["envelope"]["payload"]["log"]["adaptor"];
    assert_eq!(field_str(adaptor, "id").expect("pinned id"), "ahl-test-atl-leaf-v1");
    assert_eq!(field_str(adaptor, "hash").expect("pinned hash"), pinned);

    // Nothing under the ATL binding's own id is shipped, anywhere.
    for entry in std::fs::read_dir(test_data().join("profiles"))
        .expect("profiles directory")
        .chain(std::fs::read_dir(test_data().join("adaptor")).expect("adaptor directory"))
    {
        let name = entry.expect("directory entry").file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains("ahl-adaptor-atl-v1"),
            "no artifact may be published under the ATL binding's id: {name}"
        );
    }

    // A receipt pinning `ahl-adaptor-atl-v1` — at ANY digest — is refused by this policy, and
    // the outcome is `unverifiable` rather than `invalid`: I-D §7.5 step 2 separates the two,
    // and "if the verifier possesses NO profile under that id, it lacks a capability". The
    // corpus holds no artifact under that id, so every such receipt is short of a capability
    // rather than defective — a fact about this verifier's configuration, not about the receipt.
    // A verifier that DID hold the released artifact would resolve the id and verify normally,
    // which is why the build implements it.
    let policy = atl_trust_policy();
    let (_, base) = read_atl_receipt("statement-anchored-atl-leaf.ahl");
    for digest in [pinned.as_str(), &sha256_hex(b"some other artifact")] {
        let mut receipt = base.clone();
        receipt["anchoring"]["adaptor"]["id"] = json!("ahl-adaptor-atl-v1");
        receipt["anchoring"]["adaptor"]["hash"] = json!(digest);
        let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
        assert_eq!(report.result, Outcome::Unverifiable, "{:#?}", report.findings);
        let finding = report.finding(Assertion::AdaptorProfile).expect("adaptor-profile finding");
        assert_eq!(finding.outcome, Outcome::Unverifiable);
        assert_eq!(finding.rests_on, None, "the cause, not a derivation");
        assert!(matches!(
            verify_receipt(&receipt, &policy),
            Err(ReceiptError::AdaptorUnknown { ref id }) if id == "ahl-adaptor-atl-v1"
        ));
    }

    // The neighbouring rule, which IS a defect: pinning THIS id at a digest the held document
    // does not recompute to. `invalid`, "decidable from the bytes in hand" (§7.5 step 2).
    let (_, unheld) = read_atl_receipt("statement-anchored-atl-unheld-manifest-pin-must-fail.ahl");
    let manifest = &unheld["governance"]["chain"][1]["envelope"]["payload"];
    assert_eq!(field_str(&manifest["log"]["adaptor"], "id").expect("id"), "ahl-test-atl-leaf-v1");
    assert_ne!(field_str(&manifest["log"]["adaptor"], "hash").expect("hash"), pinned);
    let report = verify_receipt_report(&unheld, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
    assert_eq!(
        report.dominating().map(|finding| finding.assertion),
        Some(Assertion::AdaptorProfile),
        "{:#?}",
        report.findings
    );
}

/// Profile §9 and §8 over receipts rather than helpers.
///
/// Round 1 left every ATL receipt `declared` with `continued_history: false`, so the §4.2 leaf
/// construction never ran through the enumerated path and no ATL `later_checkpoint` was ever
/// authenticated. These two vectors are what put both through it.
#[test]
fn atl_enumeration_and_continued_history_run_through_the_profile() {
    let policy = atl_trust_policy();

    // Enumerated governance currency over exactly [0, tree_size(C)), authenticated by a §10.4
    // range proof whose carried leaves are §4.2's.
    let (_, enumerated) = read_atl_receipt("governance-state-atl-leaf.ahl");
    let report = verify_receipt_report(&enumerated, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert_eq!(enumerated["claim"]["assurance"]["governance"], json!("enumerated"));
    let material = &enumerated["governance"]["currency"]["material"];
    assert_eq!(material["range"]["from_index"], json!(0));
    assert_eq!(
        material["range"]["to_index"], enumerated["anchoring"]["checkpoint"]["tree_size"],
        "§4 fixes enumerated material at exactly [0, tree_size(C))"
    );
    assert!(field_str(&material["range_proof"], "adaptor_form")
        .expect("adaptor_form")
        .starts_with("base64:"));

    // A trigger proven effective over an ATL competing range — a PROPER sub-range, so the proof
    // actually carries subtree hashes.
    let (_, trigger) = read_atl_receipt("trigger-effective-atl-leaf.ahl");
    let report = verify_receipt_report(&trigger, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    let competing = &trigger["claim_material"]["competing"]["corpus_range"];
    assert_eq!(competing["range"]["from_index"], json!(1));
    assert!(
        competing["entries"].as_array().expect("entries").len() < 5,
        "the competing range must be a proper sub-range"
    );

    // The same range built over leaves hashed with a metadata digest the profile does not pin
    // is refused — which is what shows the enumerated path dispatches the leaf rule at all.
    let (_, wrong) = read_atl_receipt("trigger-effective-atl-metadata-hash-must-fail.ahl");
    assert!(matches!(
        verify_receipt(&wrong, &policy),
        Err(ReceiptError::RangeProofInvalid { what: "competing triggers", .. })
    ));

    // `continued_history: true`, backed by an ATL `later_checkpoint` with its own 98-byte blob
    // signature, its own cosignatures, and an RFC 9162 proof between the two sizes.
    let (_, continued) = read_atl_receipt("statement-anchored-atl-continued-history.ahl");
    let report = verify_receipt_report(&continued, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Verified, "{:#?}", report.findings);
    assert_eq!(continued["claim"]["assurance"]["continued_history"], json!(true));
    let anchoring = &continued["anchoring"];
    let later = &anchoring["later_checkpoint"];
    assert!(
        later["tree_size"].as_u64() > anchoring["checkpoint"]["tree_size"].as_u64(),
        "the later checkpoint must extend the primary one"
    );
    assert_eq!(anchoring["later_witnesses"].as_array().expect("later_witnesses").len(), 1);
    let later_blob = atl_checkpoint_blob_from_json(later).expect("well-formed checkpoint");
    let log_key = &continued["keys"]["log"][0];
    assert!(
        verify_signature(
            &decode_pubkey(field_str(log_key, "pubkey").expect("pubkey")).expect("pubkey"),
            &later_blob,
            field_str(later, "signature").expect("signature"),
        )
        .expect("well-formed signature"),
        "the later checkpoint is signed over its OWN 98-byte blob"
    );
    reconcile_atl_checkpoint_raw(later, field_str(later, "raw").expect("§5.4 raw"))
        .expect("the later checkpoint's raw must reconcile too");
    for element in strings(&anchoring["consistency_path"]) {
        parse_hash_hex(&element).expect("§8: every element is a `sha256:<hex>` family string");
    }

    // And the negative: one element outside that grammar is not a proof node a verifier may
    // interpret, so `continued_history` cannot be true.
    let (_, malformed) =
        read_atl_receipt("statement-anchored-atl-consistency-path-malformed-must-fail.ahl");
    let report = verify_receipt_report(&malformed, &policy).expect("the run completes");
    assert_eq!(report.result, Outcome::Invalid, "{:#?}", report.findings);
}
