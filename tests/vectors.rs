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
use ahl_core::receipt::{verify_receipt, Limits, ReceiptError, TrustPolicy};
use ahl_core::tree::ValidatedLeafSet;
use ahl_core::{
    checkpoint_signing_bytes, cosignature_bytes, decode_pubkey, entry_id, field_str, hash_hex, jcs,
    leaf_hash, parse_hash_hex, proof_from_hex, range_proof, sha256_hex, statement_id, tree_root,
    verify_envelope, verify_inclusion_proof, verify_signature,
};
use serde_json::Value;

/// The twenty statement vectors, in entry-index order.
const STATEMENT_FILES: [&str; 20] = [
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
    "10-derivation-wide-inputs.json",
    "11-ingestion-customers-a3.json",
    "12-correction-a-to-a3-superseding.json",
    "13-ingestion-customers-c.json",
    "14-derivation-e1-point-past.json",
    "15-derivation-e2-open-interval.json",
    "16-derivation-e3-closed-past-interval.json",
    "17-retraction-c-non-retroactive.json",
    "18-manifest-v2-witness-rotation.json",
    "19-ingestion-customers-d-under-v2.json",
];

/// The three published closure scenarios.
const CLOSURE_FILES: [&str; 3] =
    ["toy-corpus.json", "supersession-chain.json", "non-retroactive-retraction.json"];

const TREE_VECTORS: [(&str, &str, &str); 3] = [
    ("batch-tree.json", "outputs_root", "outputs_count"),
    ("input-set-tree.json", "input_set_root", "input_set_count"),
    ("disposition-tree.json", "affected_root", "affected_count"),
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
    for index in [0usize, 18] {
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
    let m2 = field_str(&vectors[18], "statement_id").expect("vector carries statement_id");

    // A manifest statement declares no `manifest` member (spec §2.2, receipt §2.3).
    for index in [0usize, 18] {
        assert!(
            vectors[index]["envelope"]["payload"].get("manifest").is_none(),
            "a manifest statement must not declare a `manifest` member"
        );
    }
    for (index, vector) in vectors.iter().enumerate() {
        if index == 0 || index == 18 {
            continue;
        }
        // The manifest version id is the manifest statement's *statement id* (spec §2.3.5).
        let expected = if index < 18 { m1 } else { m2 };
        assert_eq!(
            field_str(&vector["envelope"]["payload"], "manifest")
                .expect("payload carries manifest"),
            expected,
            "{}: must bind to the manifest version active at its entry index",
            STATEMENT_FILES[index]
        );
    }
}

#[test]
fn the_manifest_chain_links_by_entry_id_and_rotates_the_witness_set() {
    let vectors = statement_vectors();
    let genesis = &vectors[0]["envelope"];
    let successor = &vectors[18]["envelope"]["payload"];

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
    let vectors = statement_vectors();
    let keys = key_set(&vectors);
    for (index, vector) in vectors.iter().enumerate() {
        let ok = verify_envelope(&vector["envelope"], |key_id| keys.get(key_id).cloned())
            .expect("well-formed envelope");
        assert!(ok, "{}: signature did not verify", STATEMENT_FILES[index]);
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
        substituted[0] = b"forged entry".to_vec();
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
        // than the checkpoint's tree size.
        let tree_size = cp["tree_size"].as_u64().expect("tree_size");
        let expected = if tree_size > 18 { 18 } else { 0 };
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
        // The witness must be the one the active manifest version declares.
        let tree_size = cp["tree_size"].as_u64().expect("tree_size");
        assert_eq!(witness_id, if tree_size > 18 { "witness-2" } else { "witness-1" });
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

    // Step 3: the conflict — equal tree size, different roots. No append-only log can do that.
    assert_eq!(field_str(refusal, "reason").expect("reason"), "inconsistent");
    assert_eq!(refusal["retained"]["tree_size"], refusal["offered"]["tree_size"]);
    assert_ne!(refusal["retained"]["root_hash"], refusal["offered"]["root_hash"]);

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
    let w = (
        "scores".to_owned(),
        field_str(&vectors[10]["envelope"]["payload"]["outputs"][0], "record")
            .expect("record")
            .to_owned(),
    );
    assert!(closure.affected.contains(&s1p), "S1' consumed the superseded replacement");
    assert!(
        closure.affected.contains(&w),
        "W consumed the superseded replacement through an input-set tree"
    );

    // Seeding only the original would miss both — the regression this vector exists for.
    let seeds_only_original = affected_set(&envelopes, &tree_material(), 6, 13).expect("corpus");
    assert!(!seeds_only_original.affected.contains(&w));
}

#[test]
fn the_non_retroactive_retraction_excludes_out_of_scope_derivations() {
    let vectors = statement_vectors();
    let envelopes = envelopes(&vectors);
    let closure = affected_set(&envelopes, &tree_material(), 17, 18).expect("corpus");

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
    let root = field_str(&vectors[10]["envelope"]["payload"]["inputs"], "input_set_root")
        .expect("input_set_root")
        .to_owned();
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
        genesis_key_ids: strings(&policy["genesis_key_ids"]).into_iter().collect(),
        adaptor_profiles: policy["adaptor_profiles"]
            .as_object()
            .expect("adaptor profiles")
            .iter()
            .map(|(id, hash)| (id.clone(), hash.as_str().expect("hash").to_owned()))
            .collect(),
        dataset_keys: BTreeMap::from([(
            "customers".to_owned(),
            hex::decode(dataset_key.trim()).expect("hex dataset key"),
        )]),
        trusted_witness_key_ids: BTreeSet::new(),
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
    assert!(on_disk.len() >= 18, "one positive and one negative vector per registry claim type");
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
    assert!(accepted >= 9, "every registry claim type needs a positive vector, got {accepted}");
}

/// Assert that a rejection is the *specific* rule the index entry names.
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
    assert!(rejected >= 9, "every registry claim type needs a negative vector, got {rejected}");
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
fn a_receipt_pinning_an_unknown_adaptor_profile_is_rejected() {
    let mut policy = trust_policy();
    policy.adaptor_profiles.clear();
    let (_, receipt) = read_receipt("statement-anchored-valid.ahl");
    assert!(matches!(verify_receipt(&receipt, &policy), Err(ReceiptError::AdaptorUnknown { .. })));
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

    for index in [0usize, 18] {
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
