//! The 28-entry toy corpus and every non-receipt vector file it produces.

use std::collections::BTreeSet;
use std::path::Path;

use ahl_core::closure::{affected_set, RecordRef, TreeMaterial};
use ahl_core::{
    checkpoint, checkpoint_signing_bytes, commit_keyed, commit_plain, cosignature_bytes, entry_id,
    envelope, field_str, hash_hex, inclusion_proof, jcs, leaf_hash, proof_path_hex, range_proof,
    record_sorted, sha256_hex, statement_id, tree_root, verify_envelope, verify_inclusion_proof,
    verify_signature,
};
use serde_json::{json, Value};

use crate::scenario::{
    leaf_bytes, manifest, payload, signed, transform, write_json, Keys, ADAPTOR_ID, DS_CUSTOMERS,
    DS_SCORES, LEAF_FORMAT, LOG_OPERATOR, LOG_SEED, PIPELINE, T0, T_EARLY, T_OPEN_FROM,
    T_PAST_FROM, T_PAST_TO, T_RETRACTION, WITNESS_1, WITNESS_2,
};

/// Entry-index labels, one per anchored envelope.
pub const NAMES: [&str; 28] = [
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
    "10-derivation-batch-wide-inputs",
    "11-ingestion-customers-a3",
    "12-correction-a-to-a3-superseding",
    "13-ingestion-customers-c",
    "14-derivation-e1-point-past",
    "15-derivation-e2-open-interval",
    "16-derivation-e3-closed-past-interval",
    "17-retraction-c-non-retroactive",
    "18-retraction-a-original-after-correction",
    "19-retraction-s1-prime-derived-authority",
    "20-ingestion-customers-f",
    "21-derivation-h-from-f",
    "22-retraction-f-authorized",
    "23-challenge-retraction-f-unauthorized",
    "24-propagation-over-challenge",
    "25-manifest-v2-rotate-witness-drop-key",
    "26-ingestion-customers-d-under-v2",
    "27-derivation-z-from-affected-descendant",
];

/// A signed checkpoint plus its witness cosignature, as the corpus publishes them.
pub struct Anchor {
    pub name: &'static str,
    pub checkpoint: Value,
    pub witness_id: &'static str,
    pub cosignature: String,
    /// Entry index of the manifest version active for this checkpoint (format §2.2).
    pub manifest_index: u64,
}

impl Anchor {
    pub fn tree_size(&self) -> u64 {
        self.checkpoint["tree_size"].as_u64().expect("signed checkpoint")
    }

    pub fn root(&self) -> &str {
        field_str(&self.checkpoint, "root_hash").expect("signed checkpoint")
    }

    /// The `anchoring.witnesses` entry a receipt carries for this anchor.
    pub fn witness_entry(&self, keys: &Keys) -> Value {
        let (key, _) = keys.witness_for(self.manifest_index);
        json!({
            "witness_id": self.witness_id,
            "key_id": key.key_id(),
            "cosignature": self.cosignature,
            "cosigned_at": T0,
        })
    }
}

/// One closure scenario the corpus publishes and the generator re-checks.
pub struct ClosureCase {
    pub name: &'static str,
    pub trigger_index: usize,
    pub through_size: usize,
    pub expected_seeds: Vec<RecordRef>,
    pub expected_affected: Vec<RecordRef>,
    pub note: String,
}

/// Every record commitment the scenario uses.
pub struct Records {
    pub c_a: String,
    pub c_b: String,
    pub c_a2: String,
    pub c_a3: String,
    pub c_c: String,
    pub c_d: String,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub s4: String,
    pub s1p: String,
    pub w1: String,
    pub w2: String,
    pub e1: String,
    pub e2: String,
    pub e3: String,
    pub c_f: String,
    pub h: String,
    pub z: String,
    /// Canonical bytes of record A, carried by the `record-ingested` receipt.
    pub c_a_bytes: Vec<u8>,
    /// Canonical bytes of record B — the wrong bytes for the negative receipt.
    pub c_b_bytes: Vec<u8>,
}

pub struct Corpus {
    /// The twenty-eight anchored envelopes, in entry-index order.
    pub envelopes: Vec<Value>,
    /// Committed tree material keyed by root (spec §3.5).
    pub trees: TreeMaterial,
    pub batch_root: String,
    pub wide_outputs_root: String,
    pub input_set_root: String,
    pub affected_root: String,
    pub challenge_affected_root: String,
    pub records: Records,
    pub log_id: String,
    pub anchors: Vec<Anchor>,
    pub adaptor_hash: String,
    pub closures: Vec<ClosureCase>,
    /// Witness refusal evidence (spec §3.3 step 3, adaptor profile §6.1).
    pub refusal: Value,
}

impl Corpus {
    // `env_10` and `env_19` differ by one character on purpose: the binding name IS the entry
    // index, which is the corpus's only ordering primitive, and renaming them would hide it.
    #[allow(clippy::similar_names)]
    #[allow(clippy::too_many_lines)] // One linear scenario; splitting it would obscure the order.
    pub fn build(keys: &Keys, dataset_key: &[u8], adaptor_hash: &str) -> Self {
        let log_id = sha256_hex(LOG_SEED);
        let records = Records::build(dataset_key);
        let r = &records;

        // --- entry 0: the genesis manifest (spec §2.3.5, §7.2) ---------------------
        let env_0 = envelope(manifest(keys, &log_id, adaptor_hash, 0, None), &keys.producer_1);
        let m1 = statement_id(&env_0).expect("well-formed envelope");
        let ingest = |record: &str, batch: &str| json!({ "dataset": DS_CUSTOMERS, "record": record, "origin": format!("batch:{batch}") });

        // --- entries 1, 2: ingestion of the two source records (spec §2.3.1) -------
        let env_1 =
            signed("ingestion", &m1, ingest(&r.c_a, "2026-08-16/customers-01"), &keys.producer_1);
        let id_1 = statement_id(&env_1).expect("well-formed envelope");
        let env_2 =
            signed("ingestion", &m1, ingest(&r.c_b, "2026-08-16/customers-01"), &keys.producer_1);
        let id_2 = statement_id(&env_2).expect("well-formed envelope");

        // --- entry 3: unbatched derivation S1 <- A(feature), B(reference) ----------
        let env_3 = signed(
            "derivation",
            &m1,
            json!({
                "pipeline": PIPELINE,
                "outputs": [ { "dataset": DS_SCORES, "record": r.s1, "locator": "urn:ahl-test:scores/S1" } ],
                "inputs": [
                    { "dataset": DS_CUSTOMERS, "record": r.c_a, "role": "feature", "statement": id_1 },
                    { "dataset": DS_CUSTOMERS, "record": r.c_b, "role": "reference", "statement": id_2 },
                ],
                "transform": transform(),
            }),
            &keys.producer_1,
        );

        // --- entry 4: batch derivation of S2, S3, S4 (spec §2.5) -------------------
        let batch_input = json!([ { "dataset": DS_CUSTOMERS, "record": r.c_a, "role": "feature", "statement": id_1 } ]);
        let batch_leaves = record_sorted(
            [&r.s2, &r.s3, &r.s4]
                .iter()
                .map(|record| {
                    json!({ "dataset": DS_SCORES, "record": record, "inputs": batch_input })
                })
                .collect(),
        )
        .expect("distinct batch outputs");
        let batch_root = hash_hex(&tree_root(&leaf_bytes(&batch_leaves)));
        let env_4 = signed(
            "derivation",
            &m1,
            json!({
                "pipeline": PIPELINE,
                "outputs_root": batch_root,
                "outputs_count": batch_leaves.len(),
                "leaf_format": LEAF_FORMAT,
                "transform": transform(),
            }),
            &keys.producer_1,
        );

        // --- entry 5: ingestion of the replacement record A2 -----------------------
        let env_5 =
            signed("ingestion", &m1, ingest(&r.c_a2, "2026-08-16/customers-02"), &keys.producer_1);
        let id_5 = statement_id(&env_5).expect("well-formed envelope");

        // --- entry 6: a retroactive correction A -> A2 (spec §2.3.3) ---------------
        let env_6 = signed(
            "correction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_a,
                "replacement": r.c_a2,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "error",
            }),
            &keys.producer_1,
        );
        let id_6 = statement_id(&env_6).expect("well-formed envelope");

        // --- entry 7: the successor derivation S1' <- A2, B ------------------------
        let env_7 = signed(
            "derivation",
            &m1,
            json!({
                "pipeline": PIPELINE,
                "outputs": [ { "dataset": DS_SCORES, "record": r.s1p, "locator": "urn:ahl-test:scores/S1-prime" } ],
                "inputs": [
                    { "dataset": DS_CUSTOMERS, "record": r.c_a2, "role": "feature", "statement": id_5 },
                    { "dataset": DS_CUSTOMERS, "record": r.c_b, "role": "reference", "statement": id_2 },
                ],
                "transform": transform(),
            }),
            &keys.producer_1,
        );
        let id_7 = statement_id(&env_7).expect("well-formed envelope");

        // --- entry 8: propagation over a checkpoint committing the trigger --------
        let prefix_8 = vec![
            env_0.clone(),
            env_1.clone(),
            env_2.clone(),
            env_3.clone(),
            env_4.clone(),
            env_5.clone(),
            env_6.clone(),
            env_7.clone(),
        ];
        let root_8 = hash_hex(&tree_root(&leaf_bytes(&prefix_8)));
        let dispositions = record_sorted(vec![
            json!({
                "dataset": DS_SCORES, "record": r.s1,
                "disposition": "recomputed", "successor_statement": id_7,
            }),
            json!({ "dataset": DS_SCORES, "record": r.s2, "disposition": "invalidated" }),
            json!({ "dataset": DS_SCORES, "record": r.s3, "disposition": "invalidated" }),
            json!({ "dataset": DS_SCORES, "record": r.s4, "disposition": "invalidated" }),
        ])
        .expect("distinct dispositioned records");
        let affected_root = hash_hex(&tree_root(&leaf_bytes(&dispositions)));
        let env_8 = signed(
            "propagation",
            &m1,
            json!({
                "trigger": id_6,
                "corpus_checkpoint": { "log_id": log_id, "tree_size": 8, "root_hash": root_8 },
                "affected_root": affected_root,
                "affected_count": dispositions.len(),
                "complete_relative_to_manifest": true,
            }),
            &keys.producer_1,
        );

        // --- entry 9: key transition adding producer-2 (spec §2.3.6) --------------
        let env_9 = signed(
            "key",
            &m1,
            json!({
                "action": "add",
                "key": {
                    "key_id": keys.producer_2.key_id(),
                    "pubkey": keys.producer_2.pubkey(),
                    "valid_from": T0,
                },
            }),
            &keys.producer_1,
        );

        // --- entry 10: batch derivation whose leaves carry wide inputs (spec §2.5) -
        // Receipt format §3 makes `input_members` apply "ONLY when `batch_leaf.inputs` is the
        // input-set form", so the two batching mechanisms compose: an outputs tree whose
        // leaves commit their input set by root rather than inline.
        let input_leaves = record_sorted(vec![
            json!({ "dataset": DS_CUSTOMERS, "record": r.c_a2, "role": "feature", "statement": id_5 }),
            json!({ "dataset": DS_CUSTOMERS, "record": r.c_b, "role": "reference", "statement": id_2 }),
            json!({ "dataset": DS_SCORES, "record": r.s1p, "role": "feature", "statement": id_7 }),
        ])
        .expect("distinct input records");
        let input_set_root = hash_hex(&tree_root(&leaf_bytes(&input_leaves)));
        let wide_inputs =
            json!({ "input_set_root": input_set_root, "input_set_count": input_leaves.len() });
        let wide_leaves = record_sorted(
            [&r.w1, &r.w2]
                .iter()
                .map(|record| {
                    json!({ "dataset": DS_SCORES, "record": record, "inputs": wide_inputs })
                })
                .collect(),
        )
        .expect("distinct batch outputs");
        let wide_outputs_root = hash_hex(&tree_root(&leaf_bytes(&wide_leaves)));
        let env_10 = signed(
            "derivation",
            &m1,
            json!({
                "pipeline": PIPELINE,
                "outputs_root": wide_outputs_root,
                "outputs_count": wide_leaves.len(),
                "leaf_format": LEAF_FORMAT,
                "transform": transform(),
            }),
            &keys.producer_1,
        );

        // --- entries 11, 12: a second correction of A, superseding entry 6 ---------
        let env_11 =
            signed("ingestion", &m1, ingest(&r.c_a3, "2026-08-16/customers-03"), &keys.producer_1);
        let env_12 = signed(
            "correction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_a,
                "replacement": r.c_a3,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "error",
            }),
            &keys.producer_1,
        );

        // --- entries 13..17: the non-retroactive retraction scenario (spec §2.3.3) -
        let env_13 =
            signed("ingestion", &m1, ingest(&r.c_c, "2026-08-16/customers-04"), &keys.producer_1);
        let id_13 = statement_id(&env_13).expect("well-formed envelope");
        let from_c = |record: &str, valid_time: Value| {
            envelope(
                payload(
                    "derivation",
                    &m1,
                    valid_time,
                    json!({
                        "pipeline": PIPELINE,
                        "outputs": [ { "dataset": DS_SCORES, "record": record } ],
                        "inputs": [ {
                            "dataset": DS_CUSTOMERS, "record": r.c_c,
                            "role": "feature", "statement": id_13,
                        } ],
                        "transform": transform(),
                    }),
                ),
                &keys.producer_1,
            )
        };
        let env_14 = from_c(&r.e1, json!(T_EARLY));
        let env_15 = from_c(&r.e2, json!({ "from": T_OPEN_FROM, "to": null }));
        let env_16 = from_c(&r.e3, json!({ "from": T_PAST_FROM, "to": T_PAST_TO }));
        let env_17 = signed(
            "retraction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_c,
                "scope": { "effective_from": T_RETRACTION, "retroactive": false },
                "reason_code": "consent_withdrawn",
            }),
            &keys.producer_1,
        );

        // --- entry 18: retraction of the ORIGINAL A, after two corrections of it ---
        // Spec §5.1: a retraction seeds exactly its own record. Consumers of the superseded
        // replacements must stay out of the affected set.
        let env_18 = signed(
            "retraction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_a,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "legal_obligation",
            }),
            &keys.producer_1,
        );

        // --- entry 19: a trigger on a DERIVED record, signed by a post-rotation key -
        // S1' was introduced by the derivation at entry 7, under a key set that did not yet
        // contain producer-2. The `key` statement at entry 9 added it. Spec §2.3.3: a derived
        // record's authority is "the introducing producer's key set as of the trigger's entry
        // index (not the introduction index: key rotation between introduction and trigger
        // applies)" — so this retraction IS effective, though it would not have been under an
        // introduction-indexed reading.
        let env_19 = signed(
            "retraction",
            &m1,
            json!({
                "dataset": DS_SCORES,
                "record": r.s1p,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "superseded",
            }),
            &keys.producer_2,
        );

        // --- entries 20..24: an authorized trigger, a challenge, and a propagation -
        let env_20 =
            signed("ingestion", &m1, ingest(&r.c_f, "2026-08-16/customers-06"), &keys.producer_1);
        let id_19 = statement_id(&env_20).expect("well-formed envelope");
        let env_21 = signed(
            "derivation",
            &m1,
            json!({
                "pipeline": PIPELINE,
                "outputs": [ { "dataset": DS_SCORES, "record": r.h, "locator": "urn:ahl-test:scores/H" } ],
                "inputs": [ {
                    "dataset": DS_CUSTOMERS, "record": r.c_f,
                    "role": "feature", "statement": id_19,
                } ],
                "transform": transform(),
            }),
            &keys.producer_1,
        );
        // Entry 22: a genuine, AUTHORIZED retraction of F by the dataset authority.
        let env_22 = signed(
            "retraction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_f,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "consent_withdrawn",
            }),
            &keys.producer_1,
        );

        // Entry 23: a LATER trigger on the SAME record signed by `producer-2` — a valid
        // producer key at this entry index, but not in the authority key set the manifest
        // declares for `customers`. Spec §2.3.3 anchors it as a challenge: surfaced by
        // verification, never traversed. Because it sits at a greater entry index than the
        // authorized retraction at 22, a verifier that selected the governing trigger by index
        // *before* filtering challenges would let it unseat entry 22 — which is exactly the
        // attack this pair exists to catch.
        let env_23 = signed(
            "retraction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_f,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "other",
            }),
            &keys.producer_2,
        );
        let id_21 = statement_id(&env_23).expect("well-formed envelope");
        let challenge_dispositions =
            vec![json!({ "dataset": DS_SCORES, "record": r.h, "disposition": "invalidated" })];
        let challenge_affected_root = hash_hex(&tree_root(&leaf_bytes(&challenge_dispositions)));
        let prefix_24: Vec<Value> = vec![
            env_0.clone(),
            env_1.clone(),
            env_2.clone(),
            env_3.clone(),
            env_4.clone(),
            env_5.clone(),
            env_6.clone(),
            env_7.clone(),
            env_8.clone(),
            env_9.clone(),
            env_10.clone(),
            env_11.clone(),
            env_12.clone(),
            env_13.clone(),
            env_14.clone(),
            env_15.clone(),
            env_16.clone(),
            env_17.clone(),
            env_18.clone(),
            env_19.clone(),
            env_20.clone(),
            env_21.clone(),
            env_22.clone(),
            env_23.clone(),
        ];
        let root_24 = hash_hex(&tree_root(&leaf_bytes(&prefix_24)));
        let env_24 = signed(
            "propagation",
            &m1,
            json!({
                "trigger": id_21,
                "corpus_checkpoint": { "log_id": log_id, "tree_size": 24, "root_hash": root_24 },
                "affected_root": challenge_affected_root,
                "affected_count": challenge_dispositions.len(),
                "complete_relative_to_manifest": true,
            }),
            &keys.producer_1,
        );

        // --- entries 25, 26: manifest rotation and a statement under the successor -
        // Signed by a key valid under the *previous* manifest version, referencing that
        // version by entry id (spec §2.3.5). Version 2 rotates the witness key set AND drops
        // `producer-2` from the producer snapshot (spec §7.2).
        let env_25 = envelope(
            manifest(keys, &log_id, adaptor_hash, 25, Some(&entry_id(&env_0))),
            &keys.producer_1,
        );
        let m2 = statement_id(&env_25).expect("well-formed envelope");
        let env_26 =
            signed("ingestion", &m2, ingest(&r.c_d, "2026-08-16/customers-05"), &keys.producer_1);

        // --- entry 27: a derivation consuming an AFFECTED DESCENDANT ---------------
        // S2 is in the affected set the propagation at entry 8 dispositioned at its declared
        // checkpoint D (tree size 8). Spec §2.3.2 bars re-consuming the *triggered* record A —
        // it says nothing about A's descendants, so this derivation is legal. Its effect is
        // that the transitive closure of the entry-6 trigger GROWS past D: at any checkpoint
        // committing entry 27 the closure also contains Z. That is why §2.3.4 defines
        // completeness at D only, and why a `propagation-complete` receipt may never be
        // grounded at a later checkpoint.
        let env_27 = signed(
            "derivation",
            &m2,
            json!({
                "pipeline": PIPELINE,
                "outputs": [ { "dataset": DS_SCORES, "record": r.z, "locator": "urn:ahl-test:scores/Z" } ],
                "inputs": [ {
                    "dataset": DS_SCORES, "record": r.s2,
                    "role": "feature", "statement": statement_id(&env_4).expect("well-formed"),
                } ],
                "transform": transform(),
            }),
            &keys.producer_1,
        );

        let envelopes = vec![
            env_0, env_1, env_2, env_3, env_4, env_5, env_6, env_7, env_8, env_9, env_10, env_11,
            env_12, env_13, env_14, env_15, env_16, env_17, env_18, env_19, env_20, env_21, env_22,
            env_23, env_24, env_25, env_26, env_27,
        ];

        let mut trees = TreeMaterial::new();
        trees.insert(batch_root.clone(), batch_leaves);
        trees.insert(wide_outputs_root.clone(), wide_leaves);
        trees.insert(input_set_root.clone(), input_leaves);
        trees.insert(affected_root.clone(), dispositions);
        trees.insert(challenge_affected_root.clone(), challenge_dispositions);

        let log_leaves = leaf_bytes(&envelopes);
        let anchors = [(8u64, 0u64), (13, 0), (20, 0), (24, 0), (25, 0), (28, 25)]
            .into_iter()
            .map(|(size, manifest_index)| {
                let root = hash_hex(&tree_root(&log_leaves[..at(size)]));
                let cp = checkpoint(&log_id, size, &root, T0, &keys.log_1);
                let (key, witness_id) = keys.witness_for(manifest_index);
                let cosignature = key.sign(&cosignature_bytes(&cp, witness_id));
                Anchor {
                    name: match size {
                        8 => "cp8",
                        13 => "cp13",
                        20 => "cp20",
                        24 => "cp24",
                        25 => "cp25",
                        _ => "cp28",
                    },
                    checkpoint: cp,
                    witness_id,
                    cosignature,
                    manifest_index,
                }
            })
            .collect::<Vec<_>>();

        let refusal = refusal_evidence(keys, &log_id, &anchors[1]);
        let closures = closure_cases(r);

        Self {
            envelopes,
            trees,
            batch_root,
            wide_outputs_root,
            input_set_root,
            affected_root,
            challenge_affected_root,
            records,
            log_id,
            anchors,
            adaptor_hash: adaptor_hash.to_owned(),
            closures,
            refusal,
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn manifest_id(&self, entry_index: usize) -> String {
        statement_id(&self.envelopes[entry_index]).expect("well-formed envelope")
    }

    pub fn statement_id(&self, entry_index: usize) -> String {
        statement_id(&self.envelopes[entry_index]).expect("well-formed envelope")
    }

    pub fn payload(&self, entry_index: usize) -> &Value {
        &self.envelopes[entry_index]["payload"]
    }

    pub fn log_leaves(&self) -> Vec<Vec<u8>> {
        leaf_bytes(&self.envelopes)
    }

    pub fn anchor(&self, name: &str) -> &Anchor {
        self.anchors.iter().find(|a| a.name == name).expect("named checkpoint")
    }

    /// Inclusion path of entry `index` under a checkpoint of size `tree_size`.
    pub fn log_path(&self, index: usize, tree_size: u64) -> Vec<String> {
        let leaves = self.log_leaves();
        let proof = inclusion_proof(&leaves[..at(tree_size)], index)
            .expect("entry index within the checkpoint");
        proof_path_hex(&proof)
    }

    /// Inclusion path of leaf `index` in a committed record-sorted tree.
    pub fn tree_path(&self, root: &str, index: usize) -> Vec<String> {
        let leaves = self.trees.get(root).expect("committed tree material");
        let proof = inclusion_proof(&leaf_bytes(leaves), index).expect("index within tree");
        proof_path_hex(&proof)
    }

    pub fn tree_leaves(&self, root: &str) -> &[Value] {
        self.trees.get(root).expect("committed tree material")
    }

    /// The §4.2 inline enumeration form for `[from, to)` under a named checkpoint.
    pub fn enumeration(&self, from: u64, to: u64, anchor: &Anchor) -> Value {
        let leaves = self.log_leaves();
        let hashes: Vec<_> =
            leaves[..at(anchor.tree_size())].iter().map(|l| leaf_hash(l)).collect();
        let proof = range_proof::generate(&hashes, from, to).expect("range within the checkpoint");
        json!({
            "range": { "from_index": from, "to_index": to },
            "entries": (from..to)
                .map(|index| json!({
                    "entry_index": index,
                    "envelope": self.envelopes[at(index)],
                }))
                .collect::<Vec<_>>(),
            "range_proof": { "adaptor_form": range_proof::encode(&proof) },
        })
    }

    // -----------------------------------------------------------------------
    // Self-checks: verify or abort
    // -----------------------------------------------------------------------

    pub fn self_check(&self, keys: &Keys) {
        println!("self-check");
        self.check_signatures(keys);
        self.check_anchors(keys);
        self.check_trees();
        self.check_range_proofs();
        self.check_refusal(keys);
        self.check_closures();
    }

    fn check_signatures(&self, keys: &Keys) {
        for (index, env) in self.envelopes.iter().enumerate() {
            let ok = verify_envelope(env, |key_id| keys.resolve(key_id))
                .expect("generated envelope is well-formed");
            assert!(ok, "entry {index}: envelope signature did not verify");
        }
        println!("  [ok] {} envelope signatures verified", self.envelopes.len());

        // Manifest lineage: the successor references its predecessor by entry id (§2.3.5).
        assert_eq!(
            field_str(self.payload(25), "predecessor").expect("successor manifest"),
            entry_id(&self.envelopes[0]),
            "manifest v2 must reference the genesis manifest by entry id"
        );
        assert!(self.payload(0).get("predecessor").is_none());
        assert_eq!(
            field_str(self.payload(26), "manifest").expect("statement under v2"),
            self.manifest_id(25),
            "entry 26 must bind to the manifest version id of v2 (its statement id)"
        );
        let witnesses = |index: usize| {
            self.payload(index)["witnesses"][0]["witness_id"]
                .as_str()
                .expect("witness id")
                .to_owned()
        };
        assert_eq!(witnesses(0), WITNESS_1);
        assert_eq!(witnesses(25), WITNESS_2, "v2 replaces the witness key set in full (§7.2)");

        // §7.2: the producer `keys` array is a snapshot that DISCARDS the prior one. Version 2
        // therefore drops the key that entry 9 added, and nothing it signs after entry 23 can
        // verify against the v2 state.
        let snapshot = |index: usize| {
            self.payload(index)["keys"]
                .as_array()
                .expect("producer key objects")
                .iter()
                .map(|k| field_str(k, "key_id").expect("key_id").to_owned())
                .collect::<BTreeSet<String>>()
        };
        assert_eq!(snapshot(0), BTreeSet::from([keys.producer_1.key_id()]));
        assert_eq!(
            snapshot(25),
            BTreeSet::from([keys.producer_1.key_id()]),
            "manifest v2 must drop producer-2 from its producer-key snapshot"
        );
        assert_eq!(
            field_str(&self.payload(9)["key"], "key_id").expect("key statement"),
            keys.producer_2.key_id(),
            "entry 9 is the key transition v2's snapshot discards"
        );
        println!(
            "  [ok] manifest lineage: v2 chains to genesis by entry id, rotates the witness \
             set, and drops producer-2 from the producer-key snapshot (§7.2)"
        );

        // The challenge at entry 21 must be a *valid signature* by a key that is not the
        // dataset authority — otherwise it would be malformed rather than a challenge.
        let authority: BTreeSet<String> = self.payload(0)["datasets"][DS_CUSTOMERS]["authority"]
            ["key_ids"]
            .as_array()
            .expect("dataset authority key set")
            .iter()
            .map(|k| k.as_str().expect("key id").to_owned())
            .collect();
        let challenge_signer =
            field_str(&self.envelopes[23]["signatures"][0], "key_id").expect("signed").to_owned();
        assert_eq!(authority, BTreeSet::from([keys.producer_1.key_id()]));
        assert!(
            !authority.contains(&challenge_signer),
            "the challenge at entry 23 must be signed by a non-authority key"
        );
        assert_eq!(challenge_signer, keys.producer_2.key_id());
        assert_eq!(
            field_str(self.payload(24), "trigger").expect("propagation trigger"),
            self.statement_id(23),
            "entry 24 propagates over the challenge, which no verifier may traverse"
        );
        println!(
            "  [ok] challenge at entry 23: valid producer-2 signature, not the `{DS_CUSTOMERS}` \
             authority; entry 24 propagates over it (spec §2.3.3)"
        );
    }

    fn check_anchors(&self, keys: &Keys) {
        for anchor in &self.anchors {
            let msg = checkpoint_signing_bytes(&anchor.checkpoint).expect("checkpoint object");
            let sig = field_str(&anchor.checkpoint, "signature").expect("signed checkpoint");
            assert!(
                verify_signature(&keys.log_1.verifying_key(), &msg, sig)
                    .expect("well-formed signature"),
                "{}: checkpoint signature did not verify",
                anchor.name
            );
            let (witness_key, _) = keys.witness_for(anchor.manifest_index);
            assert!(
                verify_signature(
                    &witness_key.verifying_key(),
                    &cosignature_bytes(&anchor.checkpoint, anchor.witness_id),
                    &anchor.cosignature,
                )
                .expect("well-formed signature"),
                "{}: witness cosignature did not verify",
                anchor.name
            );
        }
        println!(
            "  [ok] {} checkpoints signed by log-1 and cosigned by the witness of their active \
             manifest version",
            self.anchors.len()
        );

        let leaves = self.log_leaves();
        for anchor in &self.anchors {
            let size = at(anchor.tree_size());
            let root = tree_root(&leaves[..size]);
            assert_eq!(&hash_hex(&root), anchor.root(), "{}: root mismatch", anchor.name);
            for index in [0usize, size - 1, size / 2] {
                let proof =
                    inclusion_proof(&leaves[..size], index).expect("index within the checkpoint");
                assert!(
                    verify_inclusion_proof(&leaves[index], &proof, &root)
                        .expect("well-formed proof"),
                    "{}: inclusion proof for entry {index} did not verify",
                    anchor.name
                );
            }
        }
        println!("  [ok] log-tree inclusion proofs verified at every checkpoint (atl-core)");
    }

    fn check_trees(&self) {
        for (label, root_hex) in [
            ("batch-tree", &self.batch_root),
            ("wide-outputs-tree", &self.wide_outputs_root),
            ("input-set-tree", &self.input_set_root),
            ("disposition-tree", &self.affected_root),
            ("challenge-disposition-tree", &self.challenge_affected_root),
        ] {
            let leaves = self.tree_leaves(root_hex);
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
    }

    fn check_range_proofs(&self) {
        let leaves = self.log_leaves();
        for anchor in &self.anchors {
            let size = anchor.tree_size();
            let root = tree_root(&leaves[..at(size)]);
            let hashes: Vec<_> = leaves[..at(size)].iter().map(|l| leaf_hash(l)).collect();
            for (from, to) in [(0, size), (3, 7.min(size)), (size - 1, size)] {
                let proof = range_proof::generate(&hashes, from, to).expect("valid range");
                assert!(
                    range_proof::verify(&proof, &hashes[at(from)..at(to)], &root)
                        .expect("well-formed proof"),
                    "{}: range proof [{from}, {to}) did not verify",
                    anchor.name
                );
                let decoded = range_proof::decode(&range_proof::encode(&proof))
                    .expect("serialization round trip");
                assert_eq!(decoded, proof, "range proof serialization is not stable");

                // A tampered entry must not open the root.
                let mut forged = hashes[at(from)..at(to)].to_vec();
                forged[0] = leaf_hash(b"forged entry");
                assert!(
                    !range_proof::verify(&proof, &forged, &root).expect("well-formed proof"),
                    "{}: a substituted entry opened the root",
                    anchor.name
                );
            }
        }
        println!(
            "  [ok] range proofs generated, serialized, re-verified and shown to reject \
             substitution at every checkpoint (adaptor profile §8)"
        );
    }

    fn check_refusal(&self, keys: &Keys) {
        let mut unsigned = self.refusal.as_object().cloned().expect("refusal object");
        unsigned.remove("signature");
        let msg = jcs(&Value::Object(unsigned));
        assert!(
            verify_signature(
                &keys.witness_1.verifying_key(),
                &msg,
                field_str(&self.refusal, "signature").expect("signed refusal"),
            )
            .expect("well-formed signature"),
            "witness refusal evidence signature did not verify"
        );
        for side in ["retained", "offered"] {
            let cp = &self.refusal[side];
            assert!(
                verify_signature(
                    &keys.log_1.verifying_key(),
                    &checkpoint_signing_bytes(cp).expect("checkpoint object"),
                    field_str(cp, "signature").expect("signed checkpoint"),
                )
                .expect("well-formed signature"),
                "refusal evidence: the {side} checkpoint is not signed by the log"
            );
        }
        assert_eq!(
            self.refusal["retained"]["tree_size"], self.refusal["offered"]["tree_size"],
            "the conflict must be at equal tree size"
        );
        assert_ne!(
            self.refusal["retained"]["root_hash"], self.refusal["offered"]["root_hash"],
            "two checkpoints at equal tree size with equal roots are not a conflict"
        );
        println!(
            "  [ok] witness refusal evidence: witness-1 signature verified, both conflicting \
             checkpoints carry valid log-1 signatures at equal tree_size with different roots"
        );
    }

    fn check_closures(&self) {
        for case in &self.closures {
            let closure =
                affected_set(&self.envelopes, &self.trees, case.trigger_index, case.through_size)
                    .expect("well-formed corpus and complete tree material");
            let expected_seeds: BTreeSet<RecordRef> = case.expected_seeds.iter().cloned().collect();
            let expected: BTreeSet<RecordRef> = case.expected_affected.iter().cloned().collect();
            assert_eq!(closure.seeds, expected_seeds, "{}: seed set mismatch", case.name);
            assert_eq!(closure.affected, expected, "{}: affected set mismatch", case.name);
            println!(
                "  [ok] closure `{}`: {} seed(s), {} affected record(s), recomputed independently",
                case.name,
                closure.seeds.len(),
                closure.affected.len()
            );
        }

        // The anchored disposition tree must equal the closure of the entry-6 trigger at cp8.
        let dispositioned: BTreeSet<RecordRef> = self
            .tree_leaves(&self.affected_root)
            .iter()
            .map(|leaf| {
                (
                    field_str(leaf, "dataset").expect("dataset").to_owned(),
                    field_str(leaf, "record").expect("record").to_owned(),
                )
            })
            .collect();
        let closure = affected_set(&self.envelopes, &self.trees, 6, 8).expect("corpus");
        assert_eq!(
            dispositioned, closure.affected,
            "the anchored disposition tree disagrees with the recomputed closure"
        );
        println!("  [ok] anchored disposition tree equals the recomputed closure (spec §5.3)");

        // The reason completeness is pinned to D: the same trigger reaches strictly more
        // records at a later checkpoint, because a legal derivation consumed an affected
        // descendant (spec §2.3.4).
        let at_declared = affected_set(&self.envelopes, &self.trees, 6, 8).expect("corpus");
        let later =
            affected_set(&self.envelopes, &self.trees, 6, self.envelopes.len()).expect("corpus");
        assert!(
            at_declared.affected.is_subset(&later.affected)
                && at_declared.affected.len() < later.affected.len(),
            "the corpus must demonstrate closure growing past the declared checkpoint"
        );
        println!(
            "  [ok] closure of the entry-6 trigger grows from {} records at its declared \
             checkpoint D (tree size 8) to {} at tree size {} — completeness is defined at D \
             only (spec §2.3.4)",
            at_declared.affected.len(),
            later.affected.len(),
            self.envelopes.len()
        );
    }

    // -----------------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------------

    pub fn write(&self, root: &Path, keys: &Keys) {
        self.write_statements(root, keys);
        self.write_merkle(root);
        self.write_checkpoints(root, keys);
        self.write_closures(root);
        crate::scenario::write_json(
            &root.join("vectors").join("witness").join("refusal-evidence.json"),
            &json!({
                "description": "Witness refusal evidence (core spec §3.3 step 3; adaptor profile \
                                §6.1). The log signed two different roots at the same tree size, \
                                so witness-1 refused to cosign and published this. It is \
                                self-authenticating and is NOT an anchored AHL statement.",
                "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
                "signed_over": "JCS(refusal object with the \"signature\" member removed)",
                "expect": "accept as evidence of log equivocation: both checkpoints carry valid \
                           log-1 signatures, `tree_size` is equal and `root_hash` differs, which \
                           no append-only log can produce",
                "refusal": self.refusal,
            }),
        );
    }

    fn write_statements(&self, root: &Path, keys: &Keys) {
        let statements = root.join("vectors").join("statements");
        for (index, env) in self.envelopes.iter().enumerate() {
            write_json(
                &statements.join(format!("{}.json", NAMES[index])),
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
        let scopeless = signed(
            "retraction",
            &self.manifest_id(0),
            json!({
                "dataset": DS_CUSTOMERS,
                "record": self.records.c_a,
                "reason_code": "consent_withdrawn",
            }),
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
            "payload": payload(
                "ingestion",
                &self.manifest_id(0),
                json!(T0),
                json!({
                    "dataset": DS_CUSTOMERS,
                    "record": self.records.c_a,
                    "origin": "batch:2026-08-16/customers-01",
                }),
            ),
            "signatures": [],
        });
        // A statement anchored after manifest v2, signed by the key v2's snapshot dropped.
        let dropped = signed(
            "ingestion",
            &self.manifest_id(25),
            json!({
                "dataset": DS_CUSTOMERS,
                "record": self.records.c_d,
                "origin": "batch:2026-08-16/customers-05",
            }),
            &keys.producer_2,
        );
        write_json(
            &malformed.join("signed-by-dropped-producer-key.json"),
            &json!({
                "name": "signed-by-dropped-producer-key",
                "expect": "reject: core spec §7.2 — \"A manifest's producer `keys` array is the \
                           complete producer-key snapshot effective from that manifest's entry \
                           index: it discards the prior snapshot\". Manifest v2 at entry 25 \
                           declares only producer-1, so producer-2 — added by the `key` \
                           statement at entry 9 — is not in the key set as of any entry index \
                           at or after 25. The Ed25519 signature is mathematically valid; the \
                           key is simply no longer entitled to make it.",
                "signed_by": keys.producer_2.key_id(),
                "manifest": self.manifest_id(25),
                "key_set_at_entry_26": [ keys.producer_1.key_id() ],
                "envelope": dropped,
            }),
        );

        write_json(
            &malformed.join("unsigned-statement.json"),
            &json!({
                "name": "unsigned-statement",
                "expect": "reject: core spec §2.1 requires every statement to be signed at \
                           every level — \"Unsigned objects are not AHL statements\"",
                "envelope": unsigned,
            }),
        );
    }

    // A flat list of tree-vector writes, one per committed tree; splitting adds no clarity.
    #[allow(clippy::too_many_lines)]
    fn write_merkle(&self, root: &Path) {
        let merkle = root.join("vectors").join("merkle");
        let leaves = self.log_leaves();
        let cp28 = self.anchor("cp28");
        let proof_3 = inclusion_proof(&leaves, 3).expect("entry 3 is in the log");
        write_json(
            &merkle.join("log-tree.json"),
            &json!({
                "description": "AHL log tree over the 28-entry toy corpus. Leaves are the \
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
                        "name": NAMES[index],
                        "entry_id": entry_id(env),
                        "leaf_hash": hash_hex(&leaf_hash(&jcs(env))),
                    }))
                    .collect::<Vec<_>>(),
                "roots": self
                    .anchors
                    .iter()
                    .map(|a| json!({ "name": a.name, "tree_size": a.tree_size(), "root": a.root() }))
                    .collect::<Vec<_>>(),
                "inclusion": {
                    "leaf_index": 3,
                    "tree_size": 28,
                    "entry_id": entry_id(&self.envelopes[3]),
                    "path": proof_path_hex(&proof_3),
                    "root": cp28.root(),
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
            &merkle.join("wide-outputs-tree.json"),
            &self.tree_vector(
                "Batch derivation output tree of entry 10 (core spec §2.5). Each `ahl-leaf-v2` \
                 leaf commits its input set by ROOT rather than inline, so the leaf's `inputs` \
                 is the wide-input form and the input-set tree below is a second committed \
                 tree. Receipt format §3's `input_members` applies exactly to this shape.",
                &self.wide_outputs_root,
                "outputs_root",
                "outputs_count",
                Some(LEAF_FORMAT),
            ),
        );
        write_json(
            &merkle.join("input-set-tree.json"),
            &self.tree_vector(
                "Input-set tree committed by the wide-input derivation at entry 10 (core spec \
                 §2.5). Leaves are full derivation input objects. The tree mixes commitment \
                 modes, so both `hmac-sha256:` records precede the `sha256:` one under the \
                 UTF-8 byte ordering of the family string.",
                &self.input_set_root,
                "input_set_root",
                "input_set_count",
                None,
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

        write_json(
            &merkle.join("challenge-disposition-tree.json"),
            &self.tree_vector(
                "Disposition tree committed by the propagation statement at entry 22. The \
                 tree itself is well formed; the propagation it belongs to names a CHALLENGE \
                 as its trigger (core spec §2.3.3), so no `propagation-complete` receipt over \
                 it can verify — see receipts/propagation-complete-challenge-trigger-must-fail.ahl.",
                &self.challenge_affected_root,
                "affected_root",
                "affected_count",
                None,
            ),
        );

        write_json(&merkle.join("range-proof.json"), &self.range_proof_vector());
    }

    fn tree_vector(
        &self,
        description: &str,
        root_hex: &str,
        root_field: &str,
        count_field: &str,
        leaf_format: Option<&str>,
    ) -> Value {
        let leaves = self.tree_leaves(root_hex);
        let mut vector = json!({
            "description": description,
            "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
            "leaf_rule": "sha256(0x00 || JCS(leaf))",
            "node_rule": "sha256(0x01 || left || right)",
            "sort_rule": "leaves sorted ascending by the UTF-8 bytes of the canonical `record` \
                          commitment string; non-canonical strings and duplicates are rejected \
                          (core spec §2.5)",
            "leaves": leaves,
            "inclusion": {
                "leaf_index": 0,
                "tree_size": leaves.len(),
                "leaf": leaves[0],
                "path": self.tree_path(root_hex, 0),
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

    fn range_proof_vector(&self) -> Value {
        let leaves = self.log_leaves();
        let cp28 = self.anchor("cp28");
        let hashes: Vec<_> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let cases = [
            (0u64, 28u64, "the complete corpus prefix — carries no subtree hashes at all"),
            (3, 7, "a proper interior sub-range"),
            (6, 7, "a width-1 range, which is an inclusion proof in a different serialization"),
            (27, 28, "the trailing entry"),
        ];
        json!({
            "description": "Authenticated range proofs over the 28-entry log tree under cp28 \
                            (core spec §3 contract item 5, receipt format §4.2, adaptor profile \
                            §8). Each proof establishes that the listed entries are exactly and \
                            completely the leaf set of the range under the checkpoint root.",
            "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
            "checkpoint": { "name": cp28.name, "tree_size": 28, "root": cp28.root() },
            "serialization": "base64 of: \"AHLRP1\" || tree_size:u64be || from_index:u64be || \
                              to_index:u64be || node_count:u32be || node_count x 32 raw bytes",
            "cases": cases
                .iter()
                .map(|(from, to, note)| {
                    let proof = range_proof::generate(&hashes, *from, *to).expect("valid range");
                    json!({
                        "range": { "from_index": from, "to_index": to },
                        "note": note,
                        "entry_ids": (*from..*to)
                            .map(|i| entry_id(&self.envelopes[at(i)]))
                            .collect::<Vec<_>>(),
                        "node_count": proof.nodes.len(),
                        "nodes": proof.nodes.iter().map(hash_hex).collect::<Vec<_>>(),
                        "adaptor_form": range_proof::encode(&proof),
                    })
                })
                .collect::<Vec<_>>(),
            "negative": {
                "expect": "reject: substituting, reordering, dropping or adding any entry in the \
                           carried range changes the recomputed root, and a carried leaf count \
                           other than `to_index - from_index` is rejected structurally",
            },
        })
    }

    fn write_checkpoints(&self, root: &Path, keys: &Keys) {
        write_json(
            &root.join("vectors").join("checkpoints").join("checkpoints.json"),
            &json!({
                "description": "Signed log checkpoints and their witness cosignatures (core spec \
                                §1.2, §3.3). Signing rules are pinned by the adaptor profile. \
                                cp28 is cosigned by witness-2 because manifest v2, anchored at \
                                entry 25, replaced the witness key set in full (§7.2) and is the \
                                manifest version active for tree_size 28.",
                "adaptor": { "id": ADAPTOR_ID, "hash": self.adaptor_hash },
                "log": { "log_id": self.log_id, "operator": LOG_OPERATOR, "key_id": keys.log_1.key_id() },
                "checkpoints": self
                    .anchors
                    .iter()
                    .map(|a| json!({
                        "name": a.name,
                        "active_manifest_entry_index": a.manifest_index,
                        "checkpoint": a.checkpoint,
                    }))
                    .collect::<Vec<_>>(),
                "cosignatures": self
                    .anchors
                    .iter()
                    .map(|a| {
                        let (key, _) = keys.witness_for(a.manifest_index);
                        json!({
                            "checkpoint": a.name,
                            "witness_id": a.witness_id,
                            "key_id": key.key_id(),
                            "cosignature": a.cosignature,
                            "cosigned_at": T0,
                            "signed_over": format!(
                                "JCS({{\"checkpoint\": <signed {}>, \"witness_id\": \"{}\"}})",
                                a.name, a.witness_id
                            ),
                        })
                    })
                    .collect::<Vec<_>>(),
            }),
        );
    }

    fn write_closures(&self, root: &Path) {
        let dir = root.join("vectors").join("closure");
        for case in &self.closures {
            let anchor = self
                .anchors
                .iter()
                .find(|a| a.tree_size() == case.through_size as u64)
                .expect("each closure case is evaluated at a published checkpoint");
            let trigger = self.payload(case.trigger_index);
            let mut vector = json!({
                "description": format!(
                    "Revocation closure `{}` over the 28-entry toy corpus (core spec §5.1, §5.3), \
                     evaluated at the checkpoint committing the trigger.",
                    case.name
                ),
                "trigger": {
                    "statement_id": self.statement_id(case.trigger_index),
                    "entry_index": case.trigger_index,
                    "type": field_str(trigger, "type").expect("trigger type"),
                    "dataset": field_str(trigger, "dataset").expect("dataset"),
                    "record": field_str(trigger, "record").expect("record"),
                    "scope": trigger["scope"],
                },
                "corpus_checkpoint": {
                    "log_id": self.log_id,
                    "tree_size": case.through_size,
                    "root_hash": anchor.root(),
                },
                "expected_seeds": record_list(&case.expected_seeds),
                "expected_affected": record_list(&case.expected_affected),
                "note": case.note,
            });
            if trigger.get("replacement").is_some() {
                vector["trigger"]["replacement"] = trigger["replacement"].clone();
            }
            if case.trigger_index == 6 {
                vector["expected_dispositions"] = json!(self.tree_leaves(&self.affected_root));
                vector["affected_root"] = json!(self.affected_root);
                vector["affected_count"] = json!(self.tree_leaves(&self.affected_root).len());
            }
            write_json(&dir.join(format!("{}.json", case.name)), &vector);
        }
    }
}

/// A corpus index as a `usize`. The corpus has twenty-five entries, so this never truncates; the
/// checked form keeps the generator honest on 32-bit targets rather than relying on that.
fn at(index: u64) -> usize {
    usize::try_from(index).expect("corpus indices fit in usize")
}

fn record_list(records: &[RecordRef]) -> Vec<Value> {
    records
        .iter()
        .map(|(dataset, record)| json!({ "dataset": dataset, "record": record }))
        .collect()
}

/// Witness refusal evidence: the log signed a second, different root at a tree size the
/// witness had already cosigned (spec §3.3 step 3, adaptor profile §6.1).
fn refusal_evidence(keys: &Keys, log_id: &str, retained: &Anchor) -> Value {
    let conflicting_root = sha256_hex(b"ahl-test-log-1 equivocating root at tree size 13");
    let offered = checkpoint(log_id, retained.tree_size(), &conflicting_root, T0, &keys.log_1);
    let mut refusal = json!({
        "type": "witness-refusal",
        "witness_id": WITNESS_1,
        "log_id": log_id,
        "reason": "inconsistent",
        "retained": retained.checkpoint,
        "offered": offered,
        "detail": "the log offered a second checkpoint at tree_size 13 whose root differs from \
                   the one witness-1 had already cosigned; no append-only log can produce two \
                   roots at one tree size, so no consistency proof between them can exist",
        "refused_at": T0,
        "key_id": keys.witness_1.key_id(),
    });
    let signature = keys.witness_1.sign(&jcs(&refusal));
    refusal["signature"] = json!(signature);
    refusal
}

/// The closure scenarios the corpus publishes.
// A flat catalogue of scenarios, each with the prose that explains what it pins down;
// splitting it would separate the expectations from their justifications.
#[allow(clippy::too_many_lines)]
fn closure_cases(r: &Records) -> Vec<ClosureCase> {
    let customers = |record: &String| (DS_CUSTOMERS.to_owned(), record.clone());
    let scores = |record: &String| (DS_SCORES.to_owned(), record.clone());
    let sorted = |mut refs: Vec<RecordRef>| {
        refs.sort();
        refs
    };

    vec![
        ClosureCase {
            name: "toy-corpus",
            trigger_index: 6,
            through_size: 8,
            expected_seeds: vec![customers(&r.c_a)],
            expected_affected: sorted(vec![
                scores(&r.s1),
                scores(&r.s2),
                scores(&r.s3),
                scores(&r.s4),
            ]),
            note: format!(
                "The derivation at entry 7 produces S1' ({}) from the replacement A2 and is \
                 therefore NOT affected: closure traverses (dataset, record) edges only (core \
                 spec §2.3.2), and S1' never consumed the corrected record. It appears in the \
                 corpus solely as the `successor_statement` of the `recomputed` disposition of \
                 S1. This trigger is the first correction of A, so its seed set is just {{A}}: \
                 a correction never seeds its own replacement (§5.1).",
                r.s1p
            ),
        },
        ClosureCase {
            name: "supersession-chain",
            trigger_index: 12,
            through_size: 13,
            expected_seeds: sorted(vec![customers(&r.c_a), customers(&r.c_a2)]),
            expected_affected: sorted(vec![
                scores(&r.s1),
                scores(&r.s2),
                scores(&r.s3),
                scores(&r.s4),
                scores(&r.s1p),
                scores(&r.w1),
                scores(&r.w2),
            ]),
            note: format!(
                "The correction at entry 12 supersedes the correction at entry 6, which had \
                 replaced A with A2. Core spec §5.1: the later correction's seeds are the \
                 original A *and every prior superseded replacement*, here A2 — but never its \
                 own replacement A3 ({}). Seeding A2 is what pulls in S1' (entry 7) and W \
                 (entry 10); seeding only A would silently leave both outside the affected set, \
                 and seeding A3 would be wrong in the other direction. W1 and W2 are reached \
                 only through *two* committed trees — the outputs tree of the batch at entry \
                 10 and the input-set tree its leaves commit — so this closure is computable \
                 solely by a verifier holding the published leaf material (§3.5).",
                r.c_a3
            ),
        },
        ClosureCase {
            name: "non-retroactive-retraction",
            trigger_index: 17,
            through_size: 20,
            expected_seeds: vec![customers(&r.c_c)],
            expected_affected: vec![scores(&r.e2)],
            note: format!(
                "The retraction at entry 17 is `retroactive: false` with `effective_from` \
                 {T_RETRACTION}, so a derivation is affected only if its `valid_time` \
                 intersects [{T_RETRACTION}, infinity) (core spec §2.3.3). E1 ({}) has point \
                 valid_time {T_EARLY} and is NOT affected. E3 ({}) has the closed interval \
                 [{T_PAST_FROM}, {T_PAST_TO}], whose upper bound precedes the boundary, and is \
                 NOT affected. E2 ({}) has the open interval [{T_OPEN_FROM}, null) and IS \
                 affected. All three consume the retracted record C, so only the scope rule \
                 separates them.",
                r.e1, r.e3, r.e2
            ),
        },
        ClosureCase {
            name: "retraction-after-correction",
            trigger_index: 18,
            through_size: 20,
            expected_seeds: vec![customers(&r.c_a)],
            expected_affected: sorted(vec![
                scores(&r.s1),
                scores(&r.s2),
                scores(&r.s3),
                scores(&r.s4),
            ]),
            note: format!(
                "Record A was corrected twice earlier in the corpus — to A2 at entry 6 and to \
                 A3 ({}) at entry 12 — and is now RETRACTED outright at entry 18. Core spec \
                 §5.1: \"For a retraction on (ds, X), the seed set is exactly {{(ds, X)}} — \
                 retractions never seed superseded replacements.\" So the seeds are {{A}} \
                 alone, and the consumers of A2 — S1' ({}) at entry 7 and W1/W2 at entry 10 — \
                 are NOT affected. Retracting A says nothing about A2: A2 is a separately \
                 introduced record with its own history. Contrast `supersession-chain`, where \
                 a *correction* of the same original does seed A2, because that correction \
                 supersedes the one that produced it.",
                r.c_a3, r.s1p
            ),
        },
        ClosureCase {
            name: "derived-record-authority-after-rotation",
            trigger_index: 19,
            through_size: 20,
            expected_seeds: vec![scores(&r.s1p)],
            expected_affected: sorted(vec![scores(&r.w1), scores(&r.w2)]),
            note: format!(
                "S1' ({}) is a DERIVED record, introduced by the derivation at entry 7. The \
                 `key` statement at entry 9 then added producer-2 to the producer key set, and \
                 the retraction at entry 19 is signed with that post-rotation key. Core spec \
                 §2.3.3 resolves a derived record's authority as \"the introducing producer's \
                 key set as of the trigger's entry index (not the introduction index: key \
                 rotation between introduction and trigger applies)\", so this trigger IS \
                 effective. Resolving the key set at the introduction index instead would have \
                 rejected it as a challenge. The batch at entry 10 consumed S1' through its \
                 input-set tree, so W1 and W2 are the affected set.",
                r.s1p
            ),
        },
        ClosureCase {
            name: "descendant-enlargement-past-declared-checkpoint",
            trigger_index: 6,
            through_size: 28,
            expected_seeds: vec![customers(&r.c_a)],
            expected_affected: sorted(vec![
                scores(&r.s1),
                scores(&r.s2),
                scores(&r.s3),
                scores(&r.s4),
                scores(&r.z),
            ]),
            note: format!(
                "The SAME trigger as `toy-corpus`, recomputed at a much later checkpoint. At \
                 the propagation's declared checkpoint D (tree size 8) the affected set is \
                 four records; here it is five, because the derivation at entry 27 consumed S2 \
                 — an already-affected descendant — and produced Z ({}). Core spec §2.3.2 bars \
                 re-consuming the triggered record A itself, but says nothing about its \
                 descendants, so entry 27 is perfectly legal. Closure is therefore NOT stable \
                 across checkpoints, and §2.3.4 defines completeness at D only: the propagation \
                 at entry 8 remains complete at D, and the enlargement creates a fresh \
                 propagation duty (§5.2) rather than retroactively invalidating it. A \
                 `propagation-complete` receipt grounded at any checkpoint later than D would \
                 be claiming something the producer never asserted and cannot support.",
                r.z
            ),
        },
    ]
}

impl Records {
    fn build(dataset_key: &[u8]) -> Self {
        let keyed = |value: &Value| {
            commit_keyed(dataset_key, DS_CUSTOMERS, &jcs(value)).expect("32-byte dataset key")
        };
        let plain = |value: &Value| commit_plain(DS_SCORES, &jcs(value));

        let a = json!({ "customer_id": "C-1001", "country": "DE", "segment": "retail" });
        let b = json!({ "customer_id": "C-2002", "country": "FR", "segment": "sme" });
        Self {
            c_a: keyed(&a),
            c_b: keyed(&b),
            c_a2: keyed(&json!({ "customer_id": "C-1001", "country": "AT", "segment": "retail" })),
            c_a3: keyed(&json!({ "customer_id": "C-1001", "country": "CH", "segment": "retail" })),
            c_c: keyed(&json!({ "customer_id": "C-3003", "country": "ES", "segment": "retail" })),
            c_d: keyed(&json!({ "customer_id": "C-4004", "country": "IT", "segment": "sme" })),
            s1: plain(&json!({ "customer_id": "C-1001", "model": "risk-v4.2", "score": 712 })),
            s2: plain(
                &json!({ "customer_id": "C-1001", "metric": "affordability", "value_bp": 3100 }),
            ),
            s3: plain(
                &json!({ "customer_id": "C-1001", "metric": "propensity", "value_bp": 6200 }),
            ),
            s4: plain(&json!({ "customer_id": "C-1001", "metric": "churn", "value_bp": 800 })),
            s1p: plain(&json!({ "customer_id": "C-1001", "model": "risk-v4.2", "score": 698 })),
            w1: plain(&json!({ "customer_id": "C-1001", "model": "portfolio-v1", "score": 640 })),
            w2: plain(&json!({ "customer_id": "C-1001", "model": "portfolio-v1", "score": 655 })),
            e1: plain(&json!({ "customer_id": "C-3003", "model": "risk-v4.2", "score": 501 })),
            e2: plain(&json!({ "customer_id": "C-3003", "model": "risk-v4.2", "score": 502 })),
            e3: plain(&json!({ "customer_id": "C-3003", "model": "risk-v4.2", "score": 503 })),
            c_f: keyed(&json!({ "customer_id": "C-5005", "country": "PT", "segment": "retail" })),
            h: plain(&json!({ "customer_id": "C-5005", "model": "risk-v4.2", "score": 421 })),
            z: plain(&json!({ "customer_id": "C-1001", "metric": "rollup", "value_bp": 4200 })),
            c_a_bytes: jcs(&a),
            c_b_bytes: jcs(&b),
        }
    }
}
