//! The 28-entry toy corpus and every non-receipt vector file it produces.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;

use ahl_core::closure::{affected_set, RecordRef, TreeMaterial};
use ahl_core::descriptor::CanonicalizationDescriptor;
use ahl_core::{
    checkpoint, checkpoint_signing_bytes, commit_keyed, commit_plain, consistency_path_hex,
    consistency_proof, cosignature_bytes, entry_id, envelope, field_str, hash_hex, inclusion_proof,
    jcs, leaf_hash, parse_hash_hex, proof_path_hex, range_proof, record_sorted, sha256_hex,
    statement_id, tree_root, verify_consistency_proof, verify_envelope, verify_inclusion_proof,
    verify_signature,
};
use serde_json::{json, Value};

use crate::scenario::{
    leaf_bytes, manifest, payload, signed, transform, write_json, Keys, ADAPTOR_ID,
    CANONICALIZATION, DS_CUSTOMERS, DS_SCORES, LEAF_FORMAT, LOG_OPERATOR, LOG_SEED, PIPELINE, T0,
    T_EARLY, T_OPEN_FROM, T_PAST_FROM, T_PAST_TO, T_REKEY, T_RETRACTION, WITNESS_1, WITNESS_2,
};

/// The corpus prefix over which closure recomputation is defined.
///
/// Entry 37 anchors a batch whose three input-set trees deliberately break one I-D §2.7 tree
/// rule each. Closure traversal opens every committed tree it reaches and validates it against
/// those rules before reading an edge from it, so a walk reaching entry 37 fails by §2.7 —
/// which is precisely what the `record-derived-input-set-*-must-fail.ahl` vectors prove, and
/// the same shape of consequence the non-verifying envelopes at entries 32 and 33 have for
/// enumerated claims. Every closure scenario this corpus publishes stops at tree size 28 or
/// below; this constant names the boundary for the walks that would otherwise run to the end.
pub const CONFORMING_TREE_PREFIX: usize = 37;

/// Entry-index labels, one per anchored envelope.
pub const NAMES: [&str; 38] = [
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
    "28-key-readd-producer-2",
    "29-retraction-f-co-signed-authority-and-producer-2",
    "30-key-retire-producer-2-self-signed",
    "31-key-readd-producer-2-after-self-retire",
    "32-invalid-signature-trigger-f",
    "33-unverified-authority-signature-trigger-f",
    "34-ingestion-customers-e-stale-manifest",
    "35-correction-a-to-cross-dataset-replacement",
    "36-retraction-cross-dataset-record",
    "37-derivation-batch-defective-input-sets",
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

    /// This anchor's cosignature, as the one-element `anchoring.later_witnesses` array a
    /// receipt carries alongside — never inside — `anchoring.later_checkpoint` (I-D §7.1:
    /// "Present if and only if `later_checkpoint` is carried. An array in the shape of
    /// `anchoring.witnesses[]`, each element a cosignature over `later_checkpoint`"). Nesting
    /// it INSIDE the checkpoint object would change the very bytes the log's own signature
    /// (`checkpoint_signing_bytes`, "`JCS(cp)` with `signature` removed") and each
    /// cosignature's own preimage (`cosignature_bytes`, "the signed checkpoint object") are
    /// computed over.
    ///
    /// `propagation-complete`'s declared checkpoint D has no counterpart at all: format §7.2
    /// authenticates D by consistency-proof-or-prefix-recomputation, no cosignature.
    pub fn witnesses_array(&self, keys: &Keys) -> Value {
        json!([self.witness_entry(keys)])
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
    /// Introduced solely by the stale-manifest-binding negative vector's entry 32.
    pub c_e: String,
    pub h: String,
    pub z: String,
    /// Outputs of the entry-37 batch. Each leaf commits an input-set tree that breaks exactly
    /// one of the I-D §2.7 tree rules, so a receipt carrying that tree's complete leaf set is
    /// rejected by the rule it breaks rather than by a membership path.
    pub x_unsorted: String,
    pub x_duplicate: String,
    pub x_noncanonical: String,
    /// Canonical bytes of record B — the wrong bytes for the negative receipt.
    pub c_b_bytes: Vec<u8>,
    /// Record A's content, encoded AS RECEIVED — non-canonical key order and insignificant
    /// whitespace JCS strips — carried by `record-ingested-valid.ahl` (I-D §2.6/§7.2: the
    /// verifier canonicalizes the record as received before recomputing the commitment; this is
    /// what proves it actually does, rather than merely accepting already-canonical bytes and
    /// looking like it canonicalizes).
    pub c_a_bytes_as_received: Vec<u8>,
}

pub struct Corpus {
    /// The anchored envelopes, in entry-index order.
    pub envelopes: Vec<Value>,
    /// Committed tree material keyed by root (spec §3.5).
    pub trees: TreeMaterial,
    pub batch_root: String,
    pub wide_outputs_root: String,
    pub input_set_root: String,
    /// Outputs tree of the entry-37 batch (see [`Records::x_unsorted`] and its siblings).
    pub defective_outputs_root: String,
    /// Input-set roots of that batch, one per I-D §2.7 tree rule they break.
    pub unsorted_input_root: String,
    pub duplicate_input_root: String,
    pub noncanonical_input_root: String,
    pub affected_root: String,
    pub challenge_affected_root: String,
    pub records: Records,
    pub log_id: String,
    pub anchors: Vec<Anchor>,
    pub adaptor_hash: String,
    /// The exact bytes of the published adaptor document — what a `TrustPolicy` actually
    /// HOLDS (I-D §3.2, §7.5 step 2: the digest is recomputed from this, never trusted as a
    /// value carried alongside it).
    pub adaptor_document: Vec<u8>,
    pub closures: Vec<ClosureCase>,
    /// Witness refusal evidence (spec §3.3 step 3, adaptor profile §6.1).
    pub refusal: Value,
}

impl Corpus {
    // `env_10` and `env_19` differ by one character on purpose: the binding name IS the entry
    // index, which is the corpus's only ordering primitive, and renaming them would hide it.
    #[allow(clippy::similar_names)]
    #[allow(clippy::too_many_lines)] // One linear scenario; splitting it would obscure the order.
    pub fn build(
        keys: &Keys,
        dataset_key: &[u8],
        adaptor_hash: &str,
        adaptor_document: Vec<u8>,
    ) -> Self {
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
            // S2 is assessed_unaffected, not invalidated: entry 27 later derives Z from S2, and
            // spec §2.3.4 bars relying on an `invalidated` record for covered purposes, which
            // would make that derivation non-conformant. `assessed_unaffected` carries the
            // required assessment digest and is the disposition an unaffected descendant of a
            // retroactive correction can legitimately receive, so consuming S2 downstream stays
            // conforming while S2 remains, correctly, part of the affected set at D.
            json!({
                "dataset": DS_SCORES, "record": r.s2,
                "disposition": "assessed_unaffected",
                "assessment": sha256_hex(b"ahl-test-assessment-s2-unaffected"),
            }),
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
        // S2 is in the affected set the propagation at entry 8 dispositioned, at its declared
        // checkpoint D (tree size 8), as `assessed_unaffected` — not `invalidated`. Spec §2.3.2
        // bars re-consuming the *triggered* record A itself; §2.3.4 additionally bars relying on
        // an `invalidated` record, but says nothing about a merely-affected, assessed-unaffected
        // one, so consuming S2 here is unambiguously conforming. Its effect is that the
        // transitive closure of the entry-6 trigger GROWS past D: at any checkpoint committing
        // entry 27 the closure also contains Z. That is why §2.3.4 defines completeness at D
        // only, and why a `propagation-complete` receipt may never be grounded at a later
        // checkpoint.
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

        // --- entry 28: re-add producer-2 to the producer snapshot after manifest v2 dropped
        // it (spec §7.2, §2.3.6). This is what makes a genuinely CO-SIGNED trigger reachable:
        // a signer must be an active producer key at the co-signed statement's entry index,
        // and manifest v2 (entry 25) discarded producer-2. A fresh `key` "add" event brings it
        // back into force from this entry onward, exactly as entry 9 originally added it.
        let env_28 = signed(
            "key",
            &m2,
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

        // --- entry 29: a trigger on F CO-SIGNED by both the `customers` authority and
        // producer-2 --- Both signature entries are genuinely valid: `producer-1` (the
        // authority) and `producer-2` (another producer key active as of this entry, following
        // entry 28's re-add). Receipt format §5 step 3a: authorization requires AT LEAST ONE
        // verified signer to be the authority, never signing EXCLUSIVELY by authority keys — a
        // legitimately co-signed trigger like this one must still classify as authorized and
        // must still govern.
        //
        // It is anchored BEFORE the two non-verifying fixtures below, and that ordering is
        // load-bearing rather than incidental. I-D §7.5.1 4d requires every carried envelope —
        // enumerated material included — to verify under K at its own entry index, and
        // enumerated governance currency covers exactly `[0, tree_size(C))` (§7.4). A
        // non-verifying envelope anchored at index i therefore makes every enumerated claim at
        // a tree size greater than i invalid, so a corpus that placed the deliberately
        // non-verifying fixtures before this one could carry no enumerated receipt about it at
        // all. The fixtures sit at the tail for that reason.
        //
        // The three retractions of F at entries 29, 32 and 33 carry DIFFERENT `reason_code`
        // values for one reason: spec §2.1 forbids anchoring two envelopes with the same
        // statement id, and the statement id is the digest of the payload alone. Identical
        // payloads under different signature sets would be one statement anchored three times,
        // of which only the smallest entry index governs and the later two are void — so the
        // two non-verifying fixtures below could not be reasoned about, and this positive one
        // could never govern. The reason code is the payload member that carries no
        // verification weight, so it is the honest place to make them distinct.
        let f_retraction_29 = payload(
            "retraction",
            &m2,
            json!(T0),
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_f,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "superseded",
            }),
        );
        let producer_1_sig_29 = keys.producer_1.sign(&jcs(&f_retraction_29));
        let producer_2_sig_29 = keys.producer_2.sign(&jcs(&f_retraction_29));
        let mut env_29_map = serde_json::Map::new();
        env_29_map.insert("payload".to_owned(), f_retraction_29);
        env_29_map.insert(
            "signatures".to_owned(),
            json!([
                { "key_id": keys.producer_1.key_id(), "sig": producer_1_sig_29 },
                { "key_id": keys.producer_2.key_id(), "sig": producer_2_sig_29 },
            ]),
        );
        let env_29 = Value::Object(env_29_map);

        // --- entry 30: a `key` statement that RETIRES ITS OWN SIGNING KEY -----------
        // `producer-2` retires `producer-2`, signed by `producer-2`. This is conforming, and
        // it is the shape that separates the two key states I-D §7.5.1 4b keeps apart. Phase 1
        // verifies the envelope "against K AS ESTABLISHED SO FAR — the governance state in
        // force immediately before this statement's own entry index", where `producer-2` is
        // still active (entry 28 re-added it); phase 3 applies the effect only afterwards, and
        // from this index onward the key is gone. A verifier that re-verified this envelope
        // under the COMPLETED key state at its own index would resolve `producer-2` after its
        // own retirement had taken effect and reject a statement 4b accepted — which is why 4d
        // is written as "every carried envelope that is NOT part of the induction".
        let env_30 = signed(
            "key",
            &m2,
            json!({
                "action": "retire",
                "key": {
                    "key_id": keys.producer_2.key_id(),
                    "pubkey": keys.producer_2.pubkey(),
                    "valid_from": T0,
                },
            }),
            &keys.producer_2,
        );

        // --- entry 31: re-add producer-2, so the fixtures below keep their properties -------
        // Entry 30's retirement is what the self-retirement vector needs; entry 33 below needs
        // `producer-2` ACTIVE, so that its genuine `producer-2` signature entry resolves to a
        // key in force and its only defect is the non-verifying entry naming the authority.
        // Without this re-add that fixture would fail on an unresolvable key instead, and
        // would stop isolating the rule it exists for.
        let env_31 = signed(
            "key",
            &m2,
            json!({
                "action": "add",
                "key": {
                    "key_id": keys.producer_2.key_id(),
                    "pubkey": keys.producer_2.pubkey(),
                    "valid_from": T_REKEY,
                },
            }),
            &keys.producer_1,
        );

        // --- entry 32: a NON-VERIFYING trigger on F, claiming the real authority's key_id ---
        // Structurally this is a well-formed retraction of F, naming `producer-1`'s real
        // `key_id` — the genuine `customers` dataset authority — so `key_id`-only matching would
        // accept it. Its `sig` is garbage, not a signature `producer-1` ever produced. The log
        // anchors opaque bytes (spec §3 contract item 1) and does not itself validate AHL
        // signatures, so a statement like this really can get anchored; only cryptographic
        // verification of the candidate's own signature — not a claimed-`key_id` lookup — can
        // catch it. Anchored after entry 22's genuine, authorized retraction and after the
        // genuinely co-signed one at entry 29, it is what an enumeration reaching it must
        // refuse outright (I-D §7.5.1 4d).
        let mut env_32 = signed(
            "retraction",
            &m2,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_f,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "fraud",
            }),
            &keys.producer_1,
        );
        env_32["signatures"][0]["sig"] = json!(format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode([0xAAu8; 64])
        ));

        // --- entry 33: a trigger on F whose OWN envelope carries two signature entries ---
        // One entry is a genuinely valid signature from `producer-2` — a real, in-force
        // producer key (entry 31 re-added it after the self-retirement at entry 30) that is
        // NOT the `customers` dataset authority.
        // The other names `producer-1`'s real `key_id` — the genuine authority — but its `sig`
        // is garbage, not a signature `producer-1` ever produced. Anchored as its own subject
        // (not merely as a competing candidate), this entry exists to exercise the subject
        // envelope rule directly: a signer set that merely *contains* the authority's `key_id`
        // is not enough — that specific signature entry must itself cryptographically verify,
        // and one non-verifying entry invalidates the envelope however many others verify
        // (I-D §7.5.1 4d, §8.4).
        let f_retraction_33 = payload(
            "retraction",
            &m2,
            json!(T0),
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_f,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "error",
            }),
        );
        let producer_2_sig_33 = keys.producer_2.sign(&jcs(&f_retraction_33));
        let mut env_33_map = serde_json::Map::new();
        env_33_map.insert("payload".to_owned(), f_retraction_33);
        env_33_map.insert(
            "signatures".to_owned(),
            json!([
                { "key_id": keys.producer_2.key_id(), "sig": producer_2_sig_33 },
                {
                    "key_id": keys.producer_1.key_id(),
                    "sig": format!(
                        "base64:{}",
                        base64::engine::general_purpose::STANDARD.encode([0xAAu8; 64])
                    ),
                },
            ]),
        );
        let env_33 = Value::Object(env_33_map);

        // --- entry 34: an otherwise-ordinary ingestion, genuinely signed and genuinely
        // anchored — B2's own requirement is that this be real, not a standalone "malformed"
        // fixture, so the "structural wall" earlier rounds hit (mutating an anchored envelope
        // invalidates its own inclusion path) does not apply here: this envelope's payload
        // carries the wrong `manifest` reference FROM THE START, before it is ever signed or
        // included. Anchored after manifest v2 (entry 25), it wrongly names `m1` (genesis)
        // instead of `m2` (I-D §2.2: the manifest ACTIVE at an entry index is the one with the
        // greatest entry index smaller than it — here, v2). Every other member is genuine: a
        // real signature by the `customers` authority, over a real new record, real inclusion
        // in the rebuilt log tree.
        let env_34 = signed(
            "ingestion",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_e,
                "origin": "batch:2026-08-16/customers-06",
            }),
            &keys.producer_1,
        );

        // --- entries 35, 36: cross-dataset record-identity fixtures -----------------
        // I-D §2.4.2 and §7.6 make record identity the PAIR `(dataset, record)`: "Closure
        // traversal uses the `(dataset, record)` pair only", and every embedded receipt's
        // `record_subject` must match the referencing material. A commitment string alone is
        // not an identity, and these two entries are what makes the difference observable.
        //
        // Both deliberately reuse `c_a` — a commitment computed for the `customers` dataset —
        // as a `scores`-side reference. That reuse cannot arise from content: §2.6 puts `dsid`
        // in the preimage verbatim, so the same bytes in two datasets commit to different
        // strings. It arises from a PRODUCER naming the wrong pair, which nothing stops, since
        // a verifier recomputes a commitment only where content evidence is carried. A
        // verifier comparing the commitment alone accepts both of these; one comparing the
        // pair rejects both.
        //
        // Entry 35 is a correction whose REPLACEMENT is the collision: `dataset` is
        // `customers` for both members (§2.4.3 carries one dataset per correction), so it
        // claims the replacement is `customers`/S1 while S1 exists only as a `scores` record
        // produced by the derivation at entry 3.
        let env_35 = signed(
            "correction",
            &m2,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": r.c_a,
                "replacement": r.s1,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "other",
            }),
            &keys.producer_1,
        );

        // Entry 36 is a retraction whose own subject is the collision: it names the `scores`
        // dataset with record A's `customers` commitment, so a receipt for it can only be
        // supported by an introduction of `scores`/A — which the corpus does not contain, and
        // which the `customers` ingestion at entry 1 is not.
        let env_36 = signed(
            "retraction",
            &m2,
            json!({
                "dataset": DS_SCORES,
                "record": r.c_a,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "other",
            }),
            &keys.producer_1,
        );

        // --- entry 37: a batch whose leaves commit input-set trees that break §2.7 --------
        // I-D §2.7 states one set of tree rules, "identical for every AHL tree — outputs, input
        // sets, and dispositions": leaves sorted by `record` in ascending UTF-8 byte order of
        // the canonical commitment string, commitment strings that are family strings under
        // §2.1 ("one failing the rules there is rejected"), and no duplicate leaves. Membership
        // paths cannot reach any of that, because the producer who chooses the leaf order
        // chooses the tree: a set assembled in some other order opens its own root perfectly
        // well and is still not an AHL tree. So the trees below have to be genuinely built and
        // genuinely anchored — one leaf each of the batch's outputs tree commits one of them —
        // rather than mutated into a receipt, where the altered `input_set_root` would break
        // the outputs path before the rule under test was reached.
        //
        // The outputs tree itself is well formed. Only the three input-set trees are not, and
        // each breaks exactly one rule, so the negative built on it fails by that rule alone.
        let defective_input = |record: &str, role: &str| json!({ "dataset": DS_CUSTOMERS, "record": record, "role": role, "statement": id_2 });
        // Rule broken: ascending order. Both records are canonical and distinct; the leaves are
        // committed in descending order.
        let mut unsorted_input_leaves = record_sorted(vec![
            defective_input(&r.c_a2, "feature"),
            defective_input(&r.c_b, "reference"),
        ])
        .expect("distinct input records");
        unsorted_input_leaves.reverse();
        let unsorted_input_root = hash_hex(&tree_root(&leaf_bytes(&unsorted_input_leaves)));
        // Rule broken: no duplicate. One record appears twice under two roles, so the leaves
        // differ as bytes while the sort key repeats.
        let duplicate_input_leaves =
            vec![defective_input(&r.c_b, "feature"), defective_input(&r.c_b, "reference")];
        let duplicate_input_root = hash_hex(&tree_root(&leaf_bytes(&duplicate_input_leaves)));
        // Rule broken: the commitment string is not a family string under §2.1.
        let noncanonical_input_leaves = vec![defective_input("not-a-commitment", "feature")];
        let noncanonical_input_root = hash_hex(&tree_root(&leaf_bytes(&noncanonical_input_leaves)));
        let defective_leaves = record_sorted(vec![
            json!({
                "dataset": DS_SCORES, "record": r.x_unsorted,
                "inputs": { "input_set_root": unsorted_input_root, "input_set_count": 2 },
            }),
            json!({
                "dataset": DS_SCORES, "record": r.x_duplicate,
                "inputs": { "input_set_root": duplicate_input_root, "input_set_count": 2 },
            }),
            json!({
                "dataset": DS_SCORES, "record": r.x_noncanonical,
                "inputs": { "input_set_root": noncanonical_input_root, "input_set_count": 1 },
            }),
        ])
        .expect("distinct batch outputs");
        let defective_outputs_root = hash_hex(&tree_root(&leaf_bytes(&defective_leaves)));
        let env_37 = signed(
            "derivation",
            &m2,
            json!({
                "pipeline": PIPELINE,
                "outputs_root": defective_outputs_root,
                "outputs_count": defective_leaves.len(),
                "leaf_format": LEAF_FORMAT,
                "transform": transform(),
            }),
            &keys.producer_1,
        );

        let envelopes = vec![
            env_0, env_1, env_2, env_3, env_4, env_5, env_6, env_7, env_8, env_9, env_10, env_11,
            env_12, env_13, env_14, env_15, env_16, env_17, env_18, env_19, env_20, env_21, env_22,
            env_23, env_24, env_25, env_26, env_27, env_28, env_29, env_30, env_31, env_32, env_33,
            env_34, env_35, env_36, env_37,
        ];

        let mut trees = TreeMaterial::new();
        trees.insert(batch_root.clone(), batch_leaves);
        trees.insert(wide_outputs_root.clone(), wide_leaves);
        trees.insert(input_set_root.clone(), input_leaves);
        trees.insert(defective_outputs_root.clone(), defective_leaves);
        trees.insert(unsorted_input_root.clone(), unsorted_input_leaves);
        trees.insert(duplicate_input_root.clone(), duplicate_input_leaves);
        trees.insert(noncanonical_input_root.clone(), noncanonical_input_leaves);
        trees.insert(affected_root.clone(), dispositions);
        trees.insert(challenge_affected_root.clone(), challenge_dispositions);

        let log_leaves = leaf_bytes(&envelopes);
        let anchors = [
            (8u64, 0u64),
            (13, 0),
            (20, 0),
            (24, 0),
            (25, 0),
            // cp26: manifest_index 0 is deliberate, not the checkpoint's true active manifest
            // (v2, entry 25) — this is the I-D §7.1 rotation-anchoring EXCEPTION's own
            // checkpoint, which binds to the manifest version active IMMEDIATELY BEFORE the
            // rotating manifest's entry index (the OUTGOING state), never to the version the
            // rotation installs. Operationally it is "an ordinary artifact of the rotation": the
            // log operator anchored manifest v2 at entry 25 and kept signing checkpoints
            // cosigned by the OUTGOING witness (witness-1) for a few more entries before cutting
            // over to witness-2, which is exactly what I-D §7.1 says makes such a checkpoint
            // realizable against a real log rather than something an operator must manufacture.
            (26, 0),
            (28, 25),
            (29, 25),
            (30, 25),
            // cp32 covers [0, 32) — every entry through the `key` re-add at entry 31, and
            // nothing beyond it. It is the only checkpoint whose enumerated prefix reaches the
            // self-retiring `key` statement at entry 30 while stopping short of the two
            // deliberately non-verifying fixtures at entries 32 and 33.
            (32, 25),
            (34, 25),
            (35, 25),
            (37, 25),
            (38, 25),
        ]
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
                    26 => "cp26",
                    28 => "cp28",
                    29 => "cp29",
                    30 => "cp30",
                    32 => "cp32",
                    34 => "cp34",
                    35 => "cp35",
                    37 => "cp37",
                    _ => "cp38",
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
            defective_outputs_root,
            unsorted_input_root,
            duplicate_input_root,
            noncanonical_input_root,
            affected_root,
            challenge_affected_root,
            records,
            log_id,
            anchors,
            adaptor_hash: adaptor_hash.to_owned(),
            adaptor_document,
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

    /// Re-anchor a receipt whose carried governance material was deliberately substituted.
    ///
    /// I-D §7.5 step 3 recomputes EVERY `governance.chain[]` element's inclusion path — and the
    /// subject's — before step 4's induction reads a single member of any of them, because
    /// "the path proof IS the index proof": a governance statement whose asserted entry index
    /// is unproven could be presented in an order the log never had. A negative vector that
    /// substitutes a governance statement therefore has to put it genuinely IN the log, or it
    /// fails as an unanchored hop rather than by the rule it names.
    ///
    /// So the log tree is rebuilt over the substituted envelopes, the checkpoint re-signed by
    /// the same log key over the new root, and its cosignature reissued by the same witness.
    /// Everything the receipt asserts about anchoring is then true; the one thing wrong with it
    /// is the rule the vector exists to trip.
    pub fn reanchor(&self, receipt: &mut Value, keys: &Keys) {
        let mut envelopes = self.envelopes.clone();
        let chain = receipt["governance"]["chain"].as_array().expect("chain").clone();
        for hop in &chain {
            let index = usize::try_from(hop["entry_index"].as_u64().expect("entry_index"))
                .expect("entry index fits");
            envelopes[index] = hop["envelope"].clone();
        }
        let leaves = leaf_bytes(&envelopes);
        let checkpoint_object = receipt["anchoring"]["checkpoint"].clone();
        let tree_size = checkpoint_object["tree_size"].as_u64().expect("tree_size");
        let prefix = &leaves[..at(tree_size)];
        let root = hash_hex(&tree_root(prefix));

        let path = |index: u64| {
            let index = usize::try_from(index).expect("entry index fits");
            json!(proof_path_hex(
                &inclusion_proof(prefix, index).expect("the entry is within the checkpoint")
            ))
        };
        receipt["anchoring"]["inclusion_path"] =
            path(receipt["subject"]["entry_index"].as_u64().expect("entry_index"));
        for hop in receipt["governance"]["chain"].as_array_mut().expect("chain") {
            hop["inclusion_path"] = path(hop["entry_index"].as_u64().expect("entry_index"));
        }

        let log_key = keys.by_key_id(field_str(&checkpoint_object, "key_id").expect("key_id"));
        let reissued = checkpoint(
            field_str(&checkpoint_object, "log_id").expect("log_id"),
            tree_size,
            &root,
            field_str(&checkpoint_object, "checkpoint_time").expect("checkpoint_time"),
            log_key,
        );
        for cosignature in receipt["anchoring"]["witnesses"].as_array_mut().expect("witnesses") {
            let witness_id = field_str(cosignature, "witness_id").expect("witness_id").to_owned();
            let witness = keys.by_key_id(field_str(cosignature, "key_id").expect("key_id"));
            cosignature["cosignature"] =
                json!(witness.sign(&cosignature_bytes(&reissued, &witness_id)));
        }
        receipt["anchoring"]["checkpoint"] = reissued;
    }

    /// The `governance.rotation_proofs[]` element for manifest v2's rotation at entry 25 (I-D
    /// §7.1): `cp26` — signed by the log key (unchanged across the rotation in this corpus) and
    /// cosigned by the OUTGOING witness, witness-1 — proves the rotating manifest's own
    /// anchoring under the state it retires. This corpus has exactly one governance-key
    /// rotation, so one element suffices for every vector whose chain carries manifest v2.
    pub fn rotation_proof_element(&self, keys: &Keys) -> Value {
        let cp26 = self.anchor("cp26");
        json!({
            "manifest_entry_index": 25,
            "checkpoint": cp26.checkpoint,
            "inclusion_path": self.log_path(25, cp26.tree_size()),
            "witnesses": [ cp26.witness_entry(keys) ],
        })
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

    /// The RFC 9162 consistency path between two published tree sizes (adaptor profile §9).
    ///
    /// The sizes are not part of the serialization: they come from the two checkpoints the
    /// proof runs between, which is what binds a proof to one specific pair.
    pub fn consistency_path(&self, from_size: u64, to_size: u64) -> Vec<String> {
        let proof = consistency_proof(&self.log_leaves(), from_size, to_size)
            .expect("both sizes are within the corpus");
        consistency_path_hex(&proof)
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
        self.check_statement_ids_are_unique();
        self.check_signatures(keys);
        self.check_anchors(keys);
        self.check_trees();
        self.check_range_proofs();
        self.check_consistency_proofs();
        self.check_refusal(keys);
        self.check_closures();
    }

    /// Spec §2.1: a producer MUST NOT anchor two envelopes with the same statement id, and
    /// where duplicates occur the smallest entry index governs while later ones are void.
    ///
    /// A corpus that broke this rule could not demonstrate the rules it exists for: a vector
    /// asserting that some later entry governs would be asserting the opposite of §2.1, and no
    /// reader could tell the intended lesson from the accident. Entry ids are checked too — two
    /// envelopes sharing one would be one anchored entry counted twice.
    fn check_statement_ids_are_unique(&self) {
        let mut statements: BTreeMap<String, usize> = BTreeMap::new();
        let mut entries: BTreeMap<String, usize> = BTreeMap::new();
        for (index, env) in self.envelopes.iter().enumerate() {
            let sid = statement_id(env).expect("well-formed envelope");
            if let Some(first) = statements.insert(sid.clone(), index) {
                panic!(
                    "entries {first} and {index} share statement id {sid}: spec §2.1 voids the \
                     later one, so the corpus cannot demonstrate anything about it"
                );
            }
            let eid = entry_id(env);
            if let Some(first) = entries.insert(eid.clone(), index) {
                panic!("entries {first} and {index} share entry id {eid}");
            }
        }
        println!(
            "  [ok] {} anchored envelopes carry {} distinct statement ids and {} distinct entry \
             ids (spec §2.1 payload uniqueness)",
            self.envelopes.len(),
            statements.len(),
            entries.len()
        );
    }

    fn check_signatures(&self, keys: &Keys) {
        // Entries 32 and 33 are intentionally non-verifying vector fixtures: well-formed
        // retractions naming the real authority's `key_id` with garbage `sig` bytes (entry 33
        // also carries a second, genuinely valid entry from a non-authority key). Every OTHER
        // entry must genuinely verify; these two must genuinely NOT — both are asserted below,
        // so a generator bug that accidentally produced a valid signature (defeating the
        // vector's purpose) or an invalid one elsewhere (a real regression) would each be
        // caught.
        const NON_VERIFYING_ENTRIES: [usize; 2] = [32, 33];
        for (index, env) in self.envelopes.iter().enumerate() {
            if NON_VERIFYING_ENTRIES.contains(&index) {
                continue;
            }
            let ok = verify_envelope(env, |key_id| keys.resolve(key_id))
                .expect("generated envelope is well-formed");
            assert!(ok, "entry {index}: envelope signature did not verify");
        }
        for index in NON_VERIFYING_ENTRIES {
            let ok = verify_envelope(&self.envelopes[index], |key_id| keys.resolve(key_id))
                .expect("non-verifying envelope is still well-formed JSON");
            assert!(
                !ok,
                "entry {index}: the non-verifying-signature fixture must NOT verify, or it \
                 isn't one"
            );
        }
        println!(
            "  [ok] {} genuine envelope signatures verified, entries {NON_VERIFYING_ENTRIES:?} \
             confirmed non-verifying",
            self.envelopes.len() - NON_VERIFYING_ENTRIES.len()
        );

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
                let mut tampered = hashes[at(from)..at(to)].to_vec();
                tampered[0] = leaf_hash(b"tampered entry");
                assert!(
                    !range_proof::verify(&proof, &tampered, &root).expect("well-formed proof"),
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

    /// Every published checkpoint pair must be provably append-only, and a proof generated for
    /// one pair must not validate another (adaptor profile §9).
    fn check_consistency_proofs(&self) {
        let leaves = self.log_leaves();
        let root_at = |size: u64| tree_root(&leaves[..at(size)]);
        let mut pairs = 0;
        for older in &self.anchors {
            for newer in &self.anchors {
                if newer.tree_size() < older.tree_size() {
                    continue;
                }
                let path = self.consistency_path(older.tree_size(), newer.tree_size());
                let proof =
                    ahl_core::consistency_from_hex(older.tree_size(), newer.tree_size(), &path)
                        .expect("generated path is well formed");
                assert!(
                    verify_consistency_proof(
                        &proof,
                        &parse_hash_hex(older.root()).expect("root hash"),
                        &parse_hash_hex(newer.root()).expect("root hash"),
                    )
                    .expect("well-formed proof"),
                    "{} -> {}: consistency proof did not verify",
                    older.name,
                    newer.name
                );
                pairs += 1;
            }
        }

        // A proof for a DIFFERENT pair must not validate this one. Without this, a verifier
        // that checked only "does a path open something?" would accept a proof about sizes the
        // claim never mentioned — the same defect adaptor profile §6.1 pins down for refusal
        // evidence, in a different place.
        let wrong = ahl_core::consistency_from_hex(20, 24, &self.consistency_path(8, 24))
            .expect("well-formed path");
        assert!(
            !verify_consistency_proof(&wrong, &root_at(20), &root_at(24)).unwrap_or(false),
            "a consistency proof generated for [8, 24) must not verify as one for [20, 24)"
        );
        println!(
            "  [ok] {pairs} consistency proofs verified between published checkpoints, and a \
             proof for the wrong pair of sizes was rejected (adaptor profile §9)"
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
            affected_set(&self.envelopes, &self.trees, 6, CONFORMING_TREE_PREFIX).expect("corpus");
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
            CONFORMING_TREE_PREFIX
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
                "reason_taxonomy": [ "equivocation", "size-regression", "extension-failed" ],
                "recheck": "for `equivocation`: retained.tree_size == offered.tree_size AND \
                            retained.root_hash != offered.root_hash, over two carried, \
                            log-signed checkpoints. `proof` MUST be absent — it is required \
                            only for `extension-failed`.",
                "expect": "accept as evidence of log equivocation: both checkpoints carry valid \
                           log-1 signatures, `tree_size` is equal and `root_hash` differs, which \
                           no append-only log can produce",
                "refusal": self.refusal,
            }),
        );
    }

    // A flat list of statement-vector writes, one per corpus entry plus the malformed fixtures;
    // splitting adds no clarity, matching `write_merkle` below.
    #[allow(clippy::too_many_lines)]
    fn write_statements(&self, root: &Path, keys: &Keys) {
        let statements = root.join("vectors").join("statements");
        for (index, env) in self.envelopes.iter().enumerate() {
            let mut vector = json!({
                "entry_index": index,
                "statement_id": statement_id(env).expect("well-formed envelope"),
                "entry_id": entry_id(env),
                "envelope": env,
            });
            if index == 30 {
                // Structurally a well-formed AHL statement (statement_id/entry_id are ordinary
                // digests of it), anchored like any other entry — but its `sig` is garbage, not
                // a signature `producer-1` ever produced, even though `signatures[0].key_id`
                // names `producer-1`'s real key. The log anchors opaque bytes and does not
                // itself validate AHL signatures (core spec §3 contract item 1), so this is what
                // a real non-verifying statement anchored in the log looks like. It exists to
                // prove that enumerated material is verified envelope by envelope rather than
                // trusted on a claimed `key_id` (I-D §7.5.1 4d).
                vector["note"] = json!(
                    "INTENTIONALLY NON-VERIFYING: `signatures[0].sig` does not verify against \
                     `signatures[0].key_id`'s real public key. See \
                     trigger-effective-non-verifying-candidate-must-fail.ahl."
                );
            }
            if index == 31 {
                // Structurally well-formed, carrying two signature entries: a genuinely valid
                // one from `producer-2` (not the `customers` authority) and one naming
                // `producer-1`'s real key_id (the genuine authority) whose `sig` is garbage. It
                // exists to prove that a signature entry merely naming the authority's key_id
                // is not enough — that specific entry must itself cryptographically verify, or
                // the envelope cannot ground any claim (receipt §5 step 4).
                vector["note"] = json!(
                    "INTENTIONALLY NON-VERIFYING: `signatures[1].sig` (the entry naming the \
                     dataset authority's real key_id) does not verify against that key_id's \
                     real public key, even though `signatures[0]` is a genuine signature from a \
                     non-authority producer key. See \
                     trigger-effective-unverified-authority-signature-must-fail.ahl."
                );
            }
            write_json(&statements.join(format!("{}.json", NAMES[index])), &vector);
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

        // I-D revision 0.4 §2.6 / §6.3: "A dataset id MUST NOT contain a control octet: any
        // octet in 0x00 through 0x1F inclusive, or 0x7F" — stated as its own normative
        // requirement because it is load-bearing (an implementation validating only length and
        // printability could still admit it). §6.3's conformance table then makes a
        // syntactically invalid dataset declaration reject the WHOLE manifest, not merely the
        // affected dataset's claims: "A dataset's canonicalization descriptor is a required
        // manifest member (§6.2), and statements derive their governance from that manifest
        // (§2.2)". Each vector below is an otherwise-genuine genesis manifest with the `scores`
        // dataset renamed to an id carrying the offending octet.
        for (label, octet_char, octet_name) in [
            ("dataset-id-control-octet-0x1f", '\u{1f}', "0x1F"),
            ("dataset-id-control-octet-0x7f", '\u{7f}', "0x7F"),
        ] {
            let mut bad_manifest = manifest(keys, &self.log_id, &self.adaptor_hash, 0, None);
            let datasets = bad_manifest["datasets"].as_object_mut().expect("datasets object");
            let scores = datasets.remove(DS_SCORES).expect("scores dataset declared");
            datasets.insert(format!("scores{octet_char}bad"), scores);
            write_json(
                &malformed.join(format!("{label}.json")),
                &json!({
                    "name": label,
                    "expect": format!(
                        "reject: I-D revision 0.4 §2.6 — \"A dataset id MUST NOT contain a \
                         control octet\" ({octet_name} here); §6.3's conformance table makes a \
                         syntactically invalid dataset declaration reject the WHOLE manifest, \
                         not merely the affected dataset's claims",
                    ),
                    "envelope": envelope(bad_manifest, &keys.producer_1),
                }),
            );
        }
    }

    // A flat list of tree-vector writes, one per committed tree; splitting adds no clarity.
    #[allow(clippy::too_many_lines)]
    fn write_merkle(&self, root: &Path) {
        let merkle = root.join("vectors").join("merkle");
        let cp28 = self.anchor("cp28");
        // The `inclusion` block below is claimed against cp28's own root, so its proof must be
        // computed over exactly cp28's 28 leaves — the corpus has since grown further entries
        // that cp28 never committed.
        let leaves = &self.log_leaves()[..at(cp28.tree_size())];
        let proof_3 = inclusion_proof(leaves, 3).expect("entry 3 is in the log");
        write_json(
            &merkle.join("log-tree.json"),
            &json!({
                "description": "AHL log tree over the toy corpus. Leaves are the anchored entry \
                                bytes JCS(envelope) in entry-index order and are never sorted \
                                (core spec §2.5, §1.2).",
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
        let cp28 = self.anchor("cp28");
        // Scoped to cp28's own tree size (28): the corpus grows further entries past it, and
        // this vector's proofs must stay over exactly the leaf set cp28 actually commits, not
        // whatever the log has grown to since.
        let leaves = &self.log_leaves()[..at(cp28.tree_size())];
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
///
/// The reason is `equivocation`. That is the only reason this evidence supports: the taxonomy
/// is `equivocation | size-regression | extension-failed`, each independently recheckable from
/// what the refusal itself carries, and here the recheck is exactly `retained.tree_size ==
/// offered.tree_size` with `retained.root_hash != offered.root_hash` over two log-signed
/// checkpoints. `proof` is deliberately absent: it is required only for `extension-failed`, and
/// a carried proof no reason directs a verifier to check is unverified material inviting
/// misreading.
fn refusal_evidence(keys: &Keys, log_id: &str, retained: &Anchor) -> Value {
    let conflicting_root = sha256_hex(b"ahl-test-log-1 equivocating root at tree size 13");
    let offered = checkpoint(log_id, retained.tree_size(), &conflicting_root, T0, &keys.log_1);
    let mut refusal = json!({
        "type": "witness-refusal",
        "witness_id": WITNESS_1,
        "log_id": log_id,
        "reason": "equivocation",
        "retained": retained.checkpoint,
        "offered": offered,
        "detail": "the log offered a second checkpoint at tree_size 13 whose root differs from \
                   the one witness-1 had already cosigned; no append-only log can produce two \
                   roots at one tree size",
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
        // I-D §2.6: the descriptor digest `ddig` is part of every commitment preimage. Both
        // corpus datasets declare the identical descriptor (`{"canonicalization": "jcs"}`, no
        // `media_type` — `jcs` does not require one, see the manifest's `datasets` block in
        // `scenario::manifest`), so `ddig` is the same value for both; the two datasets still
        // commit to disjoint preimages, because domain separation by `dsid` holds
        // unconditionally, independent of whether `ddig` also differs (I-D §2.6).
        let ddig = CanonicalizationDescriptor::new(CANONICALIZATION, None)
            .expect("committed canonicalization identifier is syntactically valid")
            .ddig();
        let keyed = |value: &Value| {
            commit_keyed(dataset_key, DS_CUSTOMERS, &ddig, &jcs(value))
                .expect("32-byte dataset key and a valid dataset id")
        };
        let plain =
            |value: &Value| commit_plain(DS_SCORES, &ddig, &jcs(value)).expect("valid dataset id");

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
            c_e: keyed(&json!({ "customer_id": "C-6006", "country": "NL", "segment": "retail" })),
            h: plain(&json!({ "customer_id": "C-5005", "model": "risk-v4.2", "score": 421 })),
            z: plain(&json!({ "customer_id": "C-1001", "metric": "rollup", "value_bp": 4200 })),
            x_unsorted: plain(
                &json!({ "customer_id": "C-7007", "model": "portfolio-v1", "score": 701 }),
            ),
            x_duplicate: plain(
                &json!({ "customer_id": "C-7007", "model": "portfolio-v1", "score": 702 }),
            ),
            x_noncanonical: plain(
                &json!({ "customer_id": "C-7007", "model": "portfolio-v1", "score": 703 }),
            ),
            c_b_bytes: jcs(&b),
            // Same value as `a` above (I-D §2.6 "canonicalization equality is syntactic, not
            // semantic"), deliberately serialized in non-canonical key order with insignificant
            // whitespace: JCS (RFC 8785) sorts object members and admits no whitespace between
            // tokens, so `jcs()` of this text equals `jcs(&a)` exactly, and the record
            // commitment `c_a` — computed from `jcs(&a)` above — is unchanged.
            c_a_bytes_as_received:
                br#"{"customer_id": "C-1001", "country": "DE", "segment": "retail"}"#.to_vec(),
        }
    }
}
