//! A second toy log, bound to adaptor profile `ahl-adaptor-atl-v1`.
//!
//! The main corpus binds `ahl-test-log-v1`, whose log leaf is the anchored entry bytes. This
//! one exists so the pieces that DIFFER under the ATL binding are exercised end to end rather
//! than at the unit level: the two-digest leaf construction of adaptor §4.2, the origin-derived
//! `log_id` of §7.1, the 98-byte checkpoint blob of §6.1 with the `raw` framing of §6.4, and the
//! range-proof/inclusion geometry that follows from the leaf change (§8.2, §10.4).
//!
//! It is deliberately small — one manifest, two ingestions and a derivation — because what it
//! has to show is a serialization difference, not a scenario. Everything a scenario would need
//! is already proven over the main corpus, and both profiles share every rule that is not the
//! log leaf, the checkpoint signing bytes or the `raw` framing.
//!
//! **The profile is PRE-RELEASE.** Its §14 makes release a precondition for use: "Until this
//! document is released as an immutable, openly published artifact at a stable location, its
//! digest is not stable and no manifest may pin it." The digest this corpus pins is the CURRENT
//! DRAFT's, and it is a TEST-ONLY pin. A production manifest MUST NOT pin the profile until
//! that obligation is met, and the digest will change when it is.

use std::path::Path;

use ahl_core::receipt::{
    verify_receipt, verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Outcome,
    ReceiptError, TrustPolicy,
};
use ahl_core::{
    atl_checkpoint, atl_checkpoint_blob_from_json, atl_log_id, cosignature_bytes, entry_id,
    envelope, hash_hex, inclusion_proof, jcs, leaf_hash, log_leaf_bytes_for, parse_hash_hex,
    proof_path_hex, sha256_hex, statement_id, tree_root, verify_envelope, verify_inclusion_proof,
    verify_signature, TestKey, ATL_PROFILE_ID,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::corpus::Records;
use crate::scenario::{
    manifest, signed, transform, write_jcs, write_json, write_text, Keys, DS_CUSTOMERS, DS_SCORES,
    PIPELINE, T0, WITNESS_1,
};
use crate::text::ATL_ADAPTOR_DOC;

/// The 16-byte ATL Data Tree UUID this corpus is bound to.
///
/// A committed constant of trivially repeating bytes, like every key seed here: adaptor §7.1
/// derives the Origin ID from it as `SHA-256(uuid)` and the `log_id` as `"sha256:" ||
/// hex(Origin ID)`, so the identifier is not free-form and the corpus must say what it came
/// from. A verifier never needs the UUID itself.
const TREE_UUID: [u8; 16] = [0x0A; 16];

/// The checkpoint timestamp, in Unix nanoseconds.
///
/// `2026-08-16T12:00:00.123456789Z` — the corpus reference instant with a fractional part, so
/// the §6.3 rendering rule ("exactly nine fractional digits") is exercised by a value that
/// actually has nine significant ones. It sits inside `[cadence_epoch, cadence_epoch + PT1H]`,
/// the window core spec §7.3 requires of the earliest checkpoint committing the genesis
/// manifest.
const CHECKPOINT_NANOS: u64 = 1_786_881_600_123_456_789;

/// A metadata digest that is NOT the one adaptor §4.2 pins, for the negative that proves the
/// constant is load-bearing.
const WRONG_METADATA: &str = r#"{"ahl_adaptor":"not-this-profile"}"#;

/// Entry-index labels, one per anchored envelope.
const NAMES: [&str; 4] = [
    "00-manifest-genesis",
    "01-ingestion-customers-a",
    "02-ingestion-customers-b",
    "03-derivation-s1",
];

/// The ATL-bound corpus and everything derived from it.
pub struct AtlCorpus {
    log_id: String,
    envelopes: Vec<Value>,
    adaptor_hash: String,
    adaptor_document: Vec<u8>,
    /// The published checkpoint over `[0, 4)`, in ATL form with its `raw` framing.
    checkpoint: Value,
    cosignature: String,
    /// A second, genuinely signed checkpoint over the SAME entries hashed with a metadata
    /// digest this profile does not pin — the fixture behind the leaf-construction negative.
    wrong_metadata_checkpoint: Value,
    wrong_metadata_cosignature: String,
}

impl AtlCorpus {
    pub fn build(keys: &Keys, records: &Records, root: &Path) -> Self {
        let (adaptor_hash, adaptor_document) = write_and_hash_atl_adaptor(root);
        let log_id = atl_log_id(&TREE_UUID);

        // Entry 0: the genesis manifest. `scenario::manifest` builds the whole §7.2/§7.3 shape;
        // only the adaptor id differs, since the hash and the log id are already parameters.
        let mut genesis = manifest(keys, &log_id, &adaptor_hash, 0, None);
        genesis["log"]["adaptor"]["id"] = json!(ATL_PROFILE_ID);
        let env_0 = envelope(genesis, &keys.producer_1);
        let m1 = statement_id(&env_0).expect("well-formed envelope");

        let ingest = |record: &str, batch: &str| json!({ "dataset": DS_CUSTOMERS, "record": record, "origin": format!("batch:{batch}") });
        let env_1 =
            signed("ingestion", &m1, ingest(&records.c_a, "2026-08-16/atl-01"), &keys.producer_1);
        let id_1 = statement_id(&env_1).expect("well-formed envelope");
        let env_2 =
            signed("ingestion", &m1, ingest(&records.c_b, "2026-08-16/atl-01"), &keys.producer_1);
        let id_2 = statement_id(&env_2).expect("well-formed envelope");
        let env_3 = signed(
            "derivation",
            &m1,
            json!({
                "pipeline": PIPELINE,
                "outputs": [ { "dataset": DS_SCORES, "record": records.s1, "locator": "urn:ahl-test:scores/S1" } ],
                "inputs": [
                    { "dataset": DS_CUSTOMERS, "record": records.c_a, "role": "feature", "statement": id_1 },
                    { "dataset": DS_CUSTOMERS, "record": records.c_b, "role": "reference", "statement": id_2 },
                ],
                "transform": transform(),
            }),
            &keys.producer_1,
        );

        let envelopes = vec![env_0, env_1, env_2, env_3];
        let tree_size = envelopes.len() as u64;

        let root_hash = hash_hex(&tree_root(&atl_leaves(&envelopes)));
        let mut checkpoint =
            atl_checkpoint(&log_id, tree_size, &root_hash, CHECKPOINT_NANOS, &keys.log_1)
                .expect("family strings over 32 octets");
        // Adaptor §6.4: `raw` is the base64 of the same 98 octets the signature covers. It is a
        // convenience rather than a trust step — a verifier that reconstructs the blob from the
        // parsed object per §6.5 obtains the same bytes — so it is carried here precisely to be
        // reconciled against them.
        let blob = atl_checkpoint_blob_from_json(&checkpoint).expect("well-formed checkpoint");
        checkpoint["raw"] =
            json!(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(blob)));
        let cosignature = keys.witness_1.sign(&cosignature_bytes(&checkpoint, WITNESS_1));

        // The same entries under a metadata digest this profile does not pin. Adaptor §4.2: "An
        // entry whose ATL metadata is anything else is NOT an AHL entry under this profile and
        // MUST be rejected by an AHL verifier, even if it is a valid ATL entry." The checkpoint
        // over that tree is genuinely signed and genuinely cosigned, so nothing about it is
        // malformed — only the leaves are built the wrong way, which is exactly what a verifier
        // using the wrong constant would fail to notice.
        let wrong_root = hash_hex(&tree_root(&wrong_metadata_leaves(&envelopes)));
        let mut wrong_metadata_checkpoint =
            atl_checkpoint(&log_id, tree_size, &wrong_root, CHECKPOINT_NANOS, &keys.log_1)
                .expect("family strings over 32 octets");
        let wrong_blob = atl_checkpoint_blob_from_json(&wrong_metadata_checkpoint)
            .expect("well-formed checkpoint");
        wrong_metadata_checkpoint["raw"] = json!(format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(wrong_blob)
        ));
        let wrong_metadata_cosignature =
            keys.witness_1.sign(&cosignature_bytes(&wrong_metadata_checkpoint, WITNESS_1));

        Self {
            log_id,
            envelopes,
            adaptor_hash,
            adaptor_document,
            checkpoint,
            cosignature,
            wrong_metadata_checkpoint,
            wrong_metadata_cosignature,
        }
    }

    /// The tree size the published checkpoint commits: `[0, tree_size)`, all of this corpus.
    fn tree_size(&self) -> u64 {
        u64::try_from(self.envelopes.len()).expect("a four-entry corpus")
    }

    /// Assemble one receipt over this corpus.
    fn receipt(&self, keys: &Keys, spec: &AtlSpec<'_>) -> Value {
        let &AtlSpec {
            claim_type,
            subject_index,
            record_subject,
            checkpoint,
            cosignature,
            leaves,
            note,
        } = spec;
        let subject = &self.envelopes[subject_index];
        let mut claim = json!({
            "type": claim_type,
            "assurance": {
                "governance": "declared",
                "competing_triggers": "not-checked",
                "witnessed": true,
                "continued_history": false,
                "content_binding": "none",
            },
            "note": note,
        });
        if let Some((dataset, record)) = record_subject {
            claim["record_subject"] = json!({ "dataset": dataset, "record": record });
        }
        let mut subject_block = json!({
            "statement_id": statement_id(subject).expect("well-formed envelope"),
            "entry_id": entry_id(subject),
            "entry_index": subject_index,
        });
        if let Some(version) = subject["payload"].get("manifest") {
            subject_block["manifest"] = version.clone();
        }
        json!({
            "ahl_receipt_version": "2",
            "spec_version": "0.4.0",
            "claim": claim,
            "subject": subject_block,
            "envelope": subject,
            "keys": {
                "log": [ key_entry(&keys.log_1, None) ],
                "witness": [ key_entry(&keys.witness_1, Some(WITNESS_1)) ],
                "producer": [ json!({
                    "key_id": keys.producer_1.key_id(),
                    "pubkey": keys.producer_1.pubkey(),
                    "source": "manifest-chain",
                    "binding": { "entry_index": 0 },
                }) ],
            },
            "anchoring": {
                "adaptor": { "id": ATL_PROFILE_ID, "hash": self.adaptor_hash },
                "checkpoint": checkpoint,
                "inclusion_path": path(subject_index, leaves),
                "witnesses": [ witness_entry(keys, cosignature) ],
            },
            "governance": {
                "genesis_entry_id": entry_id(&self.envelopes[0]),
                "chain": [ json!({
                    "envelope": self.envelopes[0],
                    "entry_index": 0,
                    "inclusion_path": path(0, leaves),
                }) ],
                "currency": { "mode": "declared", "material": {} },
            },
            "claim_material": {},
        })
    }

    /// The trust policy the ATL vectors' outcomes assume.
    ///
    /// A separate policy from the main corpus's, and it has to be: a trust policy names ONE
    /// published genesis anchor (I-D §7.5.1 4a), and this is a different log with a different
    /// genesis manifest. The two vector sets therefore carry their own `index.json` each,
    /// with the policy its outcomes assume beside it.
    pub fn trust_policy(&self, keys: &Keys) -> TrustPolicy {
        TrustPolicy {
            genesis_entry_id: entry_id(&self.envelopes[0]),
            genesis_key_ids: Some(std::iter::once(keys.producer_1.key_id()).collect()),
            adaptor_profiles: std::iter::once((
                ATL_PROFILE_ID.to_owned(),
                AdaptorProfile {
                    document: self.adaptor_document.clone(),
                    capabilities: AdaptorCapabilities {
                        // Adaptor §13: the profile DEFINES a binary checkpoint framing (§6.4)
                        // and a consistency-proof serialization (§8.3). Serving consistency
                        // proofs is a deployment obligation the profile names as unmet on the
                        // published ATL stack; what the capability records is what the PROFILE
                        // defines, which is what decides whether a receipt's members are
                        // interpretable.
                        checkpoint_raw: true,
                        consistency_proofs: true,
                    },
                },
            ))
            .collect(),
            dataset_keys: std::collections::BTreeMap::new(),
            trusted_witness_keys: std::collections::BTreeMap::new(),
            limits: ahl_core::receipt::Limits::default(),
        }
    }

    /// Re-verify everything this corpus publishes, and abort on any mismatch.
    pub fn self_check(&self, keys: &Keys) {
        println!("ATL-profile corpus self-check");
        for (index, env) in self.envelopes.iter().enumerate() {
            assert!(
                verify_envelope(env, |key_id| keys.resolve(key_id)).expect("well-formed envelope"),
                "ATL entry {index}: envelope signature did not verify"
            );
        }

        // Adaptor §4.2: the leaf is `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`,
        // and its first digest is the raw form of the AHL entry id — so the entry id stays
        // derivable from the entry bytes alone even though the leaf is not the entry bytes.
        for env in &self.envelopes {
            let preimage = log_leaf_bytes_for(env, ATL_PROFILE_ID).expect("known profile");
            assert_eq!(preimage.len(), 64);
            assert_eq!(&preimage[..32], &parse_hash_hex(&entry_id(env)).expect("entry id")[..]);
            assert_eq!(&preimage[32..], &ahl_core::atl_metadata_hash()[..]);
        }

        let leaves = atl_leaves(&self.envelopes);
        let root = tree_root(&leaves);
        assert_eq!(
            hash_hex(&root),
            self.checkpoint["root_hash"].as_str().expect("root_hash"),
            "the published checkpoint must commit the ATL-geometry root"
        );
        // The two geometries really do differ: a verifier applying the main corpus's leaf rule
        // to this log would recompute a different root for the same entries.
        let plain: Vec<Vec<u8>> = self.envelopes.iter().map(jcs).collect();
        assert_ne!(hash_hex(&tree_root(&plain)), hash_hex(&root));

        for index in 0..self.envelopes.len() {
            let proof = inclusion_proof(&leaves, index).expect("index within the tree");
            assert!(
                verify_inclusion_proof(&leaves[index], &proof, &root).expect("well-formed proof"),
                "ATL entry {index}: inclusion proof did not verify"
            );
        }

        // §6.5: the signature is over the 98-byte blob assembled from the JSON members, and a
        // carried `raw` must equal that blob byte for byte.
        let blob = atl_checkpoint_blob_from_json(&self.checkpoint).expect("well-formed checkpoint");
        assert!(
            verify_signature(
                &keys.log_1.verifying_key(),
                &blob,
                self.checkpoint["signature"].as_str().expect("signature"),
            )
            .expect("well-formed signature"),
            "the ATL checkpoint signature did not verify over the 98-byte blob"
        );
        ahl_core::reconcile_atl_checkpoint_raw(
            &self.checkpoint,
            self.checkpoint["raw"].as_str().expect("raw"),
        )
        .expect("the carried `raw` must reconcile with the JSON members");
        assert!(
            verify_signature(
                &keys.witness_1.verifying_key(),
                &cosignature_bytes(&self.checkpoint, WITNESS_1),
                &self.cosignature,
            )
            .expect("well-formed signature"),
            "the ATL checkpoint cosignature did not verify"
        );
        // §7.1: `log_id` is `"sha256:" || hex(SHA-256(the 16-byte Data Tree UUID))`, and the
        // 98-byte blob binds those same 32 octets as its Origin ID.
        assert_eq!(self.log_id, atl_log_id(&TREE_UUID));
        assert_eq!(&blob[18..50], &parse_hash_hex(&self.log_id).expect("log id")[..]);
        println!("  [ok] {} ATL entries, one checkpoint, `raw` reconciled", self.envelopes.len());
    }

    /// Write the statement vectors, the checkpoint and every receipt vector.
    pub fn write(&self, keys: &Keys, records: &Records, root: &Path) {
        let dir = root.join("vectors").join("atl");
        for (index, env) in self.envelopes.iter().enumerate() {
            write_json(
                &dir.join("statements").join(format!("{}.json", NAMES[index])),
                &json!({
                    "entry_index": index,
                    "statement_id": statement_id(env).expect("well-formed envelope"),
                    "entry_id": entry_id(env),
                    "envelope": env,
                }),
            );
        }
        let leaves = atl_leaves(&self.envelopes);
        write_json(
            &dir.join("log-tree.json"),
            &json!({
                "description": "Log tree of the ATL-bound toy corpus. Leaf bytes are NOT the \
                                anchored entry bytes: adaptor profile `ahl-adaptor-atl-v1` §4.2 \
                                combines two digests, so the leaf preimage is \
                                `SHA-256(JCS(envelope)) || METADATA_HASH` and the leaf hash is \
                                `SHA-256(0x00 || that)`. The first digest is the raw form of the \
                                AHL entry id.",
                "adaptor": { "id": ATL_PROFILE_ID, "hash": self.adaptor_hash },
                "log_id": self.log_id,
                "tree_uuid": hex::encode(TREE_UUID),
                "leaf_rule": "sha256(0x00 || sha256(JCS(envelope)) || METADATA_HASH)",
                "node_rule": "sha256(0x01 || left || right)",
                "metadata": ahl_core::ATL_METADATA,
                "metadata_hash": hash_hex(&ahl_core::atl_metadata_hash()),
                "entries": self
                    .envelopes
                    .iter()
                    .enumerate()
                    .map(|(index, env)| json!({
                        "entry_index": index,
                        "entry_id": entry_id(env),
                        "leaf_hash": hash_hex(&leaf_hash(&leaves[index])),
                    }))
                    .collect::<Vec<_>>(),
                "checkpoint": self.checkpoint,
                "cosignature": witness_entry(keys, &self.cosignature),
            }),
        );

        self.write_receipts(keys, records, root);
    }

    // The vector catalogue is a flat list; splitting it would separate each receipt from the
    // sentence that says what it proves.
    #[allow(clippy::too_many_lines)]
    fn write_receipts(&self, keys: &Keys, records: &Records, root: &Path) {
        let policy = self.trust_policy(keys);
        let leaves = atl_leaves(&self.envelopes);
        let wrong_leaves = wrong_metadata_leaves(&self.envelopes);

        let mut vectors: Vec<AtlVector> = Vec::new();

        vectors.push((
            "statement-anchored-atl-profile.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "statement-anchored",
                    subject_index: 3,
                    record_subject: None,
                    checkpoint: &self.checkpoint,
                    cosignature: &self.cosignature,
                    leaves: &leaves,
                    note:                 "The same claim `statement-anchored-valid.ahl` makes over the main corpus, under \
                 the OTHER adaptor profile. Three things differ and nothing else does. The log \
                 leaf is adaptor §4.2's two-digest construction, so the inclusion path here \
                 opens a root the main corpus's leaf rule would never produce. The checkpoint is \
                 signed over §6.1's fixed 98-byte blob rather than over `JCS(cp minus \
                 \"signature\")`, with `checkpoint_time` rendered to exactly nine fractional \
                 digits (§6.3) because the blob binds the exact nanosecond value. And the \
                 checkpoint carries `raw` (§6.4), which this profile DEFINES, so it must parse \
                 to the same values as the JSON members — the JSON members govern. `log_id` is \
                 origin-derived (§7.1): the 32 octets it carries are the Origin ID the blob \
                 binds at offset 18. Everything else — node hashing, the splitting rule, the \
                 governance chain, envelope validity, the receipt container — is shared.",
                },
            ),
            None,
        ));

        vectors.push((
            "record-ingested-atl-profile.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "record-ingested",
                    subject_index: 1,
                    record_subject: Some((DS_CUSTOMERS, &records.c_a)),
                    checkpoint: &self.checkpoint,
                    cosignature: &self.cosignature,
                    leaves: &leaves,
                    note:                 "The entry-1 ingestion introduced record A into `customers`, proven under the \
                 ATL binding. `content_binding` is `none`: what this vector is about is the \
                 anchoring geometry, and the content-binding rules are §2.6's, identical under \
                 both profiles because a record commitment never touches the log tree.",
                },
            ),
            None,
        ));

        vectors.push((
            "statement-anchored-atl-metadata-hash-must-fail.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "statement-anchored",
                    subject_index: 3,
                    record_subject: None,
                    checkpoint: &self.wrong_metadata_checkpoint,
                    cosignature: &self.wrong_metadata_cosignature,
                    leaves: &wrong_leaves,
                    note:                 "MUST FAIL. Every entry, the checkpoint signature and the witness cosignature \
                 are genuine; the log tree is built with a metadata digest this profile does \
                 not pin, and the inclusion path is a correct path in THAT geometry. Adaptor \
                 §4.2 fixes the metadata object and forbids any other: \"An entry whose ATL \
                 metadata is anything else is not an AHL entry under this profile and MUST be \
                 rejected by an AHL verifier, even if it is a valid ATL entry.\" A verifier that \
                 read the constant from the receipt, or computed it from operator-supplied \
                 metadata, would accept this — and with it a leaf that depends on bytes no AHL \
                 signature covers.",
                },
            ),
            Some((
                "adaptor `ahl-adaptor-atl-v1` §4.2 — the ATL metadata digest is a fixed constant \
                 of the profile",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::InclusionPathInvalid { what: "subject" })
                },
            )),
        ));

        let mut raw_mismatch = self.receipt(
            keys,
            &AtlSpec {
                claim_type: "statement-anchored",
                subject_index: 3,
                record_subject: None,
                checkpoint: &self.checkpoint,
                cosignature: &self.cosignature,
                leaves: &leaves,
                note: "MUST FAIL. `anchoring.checkpoint.raw` carries the 98 octets of a DIFFERENT \
             checkpoint of the same log — correct magic, correct origin, correct root, and a \
             tree size the JSON members do not agree with. Adaptor §6.4 and I-D §7.5 step 2 fix \
             the precedence: \"where `raw` is carried it MUST parse to the same values as the \
             JSON members, the JSON members govern the comparison, and a mismatch is \
             `invalid`\". The checkpoint's own signature still verifies, because it is computed \
             over the blob assembled from the JSON members — which is exactly why an unchecked \
             `raw` could present a verifier with values the log never signed.",
            },
        );
        raw_mismatch["anchoring"]["checkpoint"]["raw"] = self.wrong_size_raw(&self.checkpoint);
        vectors.push((
            "statement-anchored-atl-raw-mismatch-must-fail.ahl",
            raw_mismatch,
            Some((
                "adaptor `ahl-adaptor-atl-v1` §6.4 / I-D §7.5 step 2 — a carried `raw` must \
                 parse to the same values as the JSON members",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::Malformed(detail)
                        if detail.contains("`raw` does not equal the blob assembled from the JSON"))
                },
            )),
        ));

        let mut wrong_digest = self.receipt(
            keys,
            &AtlSpec {
                claim_type: "statement-anchored",
                subject_index: 3,
                record_subject: None,
                checkpoint: &self.checkpoint,
                cosignature: &self.cosignature,
                leaves: &leaves,
                note:             "MUST FAIL. `anchoring.adaptor.hash` pins a digest that is not the one the held \
             profile document recomputes to. Adaptor §14: \"A verifier MUST resolve the profile \
             from local possession by both {id, digest}, MUST recompute the digest over the \
             artifact rather than trusting any value carried with it, and MUST reject a receipt \
             whose pinned digest does not match the artifact held.\" I-D §7.5 step 2 gives the \
             outcome: a profile held under that id whose HASH DIFFERS is a disagreement \
             \"decidable from the bytes in hand\", so the result is `invalid` — not the \
             `unverifiable` a verifier holding NO profile under that id would report.",
            },
        );
        wrong_digest["anchoring"]["adaptor"]["hash"] = json!(sha256_hex(b"not the profile"));
        vectors.push((
            "statement-anchored-atl-profile-digest-must-fail.ahl",
            wrong_digest,
            Some((
                "adaptor `ahl-adaptor-atl-v1` §14 / I-D §7.5 step 2 — the pinned digest must \
                 match the artifact held",
                |e: &ReceiptError| matches!(e, ReceiptError::AdaptorHashMismatch { .. }),
            )),
        ));

        println!("ATL-profile receipt self-check");
        let dir = root.join("receipts").join("atl");
        let mut index = Vec::new();
        for (file, receipt, expect) in &vectors {
            let report = verify_receipt_report(receipt, &policy)
                .unwrap_or_else(|error| panic!("{file}: the run must complete: {error}"));
            let outcome = verify_receipt(receipt, &policy);
            let mut entry = json!({
                "file": file,
                "claim_type": receipt["claim"]["type"],
                "expect": report.result.name(),
            });
            match expect {
                None => {
                    let verdict = outcome.unwrap_or_else(|error| {
                        panic!("{file}: must verify, but was rejected: {error}")
                    });
                    assert_eq!(report.result, Outcome::Verified, "{file}");
                    entry["boundary"] = json!(verdict.boundary);
                    println!("  [ok] {file} verified: {}", verdict.claim_type);
                }
                Some((rule, matches)) => {
                    let error = outcome
                        .err()
                        .unwrap_or_else(|| panic!("{file}: must be rejected, but verified"));
                    assert!(
                        matches(&error),
                        "{file}: rejected by the wrong rule — expected {rule}, got: {error}"
                    );
                    assert_eq!(report.result, error.class(), "{file}");
                    let finding = report
                        .findings
                        .iter()
                        .find(|finding| {
                            finding.counts_toward_result() && finding.outcome == report.result
                        })
                        .unwrap_or_else(|| panic!("{file}: a result comes from a finding"));
                    entry["finding"] = json!(finding.assertion.name());
                    entry["rule"] = json!(rule);
                    entry["reason"] = json!(error.to_string());
                    println!(
                        "  [ok] {file} {} on {} by {rule}: {error}",
                        report.result, finding.assertion
                    );
                }
            }
            index.push(entry);
            write_jcs(&dir.join(file), receipt);
        }

        write_json(
            &dir.join("index.json"),
            &json!({
                "description": "Evidence Receipt vectors over the ATL-bound toy corpus \
                                (`vectors/atl/`), with the I-D §7.7 result a conformant verifier \
                                must reach. They carry their own index because a trust policy \
                                names ONE published genesis anchor (I-D §7.5.1 4a) and this is a \
                                second log with a genesis manifest of its own.",
                "policy": {
                    "genesis_entry_id": entry_id(&self.envelopes[0]),
                    "genesis_key_ids": [ keys.producer_1.key_id() ],
                    "adaptor_profiles": {
                        ATL_PROFILE_ID: {
                            "hash": self.adaptor_hash,
                            "capabilities": { "checkpoint_raw": true, "consistency_proofs": true },
                            "release_status": "PRE-RELEASE. Adaptor §14 makes release a \
                                               precondition for use: \"Until this document is \
                                               released as an immutable, openly published \
                                               artifact at a stable location, its digest is not \
                                               stable and no manifest may pin it.\" The digest \
                                               above is the CURRENT DRAFT's and is a TEST-ONLY \
                                               pin, held so this corpus can exercise the \
                                               profile's serialization; a production manifest \
                                               MUST NOT pin the profile until that obligation is \
                                               met, and the digest will change when it is.",
                        },
                    },
                    "dataset_keys": {},
                    "limits": { "max_decoded_bytes": 8_388_608, "max_work_units": 100_000 },
                },
                "vectors": index,
            }),
        );
    }

    /// A `raw` framing that is a well-formed 98-byte ATL checkpoint blob of the same log, at a
    /// tree size the JSON members do not carry.
    fn wrong_size_raw(&self, checkpoint: &Value) -> Value {
        let mut other = checkpoint.clone();
        other["tree_size"] = json!(self.tree_size() + 1);
        let blob = atl_checkpoint_blob_from_json(&other).expect("well-formed checkpoint");
        json!(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(blob)))
    }
}

/// Everything that varies between the receipts this module assembles.
struct AtlSpec<'a> {
    claim_type: &'a str,
    subject_index: usize,
    record_subject: Option<(&'a str, &'a str)>,
    checkpoint: &'a Value,
    cosignature: &'a str,
    leaves: &'a [Vec<u8>],
    note: &'a str,
}

/// One published vector: its file name, the receipt, and — for a negative — the rule it must
/// trip with the predicate over the rejection behind it.
type AtlVector = (&'static str, Value, Option<(&'static str, fn(&ReceiptError) -> bool)>);

/// The bare inclusion path of one leaf, as a receipt carries it (adaptor §8.2).
fn path(index: usize, leaves: &[Vec<u8>]) -> Vec<String> {
    let proof = inclusion_proof(leaves, index).expect("index within the tree");
    proof_path_hex(&proof)
}

/// The `witnesses[]` element for a checkpoint of this corpus (adaptor §11.1).
fn witness_entry(keys: &Keys, cosignature: &str) -> Value {
    json!({
        "witness_id": WITNESS_1,
        "key_id": keys.witness_1.key_id(),
        "cosignature": cosignature,
        "cosigned_at": T0,
    })
}

/// Write the ATL profile document, and return `(hash, bytes)` of what landed on disk.
fn write_and_hash_atl_adaptor(root: &Path) -> (String, Vec<u8>) {
    let path = root.join("adaptor").join(format!("{ATL_PROFILE_ID}.md"));
    write_text(&path, ATL_ADAPTOR_DOC);
    let bytes = std::fs::read(&path).expect("adaptor document just written");
    (sha256_hex(&bytes), bytes)
}

/// Log-tree leaves under adaptor §4.2.
fn atl_leaves(envelopes: &[Value]) -> Vec<Vec<u8>> {
    envelopes
        .iter()
        .map(|env| log_leaf_bytes_for(env, ATL_PROFILE_ID).expect("known profile"))
        .collect()
}

/// The same leaves under a metadata digest the profile does not pin.
fn wrong_metadata_leaves(envelopes: &[Value]) -> Vec<Vec<u8>> {
    let metadata =
        parse_hash_hex(&sha256_hex(WRONG_METADATA.as_bytes())).expect("a `sha256:` family string");
    envelopes
        .iter()
        .map(|env| {
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(&parse_hash_hex(&entry_id(env)).expect("entry id"));
            preimage.extend_from_slice(&metadata);
            preimage
        })
        .collect()
}

/// A `keys` block entry bound to the genesis manifest.
fn key_entry(key: &TestKey, witness_id: Option<&str>) -> Value {
    let mut entry = json!({
        "key_id": key.key_id(),
        "pubkey": key.pubkey(),
        "source": "manifest-chain",
        "binding": { "entry_index": 0 },
    });
    if let Some(id) = witness_id {
        entry["witness_id"] = json!(id);
    }
    entry
}
