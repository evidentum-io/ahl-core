//! A second toy log, bound to the ATL-shaped adaptor profile `ahl-test-atl-leaf-v1`.
//!
//! The main corpus binds `ahl-test-log-v1`, whose log leaf is the anchored entry bytes. This
//! one exists so the pieces that DIFFER under the ATL binding are exercised end to end rather
//! than at the unit level: the two-digest leaf construction of its §3.1, the origin-derived
//! `log_id` of §4, the 98-byte checkpoint blob of §5.1 with the `raw` framing of §5.4, the range
//! enumeration of §9, and the consistency proofs of §8.
//!
//! # Which profile this corpus pins
//!
//! Not `ahl-adaptor-atl-v1`. That profile's own §14 makes identity a matter of bytes — "any
//! change to this document, however small, produces a different hash and therefore a different
//! profile. A changed profile MUST be published under a new id" — so no document a corpus could
//! ship is that artifact, and publishing one under that id would be a conformance violation
//! whatever the document said about itself and whatever a local policy held.
//!
//! What this corpus pins is `ahl-test-atl-leaf-v1`, a profile of its own with a document of its
//! own at `test_data/profiles/ahl-test-atl-leaf-v1.md`. That document defines the leaf
//! construction, the 98-byte checkpoint blob, the `raw` framing, the origin-derived log id, the
//! tree geometry and the range form AS ITS OWN rules, and cites the ATL adaptor draft as the
//! source of the shape while claiming nothing about being it. The serialization is the same,
//! which is the point: the corpus exercises those rules under an identity it may publish.
//!
//! The verifier keys both ids onto one code path, so a receipt pinning `ahl-adaptor-atl-v1`
//! against a policy holding that profile's released artifact verifies the same way. This crate
//! ships no document for that id, so its own policy holds none, and a receipt pinning it here is
//! `unverifiable` — the profile is not held (I-D §7.5 step 2), which is a gap in the verifier's
//! configuration rather than a defect of the artifact.
//!
//! Adaptor §10 records that the published ATL server serves no enumeration interface, so the
//! range material below is the material a mirror would serve — corpus material under core spec
//! §3.5, assembled here by construction rather than fetched.

use std::collections::BTreeMap;
use std::path::Path;

use ahl_core::receipt::{
    verify_receipt, verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Limits, Outcome,
    ReceiptError, TrustPolicy,
};
use ahl_core::{
    atl_checkpoint, atl_checkpoint_blob_from_json, atl_log_id, consistency_path_hex,
    consistency_proof, entry_id, envelope, hash_hex, inclusion_proof, jcs, leaf_hash,
    log_leaf_bytes_for, parse_hash_hex, proof_path_hex, range_proof, sha256_hex, statement_id,
    tree_root, verify_consistency_proof, verify_envelope, verify_inclusion_proof, verify_signature,
    TestKey, TEST_ATL_PROFILE_ID,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::corpus::Records;
use crate::scenario::{
    cosigned_bytes, manifest, signed, transform, write_jcs, write_json, write_text, Keys,
    DS_CUSTOMERS, DS_SCORES, PIPELINE, T0, WITNESS_1,
};
use crate::text::TEST_ATL_PROFILE_DOC;

/// Where this corpus's own adaptor profile document is published, relative to `test_data/`.
const PROFILE_PATH: &str = "profiles/ahl-test-atl-leaf-v1.md";

/// The 16-byte ATL Data Tree UUID this corpus is bound to.
///
/// A committed constant of trivially repeating bytes, like every key seed here: adaptor §7.1
/// derives the Origin ID from it as `SHA-256(uuid)` and the `log_id` as `"sha256:" ||
/// hex(Origin ID)`, so the identifier is not free-form and the corpus must say what it came
/// from. A verifier never needs the UUID itself.
const TREE_UUID: [u8; 16] = [0x0A; 16];

/// The checkpoint timestamp of the primary checkpoint, in Unix nanoseconds.
///
/// `2026-08-16T12:00:00.123456789Z` — the corpus reference instant with a fractional part, so
/// the §5.3 rendering rule ("exactly nine fractional digits") is exercised by a value that
/// actually has nine significant ones. It sits inside `[cadence_epoch, cadence_epoch + PT1H]`,
/// the window core spec §7.3 requires of the earliest checkpoint committing the genesis
/// manifest. Later checkpoints advance by a whole second, keeping nine significant digits.
const CHECKPOINT_NANOS: u64 = 1_786_881_600_123_456_789;

/// A metadata digest that is NOT the one the profile pins, for the two negatives that prove the
/// constant is load-bearing.
const WRONG_METADATA: &str = r#"{"ahl_adaptor":"not-this-profile"}"#;

/// The bytes whose digest manifest version 2 pins the profile id at.
///
/// It stands for any artifact a policy holding this corpus's profile document does not hold. It
/// is deliberately a marker rather than any real document: §14's identity rule makes a profile
/// its bytes, so a corpus that hard-coded some other project's digest would be asserting
/// something about that project's artifact.
const UNHELD_ARTIFACT: &[u8] = b"an adaptor profile artifact this corpus does not hold";

/// Entry-index labels, one per anchored envelope.
const NAMES: [&str; 7] = [
    "00-manifest-genesis",
    "01-ingestion-customers-a",
    "02-ingestion-customers-b",
    "03-derivation-s1",
    "04-retraction-customers-a-authorized",
    "05-ingestion-customers-c",
    "06-manifest-v2-unheld-profile-digest",
];

/// A signed ATL checkpoint plus its witness cosignature.
pub struct AtlAnchor {
    name: &'static str,
    checkpoint: Value,
    cosignature: String,
}

impl AtlAnchor {
    fn tree_size(&self) -> u64 {
        self.checkpoint["tree_size"].as_u64().expect("signed checkpoint")
    }

    /// The `anchoring.witnesses[]` / `anchoring.later_witnesses[]` element for this checkpoint.
    fn witness_entry(&self, keys: &Keys) -> Value {
        json!({
            "witness_id": WITNESS_1,
            "key_id": keys.witness_1.key_id(),
            "cosignature": self.cosignature,
            "cosigned_at": T0,
        })
    }
}

/// The ATL-bound corpus and everything derived from it.
pub struct AtlCorpus {
    log_id: String,
    envelopes: Vec<Value>,
    /// Digest of this corpus's own profile document — what the genesis manifest pins.
    profile_hash: String,
    profile_document: Vec<u8>,
    /// Digest of an artifact this corpus does not hold — what manifest v2 pins.
    unheld_hash: String,
    anchors: Vec<AtlAnchor>,
    /// A checkpoint over the same entries hashed with a metadata digest the profile does not
    /// pin, at the same tree size as the primary one.
    wrong_metadata: AtlAnchor,
}

impl AtlCorpus {
    #[allow(clippy::too_many_lines)] // One linear scenario; splitting it would obscure the order.
    pub fn build(keys: &Keys, records: &Records, root: &Path) -> Self {
        let (profile_hash, profile_document) = write_and_hash_profile(root);
        let unheld_hash = sha256_hex(UNHELD_ARTIFACT);
        let log_id = atl_log_id(&TREE_UUID);

        // Entry 0: the genesis manifest. `scenario::manifest` builds the whole §7.2/§7.3 shape;
        // only the adaptor id differs, since the hash and the log id are already parameters.
        let mut genesis = manifest(keys, &log_id, &profile_hash, 0, None);
        genesis["log"]["adaptor"]["id"] = json!(TEST_ATL_PROFILE_ID);
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

        // Entry 4: a retraction of record A by the `customers` dataset authority. It is what the
        // enumerated `trigger-effective` claim below is about, and it is the only reason this
        // corpus needs a competing range at all.
        let env_4 = signed(
            "retraction",
            &m1,
            json!({
                "dataset": DS_CUSTOMERS,
                "record": records.c_a,
                "scope": { "effective_from": T0, "retroactive": true },
                "reason_code": "consent_withdrawn",
            }),
            &keys.producer_1,
        );

        // Entry 5: an ordinary ingestion, so the later checkpoint of the continued-history vector
        // commits an entry the primary one does not.
        let env_5 =
            signed("ingestion", &m1, ingest(&records.c_c, "2026-08-16/atl-02"), &keys.producer_1);

        // Entry 6: a manifest version pinning the SAME profile id at the digest of an artifact
        // this corpus does not hold. Anchored last, so it is the active version for exactly one
        // checkpoint and nothing that must verify is governed by it. I-D §7.5 step 2: a profile
        // held under that id whose HASH DIFFERS is a disagreement "decidable from the bytes in
        // hand", and the result is `invalid`.
        let mut v2 = manifest(keys, &log_id, &unheld_hash, 6, Some(&entry_id(&env_0)));
        v2["log"]["adaptor"]["id"] = json!(TEST_ATL_PROFILE_ID);
        v2["witnesses"][0]["keys"][0]["valid_from_index"] = json!(0);
        let env_6 = envelope(v2, &keys.producer_1);

        let envelopes = vec![env_0, env_1, env_2, env_3, env_4, env_5, env_6];
        let leaves = atl_leaves(&envelopes);

        // cp5 is the primary checkpoint of every positive; cp6 is the later checkpoint the
        // continued-history vector extends to; cp7 is reached only by the negative that manifest
        // version 2 exists for.
        let anchors = ["cp5", "cp6", "cp7"]
            .into_iter()
            .zip([5u64, 6, 7])
            .map(|(name, size)| {
                let at = usize::try_from(size).expect("small tree size");
                let root_hash = hash_hex(&tree_root(&leaves[..at]));
                let nanos = CHECKPOINT_NANOS + (size - 5) * 1_000_000_000;
                signed_anchor(name, &log_id, size, &root_hash, nanos, keys)
            })
            .collect::<Vec<_>>();

        // The same entries under a metadata digest this profile does not pin. Its §3.1: "An
        // entry whose ATL metadata is anything else is NOT an AHL entry under this profile and
        // MUST be rejected by an AHL verifier, even if it is a valid ATL entry." The checkpoint
        // over that tree is genuinely signed and genuinely cosigned, so nothing about it is
        // malformed — only the leaves are built the wrong way, which is exactly what a verifier
        // using the wrong constant would fail to notice.
        let wrong_root = hash_hex(&tree_root(&wrong_metadata_leaves(&envelopes)[..5]));
        let wrong_metadata =
            signed_anchor("cp5-wrong-metadata", &log_id, 5, &wrong_root, CHECKPOINT_NANOS, keys);

        Self {
            log_id,
            envelopes,
            profile_hash,
            profile_document,
            unheld_hash,
            anchors,
            wrong_metadata,
        }
    }

    fn anchor(&self, name: &str) -> &AtlAnchor {
        self.anchors.iter().find(|a| a.name == name).expect("named checkpoint")
    }

    /// Authenticated range enumeration over `[from, to)` under `anchor` (profile §9).
    ///
    /// The byte layout is the one the rest of this corpus uses; the LEAF HASHING is §3.1's,
    /// which is the whole of the difference and the reason this material exists.
    fn enumeration(&self, from: u64, to: u64, anchor: &AtlAnchor, leaves: &[Vec<u8>]) -> Value {
        let at = usize::try_from(anchor.tree_size()).expect("small tree size");
        let hashes: Vec<_> = leaves[..at].iter().map(|leaf| leaf_hash(leaf)).collect();
        let proof = range_proof::generate(&hashes, from, to).expect("range within the checkpoint");
        json!({
            "range": { "from_index": from, "to_index": to },
            "entries": (from..to)
                .map(|index| json!({
                    "entry_index": index,
                    "envelope": self.envelopes[usize::try_from(index).expect("small index")],
                }))
                .collect::<Vec<_>>(),
            "range_proof": { "adaptor_form": range_proof::encode(&proof) },
        })
    }

    /// An RFC 9162 consistency proof between two published tree sizes (profile §8).
    fn consistency_path(&self, from_size: u64, to_size: u64) -> Vec<String> {
        let leaves = atl_leaves(&self.envelopes);
        let proof = consistency_proof(&leaves, from_size, to_size).expect("published sizes");
        consistency_path_hex(&proof)
    }

    /// Assemble one receipt over this corpus.
    fn receipt(&self, keys: &Keys, spec: &AtlSpec<'_>) -> Value {
        let AtlSpec {
            claim_type,
            subject_index,
            record_subject,
            anchor,
            leaves,
            chain,
            currency_mode,
            currency_material,
            claim_material,
            continued_history,
            note,
        } = spec;
        let subject_index = *subject_index;
        let subject = &self.envelopes[subject_index];
        let mut claim = json!({
            "type": claim_type,
            "assurance": {
                "governance": currency_mode,
                "competing_triggers": if *claim_type == "trigger-effective" {
                    "enumerated"
                } else {
                    "not-checked"
                },
                "witnessed": true,
                "continued_history": continued_history,
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
        // §3.2: `anchoring.adaptor` names the same pair the ACTIVE manifest's own `log.adaptor`
        // pins, so a receipt anchored under a checkpoint version 2 governs carries version 2's
        // pin — which is the whole point of the negative that uses it.
        let pinned = if anchor.tree_size() > 6 { &self.unheld_hash } else { &self.profile_hash };
        // A checkpoint commits `[0, tree_size)`, so every path this receipt carries is a path in
        // the tree of THAT size — not in the largest tree the corpus has grown to since.
        let committed = &leaves[..usize::try_from(anchor.tree_size()).expect("small tree size")];
        json!({
            "ahl_receipt_version": "2",
            "spec_version": "0.4.0",
            "claim": claim,
            "subject": subject_block,
            "envelope": subject,
            "keys": {
                "log": [ key_entry(&keys.log_1, None) ],
                "witness": [ key_entry(&keys.witness_1, Some(WITNESS_1)) ],
                "producer": [ key_entry(&keys.producer_1, None) ],
            },
            "anchoring": {
                "adaptor": { "id": TEST_ATL_PROFILE_ID, "hash": pinned },
                "checkpoint": anchor.checkpoint,
                "inclusion_path": path(subject_index, committed),
                "witnesses": [ anchor.witness_entry(keys) ],
            },
            "governance": {
                "genesis_entry_id": entry_id(&self.envelopes[0]),
                "chain": chain
                    .iter()
                    .map(|index| json!({
                        "envelope": self.envelopes[*index],
                        "entry_index": index,
                        "inclusion_path": path(*index, committed),
                    }))
                    .collect::<Vec<_>>(),
                "currency": { "mode": currency_mode, "material": currency_material },
            },
            "claim_material": claim_material,
        })
    }

    /// The trust policy the ATL vectors' outcomes assume.
    ///
    /// A separate policy from the main corpus's, and it has to be: a trust policy names ONE
    /// published genesis anchor (I-D §7.5.1 4a), and this is a different log with a different
    /// genesis manifest. The two vector sets therefore carry their own `index.json` each, with
    /// the policy its outcomes assume beside it. What it holds under the profile id is the
    /// document of `ahl-test-atl-leaf-v1`, which is the profile this corpus pins.
    pub fn trust_policy(&self, keys: &Keys) -> TrustPolicy {
        TrustPolicy {
            genesis_entry_id: entry_id(&self.envelopes[0]),
            genesis_key_ids: Some(std::iter::once(keys.producer_1.key_id()).collect()),
            adaptor_profiles: std::iter::once((
                TEST_ATL_PROFILE_ID.to_owned(),
                AdaptorProfile {
                    document: self.profile_document.clone(),
                    capabilities: AdaptorCapabilities {
                        // What the PROFILE defines: a binary checkpoint framing (§5.4) and a
                        // consistency-proof serialization (§8). Serving consistency proofs and
                        // the enumeration interface are deployment obligations the profile names
                        // as unmet on the published ATL stack; what a capability records is what
                        // the profile DEFINES, which is what decides whether a receipt's members
                        // are interpretable at all.
                        checkpoint_raw: true,
                        consistency_proofs: true,
                    },
                },
            ))
            .collect(),
            dataset_keys: BTreeMap::new(),
            trusted_witness_keys: BTreeMap::new(),
            limits: Limits::default(),
        }
    }

    /// Re-verify everything this corpus publishes, and abort on any mismatch.
    // One linear pass over one corpus: the identity pin, the §3.1 leaves, every checkpoint, the §7
    // inclusion proofs, the §9.1 ranges and the §8 consistency proof. Splitting it would
    // separate each assertion from the rule it restates.
    #[allow(clippy::too_many_lines)]
    pub fn self_check(&self, keys: &Keys) {
        println!("ATL-profile corpus self-check");
        for (index, env) in self.envelopes.iter().enumerate() {
            assert!(
                verify_envelope(env, |key_id| keys.resolve(key_id)).expect("well-formed envelope"),
                "ATL entry {index}: envelope signature did not verify"
            );
        }

        // The identity rule, as an assertion: what the genesis manifest pins is the digest of
        // THIS profile's own document, under THIS profile's own id.
        assert_eq!(
            self.envelopes[0]["payload"]["log"]["adaptor"]["hash"],
            json!(self.profile_hash),
            "the genesis manifest must pin this corpus's own profile document"
        );
        let opening = String::from_utf8_lossy(&self.profile_document);
        assert!(
            opening.starts_with("# Adaptor profile `ahl-test-atl-leaf-v1`"),
            "the pinned document must name the profile it defines in its first line"
        );
        assert!(
            opening.contains("**This profile is not that profile**"),
            "the pinned document must state its relationship to `ahl-adaptor-atl-v1`"
        );
        assert_ne!(self.profile_hash, self.unheld_hash);

        // Profile §3.1: the leaf is `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`,
        // and its first digest is the raw form of the AHL entry id — so the entry id stays
        // derivable from the entry bytes alone even though the leaf is not the entry bytes.
        for env in &self.envelopes {
            let preimage = log_leaf_bytes_for(env, TEST_ATL_PROFILE_ID).expect("known profile");
            assert_eq!(preimage.len(), 64);
            assert_eq!(&preimage[..32], &parse_hash_hex(&entry_id(env)).expect("entry id")[..]);
            assert_eq!(&preimage[32..], &ahl_core::atl_metadata_hash()[..]);
        }

        let leaves = atl_leaves(&self.envelopes);
        // The two geometries really do differ: a verifier applying the main corpus's leaf rule
        // to this log would recompute a different root for the same entries.
        let plain: Vec<Vec<u8>> = self.envelopes.iter().map(jcs).collect();
        assert_ne!(hash_hex(&tree_root(&plain)), hash_hex(&tree_root(&leaves)));

        for anchor in self.anchors.iter().chain(std::iter::once(&self.wrong_metadata)) {
            let size = usize::try_from(anchor.tree_size()).expect("small tree size");
            let expected = if anchor.name == "cp5-wrong-metadata" {
                tree_root(&wrong_metadata_leaves(&self.envelopes)[..size])
            } else {
                tree_root(&leaves[..size])
            };
            assert_eq!(
                hash_hex(&expected),
                anchor.checkpoint["root_hash"].as_str().expect("root_hash"),
                "{}: the checkpoint must commit the root of its own geometry",
                anchor.name
            );
            // §5.5: the signature is over the 98-byte blob assembled from the JSON members, and
            // a carried `raw` must equal that blob byte for byte.
            let blob =
                atl_checkpoint_blob_from_json(&anchor.checkpoint).expect("well-formed checkpoint");
            assert!(
                verify_signature(
                    &keys.log_1.verifying_key(),
                    &blob,
                    anchor.checkpoint["signature"].as_str().expect("signature"),
                )
                .expect("well-formed signature"),
                "{}: signature did not verify over the 98-byte blob",
                anchor.name
            );
            ahl_core::reconcile_atl_checkpoint_raw(
                &anchor.checkpoint,
                anchor.checkpoint["raw"].as_str().expect("raw"),
            )
            .unwrap_or_else(|e| panic!("{}: carried `raw` must reconcile: {e}", anchor.name));
            assert!(
                verify_signature(
                    &keys.witness_1.verifying_key(),
                    &cosigned_bytes(&anchor.checkpoint, WITNESS_1),
                    &anchor.cosignature,
                )
                .expect("well-formed signature"),
                "{}: cosignature did not verify",
                anchor.name
            );
            // §4: `log_id` is `"sha256:" || hex(SHA-256(the 16-byte Data Tree UUID))`, and the
            // blob binds those same 32 octets as its Origin ID.
            assert_eq!(&blob[18..50], &parse_hash_hex(&self.log_id).expect("log id")[..]);
        }
        assert_eq!(self.log_id, atl_log_id(&TREE_UUID));

        // §7: inclusion, in ATL geometry, at every index of the largest published checkpoint.
        let root = tree_root(&leaves);
        for index in 0..self.envelopes.len() {
            let proof = inclusion_proof(&leaves, index).expect("index within the tree");
            assert!(
                verify_inclusion_proof(&leaves[index], &proof, &root).expect("well-formed proof"),
                "ATL entry {index}: inclusion proof did not verify"
            );
        }

        // §9.1: every sub-range of the primary checkpoint opens its root, and a proof for the
        // wrong range does not.
        let cp5 = self.anchor("cp5");
        let hashes: Vec<_> = leaves[..5].iter().map(|leaf| leaf_hash(leaf)).collect();
        let cp5_root = parse_hash_hex(cp5.checkpoint["root_hash"].as_str().expect("root_hash"))
            .expect("root hash");
        for from in 0..5u64 {
            for to in (from + 1)..=5 {
                let proof = range_proof::generate(&hashes, from, to).expect("valid range");
                let span: Vec<Vec<u8>> = leaves
                    [usize::try_from(from).expect("small")..usize::try_from(to).expect("small")]
                    .to_vec();
                assert!(
                    range_proof::verify_over_leaves(&proof, &span, &cp5_root)
                        .expect("well-formed proof"),
                    "ATL range [{from}, {to}) did not open cp5's root"
                );
            }
        }

        // §8: the consistency proof between the two published sizes verifies, and one for the
        // wrong pair does not.
        let path = consistency_proof(&leaves, 5, 6).expect("published sizes");
        let cp6_root =
            parse_hash_hex(self.anchor("cp6").checkpoint["root_hash"].as_str().expect("root_hash"))
                .expect("root hash");
        assert!(
            verify_consistency_proof(&path, &cp5_root, &cp6_root).expect("well-formed proof"),
            "the ATL consistency proof 5 -> 6 did not verify"
        );
        let cp7_root =
            parse_hash_hex(self.anchor("cp7").checkpoint["root_hash"].as_str().expect("root_hash"))
                .expect("root hash");
        assert!(
            !verify_consistency_proof(&path, &cp5_root, &cp7_root).expect("well-formed proof"),
            "a proof for the wrong pair of sizes must not verify"
        );

        println!(
            "  [ok] {} ATL entries, {} checkpoints, `raw` reconciled, every sub-range of cp5 and \
             the 5 -> 6 consistency proof verified",
            self.envelopes.len(),
            self.anchors.len() + 1
        );
    }

    /// Write the statement vectors, the log tree and every receipt vector.
    pub fn write(&self, keys: &Keys, root: &Path) {
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
                                anchored entry bytes: adaptor profile `ahl-test-atl-leaf-v1` §3.1 \
                                combines two digests, so the leaf preimage is \
                                `SHA-256(JCS(envelope)) || METADATA_HASH` and the leaf hash is \
                                `SHA-256(0x00 || that)`. The first digest is the raw form of the \
                                AHL entry id. The profile pinned here is this corpus's own, \
                                whose document is under `profiles/`; the serialization has the \
                                same shape as `ahl-adaptor-atl-v1`'s and is defined there as its \
                                own.",
                "adaptor": { "id": TEST_ATL_PROFILE_ID, "hash": self.profile_hash },
                "adaptor_document": PROFILE_PATH,
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
                "checkpoints": self
                    .anchors
                    .iter()
                    .map(|anchor| json!({
                        "name": anchor.name,
                        "checkpoint": anchor.checkpoint,
                        "cosignature": anchor.witness_entry(keys),
                    }))
                    .collect::<Vec<_>>(),
                "consistency": {
                    "from_size": 5,
                    "to_size": 6,
                    "path": self.consistency_path(5, 6),
                },
            }),
        );

        self.write_receipts(keys, root);
    }

    // The vector catalogue is a flat list; splitting it would separate each receipt from the
    // sentence that says what it proves.
    #[allow(clippy::too_many_lines)]
    fn write_receipts(&self, keys: &Keys, root: &Path) {
        let policy = self.trust_policy(keys);
        let leaves = atl_leaves(&self.envelopes);
        let wrong_leaves = wrong_metadata_leaves(&self.envelopes);
        let cp5 = self.anchor("cp5");
        let cp6 = self.anchor("cp6");
        let cp7 = self.anchor("cp7");
        let records = self.record_subjects();

        let declared = |claim_type, subject_index, record_subject, note| {
            declared_spec(cp5, &leaves, claim_type, subject_index, record_subject, note)
        };

        let mut vectors: Vec<AtlVector> = Vec::new();

        vectors.push((
            "statement-anchored-atl-leaf.ahl",
            self.receipt(
                keys,
                &declared(
                    "statement-anchored",
                    3,
                    None,
                    "The same claim `statement-anchored-valid.ahl` makes over the main corpus, \
                     under the OTHER adaptor profile. Three serializations differ and nothing \
                     else does. The log leaf is the profile's §3.1 two-digest construction, so the \
                     inclusion path here opens a root the main corpus's leaf rule would never \
                     produce. The checkpoint is signed over §5.1's fixed 98-byte blob rather \
                     than over `JCS(cp minus \"signature\")`, with `checkpoint_time` rendered to \
                     exactly nine fractional digits (§5.3) because the blob binds the exact \
                     nanosecond value. And the checkpoint carries `raw` (§5.4), which this \
                     binding DEFINES, so it must parse to the same values as the JSON members — \
                     the JSON members govern. `log_id` is origin-derived (§4): the 32 octets \
                     it carries are the Origin ID the blob binds at offset 18. The profile is \
                     this corpus's own `ahl-test-atl-leaf-v1`, pinned at the digest of its own \
                     document under `profiles/`; its serialization has the same shape as \
                     `ahl-adaptor-atl-v1`'s, which it cites as the source and claims nothing \
                     about.",
                ),
            ),
            None,
        ));

        vectors.push((
            "record-ingested-atl-leaf.ahl",
            self.receipt(
                keys,
                &declared(
                    "record-ingested",
                    1,
                    Some((DS_CUSTOMERS, &records.0)),
                    "The entry-1 ingestion introduced record A into `customers`, proven under \
                     the ATL binding. `content_binding` is `none`: what this vector is about is \
                     the anchoring geometry, and the content-binding rules are §2.6's, identical \
                     under both profiles because a record commitment never touches the log tree.",
                ),
            ),
            None,
        ));

        // --- enumerated governance in §10 geometry ------------------------------------
        let currency = self.enumeration(0, 5, cp5, &leaves);
        vectors.push((
            "governance-state-atl-leaf.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "governance-state",
                    subject_index: 0,
                    record_subject: None,
                    anchor: cp5,
                    leaves: &leaves,
                    chain: vec![0],
                    currency_mode: "enumerated",
                    currency_material: currency.clone(),
                    claim_material: json!({ "target_index": 1 }),
                    continued_history: false,
                    note: "Enumerated governance currency over exactly [0, 5), authenticated by \
                           a §9.1 range proof whose CARRIED LEAVES are hashed by the \
                           §3.1 construction. The byte layout of the proof is the one the rest \
                           of this corpus uses — §9.2 makes that deliberate, \"so a single \
                           range-proof implementation serves both\" — and the leaf hashing is \
                           the whole of the difference: a verifier that applied the other \
                           profile's leaf rule would recompute a root the checkpoint does not \
                           carry. §10 records that the published ATL server serves no \
                           enumeration interface, so this is the material a mirror would serve \
                           (core spec §3.5), assembled here by construction. §9.3 also rules \
                           out typed-subset proofs under this binding, which is why the range is \
                           the full prefix rather than the governance statements alone.",
                },
            ),
            None,
        ));

        let introduction = self.receipt(
            keys,
            &declared(
                "record-ingested",
                1,
                Some((DS_CUSTOMERS, &records.0)),
                "Embedded introduction proof: establishes who may issue a trigger for this \
                 record (receipt §3 authority note). It says nothing about the record's content.",
            ),
        );
        let introduction_again = introduction.clone();
        vectors.push((
            "trigger-effective-atl-leaf.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "trigger-effective",
                    subject_index: 4,
                    record_subject: Some((DS_CUSTOMERS, &records.0)),
                    anchor: cp5,
                    leaves: &leaves,
                    chain: vec![0],
                    currency_mode: "enumerated",
                    currency_material: currency,
                    claim_material: json!({
                        "introduction": introduction,
                        "checkpoint_C": cp5.checkpoint,
                        "competing": { "corpus_range": self.enumeration(1, 5, cp5, &leaves) },
                    }),
                    continued_history: false,
                    note: "The retraction of record A at entry 4 GOVERNS at cp5: it is signed by \
                           the `customers` dataset authority the genesis manifest declares, and \
                           the competing range — the introduction-fixed [1, 5) — carries every \
                           other candidate the checkpoint commits. Both ranges are ATL range \
                           proofs (§9.1), so this is the claim type that puts §3.1 leaf \
                           construction through the enumerated path rather than only through an \
                           inclusion path, and the embedded introduction puts it through an \
                           embedded receipt's own anchoring as well.",
                },
            ),
            None,
        ));

        // --- continued history in ATL form --------------------------------------------
        let mut continued = self.receipt(
            keys,
            &AtlSpec {
                claim_type: "statement-anchored",
                subject_index: 3,
                record_subject: None,
                anchor: cp5,
                leaves: &leaves,
                chain: vec![0],
                currency_mode: "declared",
                currency_material: json!({}),
                claim_material: json!({}),
                continued_history: true,
                note: "`assurance.continued_history` is true, and adaptor §8 is what backs it: \
                       an RFC 9162 proof from cp5 to cp6, serialized as a JSON array of \
                       `sha256:<hex>` family strings, carried beside a `later_checkpoint` in ATL \
                       form. That later checkpoint is authenticated on its own terms — its own \
                       98-byte blob signature under the log key the manifest version active for \
                       ITS tree size declares (§7.5.1 4f), and its own cosignatures in \
                       `anchoring.later_witnesses[]` rather than the primary checkpoint's. §8 \
                       records that the published ATL server serves no consistency-proof route, \
                       so a deployment must supply one; the proof here is generated from the \
                       corpus, which is what a mirror holding the entries would do.",
            },
        );
        continued["anchoring"]["later_checkpoint"] = cp6.checkpoint.clone();
        continued["anchoring"]["later_witnesses"] = json!([cp6.witness_entry(keys)]);
        continued["anchoring"]["consistency_path"] = json!(self.consistency_path(5, 6));
        vectors.push(("statement-anchored-atl-continued-history.ahl", continued.clone(), None));

        let mut malformed_path = continued;
        malformed_path["anchoring"]["consistency_path"][0] = json!("not-a-family-string");
        malformed_path["claim"]["note"] = json!(
            "MUST FAIL. One element of `anchoring.consistency_path` is not a `sha256:<hex>` \
             family string. Adaptor §8 fixes the serialization as \"a JSON array of \
             `sha256:<hex>` family strings in the order produced by the RFC 9162 algorithm\", so \
             an element outside that grammar is not a proof node a verifier may interpret — and \
             `assurance.continued_history` is true if and only if both members are present AND \
             verify, which this one cannot."
        );
        vectors.push((
            "statement-anchored-atl-consistency-path-malformed-must-fail.ahl",
            malformed_path,
            Some((
                "adaptor `ahl-test-atl-leaf-v1` §8 — a consistency proof is an array of \
                 `sha256:<hex>` family strings",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::Malformed(detail)
                        if detail.contains("`anchoring.consistency_path[0]` is not a `sha256:`"))
                },
            )),
        ));

        // --- negatives on the leaf construction ---------------------------------------
        vectors.push((
            "statement-anchored-atl-metadata-hash-must-fail.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "statement-anchored",
                    subject_index: 3,
                    record_subject: None,
                    anchor: &self.wrong_metadata,
                    leaves: &wrong_leaves,
                    chain: vec![0],
                    currency_mode: "declared",
                    currency_material: json!({}),
                    claim_material: json!({}),
                    continued_history: false,
                    note: "MUST FAIL. Every entry, the checkpoint signature and the witness \
                           cosignature are genuine; the log tree is built with a metadata digest \
                           this profile does not pin, and the inclusion path is a correct path \
                           in THAT geometry. Adaptor §3.1 fixes the metadata object and forbids \
                           any other: \"An entry whose ATL metadata is anything else is not an \
                           AHL entry under this profile and MUST be rejected by an AHL verifier, \
                           even if it is a valid ATL entry.\" A verifier that read the constant \
                           from the receipt, or computed it from operator-supplied metadata, \
                           would accept this — and with it a leaf that depends on bytes no AHL \
                           signature covers.",
                },
            ),
            Some((
                "adaptor `ahl-test-atl-leaf-v1` §3.1 — the ATL metadata digest is a fixed constant \
                 of the profile",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::InclusionPathInvalid { what: "subject" })
                },
            )),
        ));

        vectors.push((
            "trigger-effective-atl-metadata-hash-must-fail.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "trigger-effective",
                    subject_index: 4,
                    record_subject: Some((DS_CUSTOMERS, &records.0)),
                    anchor: cp5,
                    leaves: &leaves,
                    chain: vec![0],
                    currency_mode: "enumerated",
                    currency_material: self.enumeration(0, 5, cp5, &leaves),
                    claim_material: json!({
                        "introduction": introduction_again,
                        "checkpoint_C": cp5.checkpoint,
                        "competing": {
                            "corpus_range": self.enumeration(1, 5, &self.wrong_metadata, &wrong_leaves),
                        },
                    }),
                    continued_history: false,
                    note: "MUST FAIL, and it is the enumerated half of the metadata rule. \
                           Everything outside the competing range is impeccable: cp5 is genuine, \
                           its `raw` reconciles, the subject's own inclusion path opens its root \
                           under the §3.1 leaf rule, and the governance currency over [0, 5) is \
                           the honest one. The competing range [1, 5) is the one thing built the \
                           wrong way — a correctly constructed §9.1 proof over leaves hashed \
                           with a metadata digest the profile does not pin, declaring the same \
                           tree size and the same range as the honest one. §9.1 fixes the leaf \
                           hash of a carried entry as the §3.1 construction, so a verifier \
                           recomputes the carried envelopes' leaves with the pinned constant, \
                           consumes the proof's subtree hashes at the positions the recursion \
                           fixes, and gets a root cp5 does not carry. The range is a PROPER \
                           sub-range on purpose: a full-prefix range carries no subtree hashes \
                           at all, so its recomputation is the carried leaves' own root either \
                           way and the substitution has nowhere to hide — which is why the \
                           enumerated governance range cannot be the one that shows this.",
                },
            ),
            Some((
                "adaptor `ahl-test-atl-leaf-v1` §9.1 — a range proof's carried leaves are hashed \
                 by the §3.1 construction",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::RangeProofInvalid { what: "competing triggers", .. })
                },
            )),
        ));

        // --- negatives on the pinned artifact -----------------------------------------
        let mut wrong_digest = self.receipt(
            keys,
            &declared(
                "statement-anchored",
                3,
                None,
                "MUST FAIL. `anchoring.adaptor.hash` pins a digest that is not the one the held \
                 artifact recomputes to. Adaptor §14: \"A verifier MUST resolve the profile from \
                 local possession by both {id, digest}, MUST recompute the digest over the \
                 artifact rather than trusting any value carried with it, and MUST reject a \
                 receipt whose pinned digest does not match the artifact held.\" I-D §7.5 step 2 \
                 gives the outcome: a profile held under that id whose HASH DIFFERS is a \
                 disagreement \"decidable from the bytes in hand\", so the result is `invalid` — \
                 not the `unverifiable` a verifier holding NO artifact under that id reports.",
            ),
        );
        wrong_digest["anchoring"]["adaptor"]["hash"] = json!(sha256_hex(b"not the artifact held"));
        vectors.push((
            "statement-anchored-atl-leaf-digest-must-fail.ahl",
            wrong_digest,
            Some((
                "adaptor `ahl-test-atl-leaf-v1` / I-D §7.5 step 2 — the pinned digest must \
                 match the artifact held",
                |e: &ReceiptError| matches!(e, ReceiptError::AdaptorHashMismatch { .. }),
            )),
        ));

        vectors.push((
            "statement-anchored-atl-unheld-manifest-pin-must-fail.ahl",
            self.receipt(
                keys,
                &AtlSpec {
                    claim_type: "statement-anchored",
                    subject_index: 5,
                    record_subject: None,
                    anchor: cp7,
                    leaves: &leaves,
                    chain: vec![0, 6],
                    currency_mode: "declared",
                    currency_material: json!({}),
                    claim_material: json!({}),
                    continued_history: false,
                    note: "MUST FAIL. Manifest version 2, anchored at entry 4, pins the same \
                           profile id at the digest of an artifact this verifier does not hold. \
                           The manifest is genuinely signed, its lineage is correct, and cp5 is \
                           a genuine checkpoint of this log; none of that helps. I-D §7.5 step 2 \
                           resolves the profile from local possession by {id, digest} before any \
                           carried material is verified, and a held artifact whose digest \
                           differs is `invalid`. That is also why a profile's identity is its \
                           bytes: a document under an id, however labelled, is either the \
                           artifact that id names or it is a different profile, which is the \
                           rule this corpus follows in pinning one of its own rather than \
                           anything belonging to `ahl-adaptor-atl-v1`.",
                },
            ),
            Some((
                "adaptor `ahl-test-atl-leaf-v1` / I-D §7.5 step 2 — a manifest pinning an \
                 artifact the verifier does not hold does not resolve",
                |e: &ReceiptError| matches!(e, ReceiptError::AdaptorHashMismatch { .. }),
            )),
        ));

        let mut raw_mismatch = self.receipt(
            keys,
            &declared(
                "statement-anchored",
                3,
                None,
                "MUST FAIL. `anchoring.checkpoint.raw` carries the 98 octets of a DIFFERENT \
                 checkpoint of the same log — correct magic, correct origin, correct root, and a \
                 tree size the JSON members do not agree with. Adaptor §5.4 and I-D §7.5 step 2 \
                 fix the precedence: \"where `raw` is carried it MUST parse to the same values \
                 as the JSON members, the JSON members govern the comparison, and a mismatch is \
                 `invalid`\". The checkpoint's own signature still verifies, because it is \
                 computed over the blob assembled from the JSON members — which is exactly why \
                 an unreconciled `raw` could present a verifier with values the log never signed.",
            ),
        );
        raw_mismatch["anchoring"]["checkpoint"]["raw"] = wrong_size_raw(&cp5.checkpoint);
        vectors.push((
            "statement-anchored-atl-raw-mismatch-must-fail.ahl",
            raw_mismatch,
            Some((
                "adaptor `ahl-test-atl-leaf-v1` §5.4 / I-D §7.5 step 2 — a carried `raw` must \
                 parse to the same values as the JSON members",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::Malformed(detail)
                        if detail.contains("`raw` does not equal the blob assembled from the JSON"))
                },
            )),
        ));

        vectors.push((
            "statement-anchored-atl-cosigned-projection.ahl",
            self.receipt(
                keys,
                &declared(
                    "statement-anchored",
                    3,
                    None,
                    "The cosignature preimage under a profile that DEFINES a binary checkpoint \
                     framing. `anchoring.checkpoint` carries `raw` (§5.4) and the cosignature in \
                     `anchoring.witnesses[]` was computed over the six members alone — `{log_id, \
                     tree_size, root_hash, checkpoint_time, key_id, signature}`, the object \
                     `ahl-adaptor-atl-v1` §11.1 draws — with `raw` EXCLUDED. A verifier that \
                     serialised the checkpoint as it stands would build different bytes and \
                     reject a cosignature the witness genuinely made, which is what an \
                     end-to-end run of a log, a witness and a verifier found: the witness \
                     cosigns a typed six-member projection, never the JSON object as received, \
                     so a verifier must reconstruct the cosigned object from those six members \
                     and no others. That the same rule holds where `raw` is absent is what \
                     makes the exclusion checkable: every other cosigned vector in this corpus \
                     shares this preimage construction.",
                ),
            ),
            None,
        ));

        let mut unknown_member = self.receipt(
            keys,
            &declared(
                "statement-anchored",
                3,
                None,
                "MUST FAIL. `anchoring.checkpoint` carries `origin_id` — a member no receipt-borne \
                 checkpoint has. I-D §7.1 draws the object complete as the committed state plus \
                 `key_id` and `signature`, and MAY add `raw`; adaptor §11.1 closes the same set \
                 from the cosignature side, since the cosigned object \"contains exactly\" the \
                 six members \"and nothing else\" and \"any other checkpoint member is \
                 `invalid`\". The value here is even redundant rather than contradictory — the \
                 origin the blob already binds, rendered again — which is the point: a member no \
                 rule compares reads to a second implementation as though something had checked \
                 it, and it silently enters a preimage two implementations must agree on. \
                 Neither the log signature nor the cosignature is disturbed; the shape is. The \
                 finding lands on `anchoring` rather than `structure`: the receipt-borne \
                 checkpoint's shape is read in §7.5 step 3's key-independent checks, where the \
                 material the paths are bound to is established, and not in the container walk \
                 that precedes it.",
            ),
        );
        unknown_member["anchoring"]["checkpoint"]["origin_id"] = cp5.checkpoint["log_id"].clone();
        vectors.push((
            "statement-anchored-atl-checkpoint-unknown-member-must-fail.ahl",
            unknown_member,
            Some((
                "I-D §7.1 / adaptor §11.1 — a checkpoint member outside the six and `raw` is \
                 invalid, on the ANCHORING assertion where §7.5 step 3 reads the shape",
                |e: &ReceiptError| {
                    matches!(e, ReceiptError::Malformed(detail)
                        if detail.contains("`checkpoint` carries `origin_id`"))
                },
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
                        TEST_ATL_PROFILE_ID: {
                            "document": PROFILE_PATH,
                            "hash": self.profile_hash,
                            "capabilities": { "checkpoint_raw": true, "consistency_proofs": true },
                            "note": "The artifact held under this id is the document at \
                                     `document`, which defines this profile's own \
                                     serialization. Its shape is the one adaptor profile \
                                     `ahl-adaptor-atl-v1` defines, cited there as the source; it \
                                     is not that profile, and no artifact under that id is held \
                                     by this policy at all. A receipt pinning \
                                     `ahl-adaptor-atl-v1` is therefore `unverifiable` here — the \
                                     profile is not held (I-D §7.5 step 2) — while a receipt \
                                     pinning THIS id at a digest this document does not \
                                     recompute to is `invalid`, which \
                                     `statement-anchored-atl-unheld-manifest-pin-must-fail.ahl` \
                                     shows.",
                        },
                    },
                    "dataset_keys": {},
                    "limits": { "max_decoded_bytes": 8_388_608, "max_work_units": 100_000 },
                },
                "vectors": index,
            }),
        );
    }

    /// The record commitments this corpus names: record A (ingested at entry 1, retracted at
    /// entry 4) and record C (ingested at entry 5).
    fn record_subjects(&self) -> (String, String) {
        let read = |index: usize| {
            self.envelopes[index]["payload"]["record"]
                .as_str()
                .expect("an ingestion names its record")
                .to_owned()
        };
        (read(1), read(5))
    }
}

/// The `declared`-mode spec every simple ATL vector shares: the primary checkpoint, the genesis
/// chain, no enumeration and no later checkpoint.
fn declared_spec<'a>(
    anchor: &'a AtlAnchor,
    leaves: &'a [Vec<u8>],
    claim_type: &'a str,
    subject_index: usize,
    record_subject: Option<(&'a str, &'a str)>,
    note: &'a str,
) -> AtlSpec<'a> {
    AtlSpec {
        claim_type,
        subject_index,
        record_subject,
        anchor,
        leaves,
        chain: vec![0],
        currency_mode: "declared",
        currency_material: json!({}),
        claim_material: json!({}),
        continued_history: false,
        note,
    }
}

/// Everything that varies between the receipts this module assembles.
struct AtlSpec<'a> {
    claim_type: &'a str,
    subject_index: usize,
    record_subject: Option<(&'a str, &'a str)>,
    anchor: &'a AtlAnchor,
    leaves: &'a [Vec<u8>],
    chain: Vec<usize>,
    currency_mode: &'a str,
    currency_material: Value,
    claim_material: Value,
    continued_history: bool,
    note: &'a str,
}

/// One published vector: its file name, the receipt, and — for a negative — the rule it must
/// trip with the predicate over the rejection behind it.
type AtlVector = (&'static str, Value, Option<(&'static str, fn(&ReceiptError) -> bool)>);

/// Build and cosign one ATL checkpoint, with the §5.4 `raw` framing carried.
fn signed_anchor(
    name: &'static str,
    log_id: &str,
    tree_size: u64,
    root_hash: &str,
    nanos: u64,
    keys: &Keys,
) -> AtlAnchor {
    let mut checkpoint = atl_checkpoint(log_id, tree_size, root_hash, nanos, &keys.log_1)
        .expect("family strings over 32 octets");
    // Adaptor §5.4: `raw` is the base64 of the same 98 octets the signature covers. It is a
    // convenience rather than a trust step — a verifier that reconstructs the blob from the
    // parsed object per §5.5 obtains the same bytes — so it is carried precisely to be
    // reconciled against them.
    let blob = atl_checkpoint_blob_from_json(&checkpoint).expect("well-formed checkpoint");
    checkpoint["raw"] =
        json!(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(blob)));
    let cosignature = keys.witness_1.sign(&cosigned_bytes(&checkpoint, WITNESS_1));
    AtlAnchor { name, checkpoint, cosignature }
}

/// A `raw` framing that is a well-formed 98-byte ATL checkpoint blob of the same log, at a tree
/// size the JSON members do not carry.
fn wrong_size_raw(checkpoint: &Value) -> Value {
    let mut other = checkpoint.clone();
    other["tree_size"] = json!(checkpoint["tree_size"].as_u64().expect("tree_size") + 1);
    let blob = atl_checkpoint_blob_from_json(&other).expect("well-formed checkpoint");
    json!(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(blob)))
}

/// Write this corpus's profile document, and return `(hash, bytes)` of what landed on disk.
///
/// The digest is recomputed from the file rather than from the constant, exactly as
/// `write_and_hash_adaptor` does for the test profile: what a policy holds, and what a manifest
/// pins, must both be the PUBLISHED artifact.
fn write_and_hash_profile(root: &Path) -> (String, Vec<u8>) {
    let path = root.join(PROFILE_PATH);
    write_text(&path, TEST_ATL_PROFILE_DOC);
    let bytes = std::fs::read(&path).expect("profile document just written");
    (sha256_hex(&bytes), bytes)
}

/// Log-tree leaves under adaptor §3.1.
fn atl_leaves(envelopes: &[Value]) -> Vec<Vec<u8>> {
    envelopes
        .iter()
        .map(|env| log_leaf_bytes_for(env, TEST_ATL_PROFILE_ID).expect("known profile"))
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

/// The bare inclusion path of one leaf, as a receipt carries it (adaptor §7).
fn path(index: usize, leaves: &[Vec<u8>]) -> Vec<String> {
    let proof = inclusion_proof(leaves, index).expect("index within the tree");
    proof_path_hex(&proof)
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
