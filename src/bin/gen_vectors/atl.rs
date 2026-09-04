//! A second toy log, bound to adaptor profile `ahl-adaptor-atl-v1`.
//!
//! The main corpus binds `ahl-test-log-v1`, whose log leaf is the anchored entry bytes. This
//! one exists so the pieces that DIFFER under the ATL binding are exercised end to end rather
//! than at the unit level: the two-digest leaf construction of adaptor §4.2, the origin-derived
//! `log_id` of §7.1, the 98-byte checkpoint blob of §6.1 with the `raw` framing of §6.4, and the
//! inclusion geometry that follows from the leaf change (§8.2).
//!
//! # What this corpus pins, and what it deliberately does not
//!
//! Adaptor §14 makes release a precondition for use: "Until this document is released as an
//! immutable, openly published artifact at a stable location, its digest is not stable and no
//! manifest may pin it." That obligation binds a corpus operator and a verifier cannot enforce
//! it — a manifest that pins a draft digest is indistinguishable from one that pins a released
//! one, and prose beside the pin is not something a policy loader reads.
//!
//! So this crate ships NO copy of the unreleased profile, and this corpus pins nothing that
//! could ever collide with the released artifact's digest. It pins the digest of the STAND-IN
//! artifact at `test_data/profiles/ahl-adaptor-atl-v1.stand-in.md`, whose own first lines say
//! what it is: different bytes from any revision of the profile, so a manifest pinning it
//! resolves only against a policy holding it, and a manifest pinning the draft's digest — or the
//! released artifact's — does not resolve here at all. The dispatch keys on the profile ID
//! string, which is what names the serialization rules; the digest is what names the artifact,
//! and a stand-in artifact is the honest thing to name while the real one is unreleased.

use std::collections::BTreeMap;
use std::path::Path;

use ahl_core::receipt::{
    verify_receipt, verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Limits, Outcome,
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
use crate::text::ATL_STAND_IN_DOC;

/// Where the stand-in artifact is published, relative to `test_data/`.
const STAND_IN_PATH: &str = "profiles/ahl-adaptor-atl-v1.stand-in.md";

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
/// the §6.3 rendering rule ("exactly nine fractional digits") is exercised by a value that
/// actually has nine significant ones. It sits inside `[cadence_epoch, cadence_epoch + PT1H]`,
/// the window core spec §7.3 requires of the earliest checkpoint committing the genesis
/// manifest. Later checkpoints advance by a whole second, keeping nine significant digits.
const CHECKPOINT_NANOS: u64 = 1_786_881_600_123_456_789;

/// A metadata digest that is NOT the one adaptor §4.2 pins, for the two negatives that prove the
/// constant is load-bearing.
const WRONG_METADATA: &str = r#"{"ahl_adaptor":"not-this-profile"}"#;

/// The bytes whose digest manifest version 2 pins the profile id at.
///
/// It stands for any artifact a policy holding the stand-in does not hold — the released profile
/// included, whatever its digest turns out to be. Deliberately not the draft's digest: this
/// crate ships no copy of the draft, and hard-coding a digest of an unreleased document would
/// pin a moving target in exactly the way §14 forbids.
const UNHELD_ARTIFACT: &[u8] = b"an adaptor profile artifact this corpus does not hold";

/// Entry-index labels, one per anchored envelope.
const NAMES: [&str; 5] = [
    "00-manifest-genesis",
    "01-ingestion-customers-a",
    "02-ingestion-customers-b",
    "03-derivation-s1",
    "04-manifest-v2-unheld-profile-digest",
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
    /// Digest of the STAND-IN artifact — what the genesis manifest pins.
    stand_in_hash: String,
    stand_in_document: Vec<u8>,
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
        let (stand_in_hash, stand_in_document) = write_and_hash_stand_in(root);
        let unheld_hash = sha256_hex(UNHELD_ARTIFACT);
        let log_id = atl_log_id(&TREE_UUID);

        // Entry 0: the genesis manifest. `scenario::manifest` builds the whole §7.2/§7.3 shape;
        // only the adaptor id differs, since the hash and the log id are already parameters.
        let mut genesis = manifest(keys, &log_id, &stand_in_hash, 0, None);
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

        // Entry 4: a manifest version pinning the SAME profile id at the digest of an artifact
        // this corpus does not hold. Anchored last, so it is the active version for exactly one
        // checkpoint and nothing that must verify is governed by it. I-D §7.5 step 2: a profile
        // held under that id whose HASH DIFFERS is a disagreement "decidable from the bytes in
        // hand", and the result is `invalid`.
        let mut v2 = manifest(keys, &log_id, &unheld_hash, 4, Some(&entry_id(&env_0)));
        v2["log"]["adaptor"]["id"] = json!(ATL_PROFILE_ID);
        v2["witnesses"][0]["keys"][0]["valid_from_index"] = json!(0);
        let env_4 = envelope(v2, &keys.producer_1);

        let envelopes = vec![env_0, env_1, env_2, env_3, env_4];
        let leaves = atl_leaves(&envelopes);

        // cp4 is the primary checkpoint of every positive; cp5 is reached only by the negative
        // that manifest version 2 exists for.
        let anchors = ["cp4", "cp5"]
            .into_iter()
            .zip([4u64, 5])
            .map(|(name, size)| {
                let at = usize::try_from(size).expect("small tree size");
                let root_hash = hash_hex(&tree_root(&leaves[..at]));
                let nanos = CHECKPOINT_NANOS + (size - 4) * 1_000_000_000;
                signed_anchor(name, &log_id, size, &root_hash, nanos, keys)
            })
            .collect::<Vec<_>>();

        // The same entries under a metadata digest this profile does not pin. Adaptor §4.2: "An
        // entry whose ATL metadata is anything else is NOT an AHL entry under this profile and
        // MUST be rejected by an AHL verifier, even if it is a valid ATL entry." The checkpoint
        // over that tree is genuinely signed and genuinely cosigned, so nothing about it is
        // malformed — only the leaves are built the wrong way, which is exactly what a verifier
        // using the wrong constant would fail to notice.
        let wrong_root = hash_hex(&tree_root(&wrong_metadata_leaves(&envelopes)[..4]));
        let wrong_metadata =
            signed_anchor("cp4-wrong-metadata", &log_id, 4, &wrong_root, CHECKPOINT_NANOS, keys);

        Self {
            log_id,
            envelopes,
            stand_in_hash,
            stand_in_document,
            unheld_hash,
            anchors,
            wrong_metadata,
        }
    }

    fn anchor(&self, name: &str) -> &AtlAnchor {
        self.anchors.iter().find(|a| a.name == name).expect("named checkpoint")
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
        let pinned = if anchor.tree_size() > 4 { &self.unheld_hash } else { &self.stand_in_hash };
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
                "adaptor": { "id": ATL_PROFILE_ID, "hash": pinned },
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
    /// STAND-IN artifact, never the unreleased profile.
    pub fn trust_policy(&self, keys: &Keys) -> TrustPolicy {
        TrustPolicy {
            genesis_entry_id: entry_id(&self.envelopes[0]),
            genesis_key_ids: Some(std::iter::once(keys.producer_1.key_id()).collect()),
            adaptor_profiles: std::iter::once((
                ATL_PROFILE_ID.to_owned(),
                AdaptorProfile {
                    document: self.stand_in_document.clone(),
                    capabilities: AdaptorCapabilities {
                        // What the BINDING defines: a binary checkpoint framing (§6.4) and a
                        // consistency-proof serialization (§8.3). Serving consistency proofs and
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
    // One linear pass over one corpus: the §14 pin, the §4.2 leaves, every checkpoint, the §8.2
    // inclusion proofs, the §10.4 ranges and the §8.3 consistency proof. Splitting it would
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

        // §14, restated as an assertion: what the genesis manifest pins is the STAND-IN's digest,
        // and the stand-in says so in its own opening lines.
        assert_eq!(
            self.envelopes[0]["payload"]["log"]["adaptor"]["hash"],
            json!(self.stand_in_hash),
            "the genesis manifest must pin the stand-in artifact, never the unreleased profile"
        );
        let opening = String::from_utf8_lossy(&self.stand_in_document);
        assert!(
            opening.starts_with("# STAND-IN artifact for adaptor profile `ahl-adaptor-atl-v1`"),
            "the pinned artifact must announce itself as a stand-in in its first line"
        );
        assert!(
            opening.contains("**This is not the profile.**"),
            "the pinned artifact must say what it is not"
        );
        assert_ne!(self.stand_in_hash, self.unheld_hash);

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
        // The two geometries really do differ: a verifier applying the main corpus's leaf rule
        // to this log would recompute a different root for the same entries.
        let plain: Vec<Vec<u8>> = self.envelopes.iter().map(jcs).collect();
        assert_ne!(hash_hex(&tree_root(&plain)), hash_hex(&tree_root(&leaves)));

        for anchor in self.anchors.iter().chain(std::iter::once(&self.wrong_metadata)) {
            let size = usize::try_from(anchor.tree_size()).expect("small tree size");
            let expected = if anchor.name == "cp4-wrong-metadata" {
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
            // §6.5: the signature is over the 98-byte blob assembled from the JSON members, and
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
                    &cosignature_bytes(&anchor.checkpoint, WITNESS_1),
                    &anchor.cosignature,
                )
                .expect("well-formed signature"),
                "{}: cosignature did not verify",
                anchor.name
            );
            // §7.1: `log_id` is `"sha256:" || hex(SHA-256(the 16-byte Data Tree UUID))`, and the
            // blob binds those same 32 octets as its Origin ID.
            assert_eq!(&blob[18..50], &parse_hash_hex(&self.log_id).expect("log id")[..]);
        }
        assert_eq!(self.log_id, atl_log_id(&TREE_UUID));

        // §8.2: inclusion, in ATL geometry, at every index of the largest published checkpoint.
        let root = tree_root(&leaves);
        for index in 0..self.envelopes.len() {
            let proof = inclusion_proof(&leaves, index).expect("index within the tree");
            assert!(
                verify_inclusion_proof(&leaves[index], &proof, &root).expect("well-formed proof"),
                "ATL entry {index}: inclusion proof did not verify"
            );
        }

        println!(
            "  [ok] {} ATL entries, {} checkpoints, `raw` reconciled, every inclusion proof \
             verified in ATL geometry",
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
                                anchored entry bytes: adaptor profile `ahl-adaptor-atl-v1` §4.2 \
                                combines two digests, so the leaf preimage is \
                                `SHA-256(JCS(envelope)) || METADATA_HASH` and the leaf hash is \
                                `SHA-256(0x00 || that)`. The first digest is the raw form of the \
                                AHL entry id. The profile id is pinned at the digest of the \
                                STAND-IN artifact under `profiles/`, never at the unreleased \
                                profile's — see that file's own opening lines.",
                "adaptor": { "id": ATL_PROFILE_ID, "hash": self.stand_in_hash },
                "adaptor_document": STAND_IN_PATH,
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
        let cp4 = self.anchor("cp4");
        let cp5 = self.anchor("cp5");
        let record_a = self.record_a();

        let declared = |claim_type, subject_index, record_subject, note| {
            declared_spec(cp4, &leaves, claim_type, subject_index, record_subject, note)
        };

        let mut vectors: Vec<AtlVector> = Vec::new();

        vectors.push((
            "statement-anchored-atl-profile.ahl",
            self.receipt(
                keys,
                &declared(
                    "statement-anchored",
                    3,
                    None,
                    "The same claim `statement-anchored-valid.ahl` makes over the main corpus, \
                     under the OTHER adaptor profile. Three serializations differ and nothing \
                     else does. The log leaf is adaptor §4.2's two-digest construction, so the \
                     inclusion path here opens a root the main corpus's leaf rule would never \
                     produce. The checkpoint is signed over §6.1's fixed 98-byte blob rather \
                     than over `JCS(cp minus \"signature\")`, with `checkpoint_time` rendered to \
                     exactly nine fractional digits (§6.3) because the blob binds the exact \
                     nanosecond value. And the checkpoint carries `raw` (§6.4), which this \
                     binding DEFINES, so it must parse to the same values as the JSON members — \
                     the JSON members govern. `log_id` is origin-derived (§7.1): the 32 octets \
                     it carries are the Origin ID the blob binds at offset 18. The profile id is \
                     pinned at the digest of the STAND-IN artifact, never at the unreleased \
                     profile's; see `profiles/ahl-adaptor-atl-v1.stand-in.md`.",
                ),
            ),
            None,
        ));

        vectors.push((
            "record-ingested-atl-profile.ahl",
            self.receipt(
                keys,
                &declared(
                    "record-ingested",
                    1,
                    Some((DS_CUSTOMERS, &record_a)),
                    "The entry-1 ingestion introduced record A into `customers`, proven under \
                     the ATL binding. `content_binding` is `none`: what this vector is about is \
                     the anchoring geometry, and the content-binding rules are §2.6's, identical \
                     under both profiles because a record commitment never touches the log tree.",
                ),
            ),
            None,
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
                           in THAT geometry. Adaptor §4.2 fixes the metadata object and forbids \
                           any other: \"An entry whose ATL metadata is anything else is not an \
                           AHL entry under this profile and MUST be rejected by an AHL verifier, \
                           even if it is a valid ATL entry.\" A verifier that read the constant \
                           from the receipt, or computed it from operator-supplied metadata, \
                           would accept this — and with it a leaf that depends on bytes no AHL \
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
            "statement-anchored-atl-profile-digest-must-fail.ahl",
            wrong_digest,
            Some((
                "adaptor `ahl-adaptor-atl-v1` §14 / I-D §7.5 step 2 — the pinned digest must \
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
                    subject_index: 3,
                    record_subject: None,
                    anchor: cp5,
                    leaves: &leaves,
                    chain: vec![0, 4],
                    currency_mode: "declared",
                    currency_material: json!({}),
                    claim_material: json!({}),
                    continued_history: false,
                    note: "MUST FAIL, and this is the one §14 is really about. Manifest version \
                           2, anchored at entry 4, pins the SAME profile id at the digest of an \
                           artifact this verifier does not hold — which is what a manifest \
                           pinning the unreleased draft, or the artifact eventually released \
                           under that id, looks like to a verifier holding the stand-in. The \
                           manifest is genuinely signed, its lineage is correct, and cp5 is a \
                           genuine checkpoint of this log; none of that helps. I-D §7.5 step 2 \
                           resolves the profile from local possession by {id, digest} before any \
                           carried material is verified, and a held artifact whose digest \
                           differs is `invalid`. The corollary is the reason this corpus pins a \
                           stand-in at all: a verifier cannot tell a test pin from a production \
                           one, so the corpus must not create a pin that could be replayed as \
                           one.",
                },
            ),
            Some((
                "adaptor `ahl-adaptor-atl-v1` §14 / I-D §7.5 step 2 — a manifest pinning an \
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
                 tree size the JSON members do not agree with. Adaptor §6.4 and I-D §7.5 step 2 \
                 fix the precedence: \"where `raw` is carried it MUST parse to the same values \
                 as the JSON members, the JSON members govern the comparison, and a mismatch is \
                 `invalid`\". The checkpoint's own signature still verifies, because it is \
                 computed over the blob assembled from the JSON members — which is exactly why \
                 an unreconciled `raw` could present a verifier with values the log never signed.",
            ),
        );
        raw_mismatch["anchoring"]["checkpoint"]["raw"] = wrong_size_raw(&cp4.checkpoint);
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
                            "document": STAND_IN_PATH,
                            "hash": self.stand_in_hash,
                            "capabilities": { "checkpoint_raw": true, "consistency_proofs": true },
                            "note": "The artifact held under this id is the STAND-IN at \
                                     `document`, not the profile: `ahl-adaptor-atl-v1` is \
                                     unreleased and its §14 says no manifest may pin it until it \
                                     is published as an immutable artifact. The stand-in's own \
                                     first lines say what it is; its digest is deliberately not \
                                     the draft's and cannot be the released artifact's, so a \
                                     manifest pinning either does not resolve against this \
                                     policy — `statement-anchored-atl-unheld-manifest-pin-must-\
                                     fail.ahl` is exactly that case.",
                        },
                    },
                    "dataset_keys": {},
                    "limits": { "max_decoded_bytes": 8_388_608, "max_work_units": 100_000 },
                },
                "vectors": index,
            }),
        );
    }

    /// The commitment of record A, ingested at entry 1.
    fn record_a(&self) -> String {
        self.envelopes[1]["payload"]["record"]
            .as_str()
            .expect("an ingestion names its record")
            .to_owned()
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

/// Build and cosign one ATL checkpoint, with the §6.4 `raw` framing carried.
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
    // Adaptor §6.4: `raw` is the base64 of the same 98 octets the signature covers. It is a
    // convenience rather than a trust step — a verifier that reconstructs the blob from the
    // parsed object per §6.5 obtains the same bytes — so it is carried precisely to be
    // reconciled against them.
    let blob = atl_checkpoint_blob_from_json(&checkpoint).expect("well-formed checkpoint");
    checkpoint["raw"] =
        json!(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(blob)));
    let cosignature = keys.witness_1.sign(&cosignature_bytes(&checkpoint, WITNESS_1));
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

/// Write the stand-in artifact, and return `(hash, bytes)` of what landed on disk.
///
/// The digest is recomputed from the file rather than from the constant, exactly as
/// `write_and_hash_adaptor` does for the test profile: what a policy holds, and what a manifest
/// pins, must both be the PUBLISHED artifact.
fn write_and_hash_stand_in(root: &Path) -> (String, Vec<u8>) {
    let path = root.join(STAND_IN_PATH);
    write_text(&path, ATL_STAND_IN_DOC);
    let bytes = std::fs::read(&path).expect("stand-in artifact just written");
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

/// The bare inclusion path of one leaf, as a receipt carries it (adaptor §8.2).
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
