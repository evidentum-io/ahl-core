//! Evidence Receipt vectors: one positive and one negative per claim-type registry entry.
//!
//! Every receipt produced here is immediately run through
//! [`ahl_core::receipt::verify_receipt`] with the same trust policy the conformance tests use.
//! A positive vector that does not accept, or a negative vector that does not reject with the
//! rule it claims to violate, aborts the generator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ahl_core::receipt::{
    verify_receipt, AdaptorCapabilities, AdaptorProfile, ReceiptError, TrustPolicy,
};
use ahl_core::{checkpoint_signing_bytes, entry_id, envelope, field_str, statement_id, TestKey};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::corpus::{Anchor, Corpus};
use crate::scenario::{
    signed, write_jcs, write_json, Keys, ADAPTOR_ID, CANONICALIZATION, DS_CUSTOMERS, DS_SCORES, T0,
    WITNESS_1,
};

/// What a receipt vector asserts about its own verification outcome.
enum Expect {
    /// `verify_receipt` must accept.
    Accept,
    /// `verify_receipt` must reject, and the rejection must satisfy this predicate.
    Reject { rule: &'static str, matches: fn(&ReceiptError) -> bool },
}

struct Vector {
    file: &'static str,
    receipt: Value,
    expect: Expect,
}

/// The locally configured trust policy for the corpus (receipt format §1 design rule 1).
///
/// Everything here is *policy*, not receipt content: the published genesis anchor, the
/// published genesis key fingerprints, the locally possessed adaptor profile, and the dataset
/// key an authorized verifier holds.
pub fn trust_policy(corpus: &Corpus, keys: &Keys, dataset_key: &[u8]) -> TrustPolicy {
    TrustPolicy {
        genesis_entry_id: entry_id(&corpus.envelopes[0]),
        genesis_key_ids: Some(BTreeSet::from([keys.producer_1.key_id()])),
        // `ahl-test-log-v1` defines the consistency-proof serialization (profile §9) but no
        // binary checkpoint framing, so a receipt carrying `anchoring.checkpoint.raw` is
        // rejected as a limitation of *this profile*, naming it, not as a limitation of the
        // format — while `continued_history` is reachable and must be really proven.
        adaptor_profiles: BTreeMap::from([(
            ADAPTOR_ID.to_owned(),
            AdaptorProfile {
                document: corpus.adaptor_document.clone(),
                capabilities: AdaptorCapabilities {
                    checkpoint_raw: false,
                    consistency_proofs: true,
                },
            },
        )]),
        dataset_keys: BTreeMap::from([(DS_CUSTOMERS.to_owned(), dataset_key.to_vec())]),
        trusted_witness_keys: BTreeMap::new(),
        limits: ahl_core::receipt::Limits::default(),
    }
}

/// Build, self-check and write every receipt vector plus the corpus receipt index.
pub fn write_all(corpus: &Corpus, keys: &Keys, root: &Path, dataset_key: &[u8]) {
    let policy = trust_policy(corpus, keys, dataset_key);
    let vectors = build_vectors(corpus, keys);

    println!("receipt self-check");
    let dir = root.join("receipts");
    let mut index = Vec::new();
    for vector in &vectors {
        let outcome = verify_receipt(&vector.receipt, &policy);
        match &vector.expect {
            Expect::Accept => {
                let verdict = outcome.unwrap_or_else(|error| {
                    panic!("{}: must verify, but was rejected: {error}", vector.file)
                });
                println!("  [ok] {} accepted: {}", vector.file, verdict.claim_type);
                index.push(json!({
                    "file": vector.file,
                    "claim_type": verdict.claim_type,
                    "expect": "accept",
                    "boundary": verdict.boundary,
                    "embedded_receipts": verdict.embedded_receipts,
                }));
            }
            Expect::Reject { rule, matches } => {
                let error = outcome
                    .err()
                    .unwrap_or_else(|| panic!("{}: must be rejected, but verified", vector.file));
                assert!(
                    matches(&error),
                    "{}: rejected by the wrong rule — expected {rule}, got: {error}",
                    vector.file
                );
                println!("  [ok] {} rejected by {rule}: {error}", vector.file);
                index.push(json!({
                    "file": vector.file,
                    "claim_type": vector.receipt["claim"]["type"],
                    "expect": "reject",
                    "rule": rule,
                    "reason": error.to_string(),
                }));
            }
        }
        write_jcs(&dir.join(vector.file), &vector.receipt);
    }

    write_json(
        &dir.join("index.json"),
        &json!({
            "description": "Every Evidence Receipt vector in this directory, with the outcome a \
                            conformant verifier must reach. Negative vectors name the normative \
                            rule that must fire. The `policy` block is the locally configured \
                            trust policy the outcomes assume (receipt format §1 design rule 1); \
                            it is deliberately NOT derived from any receipt.",
            "policy": {
                "genesis_entry_id": entry_id(&corpus.envelopes[0]),
                "genesis_key_ids": [ keys.producer_1.key_id() ],
                "adaptor_profiles": {
                    ADAPTOR_ID: {
                        "hash": corpus.adaptor_hash,
                        "capabilities": {
                            // What the profile document defines. Absent capabilities make
                            // dependent receipt material unverifiable *under this profile*.
                            "checkpoint_raw": false,
                            "consistency_proofs": true,
                        },
                    },
                },
                "dataset_keys": {
                    DS_CUSTOMERS: "test_data/keys/dataset_customers.key — held only by an \
                                   authorized verifier; never packaged in a receipt",
                },
                "limits": {
                    "max_embedded_depth": 4,
                    "max_embedded_receipts": 64,
                    "max_decoded_bytes": 8_388_608,
                    "max_work_units": 100_000,
                },
            },
            "vectors": index,
        }),
    );
}

// ---------------------------------------------------------------------------
// Receipt skeleton
// ---------------------------------------------------------------------------

/// Everything that varies between receipts. Assembled by [`Spec::build`].
struct Spec<'a> {
    claim_type: &'static str,
    subject_index: usize,
    anchor: &'a Anchor,
    /// Entry indices of the governance statements the receipt carries.
    chain: Vec<usize>,
    record_subject: Option<(String, String)>,
    competing: &'static str,
    content_binding: &'static str,
    currency_mode: &'static str,
    currency_material: Value,
    claim_material: Value,
    /// Override the `keys.producer` block, for vectors that deliberately list a key the §7.2
    /// snapshot no longer carries.
    producer_keys: Option<Vec<Value>>,
    note: String,
}

impl Spec<'_> {
    fn build(&self, corpus: &Corpus, keys: &Keys) -> Value {
        let anchor = self.anchor;
        let tree_size = anchor.tree_size();
        let subject = &corpus.envelopes[self.subject_index];

        let mut claim = json!({
            "type": self.claim_type,
            "assurance": {
                "governance": self.currency_mode,
                "competing_triggers": self.competing,
                "witnessed": true,
                "continued_history": false,
                "content_binding": self.content_binding,
            },
            "note": self.note,
        });
        // I-D §7.3: `canonicalization_namespace` is "REQUIRED where `content_binding` is not
        // `none`, and absent otherwise", and is `private-use` exactly where the carried
        // descriptor's identifier begins `x-`. Every dataset in this corpus declares the
        // registered identifier `jcs` (§2.6), so every content-binding receipt here is
        // `public` — and a receipt asserting no content binding carries the member not at all.
        if self.content_binding != "none" {
            claim["assurance"]["canonicalization_namespace"] =
                json!(if CANONICALIZATION.starts_with("x-") { "private-use" } else { "public" });
        }
        if let Some((dataset, record)) = &self.record_subject {
            claim["record_subject"] = json!({ "dataset": dataset, "record": record });
        }

        let mut subject_block = json!({
            "statement_id": statement_id(subject).expect("well-formed envelope"),
            "entry_id": entry_id(subject),
            "entry_index": self.subject_index,
        });
        // A manifest statement declares no manifest version; everything else must (§2.3).
        if let Some(manifest) = corpus.payload(self.subject_index).get("manifest") {
            subject_block["manifest"] = manifest.clone();
        }

        let (witness_key, _) = keys.witness_for(anchor.manifest_index);
        let producer_keys = self.producer_keys.clone().unwrap_or_else(|| {
            // §7.2 snapshot rule: the producer key set in force at the subject's entry index
            // starts from the manifest with the greatest entry index *below* it (the genesis
            // manifest for the corpus prefix), then applies later `key` statements. Each key
            // binds to the governance statement that actually put it there (§2.2).
            let subject = self.subject_index as u64;
            let snapshot = self
                .chain
                .iter()
                .copied()
                .rfind(|index| {
                    corpus.payload(*index)["type"] == "manifest" && (*index as u64) < subject
                })
                .unwrap_or(0) as u64;
            let mut block = vec![key_entry(&keys.producer_1, None, snapshot)];
            if self.chain.contains(&9) && snapshot < 9 && 9 <= subject {
                block.push(key_entry(&keys.producer_2, None, 9));
            }
            block
        });

        let mut receipt = json!({
            "ahl_receipt_version": "2",
            "spec_version": "0.4.0",
            "claim": claim,
            "subject": subject_block,
            "envelope": subject,
            "keys": {
                "log": [ key_entry(&keys.log_1, None, anchor.manifest_index) ],
                "witness": [ key_entry(witness_key, Some(anchor.witness_id), anchor.manifest_index) ],
                "producer": producer_keys,
            },
            "anchoring": {
                "adaptor": { "id": ADAPTOR_ID, "hash": corpus.adaptor_hash },
                "checkpoint": anchor.checkpoint,
                "inclusion_path": corpus.log_path(self.subject_index, tree_size),
                "witnesses": [ anchor.witness_entry(keys) ],
            },
            "governance": {
                "genesis_entry_id": entry_id(&corpus.envelopes[0]),
                "chain": self
                    .chain
                    .iter()
                    .map(|index| json!({
                        "envelope": corpus.envelopes[*index],
                        "entry_index": index,
                        "inclusion_path": corpus.log_path(*index, tree_size),
                    }))
                    .collect::<Vec<_>>(),
                "currency": { "mode": self.currency_mode, "material": self.currency_material },
            },
            "claim_material": self.claim_material,
        });
        // I-D §7.1: "REQUIRED IF AND ONLY IF the carried chain contains a governance-key
        // rotation... The member is ABSENT where the chain rotates neither set" — never present
        // as an empty array. This corpus rotates exactly once, at manifest v2 (entry 25), so
        // any chain carrying it needs exactly this one element, and no other chain carries the
        // member at all.
        if self.chain.contains(&25) {
            receipt["governance"]["rotation_proofs"] = json!([corpus.rotation_proof_element(keys)]);
            // I-D §7.1: "Every key used in verification MUST appear in `keys` with its source
            // and its binding", and under the rotation-proof transition exception "the
            // corresponding `keys.log[]` and `keys.witness[]` entries carry `manifest-chain`
            // bindings naming that predecessor version". This corpus's one rotation is manifest
            // v2 at entry 25, whose predecessor is the genesis manifest at entry 0, so a
            // receipt carrying that rotation lists the OUTGOING log key and the OUTGOING
            // witness bound at 0 — alongside the entries for its own checkpoint, which bind to
            // manifest v2. The log key is physically the same key in both, listed twice under
            // two different bindings, which is exactly the case receipt key binding tolerates.
            if anchor.manifest_index != 0 {
                let (outgoing_witness, outgoing_witness_id) = keys.witness_for(0);
                receipt["keys"]["log"].as_array_mut().expect("keys.log array").push(key_entry(
                    &keys.log_1,
                    None,
                    0,
                ));
                receipt["keys"]["witness"]
                    .as_array_mut()
                    .expect("keys.witness array")
                    .push(key_entry(outgoing_witness, Some(outgoing_witness_id), 0));
            }
        }
        receipt
    }
}

/// A `keys` block entry (receipt format §2.2).
pub fn key_entry(key: &TestKey, witness_id: Option<&str>, binding_index: u64) -> Value {
    let mut entry = json!({
        "key_id": key.key_id(),
        "pubkey": key.pubkey(),
        "source": "manifest-chain",
        "binding": { "entry_index": binding_index },
    });
    if let Some(id) = witness_id {
        entry["witness_id"] = json!(id);
    }
    entry
}

fn base64(bytes: &[u8]) -> String {
    format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Index of the leaf naming `record` in a committed record-sorted tree.
fn leaf_index(corpus: &Corpus, root: &str, record: &str) -> usize {
    corpus
        .tree_leaves(root)
        .iter()
        .position(|leaf| field_str(leaf, "record").ok() == Some(record))
        .expect("record is committed by the tree")
}

// ---------------------------------------------------------------------------
// The vectors
// ---------------------------------------------------------------------------

/// Build every vector. One positive and at least one negative per registry claim type.
// `s2_index` / `s3_index` name the records they open; renaming them would hide which leaf a
// vector proves and which one the negative counterpart wrongly opens.
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)] // A flat catalogue: one entry per registry claim type.
fn build_vectors(corpus: &Corpus, keys: &Keys) -> Vec<Vector> {
    let r = &corpus.records;
    let cp8 = corpus.anchor("cp8");
    let cp13 = corpus.anchor("cp13");
    let cp20 = corpus.anchor("cp20");
    let cp24 = corpus.anchor("cp24");
    let cp25 = corpus.anchor("cp25");
    let cp28 = corpus.anchor("cp28");
    let cp29 = corpus.anchor("cp29");
    let cp30 = corpus.anchor("cp30");
    let cp32 = corpus.anchor("cp32");
    let cp33 = corpus.anchor("cp33");
    let customers = |record: &String| Some((DS_CUSTOMERS.to_owned(), record.clone()));
    let scores = |record: &String| Some((DS_SCORES.to_owned(), record.clone()));

    let mut out = Vec::new();

    // --- statement-anchored ------------------------------------------------------
    let statement_anchored = Spec {
        claim_type: "statement-anchored",
        subject_index: 3,
        anchor: cp20,
        chain: vec![0],
        record_subject: None,
        competing: "not-checked",
        content_binding: "none",
        currency_mode: "declared",
        currency_material: json!({}),
        claim_material: json!({}),
        producer_keys: None,
        note: "Proves that the entry-3 derivation envelope is anchored at entry index 3 under a \
               witnessed checkpoint and signed under the producer-declared manifest chain. It \
               asserts nothing about the truth of the derivation, about competing triggers, or \
               about the governance state active at index 3."
            .to_owned(),
    }
    .build(corpus, keys);
    out.push(Vector {
        file: "statement-anchored-valid.ahl",
        receipt: statement_anchored.clone(),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "overclaim-must-fail.ahl",
        receipt: overclaim(&statement_anchored),
        expect: Expect::Reject {
            rule: "receipt §2.3 — assurance.governance must equal governance.currency.mode",
            matches: |e| matches!(e, ReceiptError::AssuranceMismatch { field: "governance" }),
        },
    });

    // --- continued history (receipt §2.1, §2.3; adaptor profile §9) ---------------
    // `assurance.continued_history` is the claim that the log's history stayed append-only past
    // the checkpoint the subject is included under. It is reachable only where the pinned
    // profile defines a consistency-proof serialization, and only against a real proof: the
    // later checkpoint is authenticated on its own terms — its log signature verified under the
    // manifest version active for ITS tree size — and then the RFC 9162 proof must open the
    // pair (cp20.root at size 20 -> cp24.root at size 24).
    let continued = |path: Vec<String>, note: &str| {
        let mut receipt = Spec {
            claim_type: "statement-anchored",
            subject_index: 3,
            anchor: cp20,
            chain: vec![0],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys);
        receipt["claim"]["assurance"]["continued_history"] = json!(true);
        receipt["anchoring"]["later_checkpoint"] = cp24.checkpoint.clone();
        receipt["anchoring"]["later_witnesses"] = cp24.witnesses_array(keys);
        receipt["anchoring"]["consistency_path"] = json!(path);
        receipt
    };

    out.push(Vector {
        file: "statement-anchored-continued-history.ahl",
        receipt: continued(
            corpus.consistency_path(20, 24),
            "Proves what `statement-anchored-valid.ahl` proves, and one thing more: that the \
             log's history continued to be append-only past cp20. The receipt carries cp24 as a \
             complete signed checkpoint object and an RFC 9162 consistency path from cp20's \
             root at tree size 20 to cp24's at tree size 24 (adaptor profile §9). cp24's own \
             log signature is verified under the manifest version active for ITS tree size, not \
             cp20's — here both resolve to the genesis manifest, but the rule is the same one \
             that lets a rotated log key set validate only the checkpoints issued under it \
             (receipt §2.1, §2.2). The boundary stops there: a consistency proof shows an \
             append-only extension, never that every checkpoint the declared cadence required \
             was actually published (core §7.3), and the rendered verdict says so.",
        ),
        expect: Expect::Accept,
    });

    out.push(Vector {
        file: "statement-anchored-continued-history-wrong-pair-must-fail.ahl",
        receipt: continued(
            corpus.consistency_path(8, 24),
            "MUST FAIL. The carried path is a genuine, correctly generated RFC 9162 consistency \
             proof — for the pair (8, 24), not the pair (20, 24) this receipt's two checkpoints \
             name. Nothing about it is malformed; it simply proves a different fact. The sizes \
             are deliberately NOT part of the serialization (adaptor profile §9.1): they come \
             from `anchoring.checkpoint` and `anchoring.later_checkpoint`, so the proof is bound \
             to one pair and a verifier that asked only \"does this path open something?\" \
             would accept evidence about sizes the claim never mentioned.",
        ),
        expect: Expect::Reject {
            rule: "receipt §2.1 / adaptor §9.2 — the consistency path must open the pair the \
                   receipt's own two checkpoints name",
            matches: |e| matches!(e, ReceiptError::ConsistencyPathInvalid),
        },
    });

    // A key the manifest v2 snapshot dropped may not be listed as in force after entry 23.
    out.push(Vector {
        file: "statement-anchored-dropped-producer-key-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 26,
            anchor: cp28,
            chain: vec![0, 9, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 9),
            ]),
            note: "MUST FAIL. The subject is anchored at entry 26, after manifest version 2 at \
                   entry 25. Core spec §7.2: a manifest's producer `keys` array is the complete \
                   snapshot effective from that manifest's entry index — it DISCARDS the prior \
                   snapshot. Version 2 lists only `producer-1`, so the key that the `key` \
                   statement at entry 9 added is no longer in force at entry 26, and a receipt \
                   that lists it as `manifest-chain`-bound is asserting a key state the \
                   governance chain does not support. A verifier that accumulated manifest key \
                   arrays additively would accept this — and would then also accept a signature \
                   made with the dropped key."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "spec §7.2 — a manifest's producer key array is a snapshot that discards the \
                   prior one",
            matches: |e| matches!(e, ReceiptError::KeyNotBound { .. }),
        },
    });

    // --- record-ingested ---------------------------------------------------------
    let ingested = |content_binding: &'static str, bytes: &[u8], note: &str| {
        Spec {
            claim_type: "record-ingested",
            subject_index: 1,
            anchor: cp20,
            chain: vec![0],
            record_subject: customers(&r.c_a),
            competing: "not-checked",
            content_binding,
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "record_bytes": base64(bytes),
                "canonicalization": CANONICALIZATION,
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };
    out.push(Vector {
        file: "record-ingested-valid.ahl",
        receipt: ingested(
            "keyed-authorized",
            &r.c_a_bytes_as_received,
            "Proves that the entry-1 ingestion introduced record A into dataset `customers`, \
             and — for a verifier authorized to hold the dataset key — that the carried \
             bytes recompute to the anchored HMAC commitment. `record_bytes` is deliberately \
             carried AS RECEIVED — non-canonical key order, insignificant whitespace JCS \
             strips — rather than pre-canonicalized, so this vector proves the verifier \
             actually applies the canonicalization procedure (I-D §2.6, §7.2) rather than \
             merely accepting bytes that already happen to be canonical. The dataset key is \
             NOT packaged: an unauthorized verifier still checks the signature, the anchoring \
             and the graph, but reads `content_binding` as unverifiable.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "record-ingested-content-mismatch-must-fail.ahl",
        receipt: ingested(
            "keyed-authorized",
            &r.c_b_bytes,
            "MUST FAIL. The claim asserts `content_binding: \"keyed-authorized\"` but the \
             carried `record_bytes` are the canonical bytes of record B, which recompute to B's \
             commitment, not to the record A the subject ingestion anchors. Receipt format §2.1 \
             requires the content-evidence fields to actually satisfy the claimed binding.",
        ),
        expect: Expect::Reject {
            rule: "receipt §2.1 — carried record bytes must recompute to the anchored commitment",
            matches: |e| matches!(e, ReceiptError::ContentBindingMismatch { .. }),
        },
    });

    // I-D §2.2 / §7.6: entry 32 is a genuine, fully anchored ingestion of record E into
    // `customers`, signed by the `customers` authority — but its payload names manifest v1
    // (genesis) as governing it, even though it is anchored well after manifest v2 (entry 25)
    // became active. This is a real corpus statement (see `corpus.rs`'s entry 32), not a
    // mutated fixture: the "structural wall" earlier rounds hit — mutating an anchored
    // envelope invalidates its own inclusion path before the rule under test is ever reached —
    // does not apply here, because the defect was baked in before the statement was ever
    // signed or included.
    out.push(Vector {
        file: "record-ingested-stale-manifest-must-fail.ahl",
        receipt: Spec {
            claim_type: "record-ingested",
            subject_index: 32,
            anchor: cp33,
            chain: vec![0, 9, 25],
            record_subject: customers(&r.c_e),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: format!(
                "MUST FAIL. Entry 32's payload names manifest `{}` (v1, genesis), but I-D §2.2 \
                 resolves \"the manifest version active at the statement's entry index\" as \
                 the manifest with the greatest entry index smaller than the statement's own — \
                 here manifest `{}` (v2, entry 25), not v1. A receipt is invalid however genuine \
                 the rest of the statement is: real signature, real inclusion, real record.",
                corpus.manifest_id(0),
                corpus.manifest_id(25),
            ),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §2.2 / §7.6 — subject.manifest must be the manifest ACTIVE at \
                   subject.entry_index, not merely an earlier one",
            matches: |e| matches!(e, ReceiptError::SubjectManifestBindingInvalid(_)),
        },
    });

    // --- record-derived (batch member, with input-set membership) ----------------
    let w1_leaf = leaf_index(corpus, &corpus.wide_outputs_root, &r.w1);
    let w2_leaf = leaf_index(corpus, &corpus.wide_outputs_root, &r.w2);
    let a2_input = leaf_index(corpus, &corpus.input_set_root, &r.c_a2);
    let derived = |path: Vec<String>, note: &str| {
        Spec {
            claim_type: "record-derived",
            subject_index: 10,
            anchor: cp20,
            chain: vec![0],
            record_subject: scores(&r.w1),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "output": { "dataset": DS_SCORES, "record": r.w1 },
                "batch_leaf": corpus.tree_leaves(&corpus.wide_outputs_root)[w1_leaf],
                "leaf_index": w1_leaf,
                "leaf_path": path,
                "input_members": [ {
                    "input": corpus.tree_leaves(&corpus.input_set_root)[a2_input],
                    "input_index": a2_input,
                    "input_path": corpus.tree_path(&corpus.input_set_root, a2_input),
                } ],
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };
    out.push(Vector {
        file: "record-derived-valid.ahl",
        receipt: derived(
            corpus.tree_path(&corpus.wide_outputs_root, w1_leaf),
            "Proves that the batch derivation at entry 10 committed output record W1, by \
             opening the batch output tree at the carried `ahl-leaf-v2` leaf, and — through \
             `input_members` — that record A2 is a member of the input set that leaf commits by \
             root. Two trees are traversed: the outputs tree against `outputs_root`, and the \
             input-set tree against the leaf's `inputs.input_set_root`. It proves nothing about \
             the batch's other output, nothing about the input set's other two members, and \
             nothing about A2's own upstream provenance — those are separate claims.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "record-derived-wrong-path-must-fail.ahl",
        receipt: derived(
            corpus.tree_path(&corpus.wide_outputs_root, w2_leaf),
            "MUST FAIL. `leaf_index` and `batch_leaf` name W1 but `leaf_path` is the inclusion \
             path of the other leaf of the same tree, so recomputation does not reach \
             `outputs_root`. Everything else is byte-identical to record-derived-valid.ahl.",
        ),
        expect: Expect::Reject {
            rule: "receipt §3 — `leaf_path` must open `outputs_root`",
            matches: |e| {
                matches!(e, ReceiptError::InclusionPathInvalid { what: "batch output leaf" })
            },
        },
    });

    // --- trigger-declared --------------------------------------------------------
    let introduction = |subject_index: usize, record: &String, anchor: &Anchor| {
        // The embedded receipt's own log/witness keys bind to the manifest version active for
        // ITS anchor (§2.2), independent of the subject's own manifest snapshot — so the
        // presented chain must include that manifest whenever it isn't genesis.
        let mut chain = vec![0];
        if anchor.manifest_index != 0 {
            chain.push(usize::try_from(anchor.manifest_index).expect("small entry index"));
        }
        Spec {
            claim_type: "record-ingested",
            subject_index,
            anchor,
            chain,
            record_subject: customers(record),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "Embedded introduction proof: establishes who may issue a trigger for this \
               record (receipt §3 authority note). It says nothing about the record's content."
                .to_owned(),
        }
        .build(corpus, keys)
    };

    let trigger_declared = |anchor: &Anchor, replacement: Value, note: &str| {
        Spec {
            claim_type: "trigger-declared",
            subject_index: 6,
            anchor,
            chain: vec![0],
            record_subject: customers(&r.c_a),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "introduction": introduction(1, &r.c_a, anchor),
                "replacement_introduction": replacement,
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "trigger-declared-valid.ahl",
        receipt: trigger_declared(
            cp8,
            introduction(5, &r.c_a2, cp8),
            "Proves that a correction naming record A is anchored at entry 6 and signed under \
             the declared manifest chain by the declared issuer, with introduction proofs for \
             both A and its replacement A2. Being a `-declared` type it does NOT claim the \
             trigger is effective, that its issuer holds authority, or that it governs A at any \
             checkpoint: no competing-trigger enumeration is carried.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "trigger-declared-replacement-ordering-must-fail.ahl",
        receipt: trigger_declared(
            cp20,
            introduction(11, &r.c_a3, cp20),
            "MUST FAIL. The embedded `replacement_introduction` is the ingestion at entry 11, \
             but the correction it supports is anchored at entry 6. Core spec §2.3.3 requires a \
             correction's replacement to be introduced at an entry index no greater than the \
             correction's, and receipt §2.3 requires embedded entry indexes to satisfy that \
             ordering. (The record also disagrees — A3 rather than A2 — but the ordering rule \
             fires first, and is the rule this vector exists to exercise.)",
        ),
        expect: Expect::Reject {
            rule: "spec §2.3.3 / receipt §2.3 — replacement introduction index <= trigger index",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::EmbeddedOrderingViolation {
                        what: "replacement introduction",
                        inner: 11,
                        outer: 6,
                    }
                )
            },
        },
    });

    // --- trigger-effective -------------------------------------------------------
    let trigger_effective = |from_index: u64, note: &str| {
        Spec {
            claim_type: "trigger-effective",
            subject_index: 6,
            anchor: cp8,
            chain: vec![0],
            record_subject: customers(&r.c_a),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 8, cp8),
            claim_material: json!({
                "introduction": introduction(1, &r.c_a, cp8),
                "replacement_introduction": introduction(5, &r.c_a2, cp8),
                "checkpoint_C": cp8.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(from_index, 8, cp8) },
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "trigger-effective-valid.ahl",
        receipt: trigger_effective(
            1,
            "Proves that the correction at entry 6 governs record A at checkpoint cp8. \
             `checkpoint_C` is byte-identical to the receipt's own `anchoring.checkpoint`, so \
             the checkpoint the claim rests on is one this verifier checked: signature, witness \
             cosignature and inclusion path (receipt §3). Governance currency is enumerated \
             over exactly [0, 8) — the whole prefix of C, per §4 — and the competing-trigger \
             range is [1, 8), the prefix from A's introduction, which §3 permits precisely \
             because a trigger anchored before the record's introduction is never effective \
             (core §2.3.3). The issuer holds the dataset authority the manifest declares. The \
             claim is bounded by cp8: the corpus later anchors a superseding correction of A at \
             entry 12 and an outright retraction at entry 18, both invisible here by \
             construction.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "trigger-effective-short-range-must-fail.ahl",
        receipt: trigger_effective(
            3,
            "MUST FAIL. The competing-trigger enumeration covers [3, 8) — a valid, correctly \
             proven range, but neither [0, tree_size(C)) nor the introduction-fixed \
             [1, tree_size(C)). Receipt §3 fixes the required range for `trigger-effective` by \
             rule, so a truncated range leaves entries 1 and 2 unaccounted for and the claim \
             that this trigger governs is unsupported.",
        ),
        expect: Expect::Reject {
            rule: "receipt §3 — competing.corpus_range must be [0, tree_size(C)) or \
                   [introduction_index, tree_size(C))",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::CompetingRangeInsufficient {
                        got_from: 3,
                        got_to: 8,
                        tree_size: 8,
                        introduction_index: 1,
                    }
                )
            },
        },
    });

    // Enumerated governance currency plus a later checkpoint: a combination the frozen format
    // cannot evidence, and therefore a refusal rather than a pass. Every individual piece here
    // is genuine — the enumeration over [0, 8) is complete and correctly proven, cp13 is a real
    // signed checkpoint, and the consistency path from cp8 to cp13 verifies — which is exactly
    // why the vector is worth carrying: nothing is malformed, and the receipt is still refused.
    let mut enumerated_with_later = trigger_effective(
        1,
        "MUST FAIL. Receipt §2.1 requires the governance material to cover through \
         `later_checkpoint.tree_size` (13 here); §4 fixes enumerated material at exactly \
         [0, tree_size(C)) for the receipt's verified checkpoint, which §3 binds to \
         `anchoring.checkpoint` (cp8, tree size 8). No single range satisfies both rules, and \
         the format defines no second authenticated range, so the coverage §2.1 mandates cannot \
         be carried at all. Every piece of this receipt is individually valid: the [0, 8) \
         enumeration is complete and correctly proven, cp13 carries a genuine log signature, and \
         the consistency path from cp8 to cp13 verifies. A verifier that checked each piece and \
         accepted would be reporting as established a coverage requirement nothing here proves — \
         a manifest anchored between the two checkpoints could have rotated the log key set, and \
         an enumeration bounded at 8 could never reveal it. The refusal names the conflict \
         rather than pretending some rule failed: a defective format is a reason not to \
         fabricate evidence, not a reason to declare missing evidence verified.",
    );
    enumerated_with_later["claim"]["assurance"]["continued_history"] = json!(true);
    enumerated_with_later["anchoring"]["later_checkpoint"] = cp13.checkpoint.clone();
    enumerated_with_later["anchoring"]["later_witnesses"] = cp13.witnesses_array(keys);
    enumerated_with_later["anchoring"]["consistency_path"] = json!(corpus.consistency_path(8, 13));
    out.push(Vector {
        file: "trigger-effective-enumerated-with-later-checkpoint-must-fail.ahl",
        receipt: enumerated_with_later,
        expect: Expect::Reject {
            rule: "receipt §2.1 vs §4 — enumerated currency cannot cover a later checkpoint, so \
                   the combination is refused rather than accepted on unproven governance",
            matches: |e| matches!(e, ReceiptError::FormatConflict { .. }),
        },
    });

    // The challenge at entry 21: a well-anchored trigger from a non-authority key.
    let non_authority_trigger = Spec {
        claim_type: "trigger-effective",
        subject_index: 23,
        anchor: cp25,
        chain: vec![0, 9],
        record_subject: customers(&r.c_f),
        competing: "enumerated",
        content_binding: "none",
        currency_mode: "enumerated",
        currency_material: corpus.enumeration(0, 25, cp25),
        claim_material: json!({
            "introduction": introduction(20, &r.c_f, cp25),
            "checkpoint_C": cp25.checkpoint,
            "competing": { "corpus_range": corpus.enumeration(20, 25, cp25) },
        }),
        producer_keys: None,
        note: "MUST FAIL. Every mechanical check passes: the retraction at entry 23 is anchored, \
               its signature verifies against a producer key in force at that index, the \
               enumeration is complete and the competing range is the introduction-fixed one. \
               It still cannot be effective, because core spec §2.3.3 makes effectiveness an \
               AUTHORITY question: `producer-2` is not in the key set the manifest declares as \
               the `customers` dataset authority, so this trigger anchors as a **challenge** — \
               surfaced by verification, never traversed."
            .to_owned(),
    }
    .build(corpus, keys);
    out.push(Vector {
        file: "trigger-effective-non-authority-issuer-must-fail.ahl",
        receipt: non_authority_trigger.clone(),
        expect: Expect::Reject {
            rule: "spec §2.3.3 — a trigger not signed by the record's authority is a challenge",
            matches: |e| matches!(e, ReceiptError::TriggerNotAuthorized { entry_index: 23, .. }),
        },
    });

    // A valid, AUTHORIZED trigger on F at entry 22, enumerated over a range that also
    // contains the later challenge at entry 23. The challenge must be filtered out before the
    // greatest-entry-index selection, or it would wrongly govern.
    out.push(Vector {
        file: "trigger-effective-later-challenge-ignored.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 22,
            anchor: cp25,
            chain: vec![0, 9],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 25, cp25),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp25),
                "checkpoint_C": cp25.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 25, cp25) },
            }),
            producer_keys: None,
            note: "Proves that the retraction at entry 22 — signed by the `customers` dataset \
                   authority — governs record F at cp25, EVEN THOUGH a second trigger naming \
                   the same record sits at the greater entry index 23. That later trigger is \
                   signed by `producer-2`, which is not in the authority key set, so core spec \
                   §2.3.3 anchors it as a challenge: \"surfaced by verification, never \
                   traversed\". Effectiveness is therefore decided BEFORE the \
                   greatest-entry-index rule is applied, not after. A verifier that selected \
                   the governing trigger by index and only then checked authority would \
                   conclude that entry 23 governs and reject this receipt — which would let \
                   anyone able to get a statement anchored unseat the governing trigger of a \
                   record they hold no authority over. The competing enumeration deliberately \
                   spans [20, 25) so the challenge IS in range and IS seen."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // A LATER NON-VERIFYING trigger on F at entry 28: `signatures[0].key_id` names
    // `producer-1`'s real key — the genuine `customers` authority — but `sig` is garbage, not a
    // signature `producer-1` ever produced. Round-5 blocker: competing-trigger selection must
    // verify each candidate's signature cryptographically before comparing authority, or an
    // envelope that merely reuses a real `key_id` with a non-verifying signature can displace
    // the genuinely authorized trigger by anchoring at a later index.
    out.push(Vector {
        file: "trigger-effective-non-verifying-signature-ignored.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 22,
            anchor: cp29,
            chain: vec![0, 9, 25],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 29, cp29),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp29),
                "checkpoint_C": cp29.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 29, cp29) },
            }),
            producer_keys: None,
            note: "Proves that the retraction at entry 22 governs record F at cp29, EVEN THOUGH \
                   a THIRD trigger naming the same record sits at the greatest entry index, 28. \
                   That entry's signature does not verify: `signatures[0].key_id` correctly \
                   names `producer-1`'s real key_id — the genuine `customers` dataset authority \
                   — but `signatures[0].sig` does not verify against that key's actual public \
                   key. A verifier that treated a matching `key_id` as proof of authorization, \
                   without cryptographically checking the signature it is attached to, would let \
                   this entry unseat the real trigger merely by anchoring later. Effectiveness \
                   requires BOTH the claimed key_id to be the record's authority AND the \
                   signature to verify against it — checked before the greatest-entry-index \
                   rule is applied, exactly as for a non-authority-but-genuine challenge \
                   (compare `trigger-effective-later-challenge-ignored.ahl`), because a \
                   non-verifying signature is never traversed either."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // Entry 29: the SUBJECT of its own `trigger-effective` claim carries two signature
    // entries — one genuinely valid, cryptographically-signed entry from `producer-2` (not the
    // `customers` authority, and no longer even in the producer snapshot after manifest v2),
    // and one naming `producer-1`'s real key_id — the genuine `customers` authority — whose
    // `sig` does not verify. A verifier that name-matched the authority's `key_id` among the
    // signers without checking that entry's own signature would be fooled into treating this
    // as authorized; instead, receipt §5 step 4 requires EVERY signature entry on the subject's
    // own envelope to verify before any claim-specific logic runs at all, so this entry is
    // rejected outright and never even reaches the claim-specific trigger-authority check.
    // (`verify_trigger_authority`'s own completeness fix — the same requirement applied to the
    // one entry that names the authority — is independently exercised end to end by
    // `trigger-effective-non-authority-issuer-must-fail.ahl`, whose sole signer is a genuine,
    // cryptographically valid non-authority signature, and by
    // `trigger-effective-non-verifying-signature-ignored.ahl`'s competing candidate at entry
    // 28, which reaches the identical `is_authorized_trigger` machinery via the
    // competing-trigger enumeration route that bypasses this subject-level gate.)
    out.push(Vector {
        file: "trigger-effective-unverified-authority-signature-must-fail.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 29,
            anchor: cp30,
            chain: vec![0, 9, 25],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 30, cp30),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp30),
                "checkpoint_C": cp30.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 30, cp30) },
            }),
            producer_keys: None,
            note: "MUST FAIL. Entry 29's own envelope carries two signature entries: \
                   `signatures[0]` is a genuine, cryptographically valid signature from \
                   `producer-2`, who is not the `customers` dataset authority; \
                   `signatures[1].key_id` correctly names `producer-1`'s real key_id — the \
                   genuine authority — but `signatures[1].sig` does not verify against that \
                   key's actual public key. Receipt §5 step 4 requires every signature entry on \
                   the subject's own envelope to verify; naming the authority's key_id is not \
                   enough when that entry's own signature does not verify, so this envelope \
                   cannot ground any claim, let alone one asserting it is an effective trigger."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "receipt §5 step 4 — every subject envelope signature entry must verify",
            matches: |e| matches!(e, ReceiptError::EnvelopeSignatureInvalid { entry_index: 29 }),
        },
    });

    // Entry 31: a trigger on F CO-SIGNED by both the `customers` authority (`producer-1`) and
    // a second, genuinely active producer key (`producer-2`, re-added by the `key` statement
    // at entry 30). Receipt format §5 step 3a states the two-step model precisely: envelope
    // validity (EVERY entry resolves to an active key and verifies) is a separate, EARLIER
    // test from authorization (at least one of those verified signers is the authority). A
    // trigger is authorized when signed BY the record's authority, not signed EXCLUSIVELY by
    // authority keys — so this legitimately co-signed envelope must still classify as
    // authorized and must still govern.
    out.push(Vector {
        file: "trigger-effective-co-signed-by-authority.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 31,
            anchor: cp32,
            chain: vec![0, 9, 25, 30],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 32, cp32),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp32),
                "checkpoint_C": cp32.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 32, cp32) },
            }),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 30),
            ]),
            note: "Proves that a trigger CO-SIGNED by both the `customers` dataset authority \
                   (`producer-1`) and another active producer key (`producer-2`, re-added at \
                   entry 30) is authorized and governs F at cp32. Every signature entry on \
                   entry 31's envelope cryptographically verifies against a producer key active \
                   at entry index 31 (receipt §5 step 3a's envelope-validity test), and at \
                   least one of them — `producer-1`'s — is the record's authority (the \
                   authorization test), so the extra, genuinely valid co-signature from \
                   `producer-2` does not disqualify it: core spec §2.3.3 requires a trigger to \
                   be signed BY the authority, never signed EXCLUSIVELY by authority keys."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // A trigger on a DERIVED record, signed with a key added after the introduction.
    out.push(Vector {
        file: "trigger-effective-derived-rotated-key.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 19,
            anchor: cp20,
            chain: vec![0, 9],
            record_subject: scores(&r.s1p),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 20, cp20),
            claim_material: json!({
                // S1' was introduced by a *derivation*, so the introduction proof is a
                // `record-derived` receipt rather than a `record-ingested` one.
                "introduction": Spec {
                    claim_type: "record-derived",
                    subject_index: 7,
                    anchor: cp20,
                    chain: vec![0],
                    record_subject: scores(&r.s1p),
                    competing: "not-checked",
                    content_binding: "none",
                    currency_mode: "declared",
                    currency_material: json!({}),
                    claim_material: json!({
                        "output": { "dataset": DS_SCORES, "record": r.s1p },
                    }),
                    producer_keys: None,
                    note: "Embedded introduction proof for a derived record: the unbatched \
                           `record-derived` form, whose output must appear in the subject \
                           derivation's `outputs` array."
                        .to_owned(),
                }
                .build(corpus, keys),
                "checkpoint_C": cp20.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(7, 20, cp20) },
            }),
            producer_keys: None,
            note: "Proves that the retraction at entry 19 governs the DERIVED record S1' at \
                   cp20. S1' was introduced by the derivation at entry 7, at which point the \
                   producer key set held only `producer-1`; the `key` statement at entry 9 then \
                   added `producer-2`, and this retraction is signed with that post-rotation \
                   key. Core spec §2.3.3 resolves a derived record's authority as \"the \
                   introducing producer's key set as of the trigger's entry index (not the \
                   introduction index: key rotation between introduction and trigger \
                   applies)\" — so the trigger is effective. A verifier that resolved the key \
                   set at the introduction index would reject it as a challenge, silently \
                   stripping the producer of the ability to retract its own outputs across a \
                   routine key rotation."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // --- disposition-declared ----------------------------------------------------
    let s1_leaf = leaf_index(corpus, &corpus.affected_root, &r.s1);
    let s2_leaf = leaf_index(corpus, &corpus.affected_root, &r.s2);
    let disposition_declared = |path: Vec<String>, note: &str| {
        Spec {
            claim_type: "disposition-declared",
            subject_index: 8,
            anchor: cp20,
            chain: vec![0],
            record_subject: scores(&r.s1),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "trigger": trigger_declared(
                    cp20,
                    introduction(5, &r.c_a2, cp20),
                    "Embedded trigger proof for the correction the propagation names.",
                ),
                "disposition_leaf": corpus.tree_leaves(&corpus.affected_root)[s1_leaf],
                "leaf_index": s1_leaf,
                "leaf_path": path,
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "disposition-declared-valid.ahl",
        receipt: disposition_declared(
            corpus.tree_path(&corpus.affected_root, s1_leaf),
            "Proves that the propagation statement at entry 8 dispositions record S1 as \
             `recomputed`, naming the successor derivation. It does NOT claim the propagation \
             is complete, nor that the embedded trigger governs A at any checkpoint — both \
             would require enumerated governance.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "disposition-declared-wrong-path-must-fail.ahl",
        receipt: disposition_declared(
            corpus.tree_path(&corpus.affected_root, s2_leaf),
            "MUST FAIL. The carried `disposition_leaf` and `leaf_index` name S1 but `leaf_path` \
             is the path of a different leaf, so recomputation does not reach the propagation \
             statement's `affected_root`.",
        ),
        expect: Expect::Reject {
            rule: "receipt §3 — `leaf_path` must open the propagation's `affected_root`",
            matches: |e| {
                matches!(e, ReceiptError::InclusionPathInvalid { what: "disposition leaf" })
            },
        },
    });

    // --- disposition-effective ---------------------------------------------------
    let disposition_effective = |trigger: Value, note: &str| {
        Spec {
            claim_type: "disposition-effective",
            subject_index: 8,
            anchor: cp13,
            // Enumerated currency over [0, 13) reveals the `key` statement at entry 9, so the
            // presented chain must account for it (receipt format §4).
            chain: vec![0, 9],
            record_subject: scores(&r.s1),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 13, cp13),
            claim_material: json!({
                "trigger": trigger,
                "disposition_leaf": corpus.tree_leaves(&corpus.affected_root)[s1_leaf],
                "leaf_index": s1_leaf,
                "leaf_path": corpus.tree_path(&corpus.affected_root, s1_leaf),
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "disposition-effective-valid.ahl",
        receipt: disposition_effective(
            trigger_effective(1, "Embedded trigger-effective proof, bounded by cp8."),
            "Proves that the propagation statement at entry 8 dispositions S1 under a trigger \
             proven *effective* at cp8, with governance enumerated over exactly [0, 13) — the \
             whole prefix of this receipt's own verified checkpoint. The nesting is three deep \
             — disposition-effective, trigger-effective, and the two introduction receipts — \
             which receipt §3.1 permits (limit 4).",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "disposition-effective-declared-trigger-must-fail.ahl",
        receipt: disposition_effective(
            trigger_declared(
                cp8,
                introduction(5, &r.c_a2, cp8),
                "A declared-mode trigger receipt, embedded where the schema requires an \
                 effective one.",
            ),
            "MUST FAIL. `disposition-effective` requires the embedded trigger receipt to be a \
             `trigger-effective`; this one is `trigger-declared`, which carries no \
             competing-trigger enumeration and never establishes authority, so it never \
             establishes that the trigger governs. Receipt §3's naming rule forbids a \
             `-effective` verdict resting on declared-mode material.",
        ),
        expect: Expect::Reject {
            rule: "receipt §3 — disposition-effective must embed a trigger-effective receipt",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::EmbeddedClaimTypeMismatch {
                        slot: "trigger",
                        expected: "trigger-effective",
                        ..
                    }
                )
            },
        },
    });

    // --- propagation-complete ----------------------------------------------------
    let trees_block = |roots: &[&String], drop_batch_leaf: bool| {
        let mut block = serde_json::Map::new();
        for root in roots {
            let mut leaves = corpus.tree_leaves(root).to_vec();
            if drop_batch_leaf && *root == &corpus.batch_root {
                leaves.pop();
            }
            block.insert((*root).clone(), json!({ "leaves": leaves }));
        }
        Value::Object(block)
    };
    let prefix_roots = [
        corpus.batch_root.clone(),
        corpus.wide_outputs_root.clone(),
        corpus.input_set_root.clone(),
        corpus.affected_root.clone(),
    ];
    let prefix_root_refs: Vec<&String> = prefix_roots.iter().collect();

    let propagation_complete = |drop_batch_leaf: bool, note: &str| {
        Spec {
        claim_type: "propagation-complete",
        subject_index: 8,
        anchor: cp13,
        chain: vec![0, 9],
        record_subject: None,
        competing: "not-checked",
        content_binding: "none",
        currency_mode: "enumerated",
        currency_material: corpus.enumeration(0, 13, cp13),
        claim_material: json!({
            // D — the propagation's own declared checkpoint, a real earlier checkpoint,
            // carried as its full signed object and authenticated against A (spec §2.3.4).
            "corpus_checkpoint": cp8.checkpoint.clone(),
            "corpus_prefix": corpus.enumeration(0, 8, cp13),
            "trees": trees_block(&prefix_root_refs, drop_batch_leaf),
            "trigger": trigger_effective(1, "Embedded trigger-effective proof, bounded by cp8."),
        }),
        producer_keys: None,
        note: note.to_owned(),
    }
    .build(corpus, keys)
    };

    out.push(Vector {
        file: "propagation-complete-valid.ahl",
        receipt: propagation_complete(
            false,
            "Proves that the affected set anchored by the propagation statement at entry 8 \
             equals the closure recomputable at the propagation's OWN declared checkpoint D — \
             cp8, tree size 8 — from the complete prefix [0, 8) plus the leaf material of \
             every committed tree that prefix references. D is carried as a full signed \
             checkpoint object and authenticated two ways: its log signature verifies under \
             the manifest version active for its tree size, and its root is recomputed from \
             the prefix, whose range proof is checked against A (cp13, the checkpoint this \
             receipt is anchored under). That recomputation IS a consistency proof D→A: it \
             establishes D as exactly the size-8 prefix of A. Completeness is claimed at D and \
             nowhere later — the corpus itself shows why, since the derivation at entry 27 \
             legally consumes an affected descendant and enlarges this trigger's closure past \
             D (core §2.3.4). The trigger is carried as an embedded `trigger-effective` \
             receipt, so a challenge could never be traversed here. There is no compact form \
             of this claim by construction (core §6.5), and the boundary stays relative: \
             complete *within the declared corpus*, not proof that the declared corpus is the \
             organisation's real corpus (core §5.3).",
        ),
        expect: Expect::Accept,
    });

    // The same claim, anchored under cp29 — past manifest v2's rotation at entry 25 — instead
    // of cp13. D (cp8) stays under the GENESIS manifest; A (cp29) is active under v2, which
    // rotated the witness set and dropped a producer key (§7.2). Round-5 substantive fix:
    // `authenticate_declared_checkpoint` must resolve D's log key against the manifest active
    // for D's OWN tree size via the normal keys.log source/binding contract, independently of
    // whatever manifest governs A — not a byte-equality shortcut that happens to work only
    // when both checkpoints share one manifest version, as every other propagation-complete
    // vector until this one did.
    let mut cross_rotation_receipt = Spec {
        claim_type: "propagation-complete",
        subject_index: 8,
        anchor: cp29,
        chain: vec![0, 9, 25],
        record_subject: None,
        competing: "not-checked",
        content_binding: "none",
        currency_mode: "enumerated",
        currency_material: corpus.enumeration(0, 29, cp29),
        claim_material: json!({
            "corpus_checkpoint": cp8.checkpoint.clone(),
            "corpus_prefix": corpus.enumeration(0, 8, cp29),
            "trees": trees_block(&prefix_root_refs, false),
            "trigger": trigger_effective(1, "Embedded trigger-effective proof, bounded by cp8."),
        }),
        producer_keys: None,
        note: "Proves the same completeness claim as `propagation-complete-valid.ahl`, but \
               anchored under cp29 instead of cp13 — A is now active under manifest v2 (entry \
               25), which replaced the witness key set in full and dropped `producer-2` from \
               the producer snapshot, while D (cp8) remains under the GENESIS manifest. \
               `keys.log` carries TWO entries for the one physical log key: D's binding at \
               entry index 0 and A's at entry index 25 — the log key itself never rotates in \
               this corpus, but each manifest version re-declares it independently, and both \
               bindings resolve through the ordinary `keys.log` source/binding contract \
               (receipt §2.2) rather than a shortcut that only happens to work when D and A \
               share one manifest version, as in every other propagation-complete vector."
            .to_owned(),
    }
    .build(corpus, keys);
    // `Spec::build` only auto-populates the ONE `keys.log` entry a receipt's own `anchoring`
    // needs (here, A at entry 25). Authenticating D (format §2.2) additionally needs the log
    // key bound to the manifest active for D's own tree size — format §7.2 requires no
    // witness cosignature on D at all, so no `keys.witness` entry is needed for it either.
    cross_rotation_receipt["keys"]["log"]
        .as_array_mut()
        .expect("keys.log is an array")
        .push(key_entry(&keys.log_1, None, 0));
    out.push(Vector {
        file: "propagation-complete-valid-across-manifest-rotation.ahl",
        receipt: cross_rotation_receipt,
        expect: Expect::Accept,
    });

    out.push(Vector {
        file: "propagation-complete-missing-leaf-must-fail.ahl",
        receipt: propagation_complete(
            true,
            "MUST FAIL. The carried leaf material for the batch output tree of entry 4 is one \
             leaf short, so it neither matches the anchored `outputs_count` nor recomputes to \
             the anchored `outputs_root`. A verifier that accepted the truncated material would \
             recompute a smaller closure and wrongly agree with the disposition tree; core spec \
             §2.5 and §3.5 exist to make exactly this undetectable-truncation attack visible.",
        ),
        expect: Expect::Reject {
            rule: "spec §2.5/§3.5 — committed tree material must open its anchored root and count",
            matches: |e| matches!(e, ReceiptError::TreeMaterialInvalid { .. }),
        },
    });

    // The reviewer's counterexample: grounding completeness at A instead of the declared D.
    out.push(Vector {
        file: "propagation-complete-past-declared-checkpoint-must-fail.ahl",
        receipt: Spec {
            claim_type: "propagation-complete",
            subject_index: 8,
            anchor: cp28,
            chain: vec![0, 9, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 28, cp28),
            claim_material: json!({
                // The attack: substitute the *anchoring* checkpoint for the propagation's own
                // declared D, so the closure would be recomputed over the whole corpus.
                "corpus_checkpoint": cp28.checkpoint.clone(),
                "corpus_prefix": corpus.enumeration(0, 28, cp28),
                "trees": trees_block(
                    &[
                        &corpus.batch_root,
                        &corpus.wide_outputs_root,
                        &corpus.input_set_root,
                        &corpus.affected_root,
                        &corpus.challenge_affected_root,
                    ],
                    false,
                ),
                "trigger": trigger_effective(1, "Embedded trigger-effective proof, bounded by cp8."),
            }),
            producer_keys: None,
            note: "MUST FAIL — this is the counterexample that forced completeness to be \
                   defined at D. The propagation at entry 8 declared corpus checkpoint D at \
                   tree size 8, where the affected set of the entry-6 trigger is four records. \
                   Later, the derivation at entry 27 consumed S2 — an already-affected \
                   DESCENDANT of the triggered record, which core spec §2.3.2 permits, since \
                   only the triggered record A itself may not be re-consumed — and produced Z. \
                   So at cp28 the true closure is five records, and the anchored disposition \
                   tree of four no longer matches. This receipt tries to ground the \
                   completeness claim at the anchoring checkpoint cp28 rather than at D, which \
                   would either fabricate a disagreement or, with a doctored disposition set, \
                   assert completeness the producer never claimed. It is rejected because \
                   `claim_material.corpus_checkpoint` must be the propagation's OWN declared \
                   checkpoint (core §2.3.4, receipt §3): cp28's identity fields do not match \
                   the `{log_id, tree_size, root_hash}` the statement itself declares. \
                   Completeness never extends past D; the enlargement creates a fresh \
                   propagation duty instead (core §5.2)."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "spec §2.3.4 / receipt §3 — completeness is defined at the propagation's \
                   declared checkpoint D, never at a later one",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::CheckpointNotBound {
                        field: "claim_material.corpus_checkpoint",
                        ..
                    }
                )
            },
        },
    });

    // Completeness over a challenge: the propagation at entry 24 names an unauthorized trigger.
    out.push(Vector {
        file: "propagation-complete-challenge-trigger-must-fail.ahl",
        receipt: Spec {
            claim_type: "propagation-complete",
            subject_index: 24,
            anchor: cp25,
            chain: vec![0, 9],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 25, cp25),
            claim_material: json!({
                "corpus_checkpoint": cp24.checkpoint.clone(),
                "corpus_prefix": corpus.enumeration(0, 24, cp25),
                "trees": trees_block(
                    &[
                        &corpus.batch_root,
                        &corpus.wide_outputs_root,
                        &corpus.input_set_root,
                        &corpus.affected_root,
                        &corpus.challenge_affected_root,
                    ],
                    false,
                ),
                "trigger": non_authority_trigger,
            }),
            producer_keys: None,
            note: "MUST FAIL. The propagation statement at entry 24 is well formed, correctly \
                   anchored, its declared checkpoint D authenticates, and its disposition tree \
                   opens cleanly — but the trigger it names at entry 23 is signed by a key that \
                   is not the dataset authority. Core spec \
                   §2.3.3 anchors such a trigger as a **challenge**: surfaced by verification, \
                   never traversed. Receipt §3 therefore REQUIRES `propagation-complete` to \
                   carry an embedded `trigger-effective` receipt, and no such receipt can be \
                   constructed for an unauthorized trigger. A verifier that merely looked up \
                   the trigger by statement id and ran the closure would certify a propagation \
                   nobody was entitled to issue."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "receipt §3 / spec §2.3.3 — propagation-complete must embed a \
                   trigger-effective receipt; challenges are never traversed",
            matches: |e| matches!(e, ReceiptError::TriggerNotAuthorized { entry_index: 23, .. }),
        },
    });

    // --- governance-state --------------------------------------------------------
    let governance_state_valid = Spec {
        claim_type: "governance-state",
        subject_index: 25,
        anchor: cp28,
        chain: vec![0, 9, 25],
        record_subject: None,
        competing: "not-checked",
        content_binding: "none",
        currency_mode: "enumerated",
        currency_material: corpus.enumeration(0, 28, cp28),
        claim_material: json!({ "target_index": 26 }),
        producer_keys: None,
        note: "Proves that manifest version 2, anchored at entry 25, is the governance \
               state active at entry index 26. The §4 material enumerates exactly \
               [0, 28) — the whole prefix of this receipt's verified checkpoint — and \
               contains no manifest or key statement in (25, 26], so nothing supersedes \
               version 2 before the target. Version 2 replaced the witness key set in full \
               and dropped `producer-2` from the producer snapshot (core §7.2), which is \
               why cp28 is cosigned by witness-2 while every earlier checkpoint is cosigned \
               by witness-1. Its `governance.rotation_proofs[]` proves that transition under \
               the OUTGOING states (I-D §7.1, §7.5.1 4b(M))."
            .to_owned(),
    }
    .build(corpus, keys);
    out.push(Vector {
        file: "governance-state-valid.ahl",
        receipt: governance_state_valid.clone(),
        expect: Expect::Accept,
    });

    // --- governance-key rotation proofs (I-D §7.1, §7.5.1 4b(M)): four ways an element can
    // fail, each mutating the one genuine rotation proof `governance_state_valid` carries.
    out.push(Vector {
        file: "governance-key-rotation-proof-missing-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| proofs.as_array_mut().expect("rotation_proofs array").clear(),
            "MUST FAIL. `governance.rotation_proofs` is emptied, so the manifest v2 rotation \
             the carried chain contains has no element proving it. I-D §7.1/§7.5.1: the \
             rotation is detected inside the signed per-hop walk, at manifest entry index 25, \
             only after that hop's own signature and schema pass — the NEXT unconsumed \
             `rotation_proofs[]` element is then required, and here there is none.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — a detected rotation requires the next unconsumed \
                   rotation_proofs[] element",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                    if detail.contains("carries no (further) element"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-wrong-index-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| proofs[0]["manifest_entry_index"] = json!(24),
            "MUST FAIL. The element's `manifest_entry_index` is changed from 25 (the rotating \
             manifest's real entry index) to 24. I-D §7.1/§7.5.1: the next unconsumed \
             `rotation_proofs[]` element at the entry-25 rotation must carry \
             `manifest_entry_index` 25 — it carries 24 instead.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — the next unconsumed rotation_proofs[] element must carry this \
                   hop's own manifest_entry_index",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                    if detail.contains("carries `manifest_entry_index` 24, not 25"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-empty-on-non-rotating-must-fail.ahl",
        receipt: {
            // `governance-state-not-current-must-fail.ahl`'s own base (chain [0, 9], no
            // rotation) is itself a MUST-FAIL vector for a different reason, so build a fresh,
            // otherwise-valid, non-rotating receipt to carry this one defect alone.
            let mut bad = Spec {
                claim_type: "governance-state",
                subject_index: 0,
                anchor: cp20,
                chain: vec![0, 9],
                record_subject: None,
                competing: "not-checked",
                content_binding: "none",
                currency_mode: "enumerated",
                currency_material: corpus.enumeration(0, 20, cp20),
                claim_material: json!({ "target_index": 15 }),
                producer_keys: None,
                note: "MUST FAIL. `governance.rotation_proofs` is present (as an empty array) \
                       even though this chain — genesis plus the entry-9 `key` statement only \
                       — rotates neither the log nor the witness key set. I-D §7.1: \"The \
                       member is ABSENT where the chain rotates neither set\"; a receipt \
                       carrying it regardless, even empty, is invalid."
                    .to_owned(),
            }
            .build(corpus, keys);
            bad["governance"]["rotation_proofs"] = json!([]);
            bad
        },
        expect: Expect::Reject {
            rule: "I-D §7.1 — rotation_proofs is ABSENT where the chain rotates neither set",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail) if detail.contains("rotates neither"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-duplicate-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| {
                let element = proofs[0].clone();
                proofs.as_array_mut().expect("rotation_proofs array").push(element);
            },
            "MUST FAIL. The genuine element for manifest entry index 25 is duplicated. The \
             walk consumes the first (matching) element at the entry-25 rotation and never \
             encounters a second rotation to consume the duplicate against — I-D §7.1 fixes \
             exactly ONE element per rotation, so the unconsumed duplicate left over after \
             the walk is invalid.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — one element per rotation, no duplicates left unconsumed",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail) if detail.contains("beyond the"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-extra-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| {
                // A second element for entry 0 — the genesis manifest, which never rotates
                // anything relative to itself — appended after the genuine one for entry 25.
                let mut extra = proofs[0].clone();
                extra["manifest_entry_index"] = json!(0);
                proofs.as_array_mut().expect("rotation_proofs array").push(extra);
            },
            "MUST FAIL. An extra element names manifest entry index 0, which never rotates \
             anything (it is the genesis manifest, with no predecessor to differ from), so the \
             walk never encounters a rotation to consume it against — it is left over, \
             unconsumed, after the walk ends.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — no extra elements for manifests that do not rotate",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail) if detail.contains("beyond the"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-incoming-key-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| {
                // This corpus's LOG key never itself rotates (only the witness set does), so
                // there is no genuine second log key to substitute; witness-1's key/signature
                // stand in for "a key outside the outgoing log set", which is exactly what the
                // check below rejects — a checkpoint whose signer is not in that set, INCOMING
                // key included.
                proofs[0]["checkpoint"]["key_id"] = json!(keys.witness_1.key_id());
                proofs[0]["checkpoint"]["signature"] = json!(keys.witness_1.sign(
                    &checkpoint_signing_bytes(&proofs[0]["checkpoint"]).expect("checkpoint")
                ));
            },
            "MUST FAIL. The element's `checkpoint` is re-signed by a key that is not a log key \
             of the OUTGOING state at manifest entry index 25 — the exact substitution I-D \
             §7.1 rules out: \"a checkpoint signed by the INCOMING key... is exactly the key \
             an attacker installs, whereas the exception accepts only the key being retired\".",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — the rotation-proof checkpoint must verify under a log key of the \
                   OUTGOING state",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, .. })
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-missing-witness-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| proofs[0]["witnesses"] = json!([]),
            "MUST FAIL. The element's `witnesses` array is emptied. Manifest v2 rotates the \
             witness set, and this corpus is L3, so I-D §7.1 requires at least one cosignature \
             verifying under a witness key of the OUTGOING state (witness-1); none is carried \
             at all.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — AT L3, a rotation-proof element needs a cosignature under the \
                   OUTGOING witness set",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, .. })
            },
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-checkpoint-missing-log-id-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| {
                proofs[0]["checkpoint"]
                    .as_object_mut()
                    .expect("rotation-proof checkpoint object")
                    .remove("log_id");
            },
            "MUST FAIL. The element's `checkpoint` is missing `log_id`. I-D §7.1: a \
             rotation-proof checkpoint is \"in the receipt-borne form defined above\" — the \
             SAME strict shape `anchoring.checkpoint` takes, `log_id` REQUIRED among the rest \
             — not a looser one that happens to carry only what this build reads.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — the rotation-proof checkpoint takes the receipt-borne shape, \
                   log_id included",
            matches: |e| matches!(e, ReceiptError::Malformed(detail) if detail.contains("log_id")),
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-malformed-witness-entry-must-fail.ahl",
        receipt: rotation_proof_case(
            &governance_state_valid,
            |proofs| {
                // A SECOND witnesses[] entry, missing `cosigned_at` — appended after the one
                // genuine, correctly-cosigning entry already present.
                let mut malformed = proofs[0]["witnesses"][0].clone();
                malformed
                    .as_object_mut()
                    .expect("witness cosignature object")
                    .remove("cosigned_at");
                proofs[0]["witnesses"]
                    .as_array_mut()
                    .expect("witnesses array")
                    .push(malformed);
            },
            "MUST FAIL. The element's `witnesses` array carries two entries: the genuine \
             outgoing-witness cosignature, and a second entry missing `cosigned_at`. I-D §7.1: \
             `witnesses` is \"an array in the shape of `anchoring.witnesses[]`\" — EVERY \
             element of that array is held to the shape, not merely the one a match happens to \
             reach; a verifier that stopped at the first cosignature that verifies would wrongly \
             accept this receipt.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — every rotation-proof witnesses[] entry takes the \
                   anchoring.witnesses[] shape, cosigned_at included",
            matches: |e| {
                matches!(e, ReceiptError::Malformed(detail) if detail.contains("cosigned_at"))
            },
        },
    });

    // --- the rotation proof's own keys must be LISTED (I-D §7.1: "Every key used in
    // verification MUST appear in `keys` with its source and its binding", and under the
    // transition exception those entries "carry `manifest-chain` bindings naming that
    // predecessor version"). Two ways that fails: the entry is missing, or it names the
    // INCOMING version — the very state the proof exists to establish a handover away from.
    out.push(Vector {
        file: "governance-key-rotation-proof-witness-key-unlisted-must-fail.ahl",
        receipt: rotation_keys_case(
            &governance_state_valid,
            |keys| {
                // Drop the outgoing witness entry (witness-1, bound at the genesis manifest),
                // leaving only the incoming one the anchoring checkpoint uses.
                keys["witness"]
                    .as_array_mut()
                    .expect("keys.witness array")
                    .retain(|entry| field_str(entry, "witness_id").ok() != Some(WITNESS_1));
            },
            "MUST FAIL. The rotation proof at entry 25 is cosigned by the OUTGOING witness, \
             witness-1, but `keys.witness[]` no longer lists that key. I-D §7.1: \"Every key \
             used in verification MUST appear in `keys` with its source and its binding\" — a \
             cosignature verified under a key the receipt never declared rests on material \
             outside the container's own account of what it uses.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — a rotation proof's outgoing witness key is listed in keys.witness[]",
            matches: |e| matches!(e, ReceiptError::KeyNotBound { .. }),
        },
    });
    out.push(Vector {
        file: "governance-key-rotation-proof-key-bound-to-incoming-must-fail.ahl",
        receipt: rotation_keys_case(
            &governance_state_valid,
            |keys| {
                // Re-bind the outgoing witness entry to the INCOMING manifest version (entry
                // 25), the one the rotation installs.
                for entry in keys["witness"].as_array_mut().expect("keys.witness array") {
                    if field_str(entry, "witness_id").ok() == Some(WITNESS_1) {
                        entry["binding"]["entry_index"] = json!(25);
                    }
                }
            },
            "MUST FAIL. The outgoing witness key is listed, but bound to manifest v2 (entry \
             25) — the INCOMING version. I-D §7.1's transition exception fixes the binding for \
             rotation material to \"the manifest version active IMMEDIATELY BEFORE \
             `manifest_entry_index`\", the outgoing state; a key bound to the incoming version \
             is not the retiring authority whose attestation the proof is for.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — a rotation proof's keys bind to the OUTGOING manifest version",
            matches: |e| matches!(e, ReceiptError::KeyNotBound { entry_index: 25, .. }),
        },
    });

    // --- key-statement 4b(K) validation (I-D §7.5.1 4b(K)): three ways a `key` statement's
    // own form can fail, each replacing the genuine entry-9 hop with a freshly signed one so
    // the rejection is phase 2, never phase 1 (I-D §7.5.1: "Type-specific validation MUST NOT
    // run on material whose signature has not verified").
    let m1 = statement_id(&corpus.envelopes[0]).expect("well-formed genesis envelope");
    out.push(Vector {
        file: "governance-key-statement-wrong-key-id-must-fail.ahl",
        receipt: key_statement_case(
            corpus,
            &governance_state_valid,
            &m1,
            &json!({
                "key_id": keys.producer_1.key_id(),
                "pubkey": keys.producer_2.pubkey(),
                "valid_from": T0,
            }),
            keys,
            "MUST FAIL. The `key` statement at entry index 9 carries `key.key_id` from \
             producer-1 alongside `key.pubkey` from producer-2 — a genuinely mismatched pair, \
             each individually well-formed. I-D §7.5.1 4b(K) requires `key_id` to be \
             RECOMPUTED from `pubkey` and equal the carried value before the statement's \
             effect ever touches K.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b(K) — key.key_id must be sha256:-of-key.pubkey",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail) if detail.contains("does not equal `sha256:`-of-`key.pubkey`"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-statement-missing-valid-from-must-fail.ahl",
        receipt: key_statement_case(
            corpus,
            &governance_state_valid,
            &m1,
            &json!({ "key_id": keys.producer_2.key_id(), "pubkey": keys.producer_2.pubkey() }),
            keys,
            "MUST FAIL. The `key` statement at entry index 9 carries no `key.valid_from` at \
             all. I-D §7.5.1 4b(K): `valid_from` is REQUIRED and well-formed RFC 3339 — \
             informative for ordering, but required regardless.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b(K) — key.valid_from is REQUIRED",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail) if detail.contains("carries no `key.valid_from`"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-statement-short-pubkey-must-fail.ahl",
        receipt: key_statement_case(
            corpus,
            &governance_state_valid,
            &m1,
            &json!({
                "key_id": keys.producer_2.key_id(),
                "pubkey": base64(&[0u8; 16]),
                "valid_from": T0,
            }),
            keys,
            "MUST FAIL. The `key` statement at entry index 9 carries `key.pubkey` that \
             decodes to 16 octets, not 32. I-D §7.5.1 4b(K): `pubkey` MUST decode to exactly \
             32 octets.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b(K) — key.pubkey must decode to exactly 32 octets",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail) if detail.contains("does not decode to exactly 32 octets"))
            },
        },
    });

    // --- I-D §2.2 common payload fields on a `key` statement (I-D §7.5.1 4b(K): "the common
    // payload fields of Section 2.2 are present and well formed"), each genuinely re-signed so
    // the rejection is phase 2, never phase 1.
    out.push(Vector {
        file: "governance-key-statement-missing-issued-at-must-fail.ahl",
        receipt: key_statement_common_field_case(
            corpus,
            &governance_state_valid,
            &m1,
            |payload| {
                payload.as_object_mut().expect("key statement payload").remove("issued_at");
            },
            keys,
            "MUST FAIL. The `key` statement at entry index 9 carries no `issued_at` at all. \
             I-D §2.2 lists `issued_at` among the common payload fields EVERY statement \
             carries, `key` statements included; §7.5.1 4b(K) requires those fields present \
             and well formed before the statement's effect is trusted.",
        ),
        expect: Expect::Reject {
            rule: "I-D §2.2 / §7.5.1 4b(K) — issued_at is a REQUIRED common payload field",
            matches: |e| {
                matches!(e, ReceiptError::Malformed(detail) if detail.contains("issued_at"))
            },
        },
    });
    out.push(Vector {
        file: "governance-key-statement-malformed-valid-time-must-fail.ahl",
        receipt: key_statement_common_field_case(
            corpus,
            &governance_state_valid,
            &m1,
            |payload| payload["valid_time"] = json!("not a timestamp"),
            keys,
            "MUST FAIL. The `key` statement at entry index 9 carries `valid_time: \"not a \
             timestamp\"` — neither an RFC 3339 instant nor a `{from, to}` interval. I-D \
             §2.2 states both admissible shapes for every statement's `valid_time`, `key` \
             statements included.",
        ),
        expect: Expect::Reject {
            rule: "I-D §2.2 / §7.5.1 4b(K) — valid_time must be RFC 3339 or a {from,to} object",
            matches: |e| {
                matches!(e, ReceiptError::Malformed(detail) if detail.contains("valid_time"))
            },
        },
    });

    out.push(Vector {
        file: "governance-state-not-current-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 0,
            anchor: cp20,
            chain: vec![0, 9],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 20, cp20),
            claim_material: json!({ "target_index": 10 }),
            producer_keys: None,
            note: "MUST FAIL. The claim is that the genesis manifest is the governance state \
                   active at entry index 10, and the §4 material does authenticate the complete \
                   prefix [0, 19). But that prefix contains the `key` statement at entry 9, \
                   which changed the producer key set inside (0, 10]. Receipt §3 requires the \
                   enumerated material to prove no manifest or key statement exists in \
                   (subject.entry_index, target_index]; here one demonstrably does, so the \
                   presented chain is not the state at the target index."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "receipt §3 — governance-state must prove absence of governance statements in \
                   (subject.entry_index, target_index]",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::GovernanceStateNotCurrent {
                        target_index: 10,
                        entry_index: 9,
                        ..
                    }
                )
            },
        },
    });
    out.push(Vector {
        file: "governance-state-short-range-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 0,
            anchor: cp28,
            // The chain presents every governance statement; what the short enumeration fails
            // to prove is that these are the ONLY ones.
            chain: vec![0, 9, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 6, cp28),
            claim_material: json!({ "target_index": 5 }),
            producer_keys: None,
            note: "MUST FAIL. The enumeration over [0, 6) is authenticated and internally \
                   correct, and it does prove that no governance statement sits in (0, 5]. That \
                   is exactly the trap: it says nothing about entries 6 through 27, where the \
                   `key` statement at entry 9 and manifest version 2 at entry 25 — which drops \
                   a producer key — actually live. Receipt §4 therefore fixes enumerated \
                   currency at exactly [0, tree_size(C)) for the receipt's verified checkpoint \
                   C, here [0, 28). A verifier that accepted any authenticated sub-range would \
                   let a receipt hide a later key retirement and validate signatures with a key \
                   the corpus had already discarded."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "receipt §4 — enumerated governance must cover exactly [0, tree_size(C))",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::GovernanceRangeNotComplete {
                        got_from: 0,
                        got_to: 6,
                        tree_size: 28
                    }
                )
            },
        },
    });
    out.push(Vector {
        file: "governance-state-key-subject-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 9,
            anchor: cp20,
            chain: vec![0, 9],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 20, cp20),
            claim_material: json!({ "target_index": 10 }),
            producer_keys: None,
            note: "MUST FAIL. The subject is the `key` statement at entry 9. Receipt §3 requires \
                   a `governance-state` subject to be a **manifest** statement — the one claimed \
                   active at `target_index` — because key state is composed from that manifest \
                   plus the later `key` statements, and a `key` statement alone carries no \
                   snapshot to be 'the state'."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "receipt §3 — governance-state subjects are manifest statements only",
            matches: |e| matches!(e, ReceiptError::GovernanceSubjectNotManifest { .. }),
        },
    });

    out
}

/// Mutate a valid receipt's `governance.rotation_proofs[0]` and set an informative note,
/// leaving everything else — including the chain, so the mutation is the ONLY thing that can
/// make the receipt fail — byte-identical to `base`.
/// A variant of `base` with its `keys` BLOCK edited rather than its rotation-proof element.
///
/// A rotation proof's log and witness keys are resolved through the receipt's own `keys` block
/// (I-D §7.1), bound to the outgoing manifest version, so removing or re-binding one of those
/// entries is a defect of the container even though the proof element itself is untouched.
fn rotation_keys_case(base: &Value, mutate: impl FnOnce(&mut Value), note: &str) -> Value {
    let mut bad = base.clone();
    mutate(&mut bad["keys"]);
    bad["claim"]["note"] = json!(note);
    bad
}

fn rotation_proof_case(base: &Value, mutate: impl FnOnce(&mut Value), note: &str) -> Value {
    let mut bad = base.clone();
    mutate(&mut bad["governance"]["rotation_proofs"]);
    bad["claim"]["note"] = json!(note);
    bad
}

/// Replace `base`'s entry-9 `key` statement hop (`governance.chain[1]`) with a FRESH envelope
/// carrying `key_extra`, genuinely signed by `keys.producer_1` — the legitimate phase-1 signer
/// at that entry index (I-D §7.5.1: phase 1 verifies "against K as established so far", and
/// producer-1 is already in K by entry 9). This is deliberate: a mutation with no re-signing
/// would fail phase 1 (`EnvelopeSignatureInvalid`) before phase 2's 4b(K) checks are ever
/// reached, which is the wrong rule for these vectors to exercise.
///
/// The replaced hop is then RE-ANCHORED ([`Corpus::reanchor`]): I-D §7.5 step 3 proves every
/// carried governance element's inclusion path before step 4's induction reads any of them, so
/// a substituted hop left at the corpus's own path would fail as an unanchored statement rather
/// than by the 4b(K) rule the vector names.
fn key_statement_case(
    corpus: &Corpus,
    base: &Value,
    manifest_id: &str,
    key_extra: &Value,
    keys: &Keys,
    note: &str,
) -> Value {
    let mut bad = base.clone();
    let fresh =
        signed("key", manifest_id, json!({ "action": "add", "key": key_extra }), &keys.producer_1);
    bad["governance"]["chain"][1]["envelope"] = fresh;
    bad["claim"]["note"] = json!(note);
    corpus.reanchor(&mut bad, keys);
    bad
}

/// Like [`key_statement_case`], but for I-D §2.2's COMMON payload fields — `issued_at`,
/// `valid_time` — which `signed`/`scenario::payload` normally fix to well-formed values
/// before this function ever sees the payload. `mutate` runs on the raw payload BEFORE
/// signing, so it can reach fields `key_statement_case` has no way to touch, while the
/// genuine re-signing by `keys.producer_1` is identical: phase 1 still passes, so a §7.5.1
/// 4b(K) common-field failure is what actually fires, not `EnvelopeSignatureInvalid`.
fn key_statement_common_field_case(
    corpus: &Corpus,
    base: &Value,
    manifest_id: &str,
    mutate: impl FnOnce(&mut Value),
    keys: &Keys,
    note: &str,
) -> Value {
    let mut bad = base.clone();
    let mut raw_payload = crate::scenario::payload(
        "key",
        manifest_id,
        json!(T0),
        json!({
            "action": "add",
            "key": {
                "key_id": keys.producer_2.key_id(),
                "pubkey": keys.producer_2.pubkey(),
                "valid_from": T0,
            },
        }),
    );
    mutate(&mut raw_payload);
    let fresh = envelope(raw_payload, &keys.producer_1);
    bad["governance"]["chain"][1]["envelope"] = fresh;
    bad["claim"]["note"] = json!(note);
    corpus.reanchor(&mut bad, keys);
    bad
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
