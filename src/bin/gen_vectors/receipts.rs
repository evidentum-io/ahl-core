//! Evidence Receipt vectors: one positive and one negative per claim-type registry entry.
//!
//! Every receipt produced here is immediately run through
//! [`ahl_core::receipt::verify_receipt`] with the same trust policy the conformance tests use.
//! A positive vector that does not accept, or a negative vector that does not reject with the
//! rule it claims to violate, aborts the generator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ahl_core::receipt::{verify_receipt, AdaptorProfile, ReceiptError, TrustPolicy};
use ahl_core::{entry_id, field_str, statement_id, TestKey};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::corpus::{Anchor, Corpus};
use crate::scenario::{
    write_jcs, write_json, Keys, ADAPTOR_ID, CANONICALIZATION, DS_CUSTOMERS, DS_SCORES,
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
        genesis_key_ids: BTreeSet::from([keys.producer_1.key_id()]),
        // `ahl-test-log-v1` defines neither a binary checkpoint framing nor a consistency-proof
        // serialization, so both capabilities are off: material needing them is rejected as a
        // limitation of *this profile*, naming it, not as a limitation of the format.
        adaptor_profiles: BTreeMap::from([(
            ADAPTOR_ID.to_owned(),
            AdaptorProfile::minimal(corpus.adaptor_hash.clone()),
        )]),
        dataset_keys: BTreeMap::from([(DS_CUSTOMERS.to_owned(), dataset_key.to_vec())]),
        trusted_witness_key_ids: BTreeSet::new(),
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
                            "consistency_proofs": false,
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

        json!({
            "ahl_receipt_version": "1",
            "spec_version": "0.3.0",
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
        })
    }
}

/// A `keys` block entry (receipt format §2.2).
fn key_entry(key: &TestKey, witness_id: Option<&str>, binding_index: u64) -> Value {
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
            &r.c_a_bytes,
            "Proves that the entry-1 ingestion introduced record A into dataset `customers`, \
             and — for a verifier authorized to hold the dataset key — that the carried \
             canonical bytes recompute to the anchored HMAC commitment. The dataset key is NOT \
             packaged: an unauthorized verifier still checks the signature, the anchoring and \
             the graph, but reads `content_binding` as unverifiable.",
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

    // The challenge at entry 21: a well-anchored trigger from a non-authority key.
    let unauthorized_trigger = Spec {
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
        file: "trigger-effective-unauthorized-issuer-must-fail.ahl",
        receipt: unauthorized_trigger.clone(),
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

    // A LATER FORGED trigger on F at entry 28: `signatures[0].key_id` names `producer-1`'s
    // real key — the genuine `customers` authority — but `sig` is garbage, not a signature
    // `producer-1` ever produced. Round-5 blocker: competing-trigger selection must verify each
    // candidate's signature cryptographically before comparing authority, or a forged envelope
    // that merely reuses a real `key_id` can displace the genuinely authorized trigger by
    // anchoring at a later index.
    out.push(Vector {
        file: "trigger-effective-forged-signature-ignored.ahl",
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
                   That entry is a forgery: `signatures[0].key_id` correctly names \
                   `producer-1`'s real key_id — the genuine `customers` dataset authority — but \
                   `signatures[0].sig` does not verify against that key's actual public key. A \
                   verifier that treated a matching `key_id` as proof of authorization, without \
                   cryptographically checking the signature it is attached to, would let this \
                   forgery unseat the real trigger merely by anchoring later. Effectiveness \
                   requires BOTH the claimed key_id to be the record's authority AND the \
                   signature to verify against it — checked before the greatest-entry-index \
                   rule is applied, exactly as for an unauthorized-but-genuine challenge \
                   (compare `trigger-effective-later-challenge-ignored.ahl`), because a forged \
                   signature is never traversed either."
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
            "corpus_checkpoint": cp8.checkpoint,
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
            "corpus_checkpoint": cp8.checkpoint,
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
    // needs (here, A at entry 25). Authenticating D (spec §2.2, round-5 substantive fix)
    // additionally needs the log key bound to the manifest active for D's own tree size.
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
                "corpus_checkpoint": cp28.checkpoint,
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
                "corpus_checkpoint": cp24.checkpoint,
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
                "trigger": unauthorized_trigger,
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
    out.push(Vector {
        file: "governance-state-valid.ahl",
        receipt: Spec {
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
                   by witness-1."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
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
