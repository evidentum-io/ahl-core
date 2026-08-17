//! Evidence Receipt vectors: one positive and one negative per claim-type registry entry.
//!
//! Every receipt produced here is immediately run through
//! [`ahl_core::receipt::verify_receipt`] with the same trust policy the conformance tests use.
//! A positive vector that does not accept, or a negative vector that does not reject with the
//! rule it claims to violate, aborts the generator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ahl_core::receipt::{verify_receipt, ReceiptError, TrustPolicy};
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
        adaptor_profiles: BTreeMap::from([(ADAPTOR_ID.to_owned(), corpus.adaptor_hash.clone())]),
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
                "adaptor_profiles": { ADAPTOR_ID: corpus.adaptor_hash },
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
        let mut producer_keys = vec![key_entry(&keys.producer_1, None, 0)];
        if self.chain.contains(&9) {
            producer_keys.push(key_entry(&keys.producer_2, None, 9));
        }

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

// `s2_index` / `s3_index` name the records they open; renaming them would hide which leaf a
// vector proves and which one the negative counterpart wrongly opens.
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)] // A flat catalogue: one entry per registry claim type.
fn build_vectors(corpus: &Corpus, keys: &Keys) -> Vec<Vector> {
    let r = &corpus.records;
    let cp8 = corpus.anchor("cp8");
    let cp13 = corpus.anchor("cp13");
    let cp18 = corpus.anchor("cp18");
    let cp20 = corpus.anchor("cp20");
    let customers = |record: &String| Some((DS_CUSTOMERS.to_owned(), record.clone()));
    let scores = |record: &String| Some((DS_SCORES.to_owned(), record.clone()));

    let mut out = Vec::new();

    // --- statement-anchored ------------------------------------------------------
    let statement_anchored = Spec {
        claim_type: "statement-anchored",
        subject_index: 3,
        anchor: cp18,
        chain: vec![0],
        record_subject: None,
        competing: "not-checked",
        content_binding: "none",
        currency_mode: "declared",
        currency_material: json!({}),
        claim_material: json!({}),
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

    // --- record-ingested ---------------------------------------------------------
    let ingested = |content_binding: &'static str, bytes: &[u8], note: &str| {
        Spec {
            claim_type: "record-ingested",
            subject_index: 1,
            anchor: cp18,
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

    // --- record-derived (batch-member form) --------------------------------------
    let s2_index = leaf_index(corpus, &corpus.batch_root, &r.s2);
    let s3_index = leaf_index(corpus, &corpus.batch_root, &r.s3);
    let derived = |path: Vec<String>, note: &str| {
        Spec {
            claim_type: "record-derived",
            subject_index: 4,
            anchor: cp18,
            chain: vec![0],
            record_subject: scores(&r.s2),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "output": { "dataset": DS_SCORES, "record": r.s2 },
                "batch_leaf": corpus.tree_leaves(&corpus.batch_root)[s2_index],
                "leaf_index": s2_index,
                "leaf_path": path,
            }),
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };
    out.push(Vector {
        file: "record-derived-valid.ahl",
        receipt: derived(
            corpus.tree_path(&corpus.batch_root, s2_index),
            "Proves that the batch derivation at entry 4 committed output record S2, by opening \
             the batch output tree at the carried `ahl-leaf-v2` leaf. It proves nothing about \
             the other two outputs of the same batch, and nothing about the upstream provenance \
             of the input the leaf names — that is a separate `record-derived` claim.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "record-derived-wrong-path-must-fail.ahl",
        receipt: derived(
            corpus.tree_path(&corpus.batch_root, s3_index),
            "MUST FAIL. `leaf_index` and `batch_leaf` name S2 but `leaf_path` is the inclusion \
             path of a different leaf of the same tree, so recomputation does not reach \
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
        Spec {
            claim_type: "record-ingested",
            subject_index,
            anchor,
            chain: vec![0],
            record_subject: customers(record),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
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
             trigger is effective or that it governs A at any checkpoint: no competing-trigger \
             enumeration is carried.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "trigger-declared-replacement-ordering-must-fail.ahl",
        receipt: trigger_declared(
            cp18,
            introduction(11, &r.c_a3, cp18),
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
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "trigger-effective-valid.ahl",
        receipt: trigger_effective(
            1,
            "Proves that the correction at entry 6 governs record A at checkpoint cp8. The \
             competing-trigger range is [1, 8) — the prefix from A's introduction rather than \
             [0, 8) — which receipt §3 permits precisely because a trigger anchored before the \
             record's introduction is never effective (core spec §2.3.3). Governance currency \
             is enumerated over [0, 8), so the presented chain is proven to be the only \
             manifest/key material through cp8. The claim is bounded by cp8: the corpus later \
             anchors a superseding correction of A at entry 12, which is invisible here by \
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

    // --- disposition-declared ----------------------------------------------------
    let s1_leaf = leaf_index(corpus, &corpus.affected_root, &r.s1);
    let s2_leaf = leaf_index(corpus, &corpus.affected_root, &r.s2);
    let disposition_declared = |path: Vec<String>, note: &str| {
        Spec {
            claim_type: "disposition-declared",
            subject_index: 8,
            anchor: cp18,
            chain: vec![0],
            record_subject: scores(&r.s1),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "trigger": trigger_declared(
                    cp18,
                    introduction(5, &r.c_a2, cp18),
                    "Embedded trigger proof for the correction the propagation names.",
                ),
                "disposition_leaf": corpus.tree_leaves(&corpus.affected_root)[s1_leaf],
                "leaf_index": s1_leaf,
                "leaf_path": path,
            }),
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
    let disposition_effective = |trigger: Value, mode: &'static str, note: &str| {
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
            currency_mode: mode,
            currency_material: if mode == "enumerated" {
                corpus.enumeration(0, 13, cp13)
            } else {
                json!({})
            },
            claim_material: json!({
                "trigger": trigger,
                "disposition_leaf": corpus.tree_leaves(&corpus.affected_root)[s1_leaf],
                "leaf_index": s1_leaf,
                "leaf_path": corpus.tree_path(&corpus.affected_root, s1_leaf),
            }),
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "disposition-effective-valid.ahl",
        receipt: disposition_effective(
            trigger_effective(1, "Embedded trigger-effective proof, bounded by cp8."),
            "enumerated",
            "Proves that the propagation statement at entry 8 dispositions S1 under a trigger \
             proven *effective* at cp8, with governance enumerated over [0, 13). The nesting is \
             three deep — disposition-effective, trigger-effective, and the two introduction \
             receipts — which receipt §3.1 permits (limit 4).",
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
            "enumerated",
            "MUST FAIL. `disposition-effective` requires the embedded trigger receipt to be a \
             `trigger-effective`; this one is `trigger-declared`, which carries no \
             competing-trigger enumeration and therefore never establishes that the trigger \
             governs. Receipt §3's naming rule forbids a `-effective` verdict resting on \
             declared-mode material.",
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
    let trees_block = |drop_batch_leaf: bool| {
        let mut batch = corpus.tree_leaves(&corpus.batch_root).to_vec();
        if drop_batch_leaf {
            batch.pop();
        }
        json!({
            corpus.batch_root.clone(): { "leaves": batch },
            corpus.affected_root.clone(): { "leaves": corpus.tree_leaves(&corpus.affected_root) },
        })
    };
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
                "corpus_prefix": corpus.enumeration(0, 8, cp8),
                "trees": trees_block(drop_batch_leaf),
            }),
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "propagation-complete-valid.ahl",
        receipt: propagation_complete(
            false,
            "Proves that the affected set anchored by the propagation statement at entry 8 \
             equals the closure recomputable from the complete corpus prefix [0, 8) together \
             with the leaf material of every committed tree that prefix references. There is no \
             compact form of this claim by construction (core spec §6.5). The boundary is \
             emphatically relative: it establishes completeness *within the declared corpus*, \
             not that the declared corpus is the organisation's real corpus (core spec §5.3).",
        ),
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

    // --- governance-state --------------------------------------------------------
    out.push(Vector {
        file: "governance-state-valid.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 18,
            anchor: cp20,
            chain: vec![0, 9, 18],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(19, 20, cp20),
            claim_material: json!({ "target_index": 19 }),
            note: "Proves that manifest version 2, anchored at entry 18, is the governance \
                   state active at entry index 19: the enumeration of (18, 19] is authenticated \
                   under cp20 and contains no further manifest or key statement. Version 2 \
                   replaced the witness key set in full (core spec §7.2), which is why cp20 is \
                   cosigned by witness-2 while every earlier checkpoint is cosigned by \
                   witness-1. The chain carries the key transition at entry 9 so the producer \
                   key set is derivable from genesis."
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
            anchor: cp18,
            chain: vec![0, 9],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(1, 11, cp18),
            claim_material: json!({ "target_index": 10 }),
            note: "MUST FAIL. The claim is that the genesis manifest is the governance state \
                   active at entry index 10, and the §4 material does authenticate the complete \
                   range (0, 10]. But that range contains the `key` statement at entry 9, which \
                   changed the producer key set. Receipt §3 requires the enumerated material to \
                   prove no manifest or key statement exists in (subject.entry_index, \
                   target_index]; here one demonstrably does, so the presented chain is not the \
                   state at the target index."
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
