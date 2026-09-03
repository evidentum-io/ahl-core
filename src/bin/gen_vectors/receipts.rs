//! Evidence Receipt vectors: one positive and one negative per claim-type registry entry.
//!
//! Every receipt produced here is immediately run through
//! [`ahl_core::receipt::verify_receipt_report`] with the same trust policy the conformance
//! tests use. A positive vector whose result is not `verified`, or a negative vector that does
//! not reject with the rule it claims to violate, aborts the generator.
//!
//! The index records each vector's I-D §7.7 result — `verified`, `invalid` or `unverifiable` —
//! and, for the two non-verified values, the assertion whose finding produced it. Neither is
//! declared here: both are read from the report the verifier actually produces, while the
//! `rule` a negative vector names, and the predicate over the rejection behind it, are what the
//! generator asserts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ahl_core::receipt::{
    verify_receipt, verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Outcome,
    ReceiptError, TrustPolicy,
};
use ahl_core::{
    checkpoint_signing_bytes, cosignature_bytes, entry_id, envelope, field_str, statement_id,
    TestKey,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::corpus::{rotation, Anchor, Corpus, ROTATIONS};
use crate::scenario::{
    signed, write_jcs, write_json, Keys, ADAPTOR_ID, CANONICALIZATION, DS_CUSTOMERS, DS_SCORES, T0,
    WITNESS_1, WITNESS_2,
};

/// What a receipt vector asserts about its own verification outcome.
enum Expect {
    /// The §7.7 result must be `verified`.
    Accept,
    /// The §7.7 result must not be `verified`, and the rejection behind the finding that
    /// produced it must satisfy this predicate. Which of the two non-verified values it is
    /// comes from [`ahl_core::receipt::ReceiptError::class`] rather than from the vector.
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
// The self-check loop reports every vector's outcome as it writes it; splitting the reporting
// from the writing would put the two out of step for a reader following the output.
#[allow(clippy::too_many_lines)]
pub fn write_all(corpus: &Corpus, keys: &Keys, root: &Path, dataset_key: &[u8]) {
    let policy = trust_policy(corpus, keys, dataset_key);
    let vectors = build_vectors(corpus, keys);

    println!("receipt self-check");
    let dir = root.join("receipts");
    let mut index = Vec::new();
    for vector in &vectors {
        let report = verify_receipt_report(&vector.receipt, &policy)
            .unwrap_or_else(|error| panic!("{}: the run must complete: {error}", vector.file));
        let outcome = verify_receipt(&vector.receipt, &policy);
        match &vector.expect {
            Expect::Accept => {
                let verdict = outcome.unwrap_or_else(|error| {
                    panic!("{}: must verify, but was rejected: {error}", vector.file)
                });
                assert_eq!(report.result, Outcome::Verified, "{}", vector.file);
                println!("  [ok] {} verified: {}", vector.file, verdict.claim_type);
                let mut entry = json!({
                    "file": vector.file,
                    "claim_type": verdict.claim_type,
                    "expect": Outcome::Verified.name(),
                    "boundary": verdict.boundary,
                    "embedded_receipts": verdict.embedded_receipts,
                });
                // I-D §7.7: "Their number is the number of void entries inspected." Recorded
                // only where the vector carries one, so a reader sees which vectors are about
                // the reliance rule of §7.5.1 4d.
                if !report.informative.is_empty() {
                    entry["informative"] = json!(report.informative.len());
                }
                index.push(entry);
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
                assert_eq!(
                    report.result,
                    error.class(),
                    "{}: the result must be the class of the rejection that produced it",
                    vector.file
                );
                // The finding the result reduces from: the one whose outcome IS the result, at
                // the receipt it was reached in. A negative vector names exactly one.
                let finding = report
                    .findings
                    .iter()
                    .find(|finding| {
                        finding.counts_toward_result() && finding.outcome == report.result
                    })
                    .unwrap_or_else(|| panic!("{}: a result comes from a finding", vector.file));
                println!(
                    "  [ok] {} {} on {} by {rule}: {error}",
                    vector.file, report.result, finding.assertion
                );
                let mut entry = json!({
                    "file": vector.file,
                    "claim_type": vector.receipt["claim"]["type"],
                    "expect": report.result.name(),
                    "finding": finding.assertion.name(),
                    "rule": rule,
                    "reason": error.to_string(),
                });
                if !report.informative.is_empty() {
                    entry["informative"] = json!(report.informative.len());
                }
                index.push(entry);
            }
        }
        write_jcs(&dir.join(vector.file), &vector.receipt);
    }

    write_json(
        &dir.join("index.json"),
        &json!({
            "description": "Every Evidence Receipt vector in this directory, with the I-D §7.7 \
                            result a conformant verifier must reach — `verified`, `invalid` or \
                            `unverifiable`. A non-verified vector also names the required \
                            assertion whose finding produced that result, and the normative rule \
                            that must fire. The `policy` block is the locally configured trust \
                            policy the outcomes assume (receipt format §1 design rule 1); it is \
                            deliberately NOT derived from any receipt.",
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
                    // The verifier-local budgets alone: I-D §7.8's fixed limits are
                    // properties of the artifact and are not policy a vector's outcome could
                    // depend on (`ahl_core::receipt::MAX_EMBEDDED_DEPTH`,
                    // `MAX_EMBEDDED_RECEIPTS`).
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

        let (witness_key, witness_id) = keys.witness_for(anchor.manifest_index);
        let producer_keys =
            self.producer_keys.clone().unwrap_or_else(|| producer_key_block(self, corpus, keys));

        let mut receipt = json!({
            "ahl_receipt_version": "2",
            "spec_version": "0.4.0",
            "claim": claim,
            "subject": subject_block,
            "envelope": subject,
            "keys": {
                "log": [ key_entry(keys.log_for(anchor.manifest_index), None, anchor.manifest_index) ],
                "witness": [ key_entry(witness_key, Some(witness_id), anchor.manifest_index) ],
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
        // as an empty array — and where it is present it carries "one element per rotation, in
        // ascending `manifest_entry_index` order". This corpus rotates twice: the witness set at
        // manifest v2 (entry 25) and the log checkpoint-signing key at manifest v4 (entry 55).
        let rotations: Vec<u64> = ROTATIONS
            .into_iter()
            .filter(|(index, _, _)| self.chain.contains(&usize::try_from(*index).expect("index")))
            .map(|(index, _, _)| index)
            .collect();
        if !rotations.is_empty() {
            receipt["governance"]["rotation_proofs"] = json!(rotations
                .iter()
                .map(|index| corpus.rotation_proof_element(keys, *index))
                .collect::<Vec<_>>());
            // I-D §7.1: "Every key used in verification MUST appear in `keys` with its source
            // and its binding", and under the rotation-proof transition exception "the
            // corresponding `keys.log[]` and `keys.witness[]` entries carry `manifest-chain`
            // bindings naming that predecessor version". So each rotation adds the OUTGOING log
            // key and the OUTGOING witness, bound to the manifest version active immediately
            // before the rotating one — which may be the same physical key the anchoring
            // checkpoint uses, listed a second time under a different binding, exactly the case
            // receipt key binding is tolerant for.
            for index in rotations {
                let (_, _, outgoing) = rotation(index);
                let (outgoing_witness, outgoing_witness_id) = keys.witness_for(outgoing);
                push_key_entry(
                    &mut receipt["keys"]["log"],
                    key_entry(keys.log_for(outgoing), None, outgoing),
                );
                push_key_entry(
                    &mut receipt["keys"]["witness"],
                    key_entry(outgoing_witness, Some(outgoing_witness_id), outgoing),
                );
            }
        }
        receipt
    }
}

/// The `keys.producer[]` block a receipt carries: the key set in force at its subject's entry
/// index, each key bound to the governance statement that put it there (I-D §7.1, §2.2).
///
/// §7.2's snapshot rule starts from the manifest with the greatest entry index *below* the
/// subject — the genesis manifest for the corpus prefix — and then applies later `key`
/// statements. WHICH of those apply is a property of the governance MODE rather than of the
/// chain: I-D §7.4 puts producer-key transitions in enumeration material alone, so a
/// declared-mode receipt sees none of them, while an enumerated one sees every transition its
/// range covers — and that range is exactly `[0, tree_size(C))`, which contains the subject, so
/// every transition at or before the subject applies.
fn producer_key_block(spec: &Spec<'_>, corpus: &Corpus, keys: &Keys) -> Vec<Value> {
    let subject = spec.subject_index as u64;
    let snapshot = spec
        .chain
        .iter()
        .copied()
        .rfind(|index| corpus.payload(*index)["type"] == "manifest" && (*index as u64) < subject)
        .unwrap_or(0) as u64;
    let mut block = vec![key_entry(&keys.producer_1, None, snapshot)];
    if spec.currency_mode != "enumerated" {
        return block;
    }
    // The transitions the snapshot has not already folded in, applied in entry order.
    let mut bound_at: Option<u64> = None;
    for index in (snapshot + 1)..=subject {
        let payload = corpus.payload(usize::try_from(index).expect("small entry index"));
        if payload["type"] != "key" || payload["key"]["key_id"] != json!(keys.producer_2.key_id()) {
            continue;
        }
        bound_at = (payload["action"] == json!("add")).then_some(index);
    }
    if let Some(index) = bound_at {
        block.push(key_entry(&keys.producer_2, None, index));
    }
    block
}

/// Add a `keys` entry unless the block already carries the identical one.
///
/// One physical key can legitimately appear more than once under different bindings, and a
/// rotation whose outgoing state is the anchoring checkpoint's own would otherwise produce two
/// byte-identical entries — which is not a second binding, only a repeat.
fn push_key_entry(block: &mut Value, entry: Value) {
    let list = block.as_array_mut().expect("keys block is an array");
    if !list.contains(&entry) {
        list.push(entry);
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
    let cp34 = corpus.anchor("cp34");
    let cp35 = corpus.anchor("cp35");
    let cp37 = corpus.anchor("cp37");
    let cp40 = corpus.anchor("cp40");
    let cp43 = corpus.anchor("cp43");
    let cp38 = corpus.anchor("cp38");
    let cp44 = corpus.anchor("cp44");
    let cp45 = corpus.anchor("cp45");
    let cp46 = corpus.anchor("cp46");
    let cp50 = corpus.anchor("cp50");
    let cp56 = corpus.anchor("cp56");
    let cp57 = corpus.anchor("cp57");
    let cp51 = corpus.anchor("cp51");
    let cp52 = corpus.anchor("cp52");
    let cp53 = corpus.anchor("cp53");
    let cp54 = corpus.anchor("cp54");
    let cp55 = corpus.anchor("cp55");
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
            chain: vec![0, 25],
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
                   made with the dropped key. This is `invalid` rather than the `unverifiable` \
                   outcome I-D §7.4 gives a declared-mode receipt whose ENVELOPE depends on an \
                   uncarried key transition: nothing here depends on one — entry 26 is signed \
                   by `producer-1`, which version 2 lists — and §7.1 decides the `keys` listing \
                   on its own terms, a `manifest-chain` binding naming an entry index that is \
                   no manifest version at all."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "spec §7.2 — a manifest's producer key array is a snapshot that discards the \
                   prior one",
            matches: |e| matches!(e, ReceiptError::KeyNotBound { .. }),
        },
    });

    // I-D §7.4, "Declared mode and producer-key transitions": the `unverifiable` outcome, and
    // its `invalid` neighbour, on two receipts that differ only in which defect they carry.
    out.push(Vector {
        file: "statement-anchored-uncarried-key-transition-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 19,
            anchor: cp20,
            chain: vec![0],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST FAIL, as UNVERIFIABLE rather than invalid. The subject at entry 19 is \
                   signed by `producer-2`, which the `key` statement at entry 9 added after the \
                   genesis manifest — and declared mode carries no `key` statements at all: \
                   I-D §7.4 puts producer-key transitions in enumeration material alone. So \
                   the induction never sees the transition, and the envelope names a key the \
                   presented state holds nothing for. I-D §7.4: \"Such a receipt is \
                   `unverifiable` (Section 7.7), for want of material the mode does not carry. \
                   It is NOT `invalid`: the omitted transition is not material this mode \
                   required the receipt to carry, and a verifier holding the enumerated \
                   material would verify the same bytes.\" That verifier exists in this \
                   corpus: `trigger-effective-derived-rotated-key.ahl` carries the same entry-19 \
                   envelope under enumerated currency and ACCEPTS. A verifier that reported \
                   this file as `invalid` would be in contradiction with that one over the \
                   same bytes; a verifier that accepted it would be treating an unproven key \
                   as active. Refusing under a variant of its own is neither."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.4 — a declared-mode envelope naming a key the mode does not carry is \
                   unverifiable, not invalid",
            matches: |e| matches!(e, ReceiptError::ProducerKeyNotCarried { entry_index: 19, .. }),
        },
    });
    out.push(Vector {
        file: "statement-anchored-non-verifying-envelope-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 32,
            anchor: cp34,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST FAIL, as INVALID. The counterpart to \
                   `statement-anchored-uncarried-key-transition-must-fail.ahl`, and the reason \
                   that file's outcome is not simply what declared mode does with every \
                   signature failure. The subject at entry 32 names `producer-1`, which \
                   manifest version 2 lists and the presented chain therefore RESOLVES — but \
                   its `sig` is not a signature `producer-1` ever produced. Nothing is missing \
                   here; the defect is demonstrated from the bytes in hand, and I-D §7.5.1 4d \
                   makes it `invalid`: \"An envelope carrying a non-verifying entry... is \
                   invalid however many other entries verify.\" The governance mode does not \
                   enter into it."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4d — a resolvable key whose signature does not verify is invalid \
                   in either governance mode",
            matches: |e| matches!(e, ReceiptError::EnvelopeSignatureInvalid { entry_index: 32 }),
        },
    });
    out.push(Vector {
        file: "statement-anchored-uncarried-key-with-bad-signature-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 33,
            anchor: cp34,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST FAIL, as INVALID — the third case, where BOTH of the preceding two \
                   defects sit on ONE envelope, and the order they sit in must not decide the \
                   outcome. Entry 33 carries two signature entries. The FIRST names \
                   `producer-2`, which reaches a verifier only through a `key` statement and \
                   which declared mode therefore does not carry — the \
                   `statement-anchored-uncarried-key-transition-must-fail.ahl` case. The SECOND \
                   names `producer-1`, which manifest version 2 lists and this chain resolves, \
                   with a `sig` that is not a signature `producer-1` ever produced — the \
                   `statement-anchored-non-verifying-envelope-must-fail.ahl` case. I-D §2.1 \
                   makes envelope validity \"the conjunction of all entries\", and an envelope \
                   \"carrying a non-verifying entry... is invalid regardless of how many other \
                   entries verify\"; §7.7 reduces the two findings the same way — \"`invalid` \
                   if any required finding is `invalid`; otherwise `unverifiable` if any \
                   required finding is `unverifiable`\", because \"a demonstrated defect in \
                   required material is a fact about the artifact, while a capability gap is \
                   not\". So the result is the SIGNATURE failure. A verifier that stopped at \
                   the first unresolvable `key_id` would report this receipt as unverifiable, \
                   and a producer could then downgrade any forgery to a capability gap by \
                   listing an uncarried key ahead of it."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §2.1 / §7.7 — a resolvable non-verifying entry is invalid however the \
                   envelope orders its signatures",
            matches: |e| matches!(e, ReceiptError::EnvelopeSignatureInvalid { entry_index: 33 }),
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

    // I-D §2.2 / §7.6: entry 34 is a genuine, fully anchored ingestion of record E into
    // `customers`, signed by the `customers` authority — but its payload names manifest v1
    // (genesis) as governing it, even though it is anchored well after manifest v2 (entry 25)
    // became active. This is a real corpus statement (see `corpus.rs`'s entry 34), not a
    // mutated fixture: the "structural wall" earlier rounds hit — mutating an anchored
    // envelope invalidates its own inclusion path before the rule under test is ever reached —
    // does not apply here, because the defect was baked in before the statement was ever
    // signed or included.
    out.push(Vector {
        file: "record-ingested-stale-manifest-must-fail.ahl",
        receipt: Spec {
            claim_type: "record-ingested",
            subject_index: 34,
            anchor: cp35,
            chain: vec![0, 25],
            record_subject: customers(&r.c_e),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: format!(
                "MUST FAIL. Entry 34's payload names manifest `{}` (v1, genesis), but I-D §2.2 \
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

    // --- content-evidence presence (I-D §7.2 record rows) ------------------------
    // The bytes and `canonicalization` are carried "if and only if `content_binding` is not
    // `none`", with `media_type` only where the descriptor requires it. Four vectors, one per
    // way the biconditional can be broken: a descriptor or a media type carried under `none`,
    // and either half of the pair carried without the other. None of them is a cryptographic
    // failure — every commitment in each still matches, or would if the missing half were
    // there — which is why the rule has to be enforced on presence rather than left to the
    // recomputation to notice.
    let evidence_shape = |content_binding: &'static str, material: Value, note: &str| {
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
            claim_material: material,
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };

    out.push(Vector {
        file: "record-ingested-none-with-canonicalization-must-fail.ahl",
        receipt: evidence_shape(
            "none",
            json!({ "canonicalization": CANONICALIZATION }),
            "MUST FAIL. `assurance.content_binding` is `none`, so this receipt asserts no \
             content evidence at all, and yet `claim_material` carries a canonicalization \
             descriptor. I-D §7.2 makes the descriptor present IF AND ONLY IF the binding is \
             not `none`. Nothing here is cryptographically wrong; what is wrong is that the \
             carried descriptor is never compared against the manifest's declared one, because \
             the `none` branch recomputes no commitment — so a verifier that ignored it would \
             let a receipt carry an unchecked descriptor beside a claim that proves nothing \
             about content.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.2 — `canonicalization` is present iff `content_binding` is not `none`",
            matches: |e| matches!(e, ReceiptError::AssuranceMismatch { field: "content_binding" }),
        },
    });

    out.push(Vector {
        file: "record-ingested-none-with-media-type-must-fail.ahl",
        receipt: evidence_shape(
            "none",
            json!({ "media_type": "application/json" }),
            "MUST FAIL. Same rule as the descriptor case, for the descriptor's other member: \
             `media_type` accompanies the carried descriptor and is admissible only where that \
             descriptor requires it (I-D §2.6, §7.2). Under `content_binding: \"none\"` there \
             is no carried descriptor for it to belong to.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.2 — `media_type` accompanies a carried descriptor, and `none` \
                   carries none",
            matches: |e| matches!(e, ReceiptError::AssuranceMismatch { field: "content_binding" }),
        },
    });

    out.push(Vector {
        file: "record-ingested-bytes-without-canonicalization-must-fail.ahl",
        receipt: evidence_shape(
            "keyed-authorized",
            json!({ "record_bytes": base64(&r.c_a_bytes_as_received) }),
            "MUST FAIL. The bytes are the genuine record A as received, and they would \
             recompute to the anchored commitment — but no descriptor is carried, and I-D §7.2 \
             pairs the two members. `record_bytes` carries the record AS RECEIVED, so without \
             a descriptor there is no canonicalization procedure to apply and no `ddig` for \
             the preimage; a verifier that fell back on the manifest's descriptor would be \
             recomputing under a descriptor the receipt never claimed.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.2 — the bytes and `canonicalization` are carried together or not at \
                   all",
            matches: |e| {
                matches!(e, ReceiptError::ClaimMaterialMissing { field: "canonicalization", .. })
            },
        },
    });

    out.push(Vector {
        file: "record-ingested-canonicalization-without-bytes-must-fail.ahl",
        receipt: evidence_shape(
            "keyed-authorized",
            json!({ "canonicalization": CANONICALIZATION }),
            "MUST FAIL. The other half of the same pair: the descriptor is carried, matches \
             the manifest's declared one exactly, and there are no bytes for it to \
             canonicalize. The receipt asserts `keyed-authorized` content binding while \
             carrying nothing that could be bound, which I-D §7.2 makes invalid rather than a \
             binding silently downgraded to `none`.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.2 — a carried descriptor without the bytes proves no content binding",
            matches: |e| {
                matches!(e, ReceiptError::ClaimMaterialMissing { field: "record_bytes", .. })
            },
        },
    });

    // --- record-derived (batch member, with input-set membership) ----------------
    let w1_leaf = leaf_index(corpus, &corpus.wide_outputs_root, &r.w1);
    let w2_leaf = leaf_index(corpus, &corpus.wide_outputs_root, &r.w2);
    // I-D §7.2: `input_members` proves "the listed inputs and no others", so the complete
    // committed input set is carried — one member per leaf of the input-set tree.
    let input_members: Vec<Value> = (0..corpus.tree_leaves(&corpus.input_set_root).len())
        .map(|index| {
            json!({
                "input": corpus.tree_leaves(&corpus.input_set_root)[index],
                "input_index": index,
                "input_path": corpus.tree_path(&corpus.input_set_root, index),
            })
        })
        .collect();
    let derived = |path: Vec<String>, members: Value, note: &str| {
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
                "input_members": members,
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
            json!(input_members),
            "Proves that the batch derivation at entry 10 committed output record W1, by \
             opening the batch output tree at the carried `ahl-leaf-v2` leaf, and — through \
             `input_members` — that the leaf's input set is exactly the three inputs carried, \
             each opening the `input_set_root` that leaf commits. Two trees are traversed: the \
             outputs tree against `outputs_root`, and the input-set tree against the leaf's \
             `inputs.input_set_root`. The whole input set is carried because I-D §7.2 asks the \
             member to prove \"the listed inputs and no others\": a subset would leave the \
             derivation's remaining inputs unstated under a root that says how many there \
             were. It proves nothing about the batch's other output, and nothing about those \
             inputs' own upstream provenance — those are separate claims.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "record-derived-wrong-path-must-fail.ahl",
        receipt: derived(
            corpus.tree_path(&corpus.wide_outputs_root, w2_leaf),
            json!(input_members),
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
    out.push(Vector {
        file: "record-derived-partial-input-members-must-fail.ahl",
        receipt: derived(
            corpus.tree_path(&corpus.wide_outputs_root, w1_leaf),
            json!([input_members[0]]),
            "MUST FAIL. One genuine, correctly proven input membership out of the three the \
             leaf's `input_set_count` commits. Nothing carried is wrong: the member opens \
             `input_set_root` at its own index. What is missing is the rest of the set. I-D \
             §7.2 requires `input_members` to prove \"the listed inputs and no others\", so a \
             partial list is not a weaker proof of the same claim but a proof of a different \
             one — and accepting it would let a producer disclose the convenient inputs of a \
             batch derivation and withhold the rest, under a root that states how many there \
             were.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.2 — `input_members` proves the listed inputs and no others",
            matches: |e| matches!(e, ReceiptError::TreeMaterialInvalid { .. }),
        },
    });
    out.push(Vector {
        file: "record-derived-missing-input-members-must-fail.ahl",
        receipt: Spec {
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
                "leaf_path": corpus.tree_path(&corpus.wide_outputs_root, w1_leaf),
            }),
            producer_keys: None,
            note: "MUST FAIL. The output side is impeccable — the leaf opens `outputs_root` at \
                   its own index — and `input_members` is simply absent. The leaf takes the \
                   input-set form of I-D §2.7, which commits its inputs by ROOT and lists none \
                   of them, so with no members the derivation's inputs are not carried at all. \
                   I-D §7.2 makes the member REQUIRED under exactly that form. A verifier \
                   treating it as optional would accept a batch derivation that states its \
                   outputs and keeps every input unstated, which is the one thing the \
                   input-set form exists to make provable."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.2 — `input_members` is REQUIRED where `batch_leaf.inputs` is the \
                   input-set form",
            matches: |e| {
                matches!(e, ReceiptError::ClaimMaterialMissing { field: "input_members", .. })
            },
        },
    });

    // The other form of §2.7's `inputs`: the batch at entry 4 lists its inputs in the leaf and
    // commits no `input_set_root`, so `input_members` is forbidden there rather than optional.
    let s2_batch_leaf = leaf_index(corpus, &corpus.batch_root, &r.s2);
    let full_array_batch = |members: Option<Value>, note: &str| {
        let mut claim_material = json!({
            "output": { "dataset": DS_SCORES, "record": r.s2 },
            "batch_leaf": corpus.tree_leaves(&corpus.batch_root)[s2_batch_leaf],
            "leaf_index": s2_batch_leaf,
            "leaf_path": corpus.tree_path(&corpus.batch_root, s2_batch_leaf),
        });
        if let Some(members) = members {
            claim_material["input_members"] = members;
        }
        Spec {
            claim_type: "record-derived",
            subject_index: 4,
            anchor: cp20,
            chain: vec![0],
            record_subject: scores(&r.s2),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material,
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };
    out.push(Vector {
        file: "record-derived-full-input-array.ahl",
        receipt: full_array_batch(
            None,
            "Proves that the batch derivation at entry 4 committed output record S2, through \
             the other form of I-D §2.7's `inputs`: the leaf carries the full array of input \
             objects rather than an input-set root. The inputs are therefore in the leaf that \
             `leaf_path` opens against `outputs_root`, already covered by the derivation's own \
             signature and anchoring, and `input_members` is absent because there is no \
             `input_set_root` for a membership path to open. Compare `record-derived-valid.ahl`, \
             whose leaf uses the input-set form and must carry the members in full.",
        ),
        expect: Expect::Accept,
    });
    out.push(Vector {
        file: "record-derived-input-members-on-full-array-must-fail.ahl",
        receipt: full_array_batch(
            Some(json!(input_members)),
            "MUST FAIL. The same claim as `record-derived-full-input-array.ahl`, with \
             `input_members` carried anyway. The members are genuine — they are the complete, \
             correctly proven input set of the OTHER batch, at entry 10 — and that is exactly \
             the problem: this leaf commits no `input_set_root`, so nothing here binds those \
             members to this derivation, and a verifier that opened them against whatever root \
             it could find would be reporting one batch's inputs as another's. I-D §7.2 carries \
             the member only where `batch_leaf.inputs` is the input-set form.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.2 / §2.7 — `input_members` is carried only with the input-set form",
            matches: |e| {
                matches!(e, ReceiptError::Malformed(detail) if detail.contains("input_members"))
            },
        },
    });

    // I-D §2.7's tree rules bind input-set trees exactly as they bind outputs and disposition
    // trees: "Tree rules, identical for every AHL tree — outputs, input sets, and
    // dispositions". Three negatives, one per rule, over the batch at entry 37 whose three
    // output leaves each commit an input-set tree breaking one of them. Every membership path
    // in all three receipts is genuine and opens the committed root at the claimed index, and
    // the complete committed set is carried — a verifier checking only paths, indexes and
    // cardinality accepts all three.
    let defective_input_set = |output: &String, input_root: &str, note: &str| {
        let leaf = leaf_index(corpus, &corpus.defective_outputs_root, output);
        let members: Vec<Value> = (0..corpus.tree_leaves(input_root).len())
            .map(|index| {
                json!({
                    "input": corpus.tree_leaves(input_root)[index],
                    "input_index": index,
                    "input_path": corpus.tree_path(input_root, index),
                })
            })
            .collect();
        Spec {
            claim_type: "record-derived",
            subject_index: 50,
            anchor: cp51,
            chain: vec![0, 25, 46],
            record_subject: scores(output),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "output": { "dataset": DS_SCORES, "record": output },
                "batch_leaf": corpus.tree_leaves(&corpus.defective_outputs_root)[leaf],
                "leaf_index": leaf,
                "leaf_path": corpus.tree_path(&corpus.defective_outputs_root, leaf),
                "input_members": members,
            }),
            producer_keys: None,
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };
    out.push(Vector {
        file: "record-derived-input-set-unsorted-must-fail.ahl",
        receipt: defective_input_set(
            &r.x_unsorted,
            &corpus.unsorted_input_root,
            "MUST FAIL. The complete input set is carried: two members, distinct indexes, each \
             opening the leaf's `input_set_root` at the index it claims, and the count matches \
             `input_set_count`. The tree behind them is committed in DESCENDING record order. \
             I-D §2.7 requires leaves \"sorted by `record`, comparing the UTF-8 bytes of the \
             canonical commitment string in ascending lexicographic order\", and says the rules \
             are identical for every AHL tree — input sets included. Order is not cosmetic \
             here: the producer who picks the leaf order picks the tree, so a set assembled in \
             any other order opens a root of its own while committing to nothing a second \
             party can reproduce.",
        ),
        expect: Expect::Reject {
            rule: "I-D §2.7 — input-set leaves are sorted by `record` in ascending byte order",
            matches: |e| {
                matches!(e, ReceiptError::TreeMaterialInvalid { detail, .. }
                    if detail.contains("ascending"))
            },
        },
    });
    out.push(Vector {
        file: "record-derived-input-set-duplicate-record-must-fail.ahl",
        receipt: defective_input_set(
            &r.x_duplicate,
            &corpus.duplicate_input_root,
            "MUST FAIL. Again the complete set, again every path genuine. The two leaves name \
             ONE record under two different roles, so they differ as bytes while the sort key \
             repeats. I-D §2.7: \"Duplicate leaves are prohibited.\" A tree that repeats a \
             record states the same input twice and makes `input_set_count` a count of leaves \
             rather than of inputs, so \"the listed inputs and no others\" (§7.2) would be \
             satisfied by a set that lists one input twice and another not at all.",
        ),
        expect: Expect::Reject {
            rule: "I-D §2.7 — duplicate leaves are prohibited in every AHL tree",
            matches: |e| {
                matches!(e, ReceiptError::TreeMaterialInvalid { detail, .. }
                    if detail.contains("ascending"))
            },
        },
    });
    out.push(Vector {
        file: "record-derived-input-set-non-canonical-record-must-fail.ahl",
        receipt: defective_input_set(
            &r.x_noncanonical,
            &corpus.noncanonical_input_root,
            "MUST FAIL. A single-leaf input set, carried complete, with a genuine membership \
             path. Its `record` is `not-a-commitment`, which is not a family string under I-D \
             §2.1. §2.7: \"Commitment strings are family strings under Section 2.1, and one \
             failing the rules there is rejected.\" A leaf whose record is not a commitment \
             names nothing a closure traversal or a second verifier could ever resolve, so \
             accepting it would let a derivation claim an input that does not exist as a \
             record at all.",
        ),
        expect: Expect::Reject {
            rule: "I-D §2.7 / §2.1 — an input-set leaf's `record` is a canonical family string",
            matches: |e| {
                matches!(e, ReceiptError::TreeMaterialInvalid { detail, .. }
                    if detail.contains("not a canonical record commitment"))
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

    // --- record identity is the (dataset, record) pair (I-D §2.4.2, §7.6) --------
    // The commitment string alone is not an identity. Both vectors below carry an embedded
    // introduction whose COMMITMENT matches the trigger exactly and whose DATASET does not, so
    // a verifier comparing the commitment alone accepts them and one comparing the pair does
    // not. Neither is a mutated fixture: the two subject statements are genuinely signed and
    // genuinely anchored, at entries 35 and 36, because a producer naming a commitment beside
    // the wrong dataset is exactly what nothing else in the format prevents.
    out.push(Vector {
        file: "trigger-declared-cross-dataset-introduction-must-fail.ahl",
        receipt: Spec {
            claim_type: "trigger-declared",
            subject_index: 36,
            anchor: cp37,
            chain: vec![0, 25],
            record_subject: scores(&r.c_a),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "introduction": introduction(1, &r.c_a, cp37),
            }),
            producer_keys: None,
            note: "MUST FAIL. The retraction at entry 36 names the `scores` dataset with record \
                   A's `customers` commitment, so its `record_subject` is `scores`/A. The \
                   embedded introduction is the genuine ingestion at entry 1, which introduces \
                   `customers`/A: same commitment string, different dataset. Every other check \
                   passes — the introduction receipt verifies in full, it is anchored at a \
                   smaller entry index than the trigger, and the trigger's own envelope and \
                   inclusion are real. I-D §2.4.2 makes identity the `(dataset, record)` pair \
                   and §7.6 requires each embedded receipt's `record_subject` to match the \
                   referencing material, so this introduction establishes who may retract a \
                   DIFFERENT record and grounds nothing about this one."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §2.4.2 / §7.6 — the embedded introduction must match the trigger on \
                   BOTH dataset and record",
            matches: |e| {
                matches!(e, ReceiptError::EmbeddedSubjectMismatch { what: "introduction", .. })
            },
        },
    });

    out.push(Vector {
        file: "trigger-declared-cross-dataset-replacement-must-fail.ahl",
        receipt: Spec {
            claim_type: "trigger-declared",
            subject_index: 35,
            anchor: cp37,
            chain: vec![0, 25],
            record_subject: customers(&r.c_a),
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({
                "introduction": introduction(1, &r.c_a, cp37),
                // S1 is introduced by the unbatched derivation at entry 3, in `scores`.
                "replacement_introduction": Spec {
                    claim_type: "record-derived",
                    subject_index: 3,
                    anchor: cp37,
                    chain: vec![0, 25],
                    record_subject: scores(&r.s1),
                    competing: "not-checked",
                    content_binding: "none",
                    currency_mode: "declared",
                    currency_material: json!({}),
                    claim_material: json!({
                        "output": { "dataset": DS_SCORES, "record": r.s1 },
                    }),
                    producer_keys: None,
                    note: "Embedded introduction proof for S1, a `scores` record produced by \
                           the derivation at entry 3."
                        .to_owned(),
                }
                .build(corpus, keys),
            }),
            producer_keys: None,
            note: "MUST FAIL. The correction at entry 35 corrects `customers`/A to S1. A \
                   correction carries ONE `dataset` (I-D §2.4.3), covering both members, so it \
                   is claiming `customers`/S1 as the replacement. The embedded \
                   `replacement_introduction` proves `scores`/S1 — the same commitment string \
                   under the dataset that actually produced it. The trigger's own introduction \
                   proof matches on both members and passes, which is what isolates the \
                   replacement rule: only the second reference disagrees, and only on the \
                   dataset. Under I-D §7.6's \"correction to replacement introduction\" this \
                   is invalid, because the record the correction promotes and the record the \
                   embedded receipt introduces are not the same record."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §2.4.3 / §7.6 — the replacement introduction must match the \
                   correction's dataset as well as its replacement commitment",
            matches: |e| {
                matches!(
                    e,
                    ReceiptError::EmbeddedSubjectMismatch { what: "replacement introduction", .. }
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
        chain: vec![0],
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
            chain: vec![0],
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

    // Two NON-VERIFYING triggers on F, at entries 32 and 33: entry 32's `signatures[0].key_id`
    // names `producer-1`'s real key — the genuine `customers` authority — but `sig` is garbage,
    // and entry 33 pairs a genuine `producer-2` signature with a second entry naming the
    // authority whose `sig` is likewise garbage. Both are competing candidates for record F,
    // and I-D §7.2 requires every competing candidate's envelope to be verified under §2.1
    // BEFORE authority is compared, with §7.5.1 4d making failure `invalid` for the run.
    out.push(Vector {
        file: "trigger-effective-void-candidate.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 29,
            anchor: cp34,
            chain: vec![0, 25],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 34, cp34),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp34),
                "checkpoint_C": cp34.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 34, cp34) },
            }),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 28),
            ]),
            note: "The subject — the genuinely co-signed retraction at entry 29 — is \
                   impeccable, and so is every proof here: the enumeration is complete over \
                   [0, 34), the competing range is the introduction-fixed [20, 34), and the \
                   range proofs open cp34's root. The competing set carries two entries that do \
                   NOT verify: entry 32's sole signature names `producer-1`'s real key_id — the \
                   `customers` authority — with `sig` bytes that key never produced, and entry \
                   33 pairs a genuine `producer-2` signature with a second entry naming the \
                   authority whose `sig` likewise does not verify (I-D §2.1: a verifier MUST \
                   NOT accept a subset). Neither is an envelope this receipt RESTS on, so \
                   §7.5.1 4d makes each VOID rather than a defect: \"excluded before any \
                   authority comparison... never effective and never traversed\", reported as \
                   an informative item naming its entry index (§7.7), and never a challenge \
                   (4e). The genuinely co-signed trigger at entry 29 therefore governs, and the \
                   receipt verifies. The reason 4d gives is the log contract: a log anchors \
                   opaque bytes and validates none, so were a void entry a defect of every \
                   later receipt, anyone able to anchor one envelope could disable every \
                   enumerated claim of that log from that index on."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // Entry 33: the SUBJECT of its own `trigger-effective` claim carries two signature
    // entries — one genuinely valid, cryptographically-signed entry from `producer-2` (not the
    // `customers` authority) and one naming `producer-1`'s real key_id — the genuine
    // `customers` authority — whose `sig` does not verify. A verifier that name-matched the
    // authority's `key_id` among the signers without checking that entry's own signature would
    // be fooled into treating this as authorized; instead, I-D §7.5.1 4d requires EVERY
    // signature entry on the subject's own envelope to verify before any claim-specific logic
    // runs at all, so this entry is rejected outright and never even reaches the
    // claim-specific trigger-authority check.
    out.push(Vector {
        file: "trigger-effective-unverified-authority-signature-must-fail.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 33,
            anchor: cp34,
            chain: vec![0, 25],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 34, cp34),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp34),
                "checkpoint_C": cp34.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 34, cp34) },
            }),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 31),
            ]),
            note: "MUST FAIL. Entry 33's own envelope carries two signature entries: \
                   `signatures[0]` is a genuine, cryptographically valid signature from \
                   `producer-2`, who is an active producer key from entry 31 onward but is not \
                   the `customers` dataset authority; `signatures[1].key_id` correctly names \
                   `producer-1`'s real key_id — the genuine authority — but `signatures[1].sig` \
                   does not verify against that key's actual public key. I-D §7.5.1 4d requires \
                   every signature entry on the subject's own envelope to verify and forbids \
                   accepting a subset; naming the authority's key_id is not enough when that \
                   entry's own signature does not verify, so this envelope cannot ground any \
                   claim, let alone one asserting it is an effective trigger."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4d — every subject envelope signature entry must verify",
            matches: |e| matches!(e, ReceiptError::EnvelopeSignatureInvalid { entry_index: 33 }),
        },
    });

    // Entry 29: a trigger on F CO-SIGNED by both the `customers` authority (`producer-1`) and
    // a second, genuinely active producer key (`producer-2`, re-added by the `key` statement
    // at entry 28). Receipt format §5 step 3a states the two-step model precisely: envelope
    // validity (EVERY entry resolves to an active key and verifies) is a separate, EARLIER
    // test from authorization (at least one of those verified signers is the authority). A
    // trigger is authorized when signed BY the record's authority, not signed EXCLUSIVELY by
    // authority keys — so this legitimately co-signed envelope must still classify as
    // authorized and must still govern.
    out.push(Vector {
        file: "trigger-effective-co-signed-by-authority.ahl",
        receipt: Spec {
            claim_type: "trigger-effective",
            subject_index: 29,
            anchor: cp30,
            chain: vec![0, 25],
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
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 28),
            ]),
            note: "Proves that a trigger CO-SIGNED by both the `customers` dataset authority \
                   (`producer-1`) and another active producer key (`producer-2`, re-added at \
                   entry 28) is authorized and governs F at cp30. Every signature entry on \
                   entry 29's envelope cryptographically verifies against a producer key active \
                   at entry index 29 (receipt §5 step 3a's envelope-validity test), and at \
                   least one of them — `producer-1`'s — is the record's authority (the \
                   authorization test), so the extra, genuinely valid co-signature from \
                   `producer-2` does not disqualify it: core spec §2.3.3 requires a trigger to \
                   be signed BY the authority, never signed EXCLUSIVELY by authority keys. The \
                   checkpoint stops at tree size 30 because the two deliberately non-verifying \
                   fixtures sit at entries 32 and 33, and I-D §7.5.1 4d refuses any enumeration \
                   that reaches them."
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
            chain: vec![0],
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
            // The `key` statement at entry 9 is inside the enumerated range, which is how a
            // verifier receives it (I-D §7.4); the chain carries manifests only.
            chain: vec![0],
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
        chain: vec![0],
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
        // The `key` statements at entries 9 and 28 are inside the enumerated range, which is
        // how a verifier receives them (I-D §7.4); the chain carries manifest v2 and genesis.
        chain: vec![0, 25],
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

    // I-D §7.5.1 4d, on a propagation prefix: "an entry of a propagation prefix" is named among
    // the carried envelopes a receipt does NOT rest on, and §2.1 adds that a void entry is
    // "never traversed by closure". The two vectors below are the same claim over two prefixes
    // that differ by exactly one envelope's signature.
    let f_trigger = |note: &str| {
        Spec {
            claim_type: "trigger-effective",
            subject_index: 29,
            anchor: cp34,
            chain: vec![0, 25],
            record_subject: customers(&r.c_f),
            competing: "enumerated",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 34, cp34),
            claim_material: json!({
                "introduction": introduction(20, &r.c_f, cp34),
                "checkpoint_C": cp34.checkpoint,
                "competing": { "corpus_range": corpus.enumeration(20, 34, cp34) },
            }),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 28),
            ]),
            note: note.to_owned(),
        }
        .build(corpus, keys)
    };
    let f_prefix_roots: Vec<&String> = vec![
        &corpus.batch_root,
        &corpus.wide_outputs_root,
        &corpus.input_set_root,
        &corpus.challenge_affected_root,
    ];

    out.push(Vector {
        file: "propagation-complete-void-prefix-entry.ahl",
        receipt: Spec {
            claim_type: "propagation-complete",
            subject_index: 44,
            anchor: cp45,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 45, cp45),
            claim_material: json!({
                "corpus_checkpoint": cp38.checkpoint,
                "corpus_prefix": corpus.enumeration(0, 38, cp45),
                "trees": trees_block(&f_prefix_roots, false),
                "trigger": f_trigger(
                    "Embedded trigger-effective proof for the retraction of record F at entry \
                     29, bounded by cp34.",
                ),
            }),
            producer_keys: None,
            note: "The propagation at entry 44 anchors the affected set of the retraction of \
                   record F at entry 29, complete at its own declared checkpoint D — cp38, tree \
                   size 38. That prefix REACHES entry 37: a derivation of a `scores` record \
                   from H, which is itself the derived record the trigger reaches, carrying a \
                   `sig` no key produced. I-D §2.1 makes it void and §7.5.1 4d says what a void \
                   entry costs a receipt that does not rest on it — \"an entry of a propagation \
                   prefix\" is named there among the carried envelopes reliance excludes: it is \
                   \"never effective and never traversed\", so the closure recomputed here has \
                   one member and not two, and the disposition tree the producer anchored agrees \
                   with it. Positions are preserved rather than dropped — an entry index IS a \
                   position in the prefix — and the prefix's own root is recomputed over the \
                   CARRIED bytes, since voiding is about traversal and not about what the log \
                   anchored. Its entry index is reported as an informative item beside the four \
                   other void entries in range, and the result is `verified`. \
                   `propagation-complete-void-prefix-entry-control-must-fail.ahl` is the same \
                   claim over a prefix that reaches the verifying copy of that derivation."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    out.push(Vector {
        file: "propagation-complete-void-prefix-entry-control-must-fail.ahl",
        receipt: Spec {
            claim_type: "propagation-complete",
            subject_index: 45,
            anchor: cp46,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 46, cp46),
            claim_material: json!({
                "corpus_checkpoint": cp44.checkpoint,
                "corpus_prefix": corpus.enumeration(0, 44, cp46),
                "trees": trees_block(&f_prefix_roots, false),
                "trigger": f_trigger(
                    "Embedded trigger-effective proof for the retraction of record F at entry \
                     29, bounded by cp34.",
                ),
            }),
            producer_keys: None,
            note: "MUST FAIL, and it is the control that makes \
                   `propagation-complete-void-prefix-entry.ahl` mean something. The propagation \
                   at entry 45 anchors the SAME affected set for the SAME trigger, and declares \
                   D at cp44 instead of cp38. Entry 43 is inside that prefix: byte for byte the \
                   payload anchored at entry 37, genuinely signed this time, so §2.1's \
                   first-wins rule leaves it governing — a void entry never becomes a governing \
                   statement and so occupies no statement id. The closure recomputable at this D \
                   therefore has two members, the anchored disposition tree still has one, and \
                   the completeness claim is `invalid` on `claim-material`. The only difference \
                   between the two receipts' prefixes is which envelope over that payload they \
                   reach, which is what shows the exclusion at cp38 to be the signature's doing \
                   rather than an artifact of prefix length."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "spec §5.3 / receipt §3 — the anchored affected set must equal the closure \
                   recomputed at D",
            matches: |e| matches!(e, ReceiptError::ClosureMismatch(_)),
        },
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
            chain: vec![0, 25],
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
            chain: vec![0],
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
        chain: vec![0, 25],
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

    // The same claim over a range that reaches the two non-verifying fixtures. Nothing here is
    // a competing candidate — `governance-state` compares no authority at all and applies no
    // trigger filter — so this is the general form of the rule: enumerated material is
    // verified envelope by envelope, whatever each envelope happens to say.
    out.push(Vector {
        file: "governance-state-void-entry.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp34,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 34, cp34),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "The claim is the one `governance-state-valid.ahl` proves — manifest version \
                   2 is the governance state active at entry index 26 — over a range that \
                   REACHES two entries which do not verify. §4 fixes enumerated material at \
                   exactly [0, tree_size(C)), and at cp34 that prefix reaches entries 32 and 33, \
                   the two deliberately non-verifying retractions of record F. I-D §7.5.1 4d \
                   requires every carried envelope to be verified at its own entry index, and \
                   decides what a failure MEANS by reliance: neither entry is one this receipt \
                   rests on — not its subject, not an embedded subject, not a \
                   `governance.chain[]` element — so each is VOID and reported as an \
                   informative item (§7.7), the result is unaffected, and the governance claim \
                   stands. §7.4 says the same from the currency side: enumerated material proves \
                   the presented statements are \"the only VERIFYING manifest and key entries in \
                   that range\", and a void entry \"is not a governance statement and its \
                   absence from the chain is not an omission\". What the range proof still \
                   guarantees is completeness: nothing is hidden by voiding, since the void \
                   entries are enumerated and reported by index."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // The same rule where the void entries are PURPORTED GOVERNANCE STATEMENTS — the case 4b
    // states in its own words rather than leaving to 4d.
    out.push(Vector {
        file: "governance-state-void-governance-entries.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp40,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 40, cp40),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "The claim of `governance-state-valid.ahl` over a range that reaches TWO \
                   purported governance statements neither the chain carries nor any key \
                   vouches for: a `key` statement at entry 38 and a manifest version at entry \
                   39, each well formed and each carrying a `sig` no key ever produced. I-D \
                   §7.5.1 4b selects an enumeration-only entry for the walk \"by its purported \
                   `type`, but it ENTERS the induction only if its envelope verifies in phase \
                   1\": neither does, so both are VOID — \"not inducted, no effect on K, the \
                   walk continues past it\" — and §7.5 step 1 exempts a non-verifying \
                   enumeration-only entry from the version read and from every type-specific \
                   check, so nothing about their payloads is ever validated. §7.4 closes the \
                   other half: enumerated currency proves the presented statements are \"the \
                   only VERIFYING manifest and key entries in that range\", so the void \
                   manifest at 39 is not an omission from `governance.chain[]` however much it \
                   looks like one. Four void entries are reported as informative items (§7.7) — \
                   32, 33, 37, 38, 39 — and the governance claim stands."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // A void entry occupies no statement id, so a LATER verifying copy of the same statement is
    // inducted and its effect applied.
    out.push(Vector {
        file: "statement-anchored-void-then-verifying-key.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 42,
            anchor: cp43,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 43, cp43),
            claim_material: json!({}),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 41),
            ]),
            note: "The subject at entry 42 is an ingestion signed by `producer-2`, and the only \
                   thing that puts that key in force at index 42 is the `key` statement at entry \
                   41. Entry 40 retired it first, and entry 41 is BYTE-FOR-BYTE the statement \
                   already anchored at entry 38 — where its envelope does not verify. I-D §2.1's \
                   first-wins rule is about GOVERNING statements, and §7.5.1 4b admits an \
                   enumeration-only entry to the induction \"only if its envelope verifies in \
                   phase 1\": the void copy at 38 governs nothing and occupies nothing, so the \
                   verifying copy at 41 is inducted and its effect applied. A verifier that \
                   claimed the statement id when it voided the first copy would skip the second \
                   as a duplicate, leave `producer-2` retired, and reject this receipt's subject \
                   envelope. Five void entries are reported as informative items — 32, 33, \
                   37, 38 and 39 — and none of them changes the result."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // I-D §2.1's own case, end to end: ONE manifest version under three signature sets, so one
    // statement id over three entry ids. The chain carries the governing copy at entry 46 and
    // the verifying duplicate at 47; the duplicate governs nothing and is still verified, since
    // §7.5 step 4 says "verify EVERY CARRIED ENVELOPE".
    let duplicate_manifest_keys = || Some(vec![key_entry(&keys.producer_1, None, 46)]);
    out.push(Vector {
        file: "statement-anchored-duplicate-manifest.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 49,
            anchor: cp50,
            chain: vec![0, 25, 46, 47],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: duplicate_manifest_keys(),
            note: "Manifest version 3 is anchored THREE times — entries 46, 47 and 48 — because \
                   the statement id digests the payload alone while the entry id digests the \
                   envelope, so one payload under three signature sets is one statement with \
                   three entry ids. Entry 46 carries `producer-1`'s signature, entry 47 that \
                   signature and `producer-2`'s beside it. I-D §2.1: \"the envelope with the \
                   smallest entry index governs and later ones are void\", so entry 46 is the \
                   version this receipt's subject resolves through and entry 47 applies no \
                   effect, consumes no rotation proof and never becomes the version a \
                   `subject.manifest` reference names. It is still a `governance.chain[]` \
                   element, which I-D §7.5.1 4d counts among the envelopes a receipt RESTS ON, \
                   so it is verified at its own entry index under the completed key state — and \
                   because it VERIFIES, it produces no finding and no informative item: an \
                   informative item reports a void entry the run inspected and found wanting, \
                   which this is not. The subject at entry 49 is an ordinary ingestion bound to \
                   version 3."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    out.push(Vector {
        file: "statement-anchored-duplicate-manifest-unsigned-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 49,
            anchor: cp50,
            chain: vec![0, 25, 46, 48],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: duplicate_manifest_keys(),
            note: "MUST FAIL. The same chain as `statement-anchored-duplicate-manifest.ahl` with \
                   the third envelope of manifest version 3 in place of the second: entry 48 \
                   carries the identical payload with a `sig` no key produced. Being void under \
                   §2.1 does not exempt it — §7.5 step 4 requires every carried envelope to \
                   verify, and §7.5.1 4d puts a `governance.chain[]` element among the three \
                   kinds of envelope a receipt rests on, so a failure there is `invalid` rather \
                   than the informative item a non-relied void entry earns. The governing copy \
                   at entry 46 is present and verifies, and that is deliberately not enough: a \
                   verifier that skipped a duplicate WHOLE, instead of skipping only its effect, \
                   would accept an unsigned envelope the receipt itself presents as its lineage."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5 step 4 / §7.5.1 4d — a void duplicate chain hop is still a carried \
                   envelope the receipt rests on",
            matches: |e| matches!(e, ReceiptError::EnvelopeSignatureInvalid { entry_index: 48 }),
        },
    });

    // The same duplicate under ENUMERATED currency, where §7.5.1 4c asks a different question:
    // not which copy governs, but whether the chain shows every manifest the range reveals.
    out.push(Vector {
        file: "governance-state-duplicate-manifest.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 46,
            anchor: cp50,
            chain: vec![0, 25, 46, 47],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 50, cp50),
            claim_material: json!({ "target_index": 46 }),
            producer_keys: Some(vec![
                key_entry(&keys.producer_1, None, 25),
                key_entry(&keys.producer_2, None, 41),
            ]),
            note: "Manifest version 3 is the governance state at its own entry index, proven \
                   over a range that carries the version TWICE. The two questions §7.5.1 asks \
                   about a duplicate are answered differently on purpose. The induction (4b) \
                   claims the statement id once, at the smallest entry index, so entry 47 \
                   applies no effect. Completeness (4c) asks whether `governance.chain[]` shows \
                   every manifest the range reveals, and both envelopes ARE manifests the range \
                   reveals and both verify, so both must be carried — a chain that showed only \
                   the governing copy would be short of an entry the enumeration proves is \
                   there. The third envelope at entry 48 does not verify, so §7.4's rule that \
                   \"a void entry is not a governance statement and its absence from the chain \
                   is not an omission\" exempts it, and it is reported as an informative item \
                   with the five other void entries the range reaches."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // A carried statement of a revision this document does not define that is NOT a governance
    // statement: it takes no rule of this document at all, and it stops nothing.
    out.push(Vector {
        file: "governance-state-foreign-revision-entry-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp52,
            chain: vec![0, 25, 46, 47],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 52, cp52),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "MUST NOT VERIFY, and not for a defect. The range reaches entry 51: an \
                   INGESTION, genuinely signed by `producer-1`, declaring `ahl_version: \
                   \"0.5\"`. I-D §7.1 settles what that is worth: a carried statement's \
                   unsupported `ahl_version` \"is `unverifiable` as for any carried statement\", \
                   and §7.5 step 1 reserves \"no further processing\" for the RECEIPT's own \
                   `ahl_receipt_version`. So the entry is set aside rather than validated under \
                   rules this document does not have — not a competing candidate, never \
                   traversed by a closure, on the same footing as a void entry — and it is \
                   reported as a FINDING rather than an informative item, because unlike a void \
                   entry it is not a fact about the artifact: a verifier of that revision could \
                   read it. It is not a governance statement, so it leaves K alone: the walk \
                   completes and the range's own governance claim is untouched. What makes the \
                   result `unverifiable` is the finding itself, and a later `invalid` would \
                   still dominate it (§7.7)."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.1 — a carried statement of an unsupported revision is unverifiable, \
                   not the end of the run",
            matches: |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_version", .. }),
        },
    });

    // A `governance.chain[]` hop of a revision this document does not define: the walk stops
    // there with the prefix state it has established, and the receipt's own subject — anchored
    // below the stop — is still verified against it.
    out.push(Vector {
        file: "statement-anchored-foreign-revision-chain-hop-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 26,
            anchor: cp54,
            chain: vec![0, 25, 46, 52],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST NOT VERIFY, and not for a defect. The chain carries three hops: the \
                   genesis manifest, version 2 at entry 25, and the manifest at entry 52 — \
                   genuinely signed by `producer-1`, and declaring `ahl_version: \"0.5\"`. I-D \
                   §7.5.1 4b: such a hop \"is not inducted, K is unestablished at and after its \
                   index, the governance finding is `unverifiable`\". The walk therefore stops \
                   at entry 52 having ESTABLISHED the prefix state — genesis and version 2 — \
                   which is what the subject at entry 26 is verified against, and every check \
                   that would need a key at or after 52 rests on `governance` instead. The \
                   hop VERIFIES, which is what the rule is about — \"A VERIFYING purported \
                   governance entry\" — so phase 1 has already passed by the time the revision \
                   is acted on, and what an unsupported one costs is this finding rather than \
                   the end of the run: \"the scalar result is reduced under Section 7.7 — a \
                   later required `invalid` still dominates\"."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b / §7.1 — a chain hop of an unsupported revision leaves K \
                   unestablished from its index",
            matches: |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_version", .. }),
        },
    });

    // The same hop, unsigned: a chain element's phase-1 failure is `invalid` whatever revision
    // it declares.
    out.push(Vector {
        file: "statement-anchored-broken-foreign-revision-chain-hop-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 26,
            anchor: cp55,
            chain: vec![0, 25, 46, 54],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST NOT VERIFY, for a DEFECT. The last hop is the manifest at entry 54: \
                   well formed, declaring `ahl_version: \"0.5\"` exactly as the hop at entry 52 \
                   does, and carrying a signature that does not verify. I-D §7.5.1 4b orders \
                   these two rules: \"A `governance.chain[]` element is different: the receipt \
                   presents it as its own lineage, so its phase-1 failure is `invalid`\", and \
                   the foreign-revision rule that follows applies to \"A VERIFYING purported \
                   governance entry\". So phase 1 settles this hop first and the receipt is \
                   `invalid` on `governance`. A verifier that read the revision member first \
                   would report a broken lineage as its own capability gap, and a receipt could \
                   hide any unsigned chain element behind a version it made up."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b — a chain element's phase-1 failure is invalid, whatever \
                   revision it declares",
            matches: |e| matches!(e, ReceiptError::EnvelopeSignatureInvalid { entry_index: 54 }),
        },
    });

    // The manifest analogue of the foreign-revision `key` statement: a different path through
    // the verifier — completeness (4c) rather than the induction (4b) — and the same outcome.
    out.push(Vector {
        file: "governance-state-foreign-revision-manifest-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp53,
            chain: vec![0, 25, 46, 47],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 53, cp53),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "MUST NOT VERIFY, and not for a defect. The range reaches entry 52: a manifest \
                   version genuinely signed by `producer-1`, absent from `governance.chain[]`, \
                   and declaring `ahl_version: \"0.5\"`. A verifier that checked completeness \
                   before revision would call that absence an omission and report `invalid` — a \
                   defect of the receipt — when what it has found is a statement of a revision \
                   this document does not define. I-D §7.5.1 4b settles it: such an entry \"is \
                   not inducted, K is unestablished at and after its index, the governance \
                   finding is `unverifiable`\". §7.4's omission rule reaches VERIFYING manifest \
                   entries of THIS revision, and this is not one."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b / §7.4 — a verifying governance entry of an unsupported \
                   revision is not an omission",
            matches: |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_version", .. }),
        },
    });

    // And the entry that VERIFIES while declaring a revision this document does not define.
    out.push(Vector {
        file: "governance-state-foreign-revision-key-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp54,
            chain: vec![0, 25, 46, 47],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 54, cp54),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "MUST NOT VERIFY, and not for a defect. The range reaches the `key` statement \
                   at entry 53: genuinely signed by `producer-1`, and declaring \
                   `ahl_version: \"0.5\"`. I-D §7.5.1 4b: \"A VERIFYING purported \
                   governance entry that declares an `ahl_version` this revision does not define \
                   is neither: it is not inducted, K is unestablished at and after its index, \
                   the governance finding is `unverifiable` (Section 2.2), every K-dependent \
                   check at or after that index rests on it, and the scalar result is reduced \
                   under Section 7.7 — a later required `invalid` still dominates.\" The \
                   signature is what separates this from entries 38 and 39: a statement no key \
                   vouches for is void and costs the run nothing, while one a key DOES vouch \
                   for, in a revision this verifier cannot interpret, is material it cannot \
                   read past. The two void entries at 32 and 33 are still reported as \
                   informative items."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4b / §2.2 — a verifying governance entry of an unsupported \
                   revision leaves K unestablished from its index",
            matches: |e| matches!(e, ReceiptError::UnsupportedVersion { field: "ahl_version", .. }),
        },
    });

    // The other side of the same rule: an enumerated range that reaches a `key` statement
    // RETIRING ITS OWN SIGNING KEY must still be accepted. I-D §7.5.1 4d scopes the
    // remaining-envelope check to "every carried envelope that is NOT part of the induction",
    // and 4b verifies a governance statement "against K AS ESTABLISHED SO FAR — the governance
    // state in force immediately before this statement's own entry index" before applying its
    // effect. Entry 30 retires `producer-2` under `producer-2`'s own signature, which is
    // conforming on those terms; a verifier that re-checked it under the COMPLETED key state at
    // its own index would resolve the key after its own retirement and reject it.
    out.push(Vector {
        file: "governance-state-self-retiring-key.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp32,
            chain: vec![0, 25],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 32, cp32),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "Proves that manifest version 2 is the governance state active at entry index \
                   26 over an enumerated prefix that REACHES a self-retiring `key` statement. \
                   The §4 material enumerates exactly [0, 32) — the whole prefix of cp32 — and \
                   entry 30 in it retires `producer-2` under `producer-2`'s own signature, with \
                   entry 31 re-adding the key afterwards. Both are induction members: I-D \
                   §7.5.1 4b verifies each against the key state in force immediately BEFORE \
                   its own entry index and applies its effect only afterwards, and 4d's \
                   remaining-envelope check covers \"every carried envelope that is NOT part of \
                   the induction\". A verifier that re-verified entry 30 under the completed \
                   key state at index 30 would resolve `producer-2` after its own retirement \
                   had taken effect and reject a statement the induction accepted, so this \
                   receipt separates the two key states 4b keeps apart."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Accept,
    });

    // I-D §7.1's container shape for `governance.chain[]`, from the other side: an element
    // that is not a manifest statement at all.
    out.push(Vector {
        file: "governance-chain-key-statement-element-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 3,
            anchor: cp20,
            chain: vec![0, 9],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST FAIL. The chain carries the genuine `key` statement anchored at entry \
                   9 as a second element: real envelope, real signature by a producer key in \
                   force at that index, real inclusion path to cp20's root. I-D §7.1 defines \
                   each `governance.chain[]` element as \"an anchored manifest statement's \
                   complete envelope\", and §7.4 says where the other governance type travels: \
                   \"`governance.chain[]` carries manifest statements; producer-key \
                   transitions are `key` statements, and those reach a verifier only through \
                   enumeration material.\" A chain that carries one anyway is a container the \
                   format does not define, and a verifier that walked it would let the chain \
                   be a second, unenumerated carrier for key transitions — the exact omission \
                   the enumerated range proof exists to foreclose. The type is read only after \
                   the element's own signature has verified, so the refusal never rests on \
                   bytes no key vouches for."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.1 / §7.4 — every governance.chain[] element is a manifest statement",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail)
                    if detail.contains("carries a `key` statement at entry index 9"))
            },
        },
    });

    // The completeness rule of I-D §7.5.1 4c, in the one direction enumerated mode still has
    // to police once `key` statements are the induction's own second stream: a MANIFEST the
    // range reveals but the chain does not carry.
    out.push(Vector {
        file: "governance-enumerated-manifest-omitted-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 25,
            anchor: cp28,
            chain: vec![0],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "enumerated",
            currency_material: corpus.enumeration(0, 28, cp28),
            claim_material: json!({ "target_index": 26 }),
            producer_keys: None,
            note: "MUST FAIL. Everything `governance-state-valid.ahl` carries is here except \
                   manifest version 2's own chain element, and the enumeration over [0, 28) \
                   proves that version 2 IS anchored at entry 25. I-D §7.5.1 4c: \"Under \
                   `enumerated` governance the range proof over exactly [0, tree_size(C)) \
                   forecloses omission, so K at each index IS the state that was in force\" — \
                   which it can only be if the induction walked every manifest the range \
                   reveals. Accepting this would report a key state derived from the genesis \
                   snapshot as the state active at entry 26, when a manifest the receipt \
                   itself proves anchored had already replaced it in full."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4c — the chain carries every manifest the enumerated range \
                   reveals",
            matches: |e| {
                matches!(e, ReceiptError::GovernanceChainInvalid(detail)
                    if detail.contains("`manifest` statement at entry index 25 that the presented chain omits"))
            },
        },
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
                chain: vec![0],
                record_subject: None,
                competing: "not-checked",
                content_binding: "none",
                currency_mode: "enumerated",
                currency_material: corpus.enumeration(0, 20, cp20),
                claim_material: json!({ "target_index": 15 }),
                producer_keys: None,
                note: "MUST FAIL. `governance.rotation_proofs` is present (as an empty array) \
                       even though this chain — the genesis manifest alone — rotates neither \
                       the log nor the witness key set. I-D §7.1: \"The \
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
                // A key from OUTSIDE the outgoing log set that is not the incoming one either.
                // `governance-key-rotation-proof-incoming-log-key-must-fail.ahl` covers the
                // incoming key itself, over the log rotation at manifest entry index 55; this
                // vector is kept beside it because the two substitutions are different facts —
                // one rules out any non-member of the outgoing set, the other rules out
                // specifically the key the rotation installs.
                proofs[0]["checkpoint"]["key_id"] = json!(keys.witness_1.key_id());
                proofs[0]["checkpoint"]["signature"] = json!(keys.witness_1.sign(
                    &checkpoint_signing_bytes(&proofs[0]["checkpoint"]).expect("checkpoint")
                ));
            },
            "MUST FAIL. The element's `checkpoint` is re-signed by a key that is not a log key \
             of the OUTGOING state at manifest entry index 25. What it rules out is any \
             non-member of that set; the INCOMING key specifically — \"exactly the key an \
             attacker installs, whereas the exception accepts only the key being retired\" (I-D \
             §7.1) — is ruled out by \
             `governance-key-rotation-proof-incoming-log-key-must-fail.ahl`, over the log \
             rotation at entry 55, where the corpus has a genuine second log key to substitute.",
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

    // --- the LOG checkpoint-signing key rotation (manifest v4, entry 55) ---------------
    // I-D §7.1 detects a governance-key rotation by comparing a manifest's log key objects and
    // its witness key objects, as sets, with its predecessor's. Manifest v2 rotates the WITNESS
    // set; manifest v4 rotates the LOG set and nothing else, so a chain carrying both needs two
    // `rotation_proofs[]` elements in ascending `manifest_entry_index` order, each proving its
    // own manifest's anchoring under the state that manifest retires.
    let log_rotation_valid = Spec {
        claim_type: "statement-anchored",
        subject_index: 56,
        anchor: cp57,
        chain: vec![0, 25, 46, 55],
        record_subject: None,
        competing: "not-checked",
        content_binding: "none",
        currency_mode: "declared",
        currency_material: json!({}),
        claim_material: json!({}),
        producer_keys: None,
        note: "Manifest version 4, at entry 55, replaces `log-1` with `log-2` in `log.keys` and \
               changes nothing else — the witness set and the producer snapshot are version 3's. \
               That makes it a governance-key rotation on the LOG side, and I-D §7.5.1 4b(M) \
               asks for the same thing it asks of the witness rotation at entry 25: a \
               `governance.rotation_proofs[]` element proving the rotating manifest's own \
               anchoring under the state it retires. Its checkpoint is cp56 — tree size 56, so \
               it commits entry 55 — signed by the OUTGOING log key `log-1` and cosigned under \
               the OUTGOING witness set, which is the ordinary artifact §7.1 describes: an \
               operator that anchors the rotating manifest and keeps signing under the retiring \
               key until cutover. The chain carries two rotations, so the member carries two \
               elements in ascending `manifest_entry_index` order, and `keys.log[]` lists \
               `log-1` three times under three bindings — the genesis version for the first \
               rotation's outgoing state, version 3 for the second's, and version 4's `log-2` \
               for this receipt's own checkpoint cp57. §7.5.1 4f is what makes cp57 resolve to \
               `log-2`: the signing key comes from the manifest version active for the \
               checkpoint's own tree size, not from whichever version the receipt happens to \
               anchor its subject under."
            .to_owned(),
    }
    .build(corpus, keys);
    out.push(Vector {
        file: "statement-anchored-log-key-rotation.ahl",
        receipt: log_rotation_valid.clone(),
        expect: Expect::Accept,
    });

    out.push(Vector {
        file: "governance-key-rotation-proof-incoming-log-key-must-fail.ahl",
        receipt: rotation_proof_case(
            &log_rotation_valid,
            |proofs| {
                proofs[1]["checkpoint"]["key_id"] = json!(keys.log_2.key_id());
                proofs[1]["checkpoint"]["signature"] = json!(keys.log_2.sign(
                    &checkpoint_signing_bytes(&proofs[1]["checkpoint"]).expect("checkpoint")
                ));
            },
            "MUST FAIL. The rotation proof for manifest v4 is re-signed by `log-2` — the \
             INCOMING log key, the one this very rotation installs. I-D §7.1: \"a checkpoint \
             signed by the INCOMING key... is exactly the key an attacker installs, whereas the \
             exception accepts only the key being retired\". This is the genuine form of that \
             substitution: the corpus now has a second log key, so the check no longer has to \
             stand in a witness key for one.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — the rotation-proof checkpoint must verify under a log key of the \
                   OUTGOING state",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 55, .. })
            },
        },
    });

    out.push(Vector {
        file: "governance-key-rotation-proofs-out-of-order-must-fail.ahl",
        receipt: rotation_proof_case(
            &log_rotation_valid,
            |proofs| proofs.as_array_mut().expect("rotation_proofs array").swap(0, 1),
            "MUST FAIL. The two elements are correct in every member and carried in the wrong \
             order: the rotation at entry 55 first, the one at entry 25 second. I-D §7.1 fixes \
             the order — \"one element per rotation, in ascending `manifest_entry_index` \
             order\" — because the induction consumes the NEXT unconsumed element when it \
             detects a rotation, so an out-of-order pair offers each rotation the other's proof.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — rotation_proofs[] elements are in ascending manifest_entry_index \
                   order",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, .. })
            },
        },
    });

    out.push(Vector {
        file: "governance-key-rotation-proof-incoming-witness-must-fail.ahl",
        receipt: rotation_proof_case(
            &log_rotation_valid,
            |proofs| {
                let cp26 = &proofs[0]["checkpoint"];
                proofs[0]["witnesses"] = json!([ {
                    "witness_id": WITNESS_2,
                    "key_id": keys.witness_2.key_id(),
                    "cosignature": keys.witness_2.sign(&cosignature_bytes(cp26, WITNESS_2)),
                    "cosigned_at": T0,
                } ]);
            },
            "MUST FAIL. The witness-set rotation at entry 25 is cosigned by witness-2 — the \
             INCOMING witness, the one that rotation installs — with a genuine cosignature over \
             the right checkpoint. I-D §7.1 requires at least one element to verify under a \
             witness key of the OUTGOING state, and the outgoing state here is the genesis \
             manifest, which declares witness-1 alone. A cosignature by a witness the outgoing \
             manifest does not declare attests nothing about the handover, so it is passed over \
             rather than refused, and the element then has no qualifying cosignature at all.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 — AT L3, a rotation-proof element needs a cosignature under the \
                   OUTGOING witness set",
            matches: |e| {
                matches!(e, ReceiptError::RotationProofInvalid { manifest_entry_index: 25, detail }
                    if detail.contains("none did"))
            },
        },
    });

    out.push(Vector {
        file: "statement-anchored-outgoing-log-key-after-rotation-must-fail.ahl",
        receipt: Spec {
            claim_type: "statement-anchored",
            subject_index: 49,
            anchor: cp56,
            chain: vec![0, 25, 46, 55],
            record_subject: None,
            competing: "not-checked",
            content_binding: "none",
            currency_mode: "declared",
            currency_material: json!({}),
            claim_material: json!({}),
            producer_keys: None,
            note: "MUST FAIL. cp56 is a real, correctly signed checkpoint of this log — it is \
                   the very checkpoint the rotation proof for manifest v4 carries — and it is \
                   signed by `log-1`, the OUTGOING key. Its tree size is 56, so the manifest \
                   version active for it is v4 at entry 55, which declares `log-2` alone. I-D \
                   §7.5.1 4f resolves a checkpoint's signing key from the version active for \
                   ITS OWN tree size, so `log-1` binds to nothing here and the checkpoint cannot \
                   be authenticated. That a checkpoint is genuine, and even required elsewhere \
                   in the same receipt, is not a licence to anchor a subject under it after the \
                   key it carries has been retired."
                .to_owned(),
        }
        .build(corpus, keys),
        expect: Expect::Reject {
            rule: "I-D §7.5.1 4f — a checkpoint's log key comes from the manifest version \
                   active for its own tree size",
            matches: |e| matches!(e, ReceiptError::KeyNotBound { .. }),
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

    // --- the phase order itself (I-D §7.5.1 4b): two independent defects on one enumerated
    // `key` statement, and which one a verifier reports is the whole observable difference
    // between running the signature first and running the payload checks first.
    out.push(Vector {
        file: "governance-key-statement-unsigned-common-field-must-fail.ahl",
        receipt: key_statement_phase_order_case(
            corpus,
            &governance_state_valid,
            &m1,
            keys,
            "MUST FAIL, and NOT on the void entry. The `key` statement at entry index 9 \
             carries TWO independent defects: `signatures[0].sig` is garbage rather than a \
             signature `producer-1` ever produced, and the payload carries no `issued_at`. I-D \
             §7.5.1 4b enters an enumeration-only entry into the induction \"only if its \
             envelope verifies in phase 1\"; this one does not, so it is VOID — not inducted, \
             no effect on K, the walk continues — and §7.5 step 1 exempts it from the version \
             read and from §2.2's common fields entirely, so the missing `issued_at` is never \
             reached and cannot be what a verifier reports. What DOES fail is what this receipt \
             rests on: it lists `producer-2` in `keys.producer[]` bound to entry index 9, and \
             the void statement applied no effect, so that binding resolves against nothing. \
             The receipt is invalid on its own key listing (I-D §7.1), with the void entry \
             reported as an informative item (§7.7) beside it.",
        ),
        expect: Expect::Reject {
            rule: "I-D §7.1 / §7.5.1 4b — a key bound to a void governance statement resolves \
                   against nothing",
            matches: |e| matches!(e, ReceiptError::KeyNotBound { entry_index: 9, .. }),
        },
    });

    out.push(Vector {
        file: "governance-state-not-current-must-fail.ahl",
        receipt: Spec {
            claim_type: "governance-state",
            subject_index: 0,
            anchor: cp20,
            chain: vec![0],
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
            chain: vec![0, 25],
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
            chain: vec![0],
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

/// Replace corpus entry 9's `key` statement with a FRESH envelope carrying `key_extra`,
/// genuinely signed by `keys.producer_1` — the legitimate phase-1 signer at that entry index
/// (I-D §7.5.1: phase 1 verifies "against K as established so far", and producer-1 is already
/// in K by entry 9). This is deliberate: a mutation with no re-signing would fail phase 1
/// (`EnvelopeSignatureInvalid`) before phase 2's 4b(K) checks are ever reached, which is the
/// wrong rule for these vectors to exercise.
///
/// The substituted entry travels in the ENUMERATION material, which is where I-D §7.4 puts
/// producer-key transitions, so the whole log tree is rebuilt around it ([`Corpus::reanchor`]):
/// the range proof authenticates the enumerated entries against the checkpoint root before the
/// induction walks them, so an entry left at the corpus's own root would fail as unauthenticated
/// material rather than by the 4b(K) rule the vector names.
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
    bad["claim"]["note"] = json!(note);
    corpus.reanchor(&mut bad, &[(9, fresh)], keys);
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
    bad["claim"]["note"] = json!(note);
    corpus.reanchor(&mut bad, &[(9, fresh)], keys);
    bad
}

/// Like [`key_statement_common_field_case`], but the substituted entry-9 `key` statement is
/// defective TWICE OVER and independently: its payload carries no `issued_at` (I-D §2.2), and
/// its `sig` is replaced after signing with bytes `producer-1` never produced.
///
/// Neither defect causes the other — the payload is genuinely signed first, so the signature
/// would verify were it not overwritten, and the missing member would be reported were the
/// signature intact. That independence is the point: I-D §7.5.1 4b fixes which of the two a
/// conformant verifier reports.
fn key_statement_phase_order_case(
    corpus: &Corpus,
    base: &Value,
    manifest_id: &str,
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
    raw_payload.as_object_mut().expect("key statement payload").remove("issued_at");
    let mut fresh = envelope(raw_payload, &keys.producer_1);
    fresh["signatures"][0]["sig"] = json!(base64(&[0xAAu8; 64]));
    bad["claim"]["note"] = json!(note);
    corpus.reanchor(&mut bad, &[(9, fresh)], keys);
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
