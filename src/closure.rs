//! Revocation closure over an anchored statement graph (spec §5.1).
//!
//! For an effective trigger evaluated at a checkpoint `C` that commits it, the affected set is
//! the transitive closure over derivations with `entry index < tree_size(C)` whose inputs match
//! a closure **seed**, then their outputs' consumers, and so on, filtered by the trigger's
//! scope.
//!
//! Three rules of §5.1 and §2.3.3 shape the implementation:
//!
//! * **Identity.** Traversal keys on `(dataset, record)` only — `representation` and
//!   `projection` narrow what was consumed but never change identity (spec §2.3.2).
//! * **Scope.** `retroactive: true` affects every consuming derivation regardless of valid
//!   time; `retroactive: false` affects a derivation iff its `valid_time` intersects
//!   `[effective_from, ∞)`. Intersection is computed on parsed instants — see
//!   [`crate::bitemporal`].
//! * **Correction supersession.** A correction `X→Xnew` never adds its own replacement `Xnew`
//!   as a seed. Where a later correction of the same original `X` supersedes an earlier
//!   correction `X→Xold`, the later correction's seeds are `X` *and every prior superseded
//!   replacement* `Xold` — otherwise records derived from the intermediate replacement would
//!   silently escape the closure. A correction targeting `Xold` directly simply starts at
//!   `Xold`, which is the same rule with an empty supersession history.
//!
//! Post-trigger consumption is prohibited (§2.3.2), so a closure computed at any checkpoint
//! committing the trigger is stable: no covered derivation anchored later may enlarge it.
//!
//! # Committed tree material
//!
//! Batch derivations commit their per-output input lists in a tree, and wide inputs are
//! committed as `{input_set_root, input_set_count}` (§2.5). Their edges are recovered from the
//! committed leaf material, which at L3 must be published outside producer control (§3.5).
//! Callers supply that material through [`TreeMaterial`] — untrusted bytes. It is validated
//! against the anchored root, count and ordering by [`ValidatedLeafSet`] *before* any edge is
//! read from it; there is no path from raw material into the traversal that skips that check.
//!
//! # Cycles
//!
//! Derived attributes feeding later training data create cycles. Traversal marks each record
//! once, so a cycle terminates and each record is dispositioned once (spec §5.4).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::Value;

use crate::bitemporal::{Scope, ValidTime};
use crate::tree::ValidatedLeafSet;
use crate::{field_str, AhlError, AhlResult};

/// A `(dataset, record)` pair — the only identity closure traversal uses (spec §2.3.2).
pub type RecordRef = (String, String);

/// Committed tree material as received: tree root (`sha256:<hex>`) to a claimed leaf set.
///
/// The values are **not** trusted. They become usable only through [`ValidatedLeafSet`].
pub type TreeMaterial = BTreeMap<String, Vec<Value>>;

/// One consumption edge: an input record was read to produce an output record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// Entry index of the derivation that recorded the edge.
    pub entry_index: usize,
    /// The recording derivation's asserted domain validity, used for scope filtering.
    pub valid_time: ValidTime,
    /// The consumed input record.
    pub input: RecordRef,
    /// The produced output record.
    pub output: RecordRef,
}

/// The result of a closure computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closure {
    /// The records traversal started from (§5.1): the trigger's record plus every replacement
    /// superseded by it. Seeds are never members of [`Closure::affected`].
    pub seeds: BTreeSet<RecordRef>,
    /// The derived records the trigger reaches, in record order.
    pub affected: BTreeSet<RecordRef>,
}

fn record_ref(value: &Value) -> AhlResult<RecordRef> {
    Ok((field_str(value, "dataset")?.to_owned(), field_str(value, "record")?.to_owned()))
}

fn payload_of(envelope: &Value) -> Option<&Value> {
    envelope.get("payload").filter(|p| p.is_object())
}

fn statement_type(payload: &Value) -> Option<&str> {
    payload.get("type").and_then(Value::as_str)
}

/// Read a `u64` member that a tree commitment requires.
fn committed_count(payload: &Value, field: &str) -> AhlResult<u64> {
    payload.get(field).and_then(Value::as_u64).ok_or_else(|| AhlError::Field(field.to_owned()))
}

/// Open committed tree material, validating it against the anchored root and count first.
fn open_tree(trees: &TreeMaterial, root: &str, declared_count: u64) -> AhlResult<ValidatedLeafSet> {
    let leaves =
        trees.get(root).ok_or_else(|| AhlError::MissingTreeMaterial(root.to_owned()))?.clone();
    ValidatedLeafSet::open(root, declared_count, leaves)
}

/// Resolve an `inputs` member to the list of input objects it denotes (spec §2.3.2, §2.5).
///
/// The member is either an inline array or a wide-input commitment
/// `{input_set_root, input_set_count}`; in the latter case the committed leaf set is opened and
/// validated, never skipped. Rejecting or ignoring such derivations would silently truncate the
/// closure, which is exactly the failure §3.5 exists to prevent.
fn resolve_inputs(inputs: &Value, trees: &TreeMaterial) -> AhlResult<Vec<Value>> {
    if let Some(array) = inputs.as_array() {
        return Ok(array.clone());
    }
    let root = field_str(inputs, "input_set_root")?;
    let count = committed_count(inputs, "input_set_count")?;
    Ok(open_tree(trees, root, count)?.leaves().to_vec())
}

/// Normalize a derivation payload to `ahl-leaf-v2`-shaped leaves: `{dataset, record, inputs}`.
///
/// A batch derivation already commits exactly this shape (spec §2.5); an unbatched derivation
/// is projected into it, every output sharing the payload's single input member.
fn derivation_leaves(payload: &Value, trees: &TreeMaterial) -> AhlResult<Vec<Value>> {
    if let Some(root) = payload.get("outputs_root").and_then(Value::as_str) {
        let count = committed_count(payload, "outputs_count")?;
        return Ok(open_tree(trees, root, count)?.leaves().to_vec());
    }
    let inputs = payload.get("inputs").ok_or_else(|| AhlError::Field("inputs".to_owned()))?;
    Ok(payload
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or_else(|| AhlError::Field("outputs".to_owned()))?
        .iter()
        .map(|output| {
            serde_json::json!({
                "dataset": output.get("dataset"),
                "record": output.get("record"),
                "inputs": inputs,
            })
        })
        .collect())
}

/// Extract every consumption edge recorded by derivations with `entry_index < through_size`.
///
/// `envelopes` must be in entry-index order — the index in the slice *is* the entry index,
/// which is AHL's only ordering primitive (spec §1.2).
///
/// # Errors
///
/// Returns [`AhlError::Field`] for a malformed derivation payload,
/// [`AhlError::MissingTreeMaterial`] when a committed tree's leaves were not supplied, any of
/// the [`ValidatedLeafSet`] errors when supplied leaves do not match their commitment, and
/// [`AhlError::Timestamp`] for an unparseable `valid_time`.
pub fn edges(
    envelopes: &[Value],
    trees: &TreeMaterial,
    through_size: usize,
) -> AhlResult<Vec<Edge>> {
    let mut out = Vec::new();
    for (entry_index, env) in envelopes.iter().enumerate().take(through_size) {
        let Some(payload) = payload_of(env) else { continue };
        if statement_type(payload) != Some("derivation") {
            continue;
        }
        let valid_time = ValidTime::from_payload(payload)?;
        for leaf in &derivation_leaves(payload, trees)? {
            let output = record_ref(leaf)?;
            let inputs = leaf.get("inputs").ok_or_else(|| AhlError::Field("inputs".to_owned()))?;
            for input in &resolve_inputs(inputs, trees)? {
                out.push(Edge {
                    entry_index,
                    valid_time,
                    input: record_ref(input)?,
                    output: output.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// The closure seeds of the trigger anchored at `trigger_index` (spec §5.1).
///
/// A **retraction** on `(ds, X)` seeds exactly `{(ds, X)}` — never a superseded replacement.
/// Retracting `X` asserts nothing about a record `X'` that an earlier correction introduced in
/// its place: `X'` is a separately introduced record with its own history, and reaching its
/// consumers through a retraction of `X` would invalidate work the retraction never spoke about.
///
/// A **correction** on `(ds, X)` seeds `X` plus the replacement of every *earlier* correction
/// that also named `X` — those replacements are superseded by this one, so records derived from
/// them must not escape the closure. A correction never seeds its own replacement.
///
/// # Errors
///
/// Returns [`AhlError::Field`] if `trigger_index` is out of range or does not address a
/// `retraction` or `correction` statement, or if the trigger payload is malformed.
pub fn trigger_seeds(envelopes: &[Value], trigger_index: usize) -> AhlResult<BTreeSet<RecordRef>> {
    let payload = envelopes
        .get(trigger_index)
        .and_then(payload_of)
        .ok_or_else(|| AhlError::Field(format!("envelope at entry index {trigger_index}")))?;
    let Some(kind @ ("retraction" | "correction")) = statement_type(payload) else {
        return Err(AhlError::Field(format!("trigger type at entry index {trigger_index}")));
    };

    let dataset = field_str(payload, "dataset")?;
    let record = field_str(payload, "record")?;
    let own_replacement = payload.get("replacement").and_then(Value::as_str);

    let mut seeds = BTreeSet::from([(dataset.to_owned(), record.to_owned())]);

    // Spec §5.1: "For a retraction on (ds, X), the seed set is exactly {(ds, X)} — retractions
    // never seed superseded replacements." A retraction of X says nothing about a record X'
    // that an earlier correction produced: X' is a different record, separately introduced,
    // and its consumers are not within this trigger's reach.
    if kind == "retraction" {
        return Ok(seeds);
    }

    for earlier in envelopes.iter().take(trigger_index).filter_map(payload_of) {
        if statement_type(earlier) != Some("correction") {
            continue;
        }
        if earlier.get("dataset").and_then(Value::as_str) != Some(dataset)
            || earlier.get("record").and_then(Value::as_str) != Some(record)
        {
            continue;
        }
        let Some(replacement) = earlier.get("replacement").and_then(Value::as_str) else {
            continue;
        };
        // A correction never seeds its own replacement, however it was reached.
        if Some(replacement) != own_replacement {
            seeds.insert((dataset.to_owned(), replacement.to_owned()));
        }
    }
    Ok(seeds)
}

/// Compute the affected set of the trigger anchored at `trigger_index`, evaluated at a
/// checkpoint of size `through_size`.
///
/// The seeds themselves are not members of the affected set: the affected set is the set of
/// *derived* records that must be dispositioned (spec §2.3.4).
///
/// # Errors
///
/// Propagates the errors of [`trigger_seeds`] and [`edges`], plus [`AhlError::Field`] if the
/// trigger carries no `scope` (spec §2.3.3: scopeless triggers are malformed).
pub fn affected_set(
    envelopes: &[Value],
    trees: &TreeMaterial,
    trigger_index: usize,
    through_size: usize,
) -> AhlResult<Closure> {
    let payload = envelopes
        .get(trigger_index)
        .and_then(payload_of)
        .ok_or_else(|| AhlError::Field(format!("envelope at entry index {trigger_index}")))?;
    let scope = Scope::from_payload(payload)?;
    let seeds = trigger_seeds(envelopes, trigger_index)?;

    let mut consumers: BTreeMap<RecordRef, BTreeSet<RecordRef>> = BTreeMap::new();
    for edge in edges(envelopes, trees, through_size)? {
        // The trigger's scope applies to every seed and to every hop (spec §5.1).
        if scope.covers(edge.valid_time) {
            consumers.entry(edge.input).or_default().insert(edge.output);
        }
    }

    let mut affected = BTreeSet::new();
    let mut seen: BTreeSet<RecordRef> = seeds.clone();
    let mut queue: VecDeque<RecordRef> = seeds.iter().cloned().collect();

    // Breadth-first; `seen` bounds the walk, so cycles terminate (spec §5.4).
    while let Some(current) = queue.pop_front() {
        let Some(next) = consumers.get(&current) else { continue };
        for record in next {
            if seen.insert(record.clone()) {
                affected.insert(record.clone());
                queue.push_back(record.clone());
            }
        }
    }
    Ok(Closure { seeds, affected })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{hash_hex, jcs, tree_root};

    const T0: &str = "2026-08-16T12:00:00Z";

    fn refs(records: &[&str]) -> BTreeSet<RecordRef> {
        records.iter().map(|r| ("d".to_owned(), (*r).to_owned())).collect()
    }

    fn derivation_at(output: &str, inputs: &[&str], valid_time: &Value) -> Value {
        json!({
            "payload": {
                "type": "derivation",
                "valid_time": valid_time,
                "outputs": [ { "dataset": "d", "record": output } ],
                "inputs": inputs
                    .iter()
                    .map(|r| json!({ "dataset": "d", "record": r }))
                    .collect::<Vec<_>>(),
            }
        })
    }

    fn derivation(output: &str, inputs: &[&str]) -> Value {
        derivation_at(output, inputs, &json!(T0))
    }

    fn correction(record: &str, replacement: &str) -> Value {
        json!({
            "payload": {
                "type": "correction",
                "valid_time": T0,
                "dataset": "d",
                "record": record,
                "replacement": replacement,
                "scope": { "effective_from": T0, "retroactive": true },
            }
        })
    }

    fn retraction(record: &str, effective_from: &str, retroactive: bool) -> Value {
        json!({
            "payload": {
                "type": "retraction",
                "valid_time": T0,
                "dataset": "d",
                "record": record,
                "scope": { "effective_from": effective_from, "retroactive": retroactive },
            }
        })
    }

    #[test]
    fn closure_is_transitive() {
        let log =
            vec![derivation("r1", &["r0"]), derivation("r2", &["r1"]), correction("r0", "rx")];
        let closure = affected_set(&log, &TreeMaterial::new(), 2, log.len()).expect("corpus");
        assert_eq!(closure.affected, refs(&["r1", "r2"]));
    }

    #[test]
    fn closure_respects_the_knowledge_boundary() {
        let log =
            vec![correction("r0", "rx"), derivation("r1", &["r0"]), derivation("r2", &["r1"])];
        let closure = affected_set(&log, &TreeMaterial::new(), 0, 2).expect("corpus");
        assert_eq!(closure.affected, refs(&["r1"]));
    }

    #[test]
    fn closure_terminates_on_cycles() {
        let log =
            vec![derivation("r1", &["r0"]), derivation("r0", &["r1"]), correction("r0", "rx")];
        let closure = affected_set(&log, &TreeMaterial::new(), 2, log.len()).expect("corpus");
        assert_eq!(closure.affected, refs(&["r1"]));
    }

    // --- supersession (spec §5.1) -------------------------------------------------------

    #[test]
    fn a_correction_never_seeds_its_own_replacement() {
        let log = vec![correction("x", "xnew")];
        assert_eq!(trigger_seeds(&log, 0).expect("trigger"), refs(&["x"]));
    }

    #[test]
    fn a_superseding_correction_seeds_the_original_and_every_prior_replacement() {
        let log = vec![correction("x", "xold"), correction("x", "xmid"), correction("x", "xnew2")];
        let seeds = trigger_seeds(&log, 2).expect("trigger");
        assert_eq!(seeds, refs(&["x", "xold", "xmid"]));
        assert!(!seeds.contains(&("d".to_owned(), "xnew2".to_owned())));
    }

    #[test]
    fn a_correction_targeting_the_replacement_starts_at_the_replacement() {
        let log = vec![correction("x", "xold"), correction("xold", "xnew")];
        assert_eq!(trigger_seeds(&log, 1).expect("trigger"), refs(&["xold"]));
    }

    #[test]
    fn supersession_reaches_records_derived_from_the_superseded_replacement() {
        let log = vec![
            correction("x", "xold"),     // 0
            derivation("s1", &["x"]),    // 1: consumed the original
            derivation("s2", &["xold"]), // 2: consumed the first replacement
            correction("x", "xnew"),     // 3: supersedes entry 0
        ];
        let closure = affected_set(&log, &TreeMaterial::new(), 3, log.len()).expect("corpus");
        assert_eq!(closure.seeds, refs(&["x", "xold"]));
        assert_eq!(closure.affected, refs(&["s1", "s2"]));
    }

    #[test]
    fn a_retraction_seeds_exactly_its_own_record() {
        // Spec §5.1: retractions never seed superseded replacements, however many corrections
        // of the same original precede them.
        let log = vec![correction("x", "xold"), correction("x", "xmid"), retraction("x", T0, true)];
        assert_eq!(trigger_seeds(&log, 2).expect("trigger"), refs(&["x"]));
    }

    #[test]
    fn a_retraction_after_a_correction_does_not_reach_the_replacement_consumers() {
        let log = vec![
            correction("x", "xnew"),     // 0: x was corrected to xnew
            derivation("s1", &["x"]),    // 1: consumed the original
            derivation("s2", &["xnew"]), // 2: consumed the replacement
            retraction("x", T0, true),   // 3: the ORIGINAL is now retracted outright
        ];
        let closure = affected_set(&log, &TreeMaterial::new(), 3, log.len()).expect("corpus");
        assert_eq!(closure.seeds, refs(&["x"]));
        assert_eq!(
            closure.affected,
            refs(&["s1"]),
            "retracting x says nothing about xnew, so s2 stays out of the affected set"
        );
    }

    #[test]
    fn seeds_are_not_members_of_the_affected_set() {
        let log = vec![correction("x", "xold"), correction("x", "xnew")];
        let closure = affected_set(&log, &TreeMaterial::new(), 1, log.len()).expect("corpus");
        assert!(closure.affected.is_empty());
        assert_eq!(closure.seeds, refs(&["x", "xold"]));
    }

    // --- scope (spec §2.3.3) ------------------------------------------------------------

    #[test]
    fn a_non_retroactive_trigger_excludes_derivations_that_predate_it() {
        let log = vec![
            derivation_at("early", &["c"], &json!("2026-06-01T00:00:00Z")),
            derivation_at("open", &["c"], &json!({ "from": "2026-09-01T00:00:00Z", "to": null })),
            derivation_at(
                "past",
                &["c"],
                &json!({ "from": "2026-05-01T00:00:00Z", "to": "2026-07-01T00:00:00Z" }),
            ),
            derivation_at("boundary", &["c"], &json!("2026-08-01T00:00:00Z")),
            retraction("c", "2026-08-01T00:00:00Z", false),
        ];
        let closure = affected_set(&log, &TreeMaterial::new(), 4, log.len()).expect("corpus");
        assert_eq!(closure.affected, refs(&["open", "boundary"]));
    }

    #[test]
    fn a_retroactive_trigger_ignores_valid_time_entirely() {
        let log = vec![
            derivation_at("early", &["c"], &json!("1999-06-01T00:00:00Z")),
            retraction("c", "2026-08-01T00:00:00Z", true),
        ];
        let closure = affected_set(&log, &TreeMaterial::new(), 1, log.len()).expect("corpus");
        assert_eq!(closure.affected, refs(&["early"]));
    }

    #[test]
    fn scope_filters_intermediate_hops_too() {
        let log = vec![
            derivation_at("s1", &["c"], &json!("2026-09-01T00:00:00Z")),
            derivation_at("s2", &["s1"], &json!("2026-06-01T00:00:00Z")),
            retraction("c", "2026-08-01T00:00:00Z", false),
        ];
        let closure = affected_set(&log, &TreeMaterial::new(), 2, log.len()).expect("corpus");
        assert_eq!(closure.affected, refs(&["s1"]), "the out-of-scope second hop is not traversed");
    }

    // --- committed tree material (spec §2.5, §3.5) --------------------------------------

    fn commitment(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn root_of(leaves: &[Value]) -> String {
        hash_hex(&tree_root(&leaves.iter().map(jcs).collect::<Vec<_>>()))
    }

    #[test]
    fn batch_edges_come_from_validated_leaf_material() {
        let out = commitment(0xaa);
        let leaves = vec![json!({
            "dataset": "d",
            "record": out,
            "inputs": [ { "dataset": "d", "record": "r0" } ],
        })];
        let root = root_of(&leaves);
        let log = vec![
            json!({ "payload": {
                "type": "derivation", "valid_time": T0,
                "outputs_root": root, "outputs_count": 1,
            } }),
            retraction("r0", T0, true),
        ];
        let trees = TreeMaterial::from([(root, leaves)]);
        let closure = affected_set(&log, &trees, 1, log.len()).expect("leaf material supplied");
        assert_eq!(closure.affected, BTreeSet::from([("d".to_owned(), out)]));
    }

    #[test]
    fn input_set_roots_are_expanded_not_skipped() {
        let a = commitment(0x11);
        let b = commitment(0x22);
        let input_leaves = vec![
            json!({ "dataset": "d", "record": a, "role": "feature" }),
            json!({ "dataset": "d", "record": b, "role": "reference" }),
        ];
        let input_root = root_of(&input_leaves);
        let log = vec![
            json!({ "payload": {
                "type": "derivation", "valid_time": T0,
                "outputs": [ { "dataset": "d", "record": "w" } ],
                "inputs": { "input_set_root": input_root, "input_set_count": 2 },
            } }),
            json!({ "payload": {
                "type": "retraction", "valid_time": T0,
                "dataset": "d", "record": b,
                "scope": { "effective_from": T0, "retroactive": true },
            } }),
        ];
        let trees = TreeMaterial::from([(input_root, input_leaves)]);
        let closure = affected_set(&log, &trees, 1, log.len()).expect("leaf material supplied");
        assert_eq!(closure.affected, refs(&["w"]));
    }

    #[test]
    fn tampered_tree_material_is_rejected_before_any_edge_is_read() {
        let a = commitment(0x11);
        let b = commitment(0x22);
        let input_leaves = vec![json!({ "dataset": "d", "record": a })];
        let input_root = root_of(&input_leaves);
        let log = vec![
            json!({ "payload": {
                "type": "derivation", "valid_time": T0,
                "outputs": [ { "dataset": "d", "record": "w" } ],
                "inputs": { "input_set_root": input_root, "input_set_count": 1 },
            } }),
            json!({ "payload": {
                "type": "retraction", "valid_time": T0,
                "dataset": "d", "record": b,
                "scope": { "effective_from": T0, "retroactive": true },
            } }),
        ];
        // An invalid extra input would add an edge the producer never committed.
        let tampered = vec![json!({ "dataset": "d", "record": b })];
        let trees = TreeMaterial::from([(input_root, tampered)]);
        assert!(matches!(
            affected_set(&log, &trees, 1, log.len()),
            Err(AhlError::TreeRootMismatch { .. })
        ));
    }

    #[test]
    fn absent_tree_material_is_an_error_not_a_silent_truncation() {
        let log = vec![
            json!({ "payload": {
                "type": "derivation", "valid_time": T0,
                "outputs_root": commitment(0xee), "outputs_count": 1,
            } }),
            retraction("r0", T0, true),
        ];
        assert!(matches!(
            affected_set(&log, &TreeMaterial::new(), 1, log.len()),
            Err(AhlError::MissingTreeMaterial(_))
        ));
    }

    #[test]
    fn entries_without_a_payload_are_skipped_rather_than_failing() {
        let log = vec![
            json!({ "not_an_envelope": true }),
            derivation("r1", &["r0"]),
            retraction("r0", T0, true),
        ];
        let closure = affected_set(&log, &TreeMaterial::new(), 2, log.len()).expect("corpus");
        assert_eq!(closure.affected, refs(&["r1"]));
    }

    #[test]
    fn malformed_derivations_are_reported_by_field() {
        let log = vec![
            json!({ "payload": { "type": "derivation", "valid_time": T0, "outputs": [] } }),
            retraction("r0", T0, true),
        ];
        assert!(matches!(edges(&log, &TreeMaterial::new(), 2), Err(AhlError::Field(_))));

        let missing_outputs =
            vec![json!({ "payload": { "type": "derivation", "valid_time": T0, "inputs": [] } })];
        assert!(matches!(
            edges(&missing_outputs, &TreeMaterial::new(), 1),
            Err(AhlError::Field(_))
        ));

        let missing_count = vec![json!({
            "payload": { "type": "derivation", "valid_time": T0, "outputs_root": commitment(1) }
        })];
        assert!(matches!(edges(&missing_count, &TreeMaterial::new(), 1), Err(AhlError::Field(_))));
    }

    #[test]
    fn a_non_trigger_entry_index_is_rejected() {
        let log = vec![derivation("r1", &["r0"])];
        assert!(matches!(trigger_seeds(&log, 0), Err(AhlError::Field(_))));
        assert!(matches!(trigger_seeds(&log, 9), Err(AhlError::Field(_))));
    }
}
