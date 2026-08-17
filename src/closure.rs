//! Revocation closure over an anchored statement graph (spec §5.1).
//!
//! For an effective trigger on `(ds, X)` evaluated at a checkpoint `C` that commits the
//! trigger, the affected set is the transitive closure over derivations with
//! `entry index < tree_size(C)` whose inputs match `(ds, X)`, then their outputs'
//! consumers, and so on.
//!
//! Two properties of the AHL model make this computable by anyone holding the corpus:
//!
//! * closure traversal keys on `(dataset, record)` only — `representation` and `projection`
//!   narrow what was consumed but never change identity (spec §2.3.2);
//! * post-trigger consumption is prohibited, so a closure computed at any checkpoint
//!   committing the trigger is stable (spec §2.3.4).
//!
//! Batch derivations (spec §2.5) commit their per-output input lists in a Merkle tree rather
//! than in the payload; their edges are recovered from the committed leaf material, which at
//! L3 must be published outside producer control (spec §3.5). Callers supply that material
//! through [`TreeMaterial`].
//!
//! # Scope of this implementation
//!
//! Implemented: the consumption closure of §5.1, cycle-safe per §5.4 (each record is visited
//! once, so a cycle terminates and is dispositioned once). Not implemented: the
//! "correction chains extend traversal through `replacement`" clause of §5.1, whose trigger
//! condition ("where a superseding correction exists") is not pinned down precisely enough in
//! v0.3-draft to implement without guessing; the toy corpus does not exercise it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::Value;

use crate::{field_str, AhlError, AhlResult};

/// A `(dataset, record)` pair — the only identity closure traversal uses (spec §2.3.2).
pub type RecordRef = (String, String);

/// Committed tree material: tree root (`sha256:<hex>`) to its full, ordered leaf set.
pub type TreeMaterial = BTreeMap<String, Vec<Value>>;

/// One consumption edge: an input record was read to produce an output record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Edge {
    /// Entry index of the derivation that recorded the edge.
    pub entry_index: usize,
    /// The consumed input record.
    pub input: RecordRef,
    /// The produced output record.
    pub output: RecordRef,
}

fn record_ref(value: &Value) -> AhlResult<RecordRef> {
    Ok((field_str(value, "dataset")?.to_owned(), field_str(value, "record")?.to_owned()))
}

/// Normalize a derivation payload to `ahl-leaf-v2`-shaped leaves: `{dataset, record, inputs}`.
///
/// A batch derivation already commits exactly this shape (spec §2.5); an unbatched derivation
/// is projected into it, every output sharing the payload's single input list (spec §2.3.2).
fn derivation_leaves(payload: &Value, trees: &TreeMaterial) -> AhlResult<Vec<Value>> {
    if let Some(root) = payload.get("outputs_root").and_then(Value::as_str) {
        return trees
            .get(root)
            .cloned()
            .ok_or_else(|| AhlError::Field(format!("tree material for {root}")));
    }
    let inputs = payload
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| AhlError::Field("inputs".to_owned()))?;
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
/// Returns [`AhlError::Field`] if a derivation payload is malformed, or if a batch derivation
/// references an `outputs_root` for which no leaf material was supplied.
pub fn edges(
    envelopes: &[Value],
    trees: &TreeMaterial,
    through_size: usize,
) -> AhlResult<Vec<Edge>> {
    let mut out = Vec::new();
    for (entry_index, env) in envelopes.iter().enumerate().take(through_size) {
        let Some(payload) = env.get("payload") else { continue };
        if payload.get("type").and_then(Value::as_str) != Some("derivation") {
            continue;
        }
        for leaf in &derivation_leaves(payload, trees)? {
            let output = record_ref(leaf)?;
            let inputs = leaf
                .get("inputs")
                .and_then(Value::as_array)
                .ok_or_else(|| AhlError::Field("inputs".to_owned()))?;
            for input in inputs {
                out.push(Edge { entry_index, input: record_ref(input)?, output: output.clone() });
            }
        }
    }
    Ok(out)
}

/// Transitive closure of records affected by a trigger naming `trigger`.
///
/// The trigger's own record is not a member of the result: the affected set is the set of
/// *derived* records that must be dispositioned (spec §2.3.4).
///
/// # Errors
///
/// Propagates the errors of [`edges`].
pub fn affected_set(
    envelopes: &[Value],
    trees: &TreeMaterial,
    trigger: &RecordRef,
    through_size: usize,
) -> AhlResult<BTreeSet<RecordRef>> {
    let mut consumers: BTreeMap<RecordRef, BTreeSet<RecordRef>> = BTreeMap::new();
    for edge in edges(envelopes, trees, through_size)? {
        consumers.entry(edge.input).or_default().insert(edge.output);
    }

    let mut affected = BTreeSet::new();
    let mut seen: BTreeSet<RecordRef> = BTreeSet::new();
    let mut queue: VecDeque<RecordRef> = VecDeque::new();
    seen.insert(trigger.clone());
    queue.push_back(trigger.clone());

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
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn derivation(output: &str, inputs: &[&str]) -> Value {
        json!({
            "payload": {
                "type": "derivation",
                "outputs": [ { "dataset": "d", "record": output } ],
                "inputs": inputs.iter().map(|r| json!({ "dataset": "d", "record": r })).collect::<Vec<_>>(),
            }
        })
    }

    #[test]
    fn closure_is_transitive() {
        let log = vec![derivation("r1", &["r0"]), derivation("r2", &["r1"])];
        let affected =
            affected_set(&log, &TreeMaterial::new(), &("d".into(), "r0".into()), log.len())
                .expect("well-formed corpus");
        assert_eq!(affected.len(), 2);
        assert!(affected.contains(&("d".to_owned(), "r2".to_owned())));
    }

    #[test]
    fn closure_respects_the_knowledge_boundary() {
        let log = vec![derivation("r1", &["r0"]), derivation("r2", &["r1"])];
        let affected = affected_set(&log, &TreeMaterial::new(), &("d".into(), "r0".into()), 1)
            .expect("well-formed corpus");
        assert_eq!(affected.len(), 1, "only derivations with entry index < through_size count");
    }

    #[test]
    fn closure_terminates_on_cycles() {
        let log = vec![derivation("r1", &["r0"]), derivation("r0", &["r1"])];
        let affected =
            affected_set(&log, &TreeMaterial::new(), &("d".into(), "r0".into()), log.len())
                .expect("well-formed corpus");
        assert_eq!(affected, BTreeSet::from([("d".to_owned(), "r1".to_owned())]));
    }

    #[test]
    fn batch_edges_come_from_committed_leaf_material() {
        let root = "sha256:deadbeef".to_owned();
        let log = vec![json!({
            "payload": { "type": "derivation", "outputs_root": root, "outputs_count": 1 }
        })];
        let trees = TreeMaterial::from([(
            root,
            vec![json!({
                "dataset": "d",
                "record": "r1",
                "inputs": [ { "dataset": "d", "record": "r0" } ],
            })],
        )]);
        let affected = affected_set(&log, &trees, &("d".into(), "r0".into()), log.len())
            .expect("leaf material supplied");
        assert_eq!(affected, BTreeSet::from([("d".to_owned(), "r1".to_owned())]));
    }
}
