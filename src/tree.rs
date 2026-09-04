//! Validated committed-tree material (spec §2.5, §3.5).
//!
//! At L3 the complete leaf set of every committed tree must be retrievable outside producer
//! control, so closure recomputation and receipt verification both consume leaf material that
//! arrives from an untrusted party. Nothing downstream may treat such material as evidence
//! until it has been checked against the anchored commitment.
//!
//! [`ValidatedLeafSet`] is the only way to get leaves into the traversal code, and its single
//! constructor performs every check the commitment supports:
//!
//! 1. the recomputed root equals the anchored root;
//! 2. the leaf count equals the anchored count (`outputs_count`, `input_set_count`,
//!    `affected_count`);
//! 3. every leaf's `record` is a canonical family string (lowercase hex, spec §2.5);
//! 4. the leaves are in strictly ascending UTF-8 byte order of that string — which is
//!    simultaneously the sort rule and the no-duplicate rule of §2.5.
//!
//! Checks 1 and 2 together rule out gaps and omissions: a missing or extra leaf changes both
//! the root and the count.

use serde_json::Value;

use crate::{field_str, hash_hex, jcs, tree_root, AhlError, AhlResult};

/// A leaf set that has been checked against the root and count an anchored statement commits.
///
/// The inner leaves are only reachable through [`ValidatedLeafSet::leaves`], and the type has
/// no public constructor other than [`ValidatedLeafSet::open`]. A value of this type is
/// therefore evidence that the checks above passed.
#[derive(Debug, Clone)]
pub struct ValidatedLeafSet {
    root: String,
    leaves: Vec<Value>,
}

impl ValidatedLeafSet {
    /// Validate `leaves` against the anchored `root` and `declared_count`.
    ///
    /// # Errors
    ///
    /// * [`AhlError::TreeCountMismatch`] — the leaf count disagrees with the anchored count;
    /// * [`AhlError::InvalidCommitment`] — a leaf's `record` is not a canonical family string;
    /// * [`AhlError::TreeUnsorted`] — the leaves are unsorted or contain a duplicate;
    /// * [`AhlError::TreeRootMismatch`] — the leaves do not recompute to `root`;
    /// * [`AhlError::Field`] — a leaf carries no string `record`.
    pub fn open(root: &str, declared_count: u64, leaves: Vec<Value>) -> AhlResult<Self> {
        if leaves.len() as u64 != declared_count {
            return Err(AhlError::TreeCountMismatch {
                root: root.to_owned(),
                declared: declared_count,
                got: leaves.len(),
            });
        }

        let mut previous: Option<&str> = None;
        for (index, leaf) in leaves.iter().enumerate() {
            let record = field_str(leaf, "record")?;
            if !is_canonical_commitment(record) {
                return Err(AhlError::InvalidCommitment(record.to_owned()));
            }
            // Ascending lexicographic comparison of the UTF-8 bytes of the commitment string
            // (spec §2.5). `str: Ord` is exactly that comparison. Strictness rejects duplicates.
            if previous.is_some_and(|prev| prev.as_bytes() >= record.as_bytes()) {
                return Err(AhlError::TreeUnsorted {
                    root: root.to_owned(),
                    index,
                    record: record.to_owned(),
                });
            }
            previous = Some(record);
        }

        let recomputed = hash_hex(&tree_root(&leaves.iter().map(jcs).collect::<Vec<_>>()));
        if recomputed != root {
            return Err(AhlError::TreeRootMismatch { root: root.to_owned(), recomputed });
        }

        Ok(Self { root: root.to_owned(), leaves })
    }

    /// The anchored root this leaf set opens.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The validated leaves, in committed order.
    #[must_use]
    pub fn leaves(&self) -> &[Value] {
        &self.leaves
    }
}

/// Whether `value` is a canonical AHL record commitment (spec §2.5: lowercase hex families).
#[must_use]
pub fn is_canonical_commitment(value: &str) -> bool {
    let digits = match value.split_once(':') {
        Some(("sha256" | "hmac-sha256", rest)) => (rest.len() == 64).then_some(rest),
        _ => None,
    };
    digits.is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

#[cfg(test)]
#[allow(
    // A test asserts; an assertion that fires IS the failure report. The crate-level no-panic
    // lints are the library's contract, not this module's.
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use serde_json::json;

    use super::*;

    fn leaf(record: &str) -> Value {
        json!({ "dataset": "d", "record": record })
    }

    fn commitment(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn good() -> Vec<Value> {
        vec![leaf(&commitment(0x11)), leaf(&commitment(0x22)), leaf(&commitment(0x33))]
    }

    fn root_of(leaves: &[Value]) -> String {
        hash_hex(&tree_root(&leaves.iter().map(jcs).collect::<Vec<_>>()))
    }

    #[test]
    fn a_correct_leaf_set_opens() {
        let leaves = good();
        let set = ValidatedLeafSet::open(&root_of(&leaves), 3, leaves.clone())
            .expect("root, count and order all agree");
        assert_eq!(set.leaves(), leaves.as_slice());
    }

    #[test]
    fn a_validated_leaf_set_remembers_the_root_it_opens() {
        let leaves = good();
        let root = root_of(&leaves);
        let set = ValidatedLeafSet::open(&root, 3, leaves).expect("valid material");
        assert_eq!(set.root(), root);
    }

    #[test]
    fn a_leaf_without_a_record_is_rejected() {
        let leaves = vec![json!({ "dataset": "d" })];
        assert!(matches!(
            ValidatedLeafSet::open(&root_of(&leaves), 1, leaves),
            Err(AhlError::Field(_))
        ));
    }

    #[test]
    fn a_missing_leaf_is_rejected_by_the_count_before_the_root() {
        let leaves = good();
        let root = root_of(&leaves);
        let short = leaves[..2].to_vec();
        assert!(matches!(
            ValidatedLeafSet::open(&root, 3, short),
            Err(AhlError::TreeCountMismatch { declared: 3, got: 2, .. })
        ));
    }

    #[test]
    fn a_substituted_leaf_is_rejected_by_the_root() {
        let leaves = good();
        let root = root_of(&leaves);
        let mut tampered = leaves;
        tampered[1] = json!({ "dataset": "d", "record": commitment(0x22), "extra": true });
        assert!(matches!(
            ValidatedLeafSet::open(&root, 3, tampered),
            Err(AhlError::TreeRootMismatch { .. })
        ));
    }

    #[test]
    fn reordered_leaves_are_rejected_before_the_root_is_recomputed() {
        let mut leaves = good();
        leaves.swap(0, 2);
        let root = root_of(&leaves);
        assert!(matches!(
            ValidatedLeafSet::open(&root, 3, leaves),
            Err(AhlError::TreeUnsorted { index: 1, .. })
        ));
    }

    #[test]
    fn duplicate_leaves_are_rejected() {
        let leaves = vec![leaf(&commitment(0x11)), leaf(&commitment(0x11))];
        let root = root_of(&leaves);
        assert!(matches!(
            ValidatedLeafSet::open(&root, 2, leaves),
            Err(AhlError::TreeUnsorted { index: 1, .. })
        ));
    }

    #[test]
    fn non_canonical_commitments_are_rejected() {
        let leaves = vec![leaf("sha256:NOTHEX"), leaf(&commitment(0xff))];
        let root = root_of(&leaves);
        assert!(matches!(
            ValidatedLeafSet::open(&root, 2, leaves),
            Err(AhlError::InvalidCommitment(_))
        ));
    }

    #[test]
    fn canonical_commitment_recognises_both_families_and_rejects_uppercase() {
        assert!(is_canonical_commitment(&commitment(0xab)));
        assert!(is_canonical_commitment(&format!("hmac-sha256:{}", hex::encode([0xcdu8; 32]))));
        assert!(!is_canonical_commitment(&format!("sha256:{}", "AB".repeat(32))));
        assert!(!is_canonical_commitment("sha256:beef"));
        assert!(!is_canonical_commitment("md5:00"));
    }
}
