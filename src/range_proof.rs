//! Authenticated range proofs (core spec §3 contract item 5, receipt format §4.2).
//!
//! The log-binding contract requires a log to "serve entries `[i, j)` under a checkpoint with
//! proof of completeness and order … a verifier can walk the whole log, or any interval, and
//! know nothing was skipped". Receipt format §4.2 carries that proof as
//! `range_proof.adaptor_form`. This module implements the construction the corpus adaptor
//! profile `ahl-test-log-v1` §8 defines.
//!
//! # Construction
//!
//! The proof is the minimal set of RFC 6962 subtree hashes that cover everything *outside* the
//! range. Verification replays the standard RFC 6962 tree decomposition of a tree of size `N`:
//!
//! ```text
//! recompute(offset, size):
//!   if [offset, offset+size) is disjoint from [i, j):   take the next carried subtree hash
//!   if [offset, offset+size) is contained in [i, j):    compute the root of the carried
//!                                                       leaf hashes for that span
//!   otherwise:                                          k = largest power of two < size
//!                                                       hash_children(recompute(offset, k),
//!                                                                     recompute(offset+k, size-k))
//! ```
//!
//! `recompute(0, N)` must equal the checkpoint root. Because the recursion is a pure function
//! of `(N, i, j)`, the position of every carried hash is fixed before any of them is read: a
//! prover cannot choose where to spend them. The verifier requires exactly `j - i` carried
//! leaves and places them positionally, so a gap, a reordering, an omission or an insertion
//! all change `recompute(0, N)` and are rejected under collision resistance of SHA-256.
//!
//! # Anti-drift
//!
//! `atl-core` has no range-proof primitive, so the combining recursion is local. Every hash it
//! computes comes from `atl_core`: subtree roots from
//! [`atl_core::core::merkle::compute_root`], interior nodes from
//! [`atl_core::core::merkle::hash_children`], and the split point from
//! [`atl_core::core::merkle::largest_power_of_2_less_than`]. A single-entry range is
//! additionally cross-checked through [`atl_core::core::merkle::verify_inclusion`], since it is
//! exactly an inclusion proof in a different serialization.

use atl_core::core::merkle::{
    compute_root, hash_children, largest_power_of_2_less_than, verify_inclusion, Hash,
    InclusionProof,
};
use base64::Engine as _;

use crate::{leaf_hash, AhlError, AhlResult, B64};

/// Serialization magic of the `ahl-test-log-v1` range proof (adaptor profile §8).
pub const RANGE_PROOF_MAGIC: &[u8; 6] = b"AHLRP1";

/// Fixed-size header: magic + `tree_size` + `from_index` + `to_index` + `node_count`.
const HEADER_LEN: usize = 6 + 8 + 8 + 8 + 4;

/// A parsed range proof: the ordered subtree hashes covering everything outside the range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    /// Size of the tree the checkpoint commits.
    pub tree_size: u64,
    /// First entry index in the proven range, inclusive.
    pub from_index: u64,
    /// End of the proven range, exclusive.
    pub to_index: u64,
    /// Subtree hashes covering `[0, from_index)` and `[to_index, tree_size)`, in the order the
    /// verification recursion consumes them (left to right).
    pub nodes: Vec<Hash>,
}

/// Where a subtree sits relative to the proven range.
enum Span {
    /// Entirely outside — one carried subtree hash covers it.
    Outside,
    /// Entirely inside — recomputed from the carried leaves.
    Inside,
    /// Straddles a boundary — must be split further.
    Straddles,
}

const fn classify(offset: u64, size: u64, from: u64, to: u64) -> Span {
    let end = offset + size;
    if end <= from || offset >= to {
        Span::Outside
    } else if offset >= from && end <= to {
        Span::Inside
    } else {
        Span::Straddles
    }
}

/// Walk the RFC 6962 decomposition of `[0, tree_size)`, visiting every maximal subtree that
/// lies entirely outside `[from, to)`, in left-to-right order.
///
/// `visit` receives `(offset, size, depth)`; `depth` is the number of splits taken to reach the
/// subtree, which is what turns a single-entry range proof back into an inclusion path.
fn walk_outside<F: FnMut(u64, u64, u32)>(
    offset: u64,
    size: u64,
    from: u64,
    to: u64,
    depth: u32,
    visit: &mut F,
) {
    match classify(offset, size, from, to) {
        Span::Outside => visit(offset, size, depth),
        Span::Inside => {}
        Span::Straddles => {
            let k = largest_power_of_2_less_than(size);
            walk_outside(offset, k, from, to, depth + 1, visit);
            walk_outside(offset + k, size - k, from, to, depth + 1, visit);
        }
    }
}

/// Validate a range against a tree size.
fn check_range(tree_size: u64, from: u64, to: u64) -> AhlResult<()> {
    if tree_size == 0 {
        return Err(AhlError::RangeProof("tree size 0".to_owned()));
    }
    if from >= to || to > tree_size {
        return Err(AhlError::RangeProof(format!(
            "range [{from}, {to}) is not a non-empty sub-range of [0, {tree_size})"
        )));
    }
    Ok(())
}

/// Generate a range proof for `[from_index, to_index)` over `leaf_hashes`.
///
/// `leaf_hashes` is the complete leaf-hash sequence of the tree the checkpoint commits.
/// Generation is local; verification is what the anti-drift rule constrains.
///
/// # Errors
///
/// Returns [`AhlError::RangeProof`] if the range is empty, inverted, or exceeds the tree.
pub fn generate(leaf_hashes: &[Hash], from_index: u64, to_index: u64) -> AhlResult<RangeProof> {
    let tree_size = leaf_hashes.len() as u64;
    check_range(tree_size, from_index, to_index)?;

    let mut nodes = Vec::new();
    walk_outside(0, tree_size, from_index, to_index, 0, &mut |offset, size, _| {
        let lo = usize::try_from(offset).unwrap_or(usize::MAX);
        let hi = usize::try_from(offset + size).unwrap_or(usize::MAX);
        nodes.push(compute_root(&leaf_hashes[lo..hi]));
    });
    Ok(RangeProof { tree_size, from_index, to_index, nodes })
}

/// Recompute the tree root from the carried leaves and the proof's subtree hashes.
fn recompute(
    offset: u64,
    size: u64,
    proof: &RangeProof,
    leaf_hashes: &[Hash],
    cursor: &mut usize,
) -> AhlResult<Hash> {
    match classify(offset, size, proof.from_index, proof.to_index) {
        Span::Outside => {
            let node = proof.nodes.get(*cursor).copied().ok_or_else(|| {
                AhlError::RangeProof("proof has too few subtree hashes".to_owned())
            })?;
            *cursor += 1;
            Ok(node)
        }
        Span::Inside => {
            let lo = usize::try_from(offset - proof.from_index)
                .map_err(|_| AhlError::RangeProof("range offset overflows usize".to_owned()))?;
            let hi = lo
                + usize::try_from(size)
                    .map_err(|_| AhlError::RangeProof("range size overflows usize".to_owned()))?;
            let span = leaf_hashes
                .get(lo..hi)
                .ok_or_else(|| AhlError::RangeProof("carried leaf set is short".to_owned()))?;
            Ok(compute_root(span))
        }
        Span::Straddles => {
            let k = largest_power_of_2_less_than(size);
            let left = recompute(offset, k, proof, leaf_hashes, cursor)?;
            let right = recompute(offset + k, size - k, proof, leaf_hashes, cursor)?;
            Ok(hash_children(&left, &right))
        }
    }
}

/// Verify that `leaf_hashes` is exactly and completely the leaf set of
/// `[proof.from_index, proof.to_index)` under `root`.
///
/// Returns `true` only if the recomputed tree root equals `root`, every carried subtree hash
/// was consumed, and the carried leaf count equals the range width. A single-entry range is
/// additionally cross-verified through `atl_core`'s inclusion verifier.
///
/// # Errors
///
/// Returns [`AhlError::RangeProof`] if the proof is structurally unusable (bad range, wrong
/// number of carried leaves, exhausted node list) and [`AhlError::Merkle`] if the
/// `atl-core` cross-check cannot run. A structurally valid proof that simply does not open the
/// root yields `Ok(false)`.
pub fn verify(proof: &RangeProof, leaf_hashes: &[Hash], root: &Hash) -> AhlResult<bool> {
    check_range(proof.tree_size, proof.from_index, proof.to_index)?;

    let width = proof.to_index - proof.from_index;
    if leaf_hashes.len() as u64 != width {
        return Err(AhlError::RangeProof(format!(
            "range [{}, {}) needs exactly {width} leaves, {} were carried",
            proof.from_index,
            proof.to_index,
            leaf_hashes.len()
        )));
    }

    let mut cursor = 0usize;
    let recomputed = recompute(0, proof.tree_size, proof, leaf_hashes, &mut cursor)?;
    if cursor != proof.nodes.len() {
        return Err(AhlError::RangeProof(format!(
            "proof carries {} subtree hashes, {cursor} were consumed",
            proof.nodes.len()
        )));
    }
    if recomputed != *root {
        return Ok(false);
    }

    // A one-entry range is an inclusion proof wearing a different serialization. Route it
    // through atl-core's verifier as well, so the two constructions cannot drift apart.
    if width == 1 {
        let mut ordered: Vec<(u32, Hash)> = Vec::with_capacity(proof.nodes.len());
        let mut index = 0usize;
        walk_outside(
            0,
            proof.tree_size,
            proof.from_index,
            proof.to_index,
            0,
            &mut |_, _, depth| {
                ordered.push((depth, proof.nodes[index]));
                index += 1;
            },
        );
        // An inclusion path runs leaf to root: deepest sibling first.
        ordered.sort_by_key(|(depth, _)| core::cmp::Reverse(*depth));
        let inclusion = InclusionProof {
            leaf_index: proof.from_index,
            tree_size: proof.tree_size,
            path: ordered.into_iter().map(|(_, hash)| hash).collect(),
        };
        if !verify_inclusion(&leaf_hashes[0], &inclusion, root)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Convenience wrapper: verify a range proof over raw leaf byte strings.
///
/// Applies the AHL leaf rule `SHA-256(0x00 || bytes)` and delegates to [`verify`].
///
/// # Errors
///
/// As [`verify`].
pub fn verify_over_leaves(proof: &RangeProof, leaves: &[Vec<u8>], root: &Hash) -> AhlResult<bool> {
    let hashes: Vec<Hash> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
    verify(proof, &hashes, root)
}

/// Serialize a range proof to the adaptor profile's `base64:<...>` form.
///
/// Byte layout (all integers big-endian): `"AHLRP1" || tree_size:u64 || from_index:u64 ||
/// to_index:u64 || node_count:u32 || node_count × 32 raw bytes`.
#[must_use]
pub fn encode(proof: &RangeProof) -> String {
    let mut bytes = Vec::with_capacity(HEADER_LEN + proof.nodes.len() * 32);
    bytes.extend_from_slice(RANGE_PROOF_MAGIC);
    bytes.extend_from_slice(&proof.tree_size.to_be_bytes());
    bytes.extend_from_slice(&proof.from_index.to_be_bytes());
    bytes.extend_from_slice(&proof.to_index.to_be_bytes());
    // A proof over a u64-sized tree can never carry more than 64 subtree hashes, so the
    // conversion cannot fail for any tree this code can construct.
    let node_count = u32::try_from(proof.nodes.len()).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&node_count.to_be_bytes());
    for node in &proof.nodes {
        bytes.extend_from_slice(node);
    }
    format!("base64:{}", B64.encode(bytes))
}

/// Parse a `base64:<...>` range proof.
///
/// # Errors
///
/// Returns [`AhlError::MissingPrefix`] or [`AhlError::Base64`] for encoding failures, and
/// [`AhlError::RangeProof`] for a wrong magic, a truncated header, or a node count that
/// disagrees with the remaining bytes.
pub fn decode(value: &str) -> AhlResult<RangeProof> {
    let bytes = B64.decode(crate::strip_prefix(value, "base64:")?)?;
    if bytes.len() < HEADER_LEN {
        return Err(AhlError::RangeProof(format!("truncated: {} bytes", bytes.len())));
    }
    if &bytes[..6] != RANGE_PROOF_MAGIC {
        return Err(AhlError::RangeProof("wrong magic; expected AHLRP1".to_owned()));
    }
    let read_u64 = |at: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[at..at + 8]);
        u64::from_be_bytes(buf)
    };
    let tree_size = read_u64(6);
    let from_index = read_u64(14);
    let to_index = read_u64(22);
    let mut count_buf = [0u8; 4];
    count_buf.copy_from_slice(&bytes[30..34]);
    let node_count = u32::from_be_bytes(count_buf) as usize;

    let body = &bytes[HEADER_LEN..];
    if body.len() != node_count * 32 {
        return Err(AhlError::RangeProof(format!(
            "declares {node_count} subtree hashes but carries {} bytes of node data",
            body.len()
        )));
    }
    let nodes = body
        .chunks_exact(32)
        .map(|chunk| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(chunk);
            hash
        })
        .collect();
    Ok(RangeProof { tree_size, from_index, to_index, nodes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_root;

    fn corpus(n: u64) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("entry-{i}").into_bytes()).collect()
    }

    fn hashes(leaves: &[Vec<u8>]) -> Vec<Hash> {
        leaves.iter().map(|l| leaf_hash(l)).collect()
    }

    /// Test indices are all below 20, so this conversion never fails.
    fn at(index: u64) -> usize {
        usize::try_from(index).expect("test indices fit in usize")
    }

    #[test]
    fn every_sub_range_of_every_tree_size_verifies() {
        for n in 1u64..=20 {
            let leaves = corpus(n);
            let all = hashes(&leaves);
            let root = tree_root(&leaves);
            for from in 0..n {
                for to in (from + 1)..=n {
                    let proof = generate(&all, from, to).expect("valid range");
                    let span = &all[at(from)..at(to)];
                    assert!(
                        verify(&proof, span, &root).expect("well-formed proof"),
                        "size {n}, range [{from}, {to}) did not verify"
                    );
                }
            }
        }
    }

    #[test]
    fn serialization_round_trips() {
        let leaves = corpus(20);
        let proof = generate(&hashes(&leaves), 3, 7).expect("valid range");
        assert_eq!(decode(&encode(&proof)).expect("round trip"), proof);
    }

    #[test]
    fn a_substituted_entry_is_rejected() {
        let leaves = corpus(20);
        let all = hashes(&leaves);
        let root = tree_root(&leaves);
        let proof = generate(&all, 3, 7).expect("valid range");
        let mut span = all[3..7].to_vec();
        span[1] = leaf_hash(b"substituted");
        assert!(!verify(&proof, &span, &root).expect("well-formed proof"));
    }

    #[test]
    fn a_reordered_range_is_rejected() {
        let leaves = corpus(20);
        let all = hashes(&leaves);
        let root = tree_root(&leaves);
        let proof = generate(&all, 3, 7).expect("valid range");
        let mut span = all[3..7].to_vec();
        span.swap(0, 3);
        assert!(!verify(&proof, &span, &root).expect("well-formed proof"));
    }

    #[test]
    fn an_omitted_entry_is_rejected_structurally() {
        let leaves = corpus(20);
        let all = hashes(&leaves);
        let root = tree_root(&leaves);
        let proof = generate(&all, 3, 7).expect("valid range");
        let short = all[3..6].to_vec();
        assert!(matches!(verify(&proof, &short, &root), Err(AhlError::RangeProof(_))));
    }

    #[test]
    fn a_proof_for_a_different_range_does_not_open_the_root() {
        let leaves = corpus(20);
        let all = hashes(&leaves);
        let root = tree_root(&leaves);
        // Claim the [3,7) span is the content of [8,12).
        let mut proof = generate(&all, 8, 12).expect("valid range");
        proof.from_index = 8;
        assert!(!verify(&proof, &all[3..7], &root).expect("well-formed proof"));
    }

    #[test]
    fn the_full_range_carries_no_subtree_hashes() {
        let leaves = corpus(20);
        let all = hashes(&leaves);
        let proof = generate(&all, 0, 20).expect("valid range");
        assert!(proof.nodes.is_empty(), "[0, n) needs no material outside the range");
        assert!(verify(&proof, &all, &tree_root(&leaves)).expect("well-formed proof"));
    }

    #[test]
    fn a_single_entry_range_agrees_with_the_atl_core_inclusion_proof() {
        let leaves = corpus(20);
        let all = hashes(&leaves);
        let root = tree_root(&leaves);
        for index in 0..20u64 {
            let proof = generate(&all, index, index + 1).expect("valid range");
            // `verify` performs the atl-core cross-check internally for width-1 ranges.
            assert!(verify(&proof, &all[at(index)..=at(index)], &root).expect("well-formed proof"));
            let generated = crate::inclusion_proof(&leaves, at(index)).expect("in tree");
            assert_eq!(
                proof.nodes.len(),
                generated.path.len(),
                "range proof and inclusion proof must carry the same sibling count"
            );
        }
    }

    #[test]
    fn empty_and_inverted_ranges_are_rejected() {
        let all = hashes(&corpus(8));
        assert!(matches!(generate(&all, 4, 4), Err(AhlError::RangeProof(_))));
        assert!(matches!(generate(&all, 5, 3), Err(AhlError::RangeProof(_))));
        assert!(matches!(generate(&all, 0, 9), Err(AhlError::RangeProof(_))));
    }

    #[test]
    fn structurally_broken_proofs_are_rejected_before_any_hashing() {
        let leaves = corpus(8);
        let all = hashes(&leaves);
        let root = tree_root(&leaves);
        let proof = generate(&all, 2, 5).expect("valid range");

        // A proof whose node list has been truncated cannot be replayed to the root.
        let mut short = proof.clone();
        short.nodes.pop();
        assert!(matches!(verify(&short, &all[2..5], &root), Err(AhlError::RangeProof(_))));

        // Nor one carrying more nodes than the recursion consumes.
        let mut long = proof;
        long.nodes.push([0u8; 32]);
        assert!(matches!(verify(&long, &all[2..5], &root), Err(AhlError::RangeProof(_))));

        // A zero-size tree has no leaves to prove anything about.
        let empty = RangeProof { tree_size: 0, from_index: 0, to_index: 1, nodes: Vec::new() };
        assert!(matches!(verify(&empty, &all[..1], &root), Err(AhlError::RangeProof(_))));
        assert!(matches!(generate(&[], 0, 1), Err(AhlError::RangeProof(_))));
    }

    #[test]
    fn a_declared_node_count_that_disagrees_with_the_body_is_rejected() {
        let all = hashes(&corpus(8));
        let proof = generate(&all, 1, 3).expect("valid range");
        let mut raw =
            B64.decode(encode(&proof).strip_prefix("base64:").expect("prefix")).expect("base64");
        raw[33] = raw[33].wrapping_add(1); // bump node_count without adding node bytes
        assert!(matches!(
            decode(&format!("base64:{}", B64.encode(&raw))),
            Err(AhlError::RangeProof(_))
        ));
    }

    #[test]
    fn a_width_one_proof_that_does_not_open_the_root_is_false_not_an_error() {
        let leaves = corpus(8);
        let all = hashes(&leaves);
        let proof = generate(&all, 3, 4).expect("valid range");
        let wrong_root = leaf_hash(b"some other tree");
        assert!(!verify(&proof, &all[3..4], &wrong_root).expect("well-formed proof"));
    }

    #[test]
    fn decoding_rejects_wrong_magic_and_bad_lengths() {
        let all = hashes(&corpus(8));
        let encoded = encode(&generate(&all, 1, 3).expect("valid range"));
        let mut raw = B64.decode(encoded.strip_prefix("base64:").expect("prefix")).expect("base64");
        raw[0] = b'X';
        assert!(matches!(
            decode(&format!("base64:{}", B64.encode(&raw))),
            Err(AhlError::RangeProof(_))
        ));
        assert!(matches!(decode("base64:AAAA"), Err(AhlError::RangeProof(_))));
        assert!(matches!(decode("notbase64"), Err(AhlError::MissingPrefix { .. })));
    }
}
