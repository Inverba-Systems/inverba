//! RFC 6962 / RFC 9162 Merkle tree.
//!
//! Three properties the audit called out (finding D3) are structural here, not
//! bolted on:
//!
//! * **Second-preimage resistance via domain separation.** Leaves are hashed as
//!   `H(0x00 || data)` and internal nodes as `H(0x01 || left || right)`, so an
//!   internal node can never be presented as a leaf. This is the flaw that bit
//!   OpenZeppelin's early implementations, BitTorrent v2 discussion, and several
//!   IPFS variants.
//!
//! * **No lonely-leaf duplication.** RFC 6962 splits at `k = largest power of
//!   two < n`, which binds tree shape to `n`. Bitcoin duplicates odd trailing
//!   nodes, which is CVE-2012-2459: two distinct leaf sets produce one root.
//!   That malleability is impossible in this construction.
//!
//! * **`(size, root)` is an inseparable pair.** Every API here takes or returns
//!   the tree size alongside the root, and `verify_inclusion` requires it. A
//!   root without its size is not a commitment — an attacker can otherwise show
//!   an inclusion proof against a *different* tree that happens to share a
//!   subtree root. The size must additionally be inside the signed manifest
//!   payload; that binding is enforced one layer up, in `record`.
//!
//! Proof-of-inclusion is meaningless unless the root is independently anchored.
//! This module produces the commitment; anchoring is the caller's obligation.

use crate::domain::{MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX};
use crate::error::{Invalid, Reason};
use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// `MTH({d}) = H(0x00 || d)`
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    sha256(&[&[MERKLE_LEAF_PREFIX], data])
}

/// `MTH(D) = H(0x01 || left || right)`
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[MERKLE_NODE_PREFIX], left, right])
}

/// Hash of the empty tree, `MTH({}) = H()`. Defined for completeness; IRF
/// manifests reject size-0 trees at the record layer.
#[must_use]
pub fn empty_root() -> Hash {
    sha256(&[])
}

/// Largest power of two **strictly** less than `n`. Requires `n >= 2`.
///
/// Computed over `n - 1` rather than `n`: for a power of two, the largest power
/// of two below it is `n / 2`, and taking the high bit of `n` directly would
/// return `n` itself. That off-by-one makes `root` split into (everything,
/// nothing) and recurse forever — caught by
/// `consistency_rejects_history_rewrite` as a stack overflow.
fn split_point(n: usize) -> usize {
    if n < 2 {
        return 0;
    }
    let m = n.saturating_sub(1);
    let bits = usize::BITS.saturating_sub(m.leading_zeros());
    let shift = bits.saturating_sub(1).min(usize::BITS.saturating_sub(1));
    1usize << shift
}

/// Merkle Tree Hash over already-computed leaf hashes.
pub fn root(leaves: &[Hash]) -> Result<Hash, Invalid> {
    match leaves.len() {
        0 => Err(Invalid::new(Reason::EmptyTree)),
        1 => leaves.first().copied().ok_or(Invalid::new(Reason::EmptyTree)),
        n => {
            let k = split_point(n);
            let (l, r) = leaves.split_at(k.min(n));
            Ok(node_hash(&root(l)?, &root(r)?))
        }
    }
}

/// Convenience: hash raw leaf data then compute the root.
pub fn root_of_data(items: &[Vec<u8>]) -> Result<Hash, Invalid> {
    let leaves: Vec<Hash> = items.iter().map(|d| leaf_hash(d)).collect();
    root(&leaves)
}

/// Audit path for `index` in a tree of `leaves`, leaf-to-root order.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Result<Vec<Hash>, Invalid> {
    let n = leaves.len();
    if n == 0 {
        return Err(Invalid::new(Reason::EmptyTree));
    }
    if index >= n {
        return Err(Invalid::new(Reason::IndexOutOfRange));
    }
    if n == 1 {
        return Ok(Vec::new());
    }
    let k = split_point(n);
    let (l, r) = leaves.split_at(k.min(n));
    if index < k {
        let mut p = inclusion_proof(l, index)?;
        p.push(root(r)?);
        Ok(p)
    } else {
        let mut p = inclusion_proof(r, index.saturating_sub(k))?;
        p.push(root(l)?);
        Ok(p)
    }
}

/// Verify an audit path. `size` is mandatory: it selects the tree shape, and
/// without it the proof does not identify a unique commitment.
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    size: usize,
    proof: &[Hash],
    expected_root: &Hash,
) -> Result<(), Invalid> {
    if size == 0 {
        return Err(Invalid::new(Reason::EmptyTree));
    }
    if index >= size {
        return Err(Invalid::new(Reason::IndexOutOfRange));
    }
    // The path length is fully determined by (index, size). A proof of any other
    // length is rejected before a single hash is computed, which removes the
    // "pad the proof to reach a chosen root" degree of freedom.
    let expected_len = path_len(index, size);
    if proof.len() != expected_len {
        return Err(Invalid::new(Reason::BadProofLength));
    }

    // The audit path is emitted leaf-to-root, but the tree shape is only
    // discoverable root-to-leaf. So: record the descent decisions first, then
    // replay them in reverse against the proof.
    let mut decisions: Vec<bool> = Vec::with_capacity(expected_len);
    let mut idx = index;
    let mut sz = size;
    while sz > 1 {
        let k = split_point(sz);
        if idx < k {
            decisions.push(true); // node is in the left half at this level
            sz = k;
        } else {
            decisions.push(false);
            idx = idx.saturating_sub(k);
            sz = sz.saturating_sub(k);
        }
    }

    let mut computed = *leaf;
    for (step, on_left) in decisions.iter().rev().enumerate() {
        let sibling = proof.get(step).ok_or(Invalid::new(Reason::BadProofLength))?;
        computed = if *on_left {
            node_hash(&computed, sibling)
        } else {
            node_hash(sibling, &computed)
        };
    }

    // Constant-shape comparison. Digest equality is not secret-dependent here,
    // but keeping the pattern uniform avoids habit drift into secret comparisons.
    if computed == *expected_root {
        Ok(())
    } else {
        Err(Invalid::new(Reason::ProofMismatch))
    }
}

/// Number of audit-path entries for `index` in a tree of `size`.
fn path_len(index: usize, size: usize) -> usize {
    let mut idx = index;
    let mut sz = size;
    let mut len = 0usize;
    while sz > 1 {
        let k = split_point(sz);
        if idx < k {
            sz = k;
        } else {
            idx = idx.saturating_sub(k);
            sz = sz.saturating_sub(k);
        }
        len = len.saturating_add(1);
    }
    len
}

/// Append-only consistency proof between tree sizes `m` and `n` (RFC 6962 §2.1.2).
///
/// Inclusion proofs alone let an operator silently rewrite history by publishing
/// a fresh tree. Consistency proofs are what make the log append-only, which is
/// the property an evidentiary archive actually needs.
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Result<Vec<Hash>, Invalid> {
    let n = leaves.len();
    if m == 0 || m > n {
        return Err(Invalid::new(Reason::SizeMismatch));
    }
    if m == n {
        return Ok(Vec::new());
    }
    subproof(leaves, m, true)
}

fn subproof(leaves: &[Hash], m: usize, is_full: bool) -> Result<Vec<Hash>, Invalid> {
    let n = leaves.len();
    if m == n {
        if is_full {
            return Ok(Vec::new());
        }
        return Ok(vec![root(leaves)?]);
    }
    if n < 2 {
        return Err(Invalid::new(Reason::SizeMismatch));
    }
    let k = split_point(n);
    let (l, r) = leaves.split_at(k.min(n));
    if m <= k {
        let mut p = subproof(l, m, is_full)?;
        p.push(root(r)?);
        Ok(p)
    } else {
        let mut p = subproof(r, m.saturating_sub(k), false)?;
        p.push(root(l)?);
        Ok(p)
    }
}

/// Verify that a tree of size `n` with root `root_n` extends the tree of size
/// `m` with root `root_m`.
pub fn verify_consistency(
    m: usize,
    root_m: &Hash,
    n: usize,
    root_n: &Hash,
    proof: &[Hash],
) -> Result<(), Invalid> {
    if m == 0 || m > n {
        return Err(Invalid::new(Reason::SizeMismatch));
    }
    if m == n {
        if !proof.is_empty() {
            return Err(Invalid::new(Reason::BadProofLength));
        }
        return if root_m == root_n {
            Ok(())
        } else {
            Err(Invalid::new(Reason::ProofMismatch))
        };
    }

    // Bound recursion: a tree addressable by usize needs at most 64 levels.
    if proof.len() > 64 {
        return Err(Invalid::new(Reason::BadProofLength));
    }

    let (fr, sr) = verify_subproof(m, n, proof, true, root_m)?;

    // The binding that matters is `sr == root_n`. `root_n` is the value the
    // caller obtained from a *signed* manifest, so reconstructing it from
    // root_m plus the supplied siblings is what proves root_m is genuinely a
    // prefix commitment of root_n. Collision resistance of SHA-256 is what
    // stops an attacker choosing a bogus root_m that still chains to root_n.
    if fr == *root_m && sr == *root_n {
        Ok(())
    } else {
        Err(Invalid::new(Reason::ProofMismatch))
    }
}

/// Recursive counterpart to `subproof`. Consumes the audit path from the end,
/// because the generator pushes the outermost sibling last.
///
/// Returns `(root of the first m leaves, root of all n leaves)` as reconstructed
/// from the proof.
fn verify_subproof(
    m: usize,
    n: usize,
    proof: &[Hash],
    is_full: bool,
    root_m: &Hash,
) -> Result<(Hash, Hash), Invalid> {
    if m == n {
        if is_full {
            // The prefix tree *is* this subtree; the caller already knows its
            // root and the generator emitted nothing.
            if !proof.is_empty() {
                return Err(Invalid::new(Reason::BadProofLength));
            }
            return Ok((*root_m, *root_m));
        }
        // Generator emitted exactly this subtree's root.
        if proof.len() != 1 {
            return Err(Invalid::new(Reason::BadProofLength));
        }
        let r = *proof.first().ok_or(Invalid::new(Reason::BadProofLength))?;
        return Ok((r, r));
    }
    if n < 2 || m == 0 || m > n {
        return Err(Invalid::new(Reason::SizeMismatch));
    }

    let k = split_point(n);
    let (last, rest) = proof
        .split_last()
        .ok_or(Invalid::new(Reason::BadProofLength))?;

    if m <= k {
        // Prefix lies wholly in the left subtree; `last` is root(right).
        let (fr, sr_left) = verify_subproof(m, k, rest, is_full, root_m)?;
        Ok((fr, node_hash(&sr_left, last)))
    } else {
        // Prefix spans all of left plus part of right; `last` is root(left).
        let (fr_right, sr_right) = verify_subproof(
            m.saturating_sub(k),
            n.saturating_sub(k),
            rest,
            false,
            root_m,
        )?;
        Ok((node_hash(last, &fr_right), node_hash(last, &sr_right)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&[u8::try_from(i).unwrap_or(0)]))
            .collect()
    }

    #[test]
    fn leaf_and_node_are_domain_separated() {
        // An internal node's preimage can never equal a leaf's preimage.
        let a = leaf_hash(b"x");
        let b = leaf_hash(b"y");
        let internal = node_hash(&a, &b);
        // Presenting the concatenation as leaf data yields a different hash.
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        assert_ne!(internal, leaf_hash(&concat));
    }

    #[test]
    fn split_points_are_powers_of_two() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(7), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }

    #[test]
    fn empty_tree_rejected() {
        assert!(root(&[]).is_err());
        assert!(inclusion_proof(&[], 0).is_err());
    }

    #[test]
    fn cve_2012_2459_no_lonely_leaf_duplication() {
        // Bitcoin duplicates the odd trailing node, so [a,b,c] and [a,b,c,c]
        // collide. Under RFC 6962 they must not.
        let l = leaves(3);
        let mut dup = l.clone();
        dup.push(*l.get(2).expect("3 leaves"));
        assert_ne!(root(&l).expect("r3"), root(&dup).expect("r4"));
    }

    #[test]
    fn inclusion_round_trips_for_all_sizes_and_indices() {
        for n in 1..=33usize {
            let l = leaves(n);
            let r = root(&l).expect("root");
            for i in 0..n {
                let p = inclusion_proof(&l, i).expect("proof");
                let leaf = *l.get(i).expect("leaf");
                verify_inclusion(&leaf, i, n, &p, &r).expect("valid inclusion");
            }
        }
    }

    #[test]
    fn inclusion_rejects_size_with_different_path_shape() {
        let l = leaves(8);
        let r = root(&l).expect("root");
        let p = inclusion_proof(&l, 3).expect("proof");
        let leaf = *l.get(3).expect("leaf");
        // Sizes 4 and 16 give index 3 a different audit-path length, so the
        // proof is rejected before any hashing happens.
        assert!(verify_inclusion(&leaf, 3, 4, &p, &r).is_err());
        assert!(verify_inclusion(&leaf, 3, 16, &p, &r).is_err());
    }

    /// Documents a limit of the construction, so nobody claims more than it gives.
    ///
    /// `size` selects the audit-path *shape*. Distinct sizes can yield the same
    /// shape for a given index — index 3 in trees of size 7 and 8 both take the
    /// path `[left, right, right]` — so an honest proof verifies under either
    /// claimed size. That is **not** a forgery: the proof still resolves to the
    /// same `root`, and a root commits to exactly one leaf multiset.
    ///
    /// The actual protection against cross-tree proof reuse is that `(root,
    /// size)` are bound together inside the *signed manifest payload*
    /// (`build::manifest_payload`). A verifier MUST take `size` from the signed
    /// manifest and never from an untrusted caller. Do not market `size` as
    /// preventing anything on its own.
    #[test]
    fn same_shape_size_is_not_a_forgery_and_is_not_claimed_to_be_rejected() {
        let l = leaves(8);
        let r = root(&l).expect("root");
        let p = inclusion_proof(&l, 3).expect("proof");
        let leaf = *l.get(3).expect("leaf");
        assert_eq!(path_len(3, 7), path_len(3, 8));
        // Verifies under the mis-stated size, and resolves to the same root.
        assert!(verify_inclusion(&leaf, 3, 7, &p, &r).is_ok());
        // But a proof for one tree never resolves to a *different* tree's root.
        let other = leaves(7);
        let other_root = root(&other).expect("root7");
        assert_ne!(r, other_root);
        assert!(verify_inclusion(&leaf, 3, 7, &p, &other_root).is_err());
    }

    #[test]
    fn inclusion_rejects_padded_or_truncated_proof() {
        let l = leaves(8);
        let r = root(&l).expect("root");
        let leaf = *l.first().expect("leaf");
        let mut p = inclusion_proof(&l, 0).expect("proof");
        p.push([0u8; 32]);
        assert!(verify_inclusion(&leaf, 0, 8, &p, &r).is_err());
        let short: Vec<Hash> = p.iter().copied().take(1).collect();
        assert!(verify_inclusion(&leaf, 0, 8, &short, &r).is_err());
    }

    #[test]
    fn inclusion_rejects_internal_node_presented_as_leaf() {
        let l = leaves(4);
        let r = root(&l).expect("root");
        let a = *l.first().expect("l0");
        let b = *l.get(1).expect("l1");
        let internal = node_hash(&a, &b);
        // Try to pass the internal node off as a leaf at index 0.
        let p = inclusion_proof(&l, 0).expect("proof");
        assert!(verify_inclusion(&internal, 0, 4, &p, &r).is_err());
    }

    #[test]
    fn inclusion_rejects_out_of_range_index() {
        let l = leaves(4);
        let r = root(&l).expect("root");
        let leaf = *l.first().expect("l0");
        assert!(verify_inclusion(&leaf, 4, 4, &[], &r).is_err());
        assert!(verify_inclusion(&leaf, usize::MAX, 4, &[], &r).is_err());
    }

    #[test]
    fn consistency_round_trips() {
        for n in 1..=24usize {
            let full = leaves(n);
            let rn = root(&full).expect("rn");
            for m in 1..=n {
                let prefix: Vec<Hash> = full.iter().copied().take(m).collect();
                let rm = root(&prefix).expect("rm");
                let p = consistency_proof(&full, m).expect("cproof");
                verify_consistency(m, &rm, n, &rn, &p).expect("consistent");
            }
        }
    }

    #[test]
    fn consistency_rejects_history_rewrite() {
        let full = leaves(8);
        let rn = root(&full).expect("rn");
        let prefix: Vec<Hash> = full.iter().copied().take(5).collect();
        let p = consistency_proof(&full, 5).expect("cproof");

        // Same size, different early history -> must fail.
        let mut tampered = prefix.clone();
        if let Some(slot) = tampered.get_mut(0) {
            *slot = leaf_hash(b"forged");
        }
        let bad_rm = root(&tampered).expect("bad rm");
        assert!(verify_consistency(5, &bad_rm, 8, &rn, &p).is_err());
    }

    #[test]
    fn consistency_rejects_shrinking_and_zero() {
        let full = leaves(4);
        let rn = root(&full).expect("rn");
        assert!(verify_consistency(0, &rn, 4, &rn, &[]).is_err());
        assert!(verify_consistency(5, &rn, 4, &rn, &[]).is_err());
    }
}
