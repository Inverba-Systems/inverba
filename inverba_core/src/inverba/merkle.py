"""
Merkle tree primitives (RFC 6962 style).

Lives in CORE, not cloud, because a self-hoster building a dataset manifest
needs corpus proofs without installing the commercial package. The cloud
transparency log reuses these rather than duplicating them -- two
implementations of the same tree is a bug farm, and a divergence between them
would silently break proofs across the boundary.

Dependency-free (stdlib hashlib only), so it runs anywhere the core does,
air-gapped included.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional


def leaf_hash(data: bytes) -> bytes:
    """0x00 domain-separation prefix for leaves (RFC 6962)."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """0x01 prefix for internal nodes. Domain separation prevents a leaf from
    being passed off as an internal node."""
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass
class InclusionProof:
    """Proof that a leaf is in a tree with a given root.

    `path_sides[i]` is True when audit_path[i] is a RIGHT sibling (so the
    running hash goes on the left). Recorded at generation time so verification
    never has to re-derive tree positions -- doing that by index arithmetic is
    where these implementations usually break.
    """
    leaf_index: int
    tree_size: int
    audit_path: list[str]              # hex
    leaf_hash: str                      # hex
    path_sides: list[bool] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "audit_path": self.audit_path,
            "leaf_hash": self.leaf_hash,
            "path_sides": self.path_sides,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InclusionProof":
        return cls(**d)


class MerkleTree:
    """Append-only Merkle tree over arbitrary leaf bytes."""

    def __init__(self):
        self._leaf_hashes: list[bytes] = []

    def append(self, data: bytes) -> int:
        self._leaf_hashes.append(leaf_hash(data))
        return len(self._leaf_hashes) - 1

    @property
    def size(self) -> int:
        return len(self._leaf_hashes)

    def root(self) -> bytes:
        return self._root(self._leaf_hashes)

    def root_hex(self) -> str:
        return self.root().hex()

    def _root(self, hashes: list[bytes]) -> bytes:
        if not hashes:
            return hashlib.sha256(b"").digest()
        if len(hashes) == 1:
            return hashes[0]
        k = 1
        while k * 2 < len(hashes):
            k *= 2
        return node_hash(self._root(hashes[:k]), self._root(hashes[k:]))

    def inclusion_proof(self, index: int) -> InclusionProof:
        if not (0 <= index < self.size):
            raise IndexError("leaf index out of range")
        path, sides = self._inclusion_path(self._leaf_hashes, index)
        return InclusionProof(
            leaf_index=index,
            tree_size=self.size,
            audit_path=[h.hex() for h in path],
            path_sides=sides,
            leaf_hash=self._leaf_hashes[index].hex(),
        )

    def _inclusion_path(self, hashes: list[bytes], index: int) -> tuple[list[bytes], list[bool]]:
        if len(hashes) <= 1:
            return [], []
        k = 1
        while k * 2 < len(hashes):
            k *= 2
        if index < k:
            sub_path, sub_sides = self._inclusion_path(hashes[:k], index)
            return sub_path + [self._root(hashes[k:])], sub_sides + [True]
        sub_path, sub_sides = self._inclusion_path(hashes[k:], index - k)
        return sub_path + [self._root(hashes[:k])], sub_sides + [False]


def verify_inclusion(proof: InclusionProof, root_hash: str) -> bool:
    """Recompute the root from leaf + audit path; compare to the published root.

    This is what lets an auditor confirm one record is in a million-record
    corpus without being handed the whole corpus.
    """
    computed = bytes.fromhex(proof.leaf_hash)
    for sibling_hex, sibling_is_right in zip(proof.audit_path, proof.path_sides):
        sibling = bytes.fromhex(sibling_hex)
        computed = (node_hash(computed, sibling) if sibling_is_right
                    else node_hash(sibling, computed))
    return computed.hex() == root_hash
