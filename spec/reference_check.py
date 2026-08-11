#!/usr/bin/env python3
"""Independent Python implementation of IRF/1, checked against the Rust vectors.

Purpose: a format spec is only real if two implementations written against it
agree byte-for-byte. This file is deliberately *not* a binding to the Rust core —
it re-derives deterministic CBOR, the RFC 6962 tree, and the COSE Sig_structure
from the spec text alone, then asserts equality with vectors.json.

It also performs a live Ed25519 sign/verify over a spec-derived preimage, and a
tamper sweep proving that mutating any byte of the signed payload breaks
verification.

Run: python3 reference_check.py vectors.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# ---------------------------------------------------------------------------
# Deterministic CBOR (IRF profile: no floats, no tags, no indefinite lengths)
# ---------------------------------------------------------------------------


class Nint:
    """CBOR negative integer, encoding the value -1 - n."""

    __slots__ = ("n",)

    def __init__(self, n: int) -> None:
        if n < 0:
            raise ValueError("Nint argument must be >= 0")
        self.n = n

    @staticmethod
    def of(value: int) -> "Nint":
        if value >= 0:
            raise ValueError("value must be negative")
        return Nint(-1 - value)


def _head(major: int, arg: int) -> bytes:
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg <= 0xFF:
        return bytes([mt | 24, arg])
    if arg <= 0xFFFF:
        return bytes([mt | 25]) + arg.to_bytes(2, "big")
    if arg <= 0xFFFFFFFF:
        return bytes([mt | 26]) + arg.to_bytes(4, "big")
    return bytes([mt | 27]) + arg.to_bytes(8, "big")


def encode(v: Any) -> bytes:
    """Deterministic encoding. One byte string per value, no exceptions."""
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, Nint):
        return _head(1, v.n)
    if isinstance(v, int):
        if v < 0:
            return _head(1, -1 - v)
        return _head(0, v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        # Sort by ENCODED KEY BYTES, not by Python ordering. This is the rule
        # that makes "z" precede "aa": the length lives in the head byte.
        items = [(encode(k), k, val) for k, val in v.items()]
        items.sort(key=lambda t: t[0])
        seen = set()
        for ek, _, _ in items:
            if ek in seen:
                raise ValueError("duplicate map key")
            seen.add(ek)
        return _head(5, len(items)) + b"".join(ek + encode(val) for ek, _, val in items)
    raise TypeError(f"type not permitted in IRF: {type(v)!r}")


# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree
# ---------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_point(n: int) -> int:
    """Largest power of two strictly less than n."""
    if n < 2:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError("empty tree")
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = split_point(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(
    leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes
) -> bool:
    if size == 0 or not 0 <= index < size:
        return False
    decisions: list[bool] = []
    idx, sz = index, size
    while sz > 1:
        k = split_point(sz)
        if idx < k:
            decisions.append(True)
            sz = k
        else:
            decisions.append(False)
            idx -= k
            sz -= k
    if len(proof) != len(decisions):
        return False
    computed = leaf
    for step, on_left in enumerate(reversed(decisions)):
        sib = proof[step]
        computed = node_hash(computed, sib) if on_left else node_hash(sib, computed)
    return computed == root


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError("bad m")
    if m == n:
        return []
    return _subproof(leaves, m, True)


def _subproof(leaves: list[bytes], m: int, is_full: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if is_full else [merkle_root(leaves)]
    k = split_point(n)
    if m <= k:
        return _subproof(leaves[:k], m, is_full) + [merkle_root(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [merkle_root(leaves[:k])]


def verify_consistency(
    m: int, root_m: bytes, n: int, root_n: bytes, proof: list[bytes]
) -> bool:
    if not 0 < m <= n:
        return False
    if m == n:
        return not proof and root_m == root_n

    def rec(mm: int, nn: int, pf: list[bytes], is_full: bool) -> tuple[bytes, bytes]:
        if mm == nn:
            if is_full:
                if pf:
                    raise ValueError("proof too long")
                return root_m, root_m
            if len(pf) != 1:
                raise ValueError("bad proof length")
            return pf[0], pf[0]
        if nn < 2 or mm == 0 or mm > nn:
            raise ValueError("size mismatch")
        k = split_point(nn)
        if not pf:
            raise ValueError("proof exhausted")
        last, rest = pf[-1], pf[:-1]
        if mm <= k:
            fr, sr_left = rec(mm, k, rest, is_full)
            return fr, node_hash(sr_left, last)
        fr_r, sr_r = rec(mm - k, nn - k, rest, False)
        return node_hash(last, fr_r), node_hash(last, sr_r)

    try:
        fr, sr = rec(m, n, proof, True)
    except ValueError:
        return False
    return fr == root_m and sr == root_n


# ---------------------------------------------------------------------------
# COSE Sig_structure (RFC 9052 §4.4)
# ---------------------------------------------------------------------------

HDR_ALG = 1
HDR_KID = 4
HDR_IRF = "irf"
CONTEXT = "Signature"

ALG_ED25519 = -8
ALG_ML_DSA_44 = -48
ALG_ML_DSA_65 = -49
ALG_ML_DSA_87 = -50
HASH_SHA_256 = -16

DOMAIN = {
    "record": b"inverba/1/record",
    "manifest": b"inverba/1/manifest",
    "anchor": b"inverba/1/anchor",
    "witness": b"inverba/1/witness",
    "renewal": b"inverba/1/renewal",
}


def body_protected(major: int = 1, minor: int = 0) -> bytes:
    return encode({HDR_IRF: [major, minor]})


def sign_protected(alg: int, kid: bytes) -> bytes:
    if not kid:
        raise ValueError("kid required")
    return encode({HDR_ALG: alg, HDR_KID: kid})


def sig_structure(bp: bytes, sp: bytes, domain: bytes, payload: bytes) -> bytes:
    return encode([CONTEXT, bp, sp, domain, payload])


def observation_payload(
    uri: str,
    hash_alg: int,
    content_hash: bytes,
    length: int,
    media_type: str,
    observed_at: int,
    observed_by: bytes,
    scope: str = "observation",
) -> bytes:
    return encode(
        {
            "uri": uri,
            "hash_alg": hash_alg,
            "hash": content_hash,
            "len": length,
            "media_type": media_type,
            "observed_at": observed_at,
            "observed_by": observed_by,
            "scope": scope,
        }
    )


def cose_sign(payload: bytes, signers: list[tuple[int, bytes, bytes]]) -> bytes:
    if not signers:
        raise ValueError("at least one signer required")
    entries = [
        [sign_protected(alg, kid), {}, sig] for alg, kid, sig in signers
    ]
    return encode([body_protected(), {}, payload, entries])


# ---------------------------------------------------------------------------
# Interop check
# ---------------------------------------------------------------------------

FAILURES: list[str] = []
CHECKS = 0


def check(name: str, got: Any, want: Any) -> None:
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILURES.append(f"{name}\n    got  {got!r}\n    want {want!r}")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    with open(path, encoding="utf-8") as fh:
        v = json.load(fh)

    # --- dCBOR ------------------------------------------------------------
    dcbor_cases = {
        "uint_0": 0,
        "uint_23": 23,
        "uint_24": 24,
        "uint_65535": 65535,
        "uint_65536": 65536,
        "nint_minus_1": -1,
        "nint_minus_8_ed25519_alg": ALG_ED25519,
        "nint_minus_49_mldsa65_alg": ALG_ML_DSA_65,
        "bytes_empty": b"",
        "bytes_deadbeef": bytes.fromhex("deadbeef"),
        "text_ascii": "inverba",
        "text_utf8": "caf\u00e9",
        "bool_true": True,
        "null": None,
        "array_empty": [],
        "map_empty": {},
        "map_key_order_by_encoded_bytes": {"aa": 1, "z": 2, 1: 3},
    }
    for case in v["dcbor"]:
        name = case["name"]
        if name not in dcbor_cases:
            FAILURES.append(f"vector {name} has no Python counterpart")
            continue
        check(f"dcbor/{name}", encode(dcbor_cases[name]).hex(), case["cbor"])

    # --- domain tags ------------------------------------------------------
    for d in v["domains"]:
        check(f"domain/{d['name']}", DOMAIN[d["name"]].hex(), d["tag_hex"])

    # --- merkle -----------------------------------------------------------
    for m in v["merkle"]:
        data = [bytes.fromhex(x) for x in m["leaf_data_hex"]]
        leaves = [leaf_hash(d) for d in data]
        check(f"merkle/root/n={m['size']}", merkle_root(leaves).hex(), m["root"])
        idx = m["proof_index"]
        proof = inclusion_proof(leaves, idx)
        check(
            f"merkle/proof/n={m['size']}",
            [p.hex() for p in proof],
            m["proof"],
        )
        # And the proof must actually verify under our own verifier.
        check(
            f"merkle/verify/n={m['size']}",
            verify_inclusion(
                leaves[idx], idx, m["size"], proof, bytes.fromhex(m["root"])
            ),
            True,
        )

    mc = v["merkle_consistency"]
    leaves8 = [leaf_hash(bytes([i])) for i in range(8)]
    check("merkle/consistency/root_n", merkle_root(leaves8).hex(), mc["root_n"])
    check("merkle/consistency/root_m", merkle_root(leaves8[:5]).hex(), mc["root_m"])
    cp = consistency_proof(leaves8, 5)
    check("merkle/consistency/proof", [p.hex() for p in cp], mc["proof"])
    check(
        "merkle/consistency/verify",
        verify_consistency(5, bytes.fromhex(mc["root_m"]), 8, bytes.fromhex(mc["root_n"]), cp),
        True,
    )
    # A rewritten prefix must be rejected.
    tampered = [leaf_hash(b"forged")] + leaves8[1:5]
    check(
        "merkle/consistency/rejects_rewrite",
        verify_consistency(5, merkle_root(tampered), 8, merkle_root(leaves8), cp),
        False,
    )

    # --- payload, headers, preimages --------------------------------------
    r = v["record"]
    content = bytes.fromhex(r["content_hex"])
    content_hash = leaf_hash(content)
    check("record/content_hash", content_hash.hex(), r["content_hash"])

    payload = observation_payload(
        "https://example.test/page",
        HASH_SHA_256,
        content_hash,
        len(content),
        "text/html",
        1_753_400_000,
        b"node-alpha",
    )
    check("record/payload", payload.hex(), r["payload"])

    bp = body_protected()
    check("record/body_protected", bp.hex(), r["body_protected"])
    sp_ed = sign_protected(ALG_ED25519, b"node-alpha")
    sp_ml = sign_protected(ALG_ML_DSA_65, b"node-alpha")
    check("record/sign_protected_ed25519", sp_ed.hex(), r["sign_protected_ed25519"])
    check("record/sign_protected_mldsa65", sp_ml.hex(), r["sign_protected_mldsa65"])

    check(
        "record/sig_structure_record_ed25519",
        sig_structure(bp, sp_ed, DOMAIN["record"], payload).hex(),
        r["sig_structure_record_ed25519"],
    )
    check(
        "record/sig_structure_record_mldsa65",
        sig_structure(bp, sp_ml, DOMAIN["record"], payload).hex(),
        r["sig_structure_record_mldsa65"],
    )
    check(
        "record/sig_structure_manifest_ed25519",
        sig_structure(bp, sp_ed, DOMAIN["manifest"], payload).hex(),
        r["sig_structure_manifest_ed25519"],
    )

    # --- envelope ---------------------------------------------------------
    env = cose_sign(
        payload,
        [
            (ALG_ED25519, b"node-alpha", b"\x11" * 64),
            (ALG_ML_DSA_65, b"node-alpha", b"\x22" * 3309),
        ],
    )
    check("envelope/cose_sign", env.hex(), v["envelope"]["cose_sign"])

    # --- live Ed25519 over the spec preimage ------------------------------
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pk = sk.public_key()
    pre = sig_structure(bp, sp_ed, DOMAIN["record"], payload)
    sig = sk.sign(pre)
    try:
        pk.verify(sig, pre)
        check("crypto/ed25519_roundtrip", True, True)
    except InvalidSignature:
        check("crypto/ed25519_roundtrip", False, True)

    # Cross-domain replay: the same signature must not verify as a manifest.
    pre_manifest = sig_structure(bp, sp_ed, DOMAIN["manifest"], payload)
    try:
        pk.verify(sig, pre_manifest)
        check("crypto/cross_domain_replay_blocked", False, True)
    except InvalidSignature:
        check("crypto/cross_domain_replay_blocked", True, True)

    # Tamper sweep: flipping any single bit of the payload must break the sig.
    survived = 0
    for i in range(len(payload)):
        for bit in range(8):
            mutated = bytearray(payload)
            mutated[i] ^= 1 << bit
            pre_m = sig_structure(bp, sp_ed, DOMAIN["record"], bytes(mutated))
            try:
                pk.verify(sig, pre_m)
                survived += 1
            except InvalidSignature:
                pass
    check("crypto/tamper_sweep_survivors", survived, 0)

    # --- report -----------------------------------------------------------
    if FAILURES:
        print(f"FAIL: {len(FAILURES)} of {CHECKS} checks failed\n")
        for f in FAILURES:
            print("  " + f)
        return 1
    print(f"OK: {CHECKS} checks passed")
    print(f"    payload bytes      {len(payload)}")
    print(f"    envelope bytes     {len(env)}")
    print(f"    tamper sweep       {len(payload) * 8} single-bit mutations, 0 survivors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
