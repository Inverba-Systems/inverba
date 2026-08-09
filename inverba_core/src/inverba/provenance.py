"""
Provenance layer.

Every fetch gets a signed, portable attestation: "worker X, holding key Y,
observed exactly this content at this URL at this time." The record is
verifiable with nothing but the public key and Python's standard library
plus `cryptography` -- a third party never needs Inverba installed to
check a claim, only this module's `verify_record` (or an equivalent
Ed25519 implementation in any language).

Multi-worker corroboration (Phase 2 / inverba-swarm) attaches additional
independently-signed records for the same URL to `corroborations`. This
module only handles the single-worker case; the swarm package builds on
top of it without changing the record format.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .models import FetchResult, ProvenanceRecord


def hash_content(content: bytes) -> str:
    """SHA-256 hex digest of raw bytes, exactly as fetched -- no normalization."""
    return hashlib.sha256(content).hexdigest()


def _signing_payload(url: str, content_hash: str, fetched_at: float,
                     fetched_by: str = "native", status_code: int = 200,
                     final_url: str = "", content_type: str = "") -> bytes:
    # CANONICAL JSON payload (sorted keys, fixed separators) -- one distinct key
    # per field, so the signature binds each field independently. This replaced a
    # `|`-delimited join whose unescaped separator let two different field-tuples
    # (e.g. final_url="a"+content_type="b" vs final_url="a|b"+content_type="")
    # produce identical signed bytes, so one signature verified two records. JSON
    # escaping + keyed structure closes that ambiguity, and it matches the
    # canonical-JSON signing already used by the manifest and keyring artifacts.
    #
    # Fields signed and why:
    # - `fetched_by`: observation vs relay -- changes what the signature MEANS;
    #   unsigned, anyone could upgrade a relay into a claimed first-hand fetch.
    # - `status_code`/`final_url`/`content_type`: bot-wall evidence. A CAPTCHA
    #   returns 200 with junk; the tell is a redirect (final_url != url) or an off
    #   content-type. Signed so that evidence can't be stripped. final_url is
    #   normalized to "" when it equals url, so a plain fetch signs identically
    #   whether or not the caller passed final_url.
    norm_final = "" if final_url == url else final_url
    return json.dumps({
        "v": 2,                        # signing-payload format version
        "url": url,
        "content_hash": content_hash,
        "fetched_at": fetched_at,
        "fetched_by": fetched_by,
        "status_code": status_code,
        "final_url": norm_final,
        "content_type": content_type,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ProvenanceSigner:
    """
    Wraps a worker's Ed25519 keypair. One instance per worker identity.

    Keys are generated once and persisted by the caller (e.g. to
    ~/.inverba/worker.key) -- this class does not manage key storage.
    """

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        self._private_key = private_key or Ed25519PrivateKey.generate()

    @classmethod
    def generate(cls) -> "ProvenanceSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "ProvenanceSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key_hex(self) -> str:
        pub = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub.hex()

    def sign(self, fetch_result: FetchResult) -> ProvenanceRecord:
        content_hash = hash_content(fetch_result.content)
        fetched_at = fetch_result.fetched_at or time.time()
        fetched_by = getattr(fetch_result, "fetched_by", "native")
        status_code = getattr(fetch_result, "status_code", 200)
        final_url = getattr(fetch_result, "final_url", "") or ""
        content_type = getattr(fetch_result, "content_type", "") or ""
        payload = _signing_payload(fetch_result.url, content_hash, fetched_at,
                                   fetched_by, status_code, final_url, content_type)
        signature = self._private_key.sign(payload)

        return ProvenanceRecord(
            url=fetch_result.url,
            content_hash=content_hash,
            fetched_at=fetched_at,
            worker_public_key=self.public_key_hex(),
            signature=signature.hex(),
            fetched_by=fetched_by,
            status_code=status_code,
            final_url="" if final_url == fetch_result.url else final_url,
            content_type=content_type,
        )


def verify_record(record: ProvenanceRecord) -> bool:
    """
    Verify a single ProvenanceRecord's signature against its own embedded
    public key. This does NOT check whether that public key is trusted
    (that's the swarm trust registry's job) -- only that the signature is
    valid for the claimed content_hash/url/fetched_at.
    """
    try:
        pub_bytes = bytes.fromhex(record.worker_public_key)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        payload = _signing_payload(
            record.url, record.content_hash, record.fetched_at,
            getattr(record, "fetched_by", "native"),
            getattr(record, "status_code", 200),
            getattr(record, "final_url", "") or "",
            getattr(record, "content_type", "") or "",
        )
        public_key.verify(bytes.fromhex(record.signature), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_with_corroborations(record: ProvenanceRecord) -> dict:
    """
    Verify a record and all attached corroborations, and report whether
    corroborators agree on content_hash (i.e. independently observed the
    same content).

    Returns a summary dict rather than a bool, since "valid but disagrees"
    is a meaningfully different outcome from "valid and corroborated" --
    collapsing both to True/False would hide the signal this layer exists
    to surface.
    """
    primary_valid = verify_record(record)
    corroboration_results = []
    for c in record.corroborations:
        corroboration_results.append({
            "worker_public_key": c.worker_public_key,
            "valid_signature": verify_record(c),
            "content_hash_matches": c.content_hash == record.content_hash,
        })

    all_agree = all(r["content_hash_matches"] for r in corroboration_results)

    return {
        "primary_valid": primary_valid,
        "corroboration_count": len(corroboration_results),
        "corroborations_agree": all_agree if corroboration_results else None,
        "corroborations": corroboration_results,
    }
