"""
C2PA-compatible provenance export (Phase C).

POSITIONING (from the adversarial review): this is a DERIVED, OPTIONAL view.
Ed25519 provenance records remain Inverba's source of truth. A C2PA manifest
is a downstream export for users who need to slot into the C2PA / Content
Credentials compliance ecosystem (EU AI Act Article 50, ISO/IEC 22144). The
sovereign path (self-signed Ed25519, zero certificate authorities) and the
compliance path (C2PA sidecar, optionally CA-signed) are BOTH available and
the user chooses — they are not forced to adopt the CA trust model to use
Inverba.

WHY A SIDECAR, NOT AN EMBEDDED MANIFEST:
C2PA manifests are normally embedded in media files (JPEG/MP4). Scraped web
data is text/JSON, which can't carry an embedded JUMBF manifest. The C2PA
AI/ML guidance explicitly supports ASSOCIATED (sidecar) manifests for
dataset files exactly this reason. Inverba emits a sidecar manifest that
references the content by hash.

CONFORMANCE BOUNDARY (stated honestly):
This produces a STRUCTURALLY C2PA-shaped manifest with the standard
training-and-data-mining assertion and content-binding hash assertion, signed
with the worker's key. FULL Trust List conformance additionally requires an
X.509 certificate from a C2PA-recognized authority — an operational step the
user performs, not something this module fabricates. With a self-signed cert
the manifest is valid and self-verifying but "valid but untrusted" to a
conformant verifier until a real cert is supplied. We label this explicitly
rather than implying full conformance.
"""

from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass
from typing import Optional, Any

from .models import ProvenanceRecord


# The CAWG training-and-data-mining assertion label (C2PA 2.1+ replaced the
# older c2pa.data_mining / c2pa.ai_training labels with CAWG equivalents).
CAWG_TRAINING_MINING = "cawg.training-mining"

# Content-binding hash assertion label.
C2PA_HASH_DATA = "c2pa.hash.data"


@dataclass
class TrainingMiningControl:
    """
    Maps to the CAWG training-and-data-mining assertion. Lets the data
    publisher declare whether this content may be used for AI training / data
    mining -- the machine-readable consent signal the compliance ecosystem
    consumes.
    """
    # "allowed", "notAllowed", or "constrained"
    ai_training: str = "notAllowed"
    ai_generative_training: str = "notAllowed"
    data_mining: str = "notAllowed"
    ai_inference: str = "allowed"

    def to_assertion(self) -> dict[str, Any]:
        return {
            "label": CAWG_TRAINING_MINING,
            "data": {
                "entries": {
                    "cawg.ai_training": {"use": self.ai_training},
                    "cawg.ai_generative_training": {"use": self.ai_generative_training},
                    "cawg.data_mining": {"use": self.data_mining},
                    "cawg.ai_inference": {"use": self.ai_inference},
                }
            },
        }


def build_manifest(
    record: ProvenanceRecord,
    *,
    normalized_content_hash: Optional[str] = None,
    training_mining: Optional[TrainingMiningControl] = None,
    claim_generator: str = "Inverba/0.1",
    title: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build a C2PA-shaped sidecar manifest (as a dict) from a Inverba provenance
    record. This is the derived view -- the record stays authoritative.

    normalized_content_hash: if given, the manifest binds to the SEMANTIC
        content hash (stable across volatile noise) in addition to the raw
        hash. Recommended for dataset provenance where you care about content
        identity, not byte identity.
    """
    assertions: list[dict[str, Any]] = []

    # Content-binding hash assertion -- ties the manifest to the fetched bytes.
    assertions.append({
        "label": C2PA_HASH_DATA,
        "data": {
            "exclusions": [],
            "alg": "sha256",
            "hash": record.content_hash,
            "name": "raw content binding",
        },
    })

    if normalized_content_hash:
        assertions.append({
            "label": "inverba.semantic_hash",
            "data": {"alg": "sha256", "hash": normalized_content_hash,
                     "note": "stable semantic content hash (volatile scaffolding removed)"},
        })

    # Provenance / capture assertion.
    assertions.append({
        "label": "c2pa.actions",
        "data": {
            "actions": [{
                "action": "c2pa.created",
                "when": _iso(record.fetched_at),
                "softwareAgent": {"name": claim_generator},
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/webCapture",
            }],
        },
    })

    # Source URL assertion.
    assertions.append({
        "label": "inverba.source",
        "data": {"url": record.url, "fetched_at": _iso(record.fetched_at)},
    })

    # Training/mining consent -- the compliance-critical assertion.
    tm = training_mining or TrainingMiningControl()
    assertions.append(tm.to_assertion())

    # Corroboration assertion -- multi-party attestation, unique to Inverba.
    if record.corroborations:
        assertions.append({
            "label": "inverba.corroboration",
            "data": {
                "corroborator_count": len(record.corroborations),
                "corroborator_keys": [c.worker_public_key for c in record.corroborations],
                "all_agree_on_hash": all(
                    c.content_hash == record.content_hash for c in record.corroborations
                ),
            },
        })

    manifest = {
        "claim_generator": claim_generator,
        "title": title or record.url,
        "format": "application/inverba+json",
        "instance_id": f"xmp:iid:{hashlib.sha256((record.url + str(record.fetched_at)).encode()).hexdigest()[:32]}",
        "assertions": assertions,
        "signature_info": {
            "alg": "ed25519",
            "issuer": record.worker_public_key,
            "signature": record.signature,
            "cert_status": "self-signed",   # see conformance boundary in module docstring
        },
    }
    return manifest


def export_manifest_json(
    record: ProvenanceRecord,
    path: str,
    **kwargs,
) -> dict[str, Any]:
    """Write a sidecar manifest to `path` (e.g. content.json.c2pa) and return it."""
    manifest = build_manifest(record, **kwargs)
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def verify_manifest_binding(manifest: dict[str, Any], raw_content: bytes) -> dict[str, Any]:
    """
    Verify that a manifest's content-binding hash actually matches the bytes
    it claims to describe. This is the check a downstream consumer runs to
    confirm the manifest belongs to this data.

    (Signature validity against the Ed25519 key is checked separately via the
    core provenance verifier -- this function checks the CONTENT binding.)
    """
    actual = hashlib.sha256(raw_content).hexdigest()
    bound = None
    for a in manifest.get("assertions", []):
        if a.get("label") == C2PA_HASH_DATA:
            bound = a["data"]["hash"]
            break
    return {
        "has_binding": bound is not None,
        "binding_matches": (bound == actual) if bound else False,
        "expected_hash": bound,
        "actual_hash": actual,
    }


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
