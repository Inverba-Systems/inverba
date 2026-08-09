"""
Inverba Core
============

Sovereign, verifiable, swarm-distributable web extraction engine.

Phase 0 scope (standalone core):
    - fetch:       async HTTP fetch engine, browser fallback optional/pluggable
    - extract:     markdown fast path + schema-driven structured extraction
    - provenance:  content-hash + Ed25519 signed attestation of every fetch
    - store:       SQLite-backed job store (no Redis required for local use)
    - cli:         `inverba scrape|crawl|verify`

No component in this package requires a network call to any Inverba-operated
service. Everything here runs standalone on one machine. The swarm/trust
layer (inverba-swarm) and Inverba Cloud are separate, optional packages.
"""

from .models import FetchResult, ExtractionResult, ProvenanceRecord, Job
from .fetch import FetchEngine
from .extract import ExtractionPipeline, OllamaBackend
from .provenance import ProvenanceSigner, verify_record, verify_with_corroborations
from .store import JobStore

# NOTE: multi-model consensus extraction is a separate commercial add-on, not
# part of the open core. The open core never imports it; it plugs into the same
# ModelBackend protocol in extract.py.

__version__ = "0.1.0"

__all__ = [
    "FetchResult",
    "ExtractionResult",
    "ProvenanceRecord",
    "Job",
    "FetchEngine",
    "ExtractionPipeline",
    "OllamaBackend",
    "ProvenanceSigner",
    "verify_record",
    "verify_with_corroborations",
    "JobStore",
]
