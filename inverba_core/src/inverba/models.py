"""Core data models shared across fetch, extract, provenance, and store."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class FetchMethod(str, Enum):
    HTTP = "http"          # plain httpx GET, no JS execution
    BROWSER = "browser"     # playwright-rendered fetch (JS-heavy pages)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    ESCALATED = "escalated"   # extraction consensus disagreed; needs review


@dataclass
class FetchResult:
    """Raw result of fetching a single URL, prior to any extraction."""
    url: str
    final_url: str              # after redirects
    status_code: int
    content: bytes               # raw bytes as received, hashed as-is
    content_type: str
    method: FetchMethod
    fetched_at: float = field(default_factory=time.time)
    headers: dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    # Who retrieved these bytes. "native" = Inverba observed the origin itself;
    # anything else (e.g. "firecrawl") = a third party retrieved it and we are
    # only relaying. This changes what a signature over it MEANS, so it is
    # carried through to the provenance record and covered by the signature.
    fetched_by: str = "native"

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 300


@dataclass
class ExtractionResult:
    """Result of running the extraction pipeline over a FetchResult."""
    url: str
    markdown: Optional[str] = None
    structured: Optional[dict[str, Any]] = None
    schema_used: Optional[dict[str, Any]] = None
    model_used: Optional[str] = None
    confidence: Optional[float] = None       # None when no consensus was run
    disagreement: Optional[dict[str, Any]] = None  # populated iff ESCALATED
    extracted_at: float = field(default_factory=time.time)


@dataclass
class ProvenanceRecord:
    """
    A portable, independently verifiable claim about what was fetched.

    Exportable as standalone signed JSON -- verification does not require
    Inverba itself, only the public key and the standard library.
    """
    url: str
    content_hash: str            # sha256 hex digest of FetchResult.content
    fetched_at: float
    worker_public_key: str        # hex-encoded Ed25519 public key
    signature: str                 # hex-encoded Ed25519 signature
    # Who actually retrieved the bytes. COVERED BY THE SIGNATURE, so it cannot
    # be edited after the fact. "native" means this signer observed the origin
    # itself; any other value means a third party fetched it and this signer is
    # attesting only "this is what <party> gave me". A consumer must be able to
    # tell an observation from a relay -- that distinction is the whole point.
    fetched_by: str = "native"
    # Signed fetch metadata. Also covered by the signature. These let a verifier
    # judge whether the fetch was REAL -- a bot-wall / CAPTCHA soft-block returns
    # HTTP 200 with junk content, and the classic tell is a redirect to a
    # challenge URL (final_url != url) or a non-HTML content-type. Without these
    # in the signed record, verification passes perfectly over a signed CAPTCHA
    # page, which is the one failure that destroys a provenance product. They
    # default to observation-consistent values so older/simple records still
    # verify, but new records carry the real fetch context.
    status_code: int = 200
    final_url: str = ""            # after redirects; "" means "same as url"
    content_type: str = ""
    corroborations: list["ProvenanceRecord"] = field(default_factory=list)

    @property
    def is_independent_observation(self) -> bool:
        return self.fetched_by == "native"

    @property
    def was_redirected(self) -> bool:
        """A redirect to a different URL is the classic bot-wall / challenge tell."""
        return bool(self.final_url) and self.final_url != self.url

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "content_hash": self.content_hash,
            "fetched_at": self.fetched_at,
            "worker_public_key": self.worker_public_key,
            "signature": self.signature,
            "fetched_by": self.fetched_by,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "content_type": self.content_type,
            "corroborations": [c.to_dict() for c in self.corroborations],
        }


@dataclass
class Job:
    """A unit of work tracked in the job store."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    url: str = ""
    status: JobStatus = JobStatus.PENDING
    schema: Optional[dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    fetch_result: Optional[FetchResult] = None
    extraction_result: Optional[ExtractionResult] = None
    provenance: Optional[ProvenanceRecord] = None
    error: Optional[str] = None
